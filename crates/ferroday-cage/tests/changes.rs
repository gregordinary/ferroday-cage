//! Integration tests for reading what a run wrote through an overlay: a real
//! sandbox makes one change of each kind through an overlay mounted at a path,
//! and the change set read from its upper names each as what it is.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ferroday_cage::provision::{ChangeKind, ChangeSet, EntryKind};
use ferroday_cage::{Cage, Overlay};

/// Lays out the tree a run starts from: one entry for each kind of change the
/// script below makes, and some it leaves alone.
fn tree(dir: &Path) -> PathBuf {
    let tree = dir.join("tree");
    for sub in [
        "keep-dir",
        "rmdir/sub",
        "replace-dir/inner",
        "chmod-dir",
        "deep/a/b",
        "touched-dir",
    ] {
        std::fs::create_dir_all(tree.join(sub)).unwrap();
    }
    for file in [
        "keep",
        "modify",
        "chmod",
        "touch",
        "same",
        "delete",
        "rename-from",
        "link-src",
        "replace-file",
        "rmdir/sub/f",
        "replace-dir/inner/f",
        "deep/a/b/f",
    ] {
        std::fs::write(tree.join(file), b"original\n").unwrap();
    }
    std::os::unix::fs::symlink("keep", tree.join("symlink")).unwrap();
    // Stated, so the run's own modes are compared against known ones whatever
    // the caller's umask.
    for (path, mode) in [
        ("chmod", 0o644),
        ("chmod-dir", 0o755),
        ("replace-dir", 0o755),
    ] {
        std::fs::set_permissions(tree.join(path), std::fs::Permissions::from_mode(mode)).unwrap();
    }
    tree
}

/// One change of each kind, through the merged view at `/work`.
const SCRIPT: &str = "set -e; cd /work
echo changed > modify
chmod 600 chmod
touch -t 200101010000 touch
echo original > same
rm delete
mv rename-from rename-to
ln link-src link-dst
rm -r rmdir
rm -r replace-dir && mkdir -m 755 replace-dir && echo new > replace-dir/g
rm replace-file && mkdir replace-file
chmod 700 chmod-dir
touch touched-dir/new
echo new > added
mkdir added-dir && echo n > added-dir/f
ln -s /etc/passwd added-link
mkfifo added-fifo
echo deep > deep/a/b/f
rm symlink && ln -s modify symlink
cat keep keep-dir/. >/dev/null 2>&1 || true
";

#[test]
fn a_change_set_names_each_change_a_run_made() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("changes-each-kind");
    if !common::require::overlay(&dir) {
        return;
    }
    let tree = tree(&dir);
    let overlay = Overlay::new().lower(&tree).upper(dir.join("upper"));
    let status = Cage::builder()
        .rootfs(rootfs)
        .overlay_at("/work", overlay.clone())
        .command("/bin/sh")
        .args(["-c", SCRIPT])
        .build()
        .expect("a valid overlay mount")
        .run()
        .expect("the sandbox launches");
    assert!(status.success(), "the script makes every change");

    let changes = ChangeSet::read(&overlay).expect("the change set reads");
    let listed: Vec<(&str, ChangeKind, Option<EntryKind>, Option<EntryKind>)> = changes
        .changes()
        .iter()
        .map(|change| {
            (
                change.path().to_str().unwrap(),
                change.kind(),
                change.before(),
                change.now(),
            )
        })
        .collect();
    use ChangeKind::{Added, Modified, Removed, Replaced};
    use EntryKind::{Directory, File, Other, Symlink};
    assert_eq!(
        listed,
        [
            ("added", Added, None, Some(File)),
            ("added-dir", Added, None, Some(Directory)),
            ("added-dir/f", Added, None, Some(File)),
            ("added-fifo", Added, None, Some(Other)),
            ("added-link", Added, None, Some(Symlink)),
            ("chmod", Modified, Some(File), Some(File)),
            ("chmod-dir", Modified, Some(Directory), Some(Directory)),
            ("deep/a/b/f", Modified, Some(File), Some(File)),
            ("delete", Removed, Some(File), None),
            ("link-dst", Added, None, Some(File)),
            ("modify", Modified, Some(File), Some(File)),
            ("rename-from", Removed, Some(File), None),
            ("rename-to", Added, None, Some(File)),
            ("replace-dir/g", Added, None, Some(File)),
            ("replace-dir/inner", Removed, Some(Directory), None),
            ("replace-file", Replaced, Some(File), Some(Directory)),
            ("rmdir", Removed, Some(Directory), None),
            ("symlink", Modified, Some(Symlink), Some(Symlink)),
            ("touched-dir/new", Added, None, Some(File)),
        ],
        "a copied-up parent, a same-byte rewrite, a change of times, and a \
         file both names of a new link share are not changes"
    );

    let change = |path: &str| {
        changes
            .changes()
            .iter()
            .find(|change| change.path() == Path::new(path))
            .unwrap()
    };
    let named = |path: &str| {
        let change = change(path);
        (
            change.content_differs(),
            change.mode_differs(),
            change.owner_differs(),
            change.attributes_differ(),
        )
    };
    assert_eq!(named("modify"), (true, false, false, false));
    assert_eq!(named("chmod"), (false, true, false, false));
    assert_eq!(named("chmod-dir"), (false, true, false, false));
    assert_eq!(named("symlink"), (true, false, false, false));
    assert_eq!(change("modify").size(), Some(8));
    assert_eq!(change("replace-file").size(), None);
    assert!(changes.changes().iter().all(|change| change.is_readable()));
    assert_eq!(
        std::fs::read_to_string(tree.join("modify")).unwrap(),
        "original\n",
        "reading the change set changes nothing"
    );
}

#[test]
fn an_overlay_the_run_left_alone_has_no_changes() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("changes-none");
    if !common::require::overlay(&dir) {
        return;
    }
    let tree = tree(&dir);
    let overlay = Overlay::new().lower(&tree).upper(dir.join("upper"));
    let status = Cage::builder()
        .rootfs(rootfs)
        .overlay_at("/work", overlay.clone())
        .command("/bin/sh")
        .args(["-c", "cat /work/keep /work/deep/a/b/f > /dev/null"])
        .build()
        .expect("a valid overlay mount")
        .run()
        .expect("the sandbox launches");
    assert!(status.success());
    assert!(ChangeSet::read(&overlay).unwrap().is_empty());
}

/// A run's changes applied to the tree it started from leave the tree as the
/// run saw it, but for the named pipe the apply does not carry.
#[test]
fn a_run_applied_to_its_tree_leaves_the_tree_as_the_run_saw_it() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("changes-apply");
    if !common::require::overlay(&dir) {
        return;
    }
    let tree = tree(&dir);
    // The upper's birth time is the reference the apply holds the tree to,
    // less a margin of ten milliseconds; the tree is laid out before that.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let overlay = Overlay::new().lower(&tree).upper(dir.join("upper"));
    let status = Cage::builder()
        .rootfs(rootfs)
        .overlay_at("/work", overlay.clone())
        .command("/bin/sh")
        .args(["-c", SCRIPT])
        .build()
        .expect("a valid overlay mount")
        .run()
        .expect("the sandbox launches");
    assert!(status.success());

    let changes = ChangeSet::read(&overlay).unwrap();
    let report = changes.apply(&tree).run().expect("the changes apply");
    assert_eq!(report.skipped(), [Path::new("added-fifo")]);
    assert_eq!(report.applied().len(), changes.changes().len() - 1);

    let read = |path: &str| std::fs::read_to_string(tree.join(path)).unwrap();
    assert_eq!(read("modify"), "changed\n");
    assert_eq!(read("deep/a/b/f"), "deep\n");
    assert_eq!(read("rename-to"), "original\n");
    assert_eq!(read("replace-dir/g"), "new\n");
    for gone in ["delete", "rename-from", "rmdir", "replace-dir/inner"] {
        assert!(!tree.join(gone).exists(), "{gone} is removed");
    }
    assert!(tree.join("replace-file").is_dir());
    assert_eq!(
        std::fs::read_link(tree.join("symlink")).unwrap(),
        Path::new("modify")
    );
    let mode = |path: &str| {
        std::fs::symlink_metadata(tree.join(path))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode("chmod"), 0o600);
    assert_eq!(mode("chmod-dir"), 0o700);

    let left = ChangeSet::read(&overlay).unwrap();
    let left: Vec<&Path> = left.changes().iter().map(|change| change.path()).collect();
    assert_eq!(left, [Path::new("added-fifo")]);
}
