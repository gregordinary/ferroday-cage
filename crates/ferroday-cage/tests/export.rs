//! Integration tests for ownership-preserving rootfs export.
//!
//! The export forks a child that re-enters an identity map and reads the tree
//! from inside it, so these tests need a host that can create unprivileged user
//! namespaces; they skip explicitly where it cannot, as the sandbox tests do.
//! The subordinate round-trip additionally needs a range-map delegate and skips
//! without one.

use std::collections::HashMap;
use std::path::Path;

use ferroday_cage::IdentityMap;
use ferroday_cage::provision;

mod common;

/// Skips a test when the host cannot create unprivileged user namespaces.
///
/// The skip is explicit on stderr, and `FERRODAY_CAGE_REQUIRE_USERNS` turns it
/// into a failure so CI can assert the export tests actually ran.
fn userns_available() -> bool {
    match ferroday_cage::host::userns_blocker() {
        None => true,
        Some(blocker) => {
            assert!(
                std::env::var_os("FERRODAY_CAGE_REQUIRE_USERNS").is_none(),
                "unprivileged user namespaces are required but unavailable: {blocker}"
            );
            eprintln!("skipping: unprivileged user namespaces are unavailable: {blocker}");
            false
        }
    }
}

/// A unique, empty scratch directory for one test, removed when it drops.
///
/// The removal goes through [`provision::remove`] rather than
/// `std::fs::remove_dir_all`: these trees hold subordinate-owned entries the
/// calling user cannot unlink, which is the whole subject of the file.
fn scratch(tag: &str) -> Scratch {
    let dir =
        std::env::temp_dir().join(format!("ferroday-cage-export-{tag}-{}", std::process::id()));
    let _ = provision::remove(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch { path: dir }
}

/// A scratch directory that takes its tree with it.
///
/// Dereferences to its [`Path`], so it stands in for one at a call site.
struct Scratch {
    path: std::path::PathBuf,
}

impl std::ops::Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    /// Best effort: a test that has already failed should report its own
    /// assertion, not a cleanup failure raised while it unwinds.
    fn drop(&mut self) {
        let _ = provision::remove(&self.path);
    }
}

/// One parsed tar entry, enough to assert ownership, type, and attributes.
#[derive(Debug)]
struct Entry {
    path: Vec<u8>,
    typeflag: u8,
    uid: u64,
    gid: u64,
    mode: u32,
    linkname: Vec<u8>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
}

/// A minimal ustar/pax reader for the archives the exporter writes: enough to
/// verify them without reaching into the crate's own (crate-private) reader.
fn parse_tar(data: &[u8]) -> Vec<Entry> {
    let field = |b: &[u8]| {
        let end = b.iter().position(|c| *c == 0).unwrap_or(b.len());
        b[..end].to_vec()
    };
    let octal = ferroday_cage_testkit::tar::read_octal;

    let mut entries = Vec::new();
    let mut pos = 0;
    let mut pax_path: Option<Vec<u8>> = None;
    let mut pax_link: Option<Vec<u8>> = None;
    let mut pax_xattrs: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    while pos + 512 <= data.len() {
        let block = &data[pos..pos + 512];
        if block.iter().all(|b| *b == 0) {
            break;
        }
        pos += 512;
        let name = field(&block[0..100]);
        let prefix = field(&block[345..500]);
        let mut path = if prefix.is_empty() {
            name
        } else {
            let mut p = prefix;
            p.push(b'/');
            p.extend_from_slice(&name);
            p
        };
        let mode = octal(&block[100..108]) as u32;
        let uid = octal(&block[108..116]);
        let gid = octal(&block[116..124]);
        let size = octal(&block[124..136]) as usize;
        let typeflag = block[156];
        let mut linkname = field(&block[157..257]);
        let body = &data[pos..pos + size];
        pos += size.div_ceil(512) * 512;

        if typeflag == b'x' {
            parse_pax(body, &mut pax_path, &mut pax_link, &mut pax_xattrs);
            continue;
        }
        if let Some(p) = pax_path.take() {
            path = p;
        }
        if let Some(l) = pax_link.take() {
            linkname = l;
        }
        let xattrs = std::mem::take(&mut pax_xattrs);
        entries.push(Entry {
            path,
            typeflag,
            uid,
            gid,
            mode,
            linkname,
            xattrs,
        });
    }
    entries
}

/// Parses the pax records this exporter emits: `path`, `linkpath`, and
/// `SCHILY.xattr.*`.
fn parse_pax(
    mut data: &[u8],
    path: &mut Option<Vec<u8>>,
    link: &mut Option<Vec<u8>>,
    xattrs: &mut Vec<(Vec<u8>, Vec<u8>)>,
) {
    while !data.is_empty() {
        let space = data.iter().position(|b| *b == b' ').unwrap();
        let len: usize = std::str::from_utf8(&data[..space])
            .unwrap()
            .parse()
            .unwrap();
        let record = &data[space + 1..len];
        data = &data[len..];
        let record = &record[..record.len() - 1]; // trailing newline
        let eq = record.iter().position(|b| *b == b'=').unwrap();
        let (key, value) = (&record[..eq], &record[eq + 1..]);
        match key {
            b"path" => *path = Some(value.to_vec()),
            b"linkpath" => *link = Some(value.to_vec()),
            _ => {
                if let Some(name) = key.strip_prefix(b"SCHILY.xattr.") {
                    xattrs.push((name.to_vec(), value.to_vec()));
                }
            }
        }
    }
}

/// Indexes entries by path for order-independent assertions.
fn by_path(entries: &[Entry]) -> HashMap<Vec<u8>, &Entry> {
    entries.iter().map(|e| (e.path.clone(), e)).collect()
}

/// Under the single-identity map the whole tree is exported as root — the
/// identity the sandbox runs everything as — and its structure round-trips:
/// nested directories, a file, a symlink and its target, a coalesced hardlink,
/// and a skipped FIFO.
#[test]
fn exports_a_single_mapped_tree() {
    if !userns_available() {
        return;
    }
    let dir = scratch("single");
    let root = dir.join("root");
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::create_dir_all(root.join("usr/bin")).unwrap();
    std::fs::create_dir_all(root.join("data")).unwrap();
    std::fs::write(root.join("etc/hostname"), b"host\n").unwrap();
    write_mode(&root.join("usr/bin/tool"), b"bin\n", 0o755);
    std::os::unix::fs::symlink("../usr/share/zoneinfo/UTC", root.join("etc/localtime")).unwrap();
    // The longest target Linux will store: `PATH_MAX - 1`, one byte short of
    // the mechanism's link buffer. `readlinkat` reports a truncated target as a
    // success, so the export refuses a target that fills that buffer — and this
    // is the boundary that must still be exported whole.
    let longest = "l".repeat(4095);
    std::os::unix::fs::symlink(&longest, root.join("etc/longest")).unwrap();
    std::fs::write(root.join("data/a"), b"shared").unwrap();
    std::fs::hard_link(root.join("data/a"), root.join("data/b")).unwrap();

    // A FIFO, best-effort: if it cannot be created the skip assertion is simply
    // not made.
    let fifo = make_fifo(&root.join("gate"));
    // A user xattr, best-effort: the filesystem may not support it.
    let xattr_set = set_user_xattr(&root.join("etc/hostname"), b"user.test", b"present");

    let mut out = Vec::new();
    provision::export_tar(&root, &mut out, IdentityMap::Single).expect("export should succeed");
    let entries = parse_tar(&out);
    let index = by_path(&entries);

    // The archive opens with the rootfs root as a `./` directory entry, so it
    // is a drop-in for `tar -C rootfs .` and every member is `./`-prefixed.
    let root_entry = &entries[0];
    assert_eq!(
        root_entry.path, b"./",
        "the archive must lead with a ./ entry"
    );
    assert_eq!(root_entry.typeflag, b'5');

    for expected in [
        &b"./etc/"[..],
        b"./etc/hostname",
        b"./usr/",
        b"./usr/bin/",
        b"./usr/bin/tool",
        b"./data/",
    ] {
        assert!(index.contains_key(expected), "missing {:?}", bstr(expected));
    }

    // Everything is root inside the single map.
    for entry in &entries {
        assert_eq!(entry.uid, 0, "{:?} uid", bstr(&entry.path));
        assert_eq!(entry.gid, 0, "{:?} gid", bstr(&entry.path));
    }

    // Directories carry a trailing slash and the directory typeflag.
    assert_eq!(index[&b"./etc/"[..]].typeflag, b'5');
    // Modes survive.
    assert_eq!(index[&b"./usr/bin/tool"[..]].mode & 0o777, 0o755);

    // The symlink and its target.
    let link = index[&b"./etc/localtime"[..]];
    assert_eq!(link.typeflag, b'2');
    assert_eq!(link.linkname, b"../usr/share/zoneinfo/UTC");

    // The longest legal target survives whole, through a pax `linkpath` record
    // the ustar header cannot hold.
    let longest_link = index[&b"./etc/longest"[..]];
    assert_eq!(longest_link.typeflag, b'2');
    assert_eq!(longest_link.linkname, longest.as_bytes());

    // Exactly one of the hardlinked pair is a full file, the other a link onto
    // it.
    let a = index[&b"./data/a"[..]];
    let b = index[&b"./data/b"[..]];
    let (regular, hard) = if a.typeflag == b'0' { (a, b) } else { (b, a) };
    assert_eq!(regular.typeflag, b'0');
    assert_eq!(hard.typeflag, b'1');
    assert_eq!(hard.linkname, regular.path);

    // The FIFO is dropped.
    if fifo {
        assert!(
            !index.contains_key(&b"./gate"[..]),
            "the FIFO should be skipped"
        );
    }

    // The user xattr survives as a SCHILY record.
    if xattr_set {
        let host = index[&b"./etc/hostname"[..]];
        let found = host
            .xattrs
            .iter()
            .find(|(k, _)| k == b"user.test")
            .map(|(_, v)| v.clone());
        assert_eq!(found.as_deref(), Some(&b"present"[..]), "user xattr lost");
    }

    let _ = provision::remove(&dir);
}

#[test]
fn a_filter_narrows_what_the_archive_holds() {
    // The filter runs on this side of the frame stream, so this is the test
    // that the exclusion survives the real walk: the child reads and streams
    // everything, and what reaches the archive is what the predicate kept.
    if !userns_available() {
        return;
    }
    let dir = scratch("filter");
    let root = dir.join("root");
    std::fs::create_dir_all(root.join("dev/pts")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    std::fs::create_dir_all(root.join("var/cache/apt")).unwrap();
    std::fs::write(root.join("etc/hostname"), b"host\n").unwrap();
    std::fs::write(root.join("dev/null-ish"), b"placeholder\n").unwrap();
    std::os::unix::fs::symlink("/proc/self/fd", root.join("dev/fd")).unwrap();
    // Large enough that the encoder has to discard several buffers of data
    // rather than a single short read.
    std::fs::write(root.join("var/cache/apt/big.deb"), vec![b'x'; 512 * 1024]).unwrap();

    let dev = Path::new("/dev");
    let cache = Path::new("/var/cache");
    let mut out = Vec::new();
    provision::Export::new(&root)
        .filter(move |entry| {
            // Keep the /dev mount point and nothing under it, and drop the
            // package cache outright.
            !entry.path().starts_with(cache)
                && (entry.path() == dev || !entry.path().starts_with(dev))
        })
        .write_to(&mut out)
        .expect("export should succeed");
    let entries = parse_tar(&out);
    let index = by_path(&entries);

    // The mount point itself is kept, so the deployed runtime has somewhere to
    // mount over.
    assert_eq!(index[&b"./dev/"[..]].typeflag, b'5');
    assert!(index.contains_key(&b"./etc/hostname"[..]));
    assert!(index.contains_key(&b"./var/"[..]));

    for gone in [
        &b"./dev/pts/"[..],
        b"./dev/null-ish",
        b"./dev/fd",
        b"./var/cache/",
        b"./var/cache/apt/",
        b"./var/cache/apt/big.deb",
    ] {
        assert!(
            !index.contains_key(gone),
            "{:?} should have been filtered out",
            bstr(gone)
        );
    }

    // The discarded half-megabyte did not desynchronize the frame stream: the
    // members are exactly the kept ones, in the walk's sorted order, so nothing
    // after the drop was misread as a header.
    let paths: Vec<Vec<u8>> = entries.iter().map(|e| e.path.clone()).collect();
    assert_eq!(
        paths,
        [
            &b"./"[..],
            b"./dev/",
            b"./etc/",
            b"./etc/hostname",
            b"./var/",
        ]
        .map(<[u8]>::to_vec)
    );

    let _ = provision::remove(&dir);
}

#[test]
fn a_failed_export_leaves_the_previous_archive_at_the_destination() {
    if !userns_available() {
        return;
    }
    let dir = scratch("atomic");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("file"), b"contents\n").unwrap();

    let archive = dir.join("rootfs.tar");
    provision::Export::new(&root)
        .map(IdentityMap::Single)
        .write_to_path(&archive)
        .expect("the first export succeeds");
    let published = std::fs::read(&archive).unwrap();
    assert!(!published.is_empty());

    // A source that is not there is the ordinary typo, and it fails only after
    // the destination has been opened. Opening the destination directly would
    // have truncated the archive above to write nothing into it, and removing
    // the truncated result does not bring the previous archive back.
    let err = provision::Export::new(dir.join("absent"))
        .map(IdentityMap::Single)
        .write_to_path(&archive)
        .expect_err("a missing source cannot be exported");
    assert!(matches!(err, provision::ProvisionError::Io { .. }), "{err}");
    assert_eq!(
        std::fs::read(&archive).unwrap(),
        published,
        "the previous archive must survive a failed export",
    );

    // And nothing of the failed run is left beside it.
    let leftovers: Vec<_> = std::fs::read_dir(&*dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().ends_with(".partial"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "staging files left behind: {leftovers:?}"
    );

    let _ = provision::remove(&dir);
}

#[test]
fn an_archive_written_inside_the_tree_it_exports_is_refused() {
    if !userns_available() {
        return;
    }
    let dir = scratch("dest-inside");
    let root = dir.join("root");
    std::fs::create_dir_all(root.join("var")).unwrap();
    std::fs::write(root.join("file"), b"contents\n").unwrap();

    // The walk would reach the archive it is being written into, so what lands
    // in it depends on how far the encoder had got. Refusing is the contract;
    // the staging file the export would otherwise have created inside the tree
    // is refused with it.
    for dest in [root.join("rootfs.tar"), root.join("var/rootfs.tar")] {
        let err = provision::Export::new(&root)
            .map(IdentityMap::Single)
            .write_to_path(&dest)
            .expect_err("a destination inside the tree is refused");
        assert!(
            matches!(err, provision::ProvisionError::ExportDestInside { .. }),
            "{err}",
        );
        assert!(!dest.exists(), "nothing was written at {}", dest.display());
    }

    // The sibling case the refusal must not take with it: a name that shares a
    // prefix with the rootfs is not inside it.
    let sibling = dir.join("rootfs.tar");
    provision::Export::new(&root)
        .map(IdentityMap::Single)
        .write_to_path(&sibling)
        .expect("a destination beside the tree is fine");
    assert!(sibling.exists());

    let _ = provision::remove(&dir);
}

/// A subordinate-mapped bootstrap chowns files to real system ids stored on the
/// host at an offset; the export reads them back at the id the tree intends, not
/// the host subordinate id. This is the export's reason to exist.
#[cfg(feature = "subid")]
#[test]
fn exports_subordinate_ownership_at_intended_ids() {
    use ferroday_cage::Cage;

    if !userns_available() {
        return;
    }
    if ferroday_cage::host::range_map_blocker().is_some() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_SUBID").is_none(),
            "a range map is required but unavailable"
        );
        eprintln!("skipping: no delegate can establish a range map");
        return;
    }
    let Some(rootfs) = fixture_rootfs() else {
        return;
    };

    let dir = scratch("subordinate");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("probe"), b"owned").unwrap();

    // Inside a subordinate map, chown the bind-mounted host file to a system id.
    // The bind shares the inode, so the host file's owner becomes the offset id.
    let cage = Cage::builder()
        .rootfs(rootfs)
        .bind(&work, "/work")
        .command("/bin/sh")
        .args(["-c", "chown 42:42 /work/probe"])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    let status = cage.run().expect("the sandbox should launch");
    assert!(status.success(), "chown in the cage failed");

    // The host now sees the file at the offset id; the export must read it as 42.
    let mut out = Vec::new();
    provision::export_tar(&work, &mut out, IdentityMap::Subordinate)
        .expect("export should succeed");
    let entries = parse_tar(&out);
    let probe = entries
        .iter()
        .find(|e| e.path == b"./probe")
        .expect("the probe file should be in the archive");
    assert_eq!(
        probe.uid, 42,
        "ownership did not round-trip to the intended id"
    );
    assert_eq!(probe.gid, 42, "group did not round-trip to the intended id");

    // The tree now holds a foreign-owned file, so the map-assisted removal is
    // what cleans it up.
    provision::remove(&dir).expect("the range-mapped tree should be removable");
}

/// The explicit-mapper variants export and remove a foreign-owned tree through a
/// caller-supplied delegate, the path a site with its own mapper takes. The
/// bundled `SubidMapper` stands in for a custom one; it exercises the same
/// `_with` code path (resolve through the given mapper, not the default chain).
#[cfg(feature = "subid")]
#[test]
fn explicit_mapper_exports_and_removes() {
    use ferroday_cage::{Cage, SubidMapper};

    if !userns_available() {
        return;
    }
    if ferroday_cage::host::range_map_blocker().is_some() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_SUBID").is_none(),
            "a range map is required but unavailable"
        );
        eprintln!("skipping: no delegate can establish a range map");
        return;
    }
    let Some(rootfs) = fixture_rootfs() else {
        return;
    };

    let dir = scratch("explicit-mapper");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("probe"), b"owned").unwrap();

    let cage = Cage::builder()
        .rootfs(rootfs)
        .bind(&work, "/work")
        .command("/bin/sh")
        .args(["-c", "chown 42:42 /work/probe"])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    assert!(cage.run().expect("the sandbox should launch").success());

    let mapper = SubidMapper::new();
    let mut out = Vec::new();
    provision::Export::new(&work)
        .map(IdentityMap::Subordinate)
        .mapper(&mapper)
        .write_to(&mut out)
        .expect("export through the explicit mapper should succeed");
    let entries = parse_tar(&out);
    let probe = entries.iter().find(|e| e.path == b"./probe").unwrap();
    assert_eq!(probe.uid, 42);

    // Remove the foreign-owned tree through the same explicit mapper.
    provision::Remove::new(&dir)
        .map(IdentityMap::Subordinate)
        .mapper(&mapper)
        .run()
        .expect("removal through the explicit mapper should succeed");
    assert!(!dir.exists());
}

/// Without a delegate, a subordinate export cannot read the tree and says so.
/// Only meaningful where no range map is available; where one is, the export
/// would instead succeed.
#[test]
fn a_subordinate_export_without_a_delegate_is_typed() {
    if ferroday_cage::host::userns_blocker().is_some() {
        return;
    }
    #[cfg(feature = "subid")]
    if ferroday_cage::host::range_map_blocker().is_none() {
        eprintln!("skipping: a delegate is available, so the export would succeed");
        return;
    }

    let dir = scratch("no-delegate");
    let root = dir.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("file"), b"x").unwrap();

    let mut out = Vec::new();
    let err = provision::export_tar(&root, &mut out, IdentityMap::Subordinate)
        .expect_err("a subordinate export needs a delegate");
    assert!(
        matches!(err, provision::ProvisionError::ExportUnprivileged { .. }),
        "{err}"
    );
    let _ = provision::remove(&dir);
}

/// A delegate that resolves the requested map and then refuses to apply it:
/// the shape of a helper that is present when the removal is planned and
/// fails at the map gate.
#[derive(Debug)]
struct RefusesToApply;

impl ferroday_cage::IdMapper for RefusesToApply {
    fn resolve(
        &self,
        _request: &IdentityMap,
    ) -> Result<ferroday_cage::ResolvedMap, ferroday_cage::IdMapError> {
        Ok(ferroday_cage::ResolvedMap::new(
            vec![ferroday_cage::IdRange {
                inside: 0,
                outside: rustix::process::getuid().as_raw(),
                count: 1,
            }],
            vec![ferroday_cage::IdRange {
                inside: 0,
                outside: rustix::process::getgid().as_raw(),
                count: 1,
            }],
        ))
    }

    fn apply(
        &self,
        _pid: u32,
        _map: &ferroday_cage::ResolvedMap,
    ) -> Result<(), ferroday_cage::IdMapError> {
        Err(ferroday_cage::IdMapError::unsatisfiable(
            "the delegate refuses at the gate",
        ))
    }
}

/// A delegate that cannot resolve the map at all: the removal fails before
/// anything is forked.
#[derive(Debug)]
struct RefusesToResolve;

impl ferroday_cage::IdMapper for RefusesToResolve {
    fn resolve(
        &self,
        _request: &IdentityMap,
    ) -> Result<ferroday_cage::ResolvedMap, ferroday_cage::IdMapError> {
        Err(ferroday_cage::IdMapError::unsatisfiable(
            "the delegate has no allocation",
        ))
    }

    fn apply(
        &self,
        _pid: u32,
        _map: &ferroday_cage::ResolvedMap,
    ) -> Result<(), ferroday_cage::IdMapError> {
        unreachable!("resolve refuses first")
    }
}

/// A tree the plain removal is refused: one entry inside a directory that
/// denies write, so `unlinkat` fails with `EACCES` and the removal escalates
/// into the identity map. Returns the tree's path.
///
/// Cheaper than building a foreign-owned tree through a range-mapped sandbox,
/// and it reaches the same escalation. Root is refused nothing, so a caller
/// that is root must skip.
fn refuses_plain_removal(dir: &Path) -> std::path::PathBuf {
    let tree = dir.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("held"), b"x").unwrap();
    set_mode(&tree, 0o500);
    tree
}

/// Skips a test that needs a permission the caller can actually be refused.
fn unprivileged_caller() -> bool {
    if rustix::process::geteuid().is_root() {
        eprintln!("skipping: root is refused nothing, so the plain removal succeeds");
        return false;
    }
    true
}

/// A removal whose delegate fails at the map gate reports that failure
/// instead of hanging.
///
/// The removal child blocks on the gate until the go byte or an end-of-file
/// arrives. A caller that returned the delegate's error while still holding
/// its own end of the gate open would strand the child there, and the wait
/// that follows would never return: this test hangs rather than fails if the
/// gate is not closed on the way out.
#[test]
fn a_removal_whose_delegate_cannot_apply_is_typed() {
    if !userns_available() || !unprivileged_caller() {
        return;
    }

    let dir = scratch("apply-refused");
    let tree = refuses_plain_removal(&dir);

    let err = provision::Remove::new(&tree)
        .mapper(&RefusesToApply)
        .run()
        .expect_err("a delegate that cannot apply the map fails the removal");
    assert!(
        matches!(err, provision::ProvisionError::RemoveUnprivileged { .. }),
        "{err}"
    );

    set_mode(&tree, 0o700);
    provision::remove(&dir).expect("the scratch tree should clean up");
}

/// An export whose delegate fails at the map gate reports that failure
/// instead of hanging: the same abandon path as the removal above, on the
/// other consumer of the gate protocol.
#[test]
fn an_export_whose_delegate_cannot_apply_is_typed() {
    if !userns_available() {
        return;
    }

    let dir = scratch("export-apply-refused");
    std::fs::write(dir.join("file"), b"x").unwrap();

    let mut out = Vec::new();
    let err = ferroday_cage::provision::Export::new(&dir)
        .map(IdentityMap::Subordinate)
        .mapper(&RefusesToApply)
        .write_to(&mut out)
        .expect_err("a delegate that cannot apply the map fails the export");
    assert!(
        matches!(err, provision::ProvisionError::ExportUnprivileged { .. }),
        "{err}"
    );

    provision::remove(&dir).expect("the scratch tree should clean up");
}

/// A removal whose delegate cannot resolve the map is typed too — the
/// counterpart of the export's own no-delegate case, one step earlier.
#[test]
fn a_removal_whose_delegate_cannot_resolve_is_typed() {
    if !unprivileged_caller() {
        return;
    }

    let dir = scratch("resolve-refused");
    let tree = refuses_plain_removal(&dir);

    let err = provision::Remove::new(&tree)
        .mapper(&RefusesToResolve)
        .run()
        .expect_err("a delegate that cannot resolve the map fails the removal");
    assert!(
        matches!(err, provision::ProvisionError::RemoveUnprivileged { .. }),
        "{err}"
    );

    set_mode(&tree, 0o700);
    provision::remove(&dir).expect("the scratch tree should clean up");
}

/// Two trees with identical content built in opposite entry-creation orders
/// export, under one epoch, to byte-identical archives, and the archive is
/// sorted. The child's sort equalizes the filesystem's storage order and the
/// clamp equalizes wall-clock stamps: the property a reproducible build needs.
#[test]
fn exports_are_reproducible_across_entry_order() {
    if !userns_available() {
        return;
    }
    let dir = scratch("reproducible");
    let forward = dir.join("forward");
    let reverse = dir.join("reverse");
    let n: usize = 6;
    build_reproducible_tree(&forward, &(0..n).collect::<Vec<usize>>());
    build_reproducible_tree(&reverse, &(0..n).rev().collect::<Vec<usize>>());

    let epoch = 1_600_000_000;
    let mut a = Vec::new();
    let mut b = Vec::new();
    provision::Export::new(&forward)
        .clamp_mtime(epoch)
        .write_to(&mut a)
        .expect("export should succeed");
    provision::Export::new(&reverse)
        .clamp_mtime(epoch)
        .write_to(&mut b)
        .expect("export should succeed");

    // Identical trees, opposite storage orders, one archive.
    assert_eq!(a, b, "identical trees did not export to identical archives");

    // The archive is sorted, so the equality is not a filesystem coincidence:
    // without the child's sort the scrambled creation order would show through.
    let entries = parse_tar(&a);
    let paths: Vec<&[u8]> = entries.iter().map(|e| e.path.as_slice()).collect();
    let expected: [&[u8]; 14] = [
        b"./",
        b"./alpha",
        b"./bravo",
        b"./charlie",
        b"./delta",
        b"./echo",
        b"./foxtrot",
        b"./nested/",
        b"./nested/alpha",
        b"./nested/bravo",
        b"./nested/charlie",
        b"./nested/delta",
        b"./nested/echo",
        b"./nested/foxtrot",
    ];
    assert_eq!(paths, expected, "entries are not in sorted order");

    let _ = provision::remove(&dir);
}

/// A directory larger than a single `getdents` batch exports with every entry
/// present and in sorted order, exercising the multi-pass successor scan.
#[test]
fn exports_a_large_directory_in_sorted_order() {
    if !userns_available() {
        return;
    }
    let dir = scratch("large-dir");
    let root = dir.join("root");
    let big = root.join("big");
    std::fs::create_dir_all(&big).unwrap();
    let count: usize = 300;
    // Create in reverse so the on-disk order is not already sorted.
    for i in (0..count).rev() {
        std::fs::write(big.join(format!("f{i:04}")), b"x").unwrap();
    }

    let mut out = Vec::new();
    provision::Export::new(&root)
        .clamp_mtime(1_600_000_000)
        .write_to(&mut out)
        .expect("export should succeed");

    let entries = parse_tar(&out);
    let got: Vec<Vec<u8>> = entries
        .iter()
        .filter(|e| e.typeflag == b'0')
        .filter_map(|e| e.path.strip_prefix(&b"./big/"[..]).map(|s| s.to_vec()))
        .collect();
    let expected: Vec<Vec<u8>> = (0..count)
        .map(|i| format!("f{i:04}").into_bytes())
        .collect();
    assert_eq!(
        got, expected,
        "the large directory did not export in sorted order"
    );

    let _ = provision::remove(&dir);
}

/// A launch leaves its mount points in the rootfs, and nothing else. What a
/// provisioning sandbox contributes to a tree is what an export of that tree
/// carries into whatever is made of it, so it is asserted rather than observed.
#[test]
fn a_launch_leaves_only_its_mount_points_in_the_exported_tree() {
    let Some(fixture) = fixture_rootfs() else {
        return;
    };
    let dir = scratch("residue");
    let root = dir.join("root");
    copy_fixture(fixture, &root);
    // The preconditions the assertions below are about: a rootfs that ships
    // none of the paths the managed profile mounts on, and no resolv.conf.
    for mount_point in ["dev", "proc", "tmp"] {
        let _ = std::fs::remove_dir_all(root.join(mount_point));
    }
    let _ = std::fs::remove_file(root.join("etc/resolv.conf"));

    // A caller's own binds alongside the managed profile: a file bind, whose
    // target the launch creates and takes away again, and a directory bind,
    // whose mount point is part of what the launch contributes and stays.
    let bound_file = dir.join("bound-file");
    let bound_dir = dir.join("bound-dir");
    std::fs::write(&bound_file, b"caller content\n").expect("the bind source is writable");
    std::fs::create_dir_all(&bound_dir).expect("the bind source is creatable");

    // Host networking is the only posture that binds resolv.conf, so it is the
    // one that creates a target to mount onto — and the one whose cleanup this
    // asserts. The command resolves a name, so the bind is exercised rather
    // than merely established.
    let cage = ferroday_cage::Cage::builder()
        .rootfs(&root)
        .command("/bin/busybox")
        .args(["nslookup", "example.com"])
        .network(ferroday_cage::Network::Host)
        .bind_ro(&bound_file, "/etc/caller-bound")
        .bind_ro(&bound_dir, "/mnt/caller-bound")
        .build()
        .expect("the cage builds");
    let bound = cage
        .resolved_inputs()
        .mounts
        .iter()
        .any(|mount| mount.get_target() == Path::new("/etc/resolv.conf"));
    let status = cage.run().expect("the cage runs");
    if bound {
        assert!(
            status.success(),
            "DNS must work in the sandbox when the host's resolv.conf is bound: {status:?}"
        );
    }

    let mut out = Vec::new();
    provision::export_tar(&root, &mut out, IdentityMap::Single).expect("export should succeed");
    let entries = parse_tar(&out);
    let index = by_path(&entries);

    // The `/dev` the sandbox assembles is built inside the tmpfs that covers
    // the mount point, so the device nodes, the symlinks, `pts` and `shm` all
    // go with the namespace. What reaches the tree is the mount point alone.
    let under_dev: Vec<String> = entries
        .iter()
        .filter(|entry| entry.path.starts_with(b"./dev/") && entry.path != b"./dev/")
        .map(|entry| bstr(&entry.path))
        .collect();
    assert!(
        under_dev.is_empty(),
        "the launch left entries under ./dev/: {under_dev:?}"
    );

    // A mount point carries the mode of the directory it stands for. `/tmp` is
    // the case that matters and the one that proves the umask cannot reach the
    // tree: `mkdir(1777)` under the conventional `umask 022` would yield 1755.
    for (path, mode) in [
        (&b"./dev/"[..], 0o755),
        (b"./proc/", 0o755),
        (b"./tmp/", 0o1777),
    ] {
        let entry = index
            .get(path)
            .unwrap_or_else(|| panic!("no {} in the export", bstr(path)));
        assert_eq!(entry.typeflag, b'5', "{} is not a directory", bstr(path));
        assert_eq!(
            entry.mode & 0o7777,
            mode,
            "{} has mode {:04o}, expected {mode:04o}",
            bstr(path),
            entry.mode & 0o7777
        );
    }

    // The files a launch creates rather than mounts on something the rootfs
    // ships. Each exists for the sandbox's life and is taken away again
    // afterwards, so the tree is as it was: the export holds no resolver
    // configuration the rootfs never had, and no empty file where a caller's
    // bind was.
    for (path, what) in [
        (&b"./etc/resolv.conf"[..], "the managed resolv.conf bind"),
        (b"./etc/caller-bound", "a caller's own file bind"),
    ] {
        assert!(
            !index.contains_key(path),
            "{what} left an empty {} behind",
            bstr(path)
        );
    }
    for path in ["etc/resolv.conf", "etc/caller-bound"] {
        assert!(
            !root.join(path).exists(),
            "the {path} mount target outlived the sandbox"
        );
    }

    // A directory mount point is the other half of the rule: the caller's
    // directory bind leaves its mount point, as the managed profile's do.
    let entry = index
        .get(&b"./mnt/caller-bound/"[..])
        .expect("a caller's directory bind leaves its mount point");
    assert_eq!(entry.typeflag, b'5');
    assert_eq!(entry.mode & 0o7777, 0o755);

    let _ = provision::remove(&dir);
}

/// The fixture rootfs, or `None` when the sandbox tests should skip.
fn fixture_rootfs() -> Option<&'static Path> {
    common::fixture_rootfs()
}

/// Copies the shared fixture into `dest`, so a test that launches a sandbox
/// over it cannot mutate the tree every other test reads.
fn copy_fixture(fixture: &Path, dest: &Path) {
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(fixture)
        .arg(dest)
        .status()
        .expect("cp runs");
    assert!(status.success(), "copying the fixture rootfs failed");
}

/// Builds a fixed tree — six top-level files and a `nested/` directory holding
/// the same six — creating entries in the sequence `order`, so two trees can be
/// built with identical content but different on-disk storage order.
fn build_reproducible_tree(root: &Path, order: &[usize]) {
    let names = ["delta", "alpha", "foxtrot", "bravo", "echo", "charlie"];
    std::fs::create_dir_all(root.join("nested")).unwrap();
    for &i in order {
        let name = names[i];
        std::fs::write(root.join(name), name.as_bytes()).unwrap();
        std::fs::write(root.join("nested").join(name), name.as_bytes()).unwrap();
    }
}

/// Writes a file with an explicit mode.
fn write_mode(path: &Path, data: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, data).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Sets an existing path's mode.
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Creates a FIFO, returning whether it was created.
fn make_fifo(path: &Path) -> bool {
    use rustix::fs::{CWD, FileType, Mode, mknodat};
    mknodat(CWD, path, FileType::Fifo, Mode::from_raw_mode(0o644), 0).is_ok()
}

/// Sets a user extended attribute, returning whether it took (the filesystem
/// may not support user xattrs).
fn set_user_xattr(path: &Path, name: &[u8], value: &[u8]) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    rustix::fs::setxattr(path, &*name, value, rustix::fs::XattrFlags::empty()).is_ok()
}

/// Renders bytes for an assertion message.
fn bstr(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A tree copied into a single-mapped rootfs lands as root, whatever the source
/// says: the child writes its own one-id map, so root inside is the caller
/// outside and no other id is representable.
#[test]
fn a_single_map_copy_lands_everything_as_root() {
    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-single");
    let source = dir.join("source");
    std::fs::create_dir_all(source.join("etc")).unwrap();
    std::fs::write(source.join("etc/motd"), b"hello\n").unwrap();
    std::os::unix::fs::symlink("motd", source.join("etc/greeting")).unwrap();
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    provision::CopyIn::new(&source, &rootfs)
        .run()
        .expect("the copy succeeds");

    assert_eq!(std::fs::read(rootfs.join("etc/motd")).unwrap(), b"hello\n");
    assert_eq!(
        std::fs::read_link(rootfs.join("etc/greeting")).unwrap(),
        Path::new("motd"),
    );
    // Everything the copy created is owned by the caller on the host, which is
    // what root inside a single map is.
    let caller = rustix::process::geteuid().as_raw();
    for entry in ["etc", "etc/motd", "etc/greeting"] {
        let meta = std::fs::symlink_metadata(rootfs.join(entry)).unwrap();
        assert_eq!(
            std::os::unix::fs::MetadataExt::uid(&meta),
            caller,
            "{entry} is not the caller's",
        );
    }
    let _ = provision::remove(&dir);
}

/// Modes and directory structure survive the copy, and a mode that denies the
/// owner write does not stop the directory's own contents being created.
#[test]
fn a_copy_preserves_modes_and_structure() {
    use std::os::unix::fs::PermissionsExt;

    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-modes");
    let source = dir.join("source");
    std::fs::create_dir_all(source.join("locked")).unwrap();
    std::fs::write(source.join("locked/inside"), b"read-only home\n").unwrap();
    std::fs::write(source.join("script"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(source.join("script"), PermissionsExt::from_mode(0o755)).unwrap();
    // Applied on the way out of the directory, after its contents exist.
    std::fs::set_permissions(source.join("locked"), PermissionsExt::from_mode(0o555)).unwrap();
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    provision::CopyIn::new(&source, &rootfs)
        .run()
        .expect("the copy succeeds");

    let mode = |path: &Path| {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode(&rootfs.join("locked")), 0o555);
    assert_eq!(mode(&rootfs.join("script")), 0o755);
    assert_eq!(
        std::fs::read(rootfs.join("locked/inside")).unwrap(),
        b"read-only home\n",
    );
    let _ = provision::remove(&dir);
}

/// A symlink in the source pointing out of the tree is recreated as a symlink
/// and never traversed, so nothing is written outside the destination.
#[test]
fn a_copy_recreates_an_escaping_symlink_without_following_it() {
    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-escape");
    let outside = dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    // Both shapes: a relative escape and an absolute one.
    std::os::unix::fs::symlink("../../outside", source.join("relative")).unwrap();
    std::os::unix::fs::symlink(&outside, source.join("absolute")).unwrap();
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    provision::CopyIn::new(&source, &rootfs)
        .run()
        .expect("the copy succeeds");

    // The links exist inside the destination, as links.
    for name in ["relative", "absolute"] {
        let meta = std::fs::symlink_metadata(rootfs.join(name)).unwrap();
        assert!(meta.file_type().is_symlink(), "{name} is not a symlink");
    }
    // And nothing was written through them.
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        0,
        "the copy wrote outside the destination",
    );
    let _ = provision::remove(&dir);
}

/// The assertion the whole thing exists for: a source entry naming a non-root
/// uid lands as that uid inside the rootfs, which `cp` running as the caller
/// cannot produce.
#[cfg(feature = "subid")]
#[test]
fn a_copy_lands_a_file_owned_by_a_non_root_target_uid() {
    use ferroday_cage::Cage;

    if !userns_available() {
        return;
    }
    if ferroday_cage::host::range_map_blocker().is_some() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_SUBID").is_none(),
            "a range map is required but unavailable"
        );
        eprintln!("skipping: no delegate can establish a range map");
        return;
    }
    let Some(fixture) = fixture_rootfs() else {
        return;
    };

    let dir = scratch("copyin-subordinate");
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("probe"), b"owned\n").unwrap();

    // The source names uid 42 as an in-rootfs id. Setting it needs the map too,
    // so the fixture rootfs stamps it through a bind, exactly as the export
    // test's own fixture does.
    let cage = Cage::builder()
        .rootfs(fixture)
        .bind(&source, "/work")
        .command("/bin/sh")
        .args(["-c", "chown 42:42 /work/probe"])
        .identity_map(IdentityMap::Subordinate)
        .build()
        .expect("the sandbox should build");
    assert!(
        cage.run().expect("the sandbox should launch").success(),
        "chown in the cage failed",
    );

    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();
    provision::CopyIn::new(&source, &rootfs)
        .map(IdentityMap::Subordinate)
        .run()
        .expect("the copy succeeds");

    // Read back through the map: the export is the instrument that reports what
    // the rootfs itself means by the ownership on disk.
    let mut out = Vec::new();
    provision::export_tar(&rootfs, &mut out, IdentityMap::Subordinate)
        .expect("the copied tree exports");
    let probe = parse_tar(&out)
        .into_iter()
        .find(|entry| entry.path == b"./probe")
        .expect("the copied file is in the archive");
    assert_eq!(probe.uid, 42, "the target uid did not survive the copy");
    assert_eq!(probe.gid, 42, "the target gid did not survive the copy");

    provision::remove(&dir).expect("the range-mapped tree should be removable");
}

/// A copy into a rootfs needing a range map that no delegate can establish is
/// reported as such, rather than as an unexplained failure inside the child.
#[test]
fn a_copy_whose_delegate_cannot_resolve_is_typed() {
    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-unprivileged");
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("probe"), b"x").unwrap();
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    // A range the host cannot possibly have allocated: resolution fails before
    // anything is forked.
    let extent = vec![ferroday_cage::IdRange {
        inside: 0,
        outside: 4_000_000_000,
        count: 1,
    }];
    let map = IdentityMap::ranges(extent.clone(), extent);
    match provision::CopyIn::new(&source, &rootfs).map(map).run() {
        Err(provision::ProvisionError::CopyUnprivileged { path, .. }) => {
            assert_eq!(path, rootfs);
        }
        other => panic!("expected a typed refusal, got {other:?}"),
    }
    let _ = provision::remove(&dir);
}

/// A copy the in-map child refuses is reported as the step the child failed at,
/// however far through the tree the walk had got.
///
/// The two sides fail in different terms. The child stops at the entry it could
/// not create; the parent, still streaming, learns of it only as a frame write
/// that could not be delivered. Which one the caller was told used to depend on
/// the size of the tree: one that fit the pipe's buffer let the walk run to the
/// end and the child's record be read, while anything larger blocked, took the
/// broken pipe, and reported that instead — the wrong way round, since the large
/// tree is where the diagnostic is worth most.
#[test]
fn a_copy_the_child_refuses_reports_the_childs_own_step() {
    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-child-step");
    let source = dir.join("source");
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(source.join("a-dir")).unwrap();
    std::fs::create_dir_all(&rootfs).unwrap();
    // The destination holds a regular file where the source holds a directory,
    // so the child's `openat` of the directory it just tried to create answers
    // ENOTDIR and it exits at once.
    std::fs::write(rootfs.join("a-dir"), b"not a directory\n").unwrap();
    // Sorted after the refused entry and larger than a pipe's 64 KiB buffer, so
    // the walk is still writing long after the child is gone and the parent
    // takes the broken pipe rather than reaching the end of the tree.
    std::fs::write(source.join("z-large"), vec![b'x'; 256 * 1024]).unwrap();

    match provision::CopyIn::new(&source, &rootfs).run() {
        Err(provision::ProvisionError::Io {
            op,
            path,
            source: cause,
            ..
        }) => {
            assert_eq!(op, "opening a directory just created");
            assert_eq!(path, rootfs);
            assert_eq!(
                cause.raw_os_error(),
                Some(rustix::io::Errno::NOTDIR.raw_os_error()),
                "the child's errno is carried through: {cause}"
            );
        }
        other => panic!("expected the child's own step, got {other:?}"),
    }
    let _ = provision::remove(&dir);
}

/// Several names for one file arrive as one file with several names.
///
/// The round trip is the point: an `Export` coalesces hard links, so a `CopyIn`
/// that did not would turn N names into N independent files with the data
/// duplicated and the sharing gone. Debian rootfs trees carry these.
#[test]
fn a_copy_keeps_several_names_for_one_file() {
    use std::os::unix::fs::MetadataExt;

    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-hardlink");
    let source = dir.join("source");
    // The links sit in three different directories, so the anchor the copy
    // records is a path rather than a name, and the walk has to carry it out of
    // the directory it was recorded in.
    std::fs::create_dir_all(source.join("usr/bin")).unwrap();
    std::fs::create_dir_all(source.join("usr/sbin")).unwrap();
    std::fs::write(source.join("usr/bin/busybox"), b"#!/multi-call\n").unwrap();
    std::fs::hard_link(source.join("usr/bin/busybox"), source.join("usr/bin/ls")).unwrap();
    std::fs::hard_link(source.join("usr/bin/busybox"), source.join("usr/sbin/init")).unwrap();
    // A file with a single name must not be recorded as an anchor, or the table
    // would hold the whole tree.
    std::fs::write(source.join("usr/bin/alone"), b"solo\n").unwrap();
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let report = provision::CopyIn::new(&source, &rootfs)
        .run()
        .expect("the copy succeeds");
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    let ino = |name: &str| {
        std::fs::symlink_metadata(rootfs.join(name))
            .unwrap_or_else(|err| panic!("{name}: {err}"))
            .ino()
    };
    let anchor = ino("usr/bin/busybox");
    assert_eq!(
        ino("usr/bin/ls"),
        anchor,
        "a second name is a separate file"
    );
    assert_eq!(
        ino("usr/sbin/init"),
        anchor,
        "a name in another directory is a separate file",
    );
    assert_ne!(ino("usr/bin/alone"), anchor);
    assert_eq!(
        std::fs::symlink_metadata(rootfs.join("usr/bin/busybox"))
            .unwrap()
            .nlink(),
        3,
        "the link count does not match the names",
    );
    assert_eq!(
        std::fs::read(rootfs.join("usr/sbin/init")).unwrap(),
        b"#!/multi-call\n",
        "a linked name does not read back as the file",
    );

    // The data was streamed once. A copy that wrote each name independently
    // would have sent it three times.
    let mut source_names = 0;
    for entry in std::fs::read_dir(rootfs.join("usr/bin")).unwrap() {
        source_names += usize::from(entry.unwrap().file_name() != "alone");
    }
    assert_eq!(source_names, 2);
}

/// A named pipe is copied rather than dropped: an unprivileged process creates
/// one perfectly well, and the extraction path already does.
#[test]
fn a_copy_creates_a_named_pipe() {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-fifo");
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let fifo = source.join("initctl");
    if !make_fifo(&fifo) {
        eprintln!("skipping: this filesystem will not hold a named pipe");
        return;
    }
    // A mode the copy does not create the pipe at, so it is the one the copy
    // applies afterwards that the assertion reads.
    std::fs::set_permissions(&fifo, PermissionsExt::from_mode(0o640)).unwrap();
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let report = provision::CopyIn::new(&source, &rootfs)
        .run()
        .expect("the copy succeeds");
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    let meta = std::fs::symlink_metadata(rootfs.join("initctl")).expect("the pipe was created");
    assert!(meta.file_type().is_fifo(), "{meta:?}");
    assert_eq!(meta.permissions().mode() & 0o7777, 0o640);
}

/// An entry the copy cannot create is named in the report rather than dropped
/// in silence.
#[test]
fn a_copy_names_what_it_could_not_create() {
    if !userns_available() {
        return;
    }
    let dir = scratch("copyin-skipped");
    let source = dir.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("kept"), b"ordinary\n").unwrap();
    // A socket is the case an unprivileged process can create and the copy
    // still declines, so it is the one that has to be reported rather than
    // explained away by a missing privilege.
    let socket = source.join("control.sock");
    let _listener =
        std::os::unix::net::UnixListener::bind(&socket).expect("the socket is bindable");

    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(&rootfs).unwrap();

    let report = provision::CopyIn::new(&source, &rootfs)
        .run()
        .expect("the copy succeeds");

    assert_eq!(report.skipped.len(), 1, "{:?}", report.skipped);
    assert_eq!(report.skipped[0].path, socket);
    assert_eq!(report.skipped[0].kind, provision::SkippedKind::Socket);
    // The reason travels with the entry, so a caller can log it without a
    // match of its own.
    assert!(
        format!("{}", report.skipped[0].kind).contains("socket"),
        "{}",
        report.skipped[0].kind,
    );
    assert!(
        rootfs.join("kept").exists(),
        "the ordinary entry was copied"
    );
    assert!(!rootfs.join("control.sock").exists());
}
