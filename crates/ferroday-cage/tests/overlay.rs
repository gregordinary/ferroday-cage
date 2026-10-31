//! Integration tests for overlay-rooted cages.
//!
//! A cage rooted on an overlay sees a merged view of a read-only lower and a
//! writable upper: writes land in the upper, the lower stays pristine, and
//! discarding the upper reverts the changes. These tests require unprivileged
//! user namespaces and an unprivileged-overlay-capable host and filesystem;
//! they skip explicitly when either is unavailable.

mod common;

use std::path::Path;

use ferroday_cage::{Cage, ExitStatus};

/// Runs `/bin/sh -c <script>` in an overlay of `lower` with writes in `upper`.
fn run(lower: &Path, upper: &Path, script: &str) -> ExitStatus {
    Cage::builder()
        .overlay_rootfs(lower, upper)
        .command("/bin/sh")
        .args(["-c", script])
        .build()
        .expect("a valid overlay cage configuration")
        .run()
        .expect("the overlay cage launches")
}

#[test]
fn writes_land_in_the_upper_and_leave_the_lower_pristine() {
    let Some(lower) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("overlay-basic");
    if !common::require::overlay(&dir) {
        return;
    }
    let upper = dir.join("upper");

    // The command reads a lower file (proving the merged view) and writes a
    // marker at the root, which the overlay must land in the upper.
    let status = run(
        lower,
        &upper,
        "test -e /bin/busybox && echo merged > /overlay-marker",
    );
    assert!(status.success(), "the merged view is readable and writable");

    let marker = upper.join("overlay-marker");
    assert!(marker.is_file(), "the write landed in the upper");
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap().trim(),
        "merged",
        "the upper holds the written content",
    );
    assert!(
        !lower.join("overlay-marker").exists(),
        "the lower stayed pristine",
    );
}

#[test]
fn a_fresh_upper_is_disposable_and_a_reused_one_persists() {
    let Some(lower) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("overlay-dispose");
    if !common::require::overlay(&dir) {
        return;
    }

    let upper1 = dir.join("u1");
    assert!(run(lower, &upper1, "echo one > /disposable").success());

    // A fresh upper does not carry the first run's write: discarding an upper
    // reverts every change made through it.
    let upper2 = dir.join("u2");
    assert!(
        run(lower, &upper2, "test ! -e /disposable").success(),
        "a fresh upper must not see a prior upper's writes",
    );

    // The first upper still holds its write: persistence versus disposal is the
    // caller's choice of whether to reuse or discard the upper.
    assert!(
        run(lower, &upper1, "test -e /disposable").success(),
        "a reused upper carries its own prior writes",
    );
}

#[test]
fn a_delete_through_the_overlay_leaves_the_lower_untouched() {
    let Some(lower) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("overlay-delete");
    if !common::require::overlay(&dir) {
        return;
    }
    assert!(
        lower.join("etc/os-release").exists(),
        "the fixture carries the file the test deletes",
    );
    let upper = dir.join("upper");

    // Remove a lower file through the overlay: it disappears from the merged
    // view (recorded as a whiteout in the upper) while the lower keeps it.
    let status = run(
        lower,
        &upper,
        "rm /etc/os-release && test ! -e /etc/os-release",
    );
    assert!(status.success(), "a lower file deletes through the overlay");
    assert!(
        lower.join("etc/os-release").exists(),
        "the lower keeps the file the overlay hid",
    );
}

#[test]
fn stacked_lowers_are_searched_base_first() {
    let Some(base) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("overlay-stacked");
    if !common::require::overlay(&dir) {
        return;
    }

    // A second lower carrying one file the base does not have, and one that
    // shadows a base path. The patches layer is added over the base, so it wins
    // the collision.
    let patches = dir.join("patches");
    std::fs::create_dir_all(patches.join("etc")).unwrap();
    std::fs::write(patches.join("etc/added"), b"from-patches\n").unwrap();
    std::fs::write(patches.join("etc/hostname"), b"from-patches\n").unwrap();
    let base_hostname = std::fs::read_to_string(base.join("etc/hostname")).unwrap_or_default();

    let upper = dir.join("upper");
    let status = Cage::builder()
        .overlay(
            ferroday_cage::Overlay::new()
                .lower(base)
                .lower(&patches)
                .upper(&upper),
        )
        .command("/bin/sh")
        .args([
            "-c",
            "cat /etc/added > /out-added && cat /etc/hostname > /out-hostname",
        ])
        .build()
        .expect("a valid stacked overlay configuration")
        .run()
        .expect("the stacked overlay cage launches");
    assert!(status.success(), "both layers are readable in the merge");

    // The later lower contributes what the base lacks.
    assert_eq!(
        std::fs::read_to_string(upper.join("out-added"))
            .unwrap()
            .trim(),
        "from-patches",
        "a file only the second lower has is visible",
    );
    // A later lower shadows an earlier one where both hold the same path.
    assert_eq!(
        std::fs::read_to_string(upper.join("out-hostname"))
            .unwrap()
            .trim(),
        "from-patches",
        "the layer added last wins a collision with the base",
    );
    assert_ne!(
        base_hostname.trim(),
        "from-patches",
        "the fixture's own file is what the patches layer shadowed",
    );
}

#[test]
fn an_overlay_without_an_upper_is_a_config_error() {
    let dir = common::scratch_dir("overlay-no-upper");
    let err = Cage::builder()
        .overlay(ferroday_cage::Overlay::new().lower(&dir))
        .command("/bin/sh")
        .build()
        .expect_err("an overlay with no upper has nowhere to write");
    assert!(
        matches!(
            err,
            ferroday_cage::Error::Config(ferroday_cage::ConfigError::OverlayUpperMissing)
        ),
        "{err}"
    );
}

/// A stacked lower that does not exist names itself as the overlay lower, not
/// as the rootfs: the first lower is the rootfs, the rest are layers.
#[test]
fn a_missing_stacked_lower_names_its_role() {
    let dir = common::scratch_dir("overlay-missing-lower");
    let err = Cage::builder()
        .overlay(
            ferroday_cage::Overlay::new()
                .lower(&dir)
                .lower(dir.join("absent"))
                .upper(dir.join("upper")),
        )
        .command("/bin/sh")
        .build()
        .expect_err("a stacked lower that does not exist cannot be merged");
    assert!(
        matches!(
            err,
            ferroday_cage::Error::Config(ferroday_cage::ConfigError::OverlayDirUnusable {
                layer: ferroday_cage::OverlayLayer::Lower,
                ..
            })
        ),
        "{err}"
    );
    assert!(
        err.to_string().contains("overlay lower directory"),
        "the message should name the layer: {err}"
    );
}

#[test]
fn a_work_directory_on_another_filesystem_is_refused_by_name() {
    let Some(lower) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("overlay-work-xdev");
    // `/dev/shm` is a tmpfs on every ordinary Linux host, and the scratch
    // directory lives under `target`, so the two are on different filesystems.
    // Without one, the premise of the test does not hold and there is nothing
    // to assert.
    let elsewhere = Path::new("/dev/shm");
    let (Ok(here), Ok(there)) = (
        std::fs::metadata(&dir).map(|meta| std::os::unix::fs::MetadataExt::dev(&meta)),
        std::fs::metadata(elsewhere).map(|meta| std::os::unix::fs::MetadataExt::dev(&meta)),
    ) else {
        common::require::premise_unmet("no second filesystem to place the work directory on");
        return;
    };
    if here == there {
        common::require::premise_unmet("the scratch directory and /dev/shm share a filesystem");
        return;
    }

    // The overlay moves files between the upper and the work directory, so the
    // kernel requires them on one filesystem. The build says so, naming the
    // work directory, rather than letting the mount fail with a bare EXDEV.
    let work = elsewhere.join(format!("fcage-work-{}", std::process::id()));
    let err = Cage::builder()
        .overlay(
            ferroday_cage::Overlay::new()
                .lower(lower)
                .upper(dir.join("upper"))
                .work(&work),
        )
        .command("/bin/sh")
        .build()
        .expect_err("a work directory on another filesystem must be refused");
    let left_behind = work.exists();
    let _ = std::fs::remove_dir(&work);
    assert!(
        err.to_string().contains("overlay work directory"),
        "the refusal must name the work directory: {err}"
    );
    assert!(
        !left_behind,
        "a refused build removes the layer directories it created"
    );
}

#[test]
fn a_bind_target_the_upper_had_deleted_stays_deleted_after_the_run() {
    let Some(lower) = common::fixture_rootfs() else {
        return;
    };
    let dir = common::scratch_dir("overlay-bind-over-deleted");
    if !common::require::overlay(&dir) {
        return;
    }
    for path in ["etc/os-release", "etc/apk/repositories"] {
        assert!(
            lower.join(path).is_file(),
            "the fixture carries {path}, which the test deletes",
        );
    }
    let upper = dir.join("upper");
    let source = dir.join("bound");
    std::fs::write(&source, b"bound\n").unwrap();

    // An earlier run deletes one file, which the upper records as a whiteout,
    // and replaces a directory, which it records as an opaque directory.
    let status = run(
        lower,
        &upper,
        "rm /etc/os-release && rm -r /etc/apk && mkdir /etc/apk",
    );
    assert!(status.success(), "the deletions go through the overlay");

    // A later run binds a file onto each deleted path. The merged view holds
    // nothing at either, so the launch creates both targets in the upper, and
    // the bind shows through them.
    let status = Cage::builder()
        .overlay_rootfs(lower, &upper)
        .bind_ro(&source, "/etc/os-release")
        .bind_ro(&source, "/etc/apk/repositories")
        .command("/bin/sh")
        .args([
            "-c",
            "test \"$(cat /etc/os-release)\" = bound && \
             test \"$(cat /etc/apk/repositories)\" = bound",
        ])
        .build()
        .expect("a valid overlay sandbox configuration")
        .run()
        .expect("the overlay sandbox launches");
    assert!(status.success(), "both binds are in place for the run");

    // Once the sandbox is gone the upper holds what it held before: the
    // deletions stand, rather than an empty file at each path or the lower's
    // files showing through again.
    assert!(
        run(
            lower,
            &upper,
            "test ! -e /etc/os-release && test ! -e /etc/apk/repositories"
        )
        .success(),
        "the run's targets were removed and the deletions restored",
    );
    let whiteout = std::fs::symlink_metadata(upper.join("etc/os-release"))
        .expect("the upper still records the deletion");
    assert!(
        std::os::unix::fs::FileTypeExt::is_char_device(&whiteout.file_type())
            && std::os::unix::fs::MetadataExt::rdev(&whiteout) == 0,
        "the deletion is recorded as a whiteout: {whiteout:?}",
    );
}
