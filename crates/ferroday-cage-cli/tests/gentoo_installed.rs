//! Integration tests for `fcage --gentoo-installed`: what it lists, and what it
//! says on stderr where the listing alone would mislead.
//!
//! Each root is a package database the test writes, so nothing here reaches
//! the network or builds a sandbox, and nothing skips.

mod common;

use std::path::Path;
use std::process::{Command, Output};

/// The built binary under test.
const FCAGE: &str = env!("CARGO_BIN_EXE_fcage");

/// Writes a package database entry with a slot into `root`.
fn entry(root: &Path, category: &str, pf: &str) {
    let dir = root.join("var/db/pkg").join(category).join(pf);
    std::fs::create_dir_all(&dir).expect("the entry directory is created");
    std::fs::write(dir.join("SLOT"), "0\n").expect("SLOT is written");
}

/// Runs `fcage --gentoo-installed root` to completion.
fn installed(root: &Path) -> Output {
    Command::new(FCAGE)
        .arg("--gentoo-installed")
        .arg(root)
        .output()
        .expect("fcage runs")
}

#[test]
fn a_root_with_no_package_database_is_said_to_be_empty_or_absent() {
    let root = common::scratch_dir("gentoo-installed-absent");
    let out = installed(&root);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("its package database is empty or absent"),
        "{stderr}"
    );
    assert!(!stderr.contains("name no package"), "{stderr}");
}

#[test]
fn a_database_whose_every_entry_names_no_package_is_not_said_to_be_empty() {
    // The database is there and holds entries, so the note says that none of
    // them names a package, after the count of what was left out.
    let root = common::scratch_dir("gentoo-installed-unnamed");
    entry(&root, "Sys_Libs!", "zlib-1.3.1");
    entry(&root, "sys-libs", "zlib");
    let out = installed(&root);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stdout.is_empty(), "{out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("2 entries of the package database"),
        "{stderr}"
    );
    assert!(
        stderr.contains("no entry of its package database names one"),
        "{stderr}"
    );
    assert!(!stderr.contains("empty or absent"), "{stderr}");
}

#[test]
fn entries_naming_no_package_are_counted_and_the_rest_listed() {
    let root = common::scratch_dir("gentoo-installed-mixed");
    entry(&root, "sys-libs", "zlib-1.3.1");
    entry(&root, "Sys_Libs!", "zlib-1.3.1");
    let out = installed(&root);
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("sys-libs/zlib-1.3.1\t"), "{stdout}");
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("1 entries of the package database"),
        "{stderr}"
    );
    assert!(!stderr.contains("no packages are installed"), "{stderr}");
}
