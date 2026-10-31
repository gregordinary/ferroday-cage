//! Shared helpers for the `fcage` integration tests.
//!
//! The fixture rootfs is the library crate's: the same pinned tarball, the same
//! script, the same cache directory, reached through `ferroday-cage-testkit`
//! so the code that reaches them is shared too, not just the files. The
//! provisioning is this suite's to supply, through the library `fcage` is built
//! on, as the testkit's documentation explains.
//!
//! Compiled into each integration-test binary; not every binary uses every
//! helper.
#![allow(unused_imports, dead_code)]

pub use ferroday_cage_testkit::process::{cpu_ticks, finish_bounded, run_bounded};
pub use ferroday_cage_testkit::pty;
pub use ferroday_cage_testkit::require;
pub use ferroday_cage_testkit::scratch::scratch_dir;

/// The pinned Alpine minirootfs, provisioned through the library's own tarball
/// provisioner, or `None` when the sandbox tests should skip.
#[track_caller]
pub fn fixture_rootfs() -> Option<&'static std::path::Path> {
    ferroday_cage_testkit::fixture::fixture_rootfs(|tarball, rootfs| {
        ferroday_cage::provision::ensure(
            rootfs,
            &mut ferroday_cage::provision::Tarball::new(tarball),
        )
    })
}
