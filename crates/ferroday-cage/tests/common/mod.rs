//! Shared helpers for the sandbox integration tests.
//!
//! Everything here comes from `ferroday-cage-testkit`, the workspace's
//! dev-only fixture crate, which both this suite and the CLI's read from. This
//! module is the re-export that lets a test say `common::fixture_rootfs()`
//! rather than name the crate.
//!
//! Compiled into each integration-test binary; not every binary uses every
//! helper.
#![allow(unused_imports)]

pub use ferroday_cage_testkit::fixture::{fixture_rootfs, scratch_rootfs};
pub use ferroday_cage_testkit::scratch::{force_remove_dir_all, scratch_dir, tun_available};

/// Builders for hermetic Debian fixtures: tar streams, `.deb` archives, and a
/// `file://` repository, all with correct digests, so the Debian provisioner
/// can be tested end to end without a network.
pub mod deb_repo {
    pub use ferroday_cage_testkit::deb::{Pkg, ar, deb, write_repo};
    pub use ferroday_cage_testkit::hex::sha256_hex;
    pub use ferroday_cage_testkit::tar::Tar;
}
