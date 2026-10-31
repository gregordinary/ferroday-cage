//! Shared helpers for the sandbox integration tests.
//!
//! Almost everything here comes from `ferroday-cage-testkit`, the workspace's
//! dev-only fixture crate, which both this suite and the CLI's read from. This
//! module is the re-export that lets a test say `common::fixture_rootfs()`
//! rather than name the crate.
//!
//! The rest is what needs a library feature, which the testkit cannot ask for
//! (its documentation says why): provisioning the fixture root through the
//! tarball provisioner, the hardening layer's host probes, and naming a
//! fixture repository by its `file://` URL. Each sits behind the feature it
//! needs, as the tests using it do.
//!
//! Compiled into each integration-test binary; not every binary uses every
//! helper.
#![allow(unused_imports, dead_code)]

pub use ferroday_cage_testkit::process::{finish_bounded, process_exists, run_bounded, wait_gone};
pub use ferroday_cage_testkit::pty;
pub use ferroday_cage_testkit::require;
pub use ferroday_cage_testkit::sandbox::{Collect, sleeper};
pub use ferroday_cage_testkit::scratch::{
    RangedScratch, download_cache, force_remove_dir_all, ranged_scratch, scratch_dir,
};
pub use ferroday_cage_testkit::tar::Tar;

/// The pinned Alpine minirootfs, provisioned through the library's own tarball
/// provisioner, or `None` when the sandbox tests should skip.
#[cfg(feature = "tarball")]
#[track_caller]
pub fn fixture_rootfs() -> Option<&'static std::path::Path> {
    ferroday_cage_testkit::fixture::fixture_rootfs(provision_fixture)
}

/// A writable copy of [`fixture_rootfs`] in a scratch directory named `name`,
/// or `None` when the sandbox tests should skip.
#[cfg(feature = "tarball")]
#[track_caller]
pub fn scratch_rootfs(name: &str) -> Option<std::path::PathBuf> {
    ferroday_cage_testkit::fixture::scratch_rootfs(name, provision_fixture)
}

/// Publishes the fixture root at `rootfs` from `tarball`, the way a caller
/// provisions any root from a tarball.
#[cfg(feature = "tarball")]
fn provision_fixture(
    tarball: &std::path::Path,
    rootfs: &std::path::Path,
) -> Result<ferroday_cage::provision::Provisioned, ferroday_cage::provision::ProvisionError> {
    ferroday_cage::provision::ensure(rootfs, &mut ferroday_cage::provision::Tarball::new(tarball))
}

/// Whether the kernel offers Landlock. The probe is the hardening layer's,
/// and the skip goes through [`require`].
#[cfg(feature = "hardening")]
#[track_caller]
pub fn landlock() -> bool {
    require::landlock(ferroday_cage::host::landlock_abi())
}

/// Whether the kernel's Landlock ABI grants network rights.
#[cfg(feature = "hardening")]
#[track_caller]
pub fn landlock_net() -> bool {
    require::landlock_net(ferroday_cage::host::landlock_abi())
}

/// Whether the kernel's Landlock ABI has scopes.
#[cfg(feature = "hardening")]
#[track_caller]
pub fn landlock_scope() -> bool {
    require::landlock_scope(ferroday_cage::host::landlock_abi())
}

/// Whether the kernel offers seccomp filtering.
#[cfg(feature = "hardening")]
#[track_caller]
pub fn seccomp() -> bool {
    require::seccomp(ferroday_cage::host::seccomp_available())
}

/// Builders for hermetic Debian fixtures: tar streams, `.deb` archives, and a
/// `file://` repository, all with correct digests, so the Debian provisioner
/// can be tested end to end without a network.
#[cfg(feature = "debian")]
pub mod deb_repo {
    pub use ferroday_cage_testkit::deb::{Pkg, deb, deb_with_control};
    pub use ferroday_cage_testkit::hex::sha256_hex;
    pub use ferroday_cage_testkit::tar::Tar;

    /// Writes an unsigned repository into `dir` and returns its mirror URL.
    ///
    /// The URL is built by the library's own `provision::file_url`, so a
    /// fixture addresses its repository in exactly the shape a caller's does.
    pub fn write_repo(dir: &std::path::Path, suite: &str, arch: &str, packages: &[Pkg]) -> String {
        ferroday_cage_testkit::deb::write_repo(dir, suite, arch, packages);
        ferroday_cage::provision::file_url(dir).expect("the fixture's path names a file:// URL")
    }
}
