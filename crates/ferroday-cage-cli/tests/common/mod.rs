//! Shared helpers for the `fcage` integration tests.
//!
//! The fixture rootfs is the library crate's: the same pinned tarball, the same
//! script, the same cache directory, reached through `ferroday-cage-testkit`
//! so the code that reaches them is shared too, not just the files.
//!
//! Compiled into each integration-test binary; not every binary uses every
//! helper.
#![allow(unused_imports)]

pub use ferroday_cage_testkit::fixture::{fixture_rootfs, scratch_rootfs};
pub use ferroday_cage_testkit::pty::drain_until;
pub use ferroday_cage_testkit::scratch::{scratch_dir, tun_available};
