//! Test fixtures shared by the workspace's integration tests.
//!
//! Both crates' suites need the same things: the pinned Alpine minirootfs, a
//! scratch directory that clears itself, a tar writer, an `ar` writer, and a
//! hex encoder. Each had its own copy, and the copies drifted — one tar writer
//! recorded per-entry ownership and another did not, one hex encoder existed
//! only because the library's was private.
//!
//! Nothing here ships. The crate is `publish = false` and is a dev-dependency
//! of both crates.
//!
//! # Features
//!
//! Every part that needs something of the library beyond its featureless core
//! sits behind a feature of this crate, and each forwards rather than enabling
//! anything itself. A test suite asks for what it uses, and the library's
//! featureless and feature-powerset checks keep meaning what they say.

#[cfg(feature = "debian")]
pub mod deb;
#[cfg(feature = "tarball")]
pub mod fixture;
#[cfg(feature = "debian")]
pub mod hex;
#[cfg(feature = "pty")]
pub mod pty;
pub mod scratch;
#[cfg(feature = "debian")]
pub mod tar;
