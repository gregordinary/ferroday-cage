//! Test fixtures and harnesses shared by the workspace's tests.
//!
//! Both crates' suites need the same things: the pinned Alpine minirootfs,
//! scratch directories that clear themselves, the rule for skipping a test the
//! host cannot run, a tar writer, `ar` and `.deb` writers, a hex encoder, a
//! pseudoterminal to play the user at, and a few descriptor, process and
//! sandbox helpers.
//! One copy of each is what keeps them agreeing: a skip that honors its
//! `REQUIRE` variable in one suite honors it in every suite.
//!
//! Nothing here ships. The crate is `publish = false` and is a dev-dependency
//! of both crates.
//!
//! # Features
//!
//! None of this crate's features enables one of the library's. Cargo resolves
//! a dev-dependency's features once for every test and example of a package,
//! so a feature here that forwarded to the library's would give every test
//! build of the library that feature. The `features` job's featureless and
//! powerset checks would then build what no combination selects, and a test
//! reaching past its `required-features` would compile anyway.
//!
//! So where a fixture needs a library feature, the dependent supplies that
//! part under a `cfg` of its own: the fixture root's provisioning
//! ([`fixture`]), and a fixture repository's `file://` URL ([`deb`]). The
//! features that remain gate this crate's own dependencies:
//!
//! - `hex`: SHA-256, for `hex` and the repository half of [`deb`].
//! - `pty`: rustix's terminal calls, for `pty`.

pub mod deb;
pub mod fd;
pub mod fixture;
#[cfg(feature = "hex")]
pub mod hex;
pub mod process;
#[cfg(feature = "pty")]
pub mod pty;
pub mod require;
pub mod sandbox;
pub mod scratch;
pub mod tar;
