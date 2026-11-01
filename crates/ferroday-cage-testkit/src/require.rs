//! Skipping a test the host cannot run, or failing it where the run says it must
//! run.
//!
//! A test that needs a host facility the host lacks skips rather than fails: a
//! missing user namespace is a property of the machine, not a defect in the
//! repository. A skip that passes silently, though, lets a run that meant to
//! exercise a security property come back green having exercised nothing. So
//! every skip is explicit, printed on stderr, and each facility has a variable
//! that turns its skips into failures. CI sets the variables for the facilities
//! its runner provides.
//!
//! Every skip in both crates' tests goes through this module, so a variable is
//! honored wherever its facility is missing rather than only where a test
//! remembered to check it. [`Requirement`] names a facility and its variable;
//! [`premise_unmet`] is the one skip no variable governs.
//!
//! The probes themselves stay with the tests where they need a library feature
//! (`host::landlock_abi` and `host::seccomp_available` are the hardening
//! layer's), and their results are handed in. The probes a featureless library
//! answers are here.

use std::fmt::Display;
use std::path::Path;

/// A host facility some tests need, and the variable that asserts they ran.
///
/// A variable counts as set whatever its value, as the existing CI
/// configuration sets each to `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirement {
    variable: &'static str,
}

/// Unprivileged user namespaces, which every sandbox needs.
pub const USERNS: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_USERNS");

/// A delegate that can establish a range map, and a subordinate allocation
/// large enough for what a test maps.
pub const SUBID: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_SUBID");

/// The native network stack's host facilities: `/dev/net/tun`, and the IPv6
/// loopback its IPv6 flows are tested against.
pub const TUN: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_TUN");

/// Overlay-rooted sandboxes, and the overlay markers a test lays into an upper
/// by hand: whiteouts, and the `user.` attributes an unprivileged overlay keeps
/// its opaque marks in.
pub const OVERLAY: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_OVERLAY");

/// The Landlock LSM, at the ABI that grants network rights (4, Linux 6.7).
pub const LANDLOCK: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_LANDLOCK");

/// Landlock scopes (ABI 6, Linux 6.12).
pub const LANDLOCK_SCOPE: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_LANDLOCK_SCOPE");

/// Seccomp filtering.
pub const SECCOMP: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_SECCOMP");

/// The network suites, which run only when their own variable opts in; see
/// [`network_suite`].
pub const NETWORK_TEST: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_NETWORK_TEST");

impl Requirement {
    const fn named(variable: &'static str) -> Requirement {
        Requirement { variable }
    }

    /// The variable that turns this facility's skips into failures.
    pub fn variable(self) -> &'static str {
        self.variable
    }

    /// Whether the variable is set, so a test needing the facility must run.
    pub fn demanded(self) -> bool {
        std::env::var_os(self.variable).is_some()
    }

    /// Reports that a test needing this facility cannot run here.
    ///
    /// Prints the skip on stderr, or fails the test when the variable demands
    /// that it run. `reason` says what is missing, in the words the skip line
    /// prints.
    ///
    /// # Panics
    ///
    /// When the variable is set.
    #[track_caller]
    pub fn skip(self, reason: impl Display) {
        self.insist(&reason);
        eprintln!("skipping: {reason}");
    }

    /// Fails the test when the variable demands that it run, and otherwise
    /// does nothing: the half of [`skip`](Self::skip) that a facility shares
    /// when another facility's skip is the one reported.
    #[track_caller]
    fn insist(self, reason: impl Display) {
        assert!(
            !self.demanded(),
            "{reason}, and {} says this test must run",
            self.variable
        );
    }

    /// Whether a test needing this facility runs: `available`, or else the skip
    /// [`skip`](Self::skip) reports, with `reason`.
    #[track_caller]
    pub fn holds(self, available: bool, reason: impl Display) -> bool {
        if !available {
            self.skip(reason);
        }
        available
    }

    /// Whether a test needing this facility runs, given the blocker a host
    /// probe reported: `None`, or else the skip [`skip`](Self::skip) reports,
    /// naming `what` and the blocker.
    #[track_caller]
    pub fn unblocked(self, blocker: Option<impl Display>, what: &str) -> bool {
        match blocker {
            None => true,
            Some(blocker) => {
                self.skip(format!("{what}: {blocker}"));
                false
            }
        }
    }
}

/// Reports a skip that no variable governs: the test's premise is a state of
/// the host or of the caller rather than a facility, and a capable runner meets
/// some of them in neither state.
///
/// A test of what happens *without* a delegate, or without Landlock, cannot run
/// on the runner that has them, and one that needs a caller other than root, or
/// a caller with a controlling terminal, depends on how the run was started.
/// None of those is a host that failed to provide something.
pub fn premise_unmet(reason: impl Display) {
    eprintln!("skipping: {reason}");
}

/// Whether the host can create unprivileged user namespaces; the skip reports
/// what blocks them.
#[track_caller]
pub fn userns() -> bool {
    USERNS.unblocked(
        ferroday_cage::host::userns_blocker(),
        "unprivileged user namespaces are unavailable",
    )
}

/// Whether a delegate can establish a range map here; the skip reports what
/// blocks one.
#[track_caller]
pub fn range_map() -> bool {
    SUBID.unblocked(
        ferroday_cage::host::range_map_blocker(),
        "no delegate can establish a range map",
    )
}

/// Whether an overlay-rooted sandbox can run here with its upper beside
/// `scratch`; the skip reports what blocks one.
#[track_caller]
pub fn overlay(scratch: &Path) -> bool {
    OVERLAY.unblocked(
        ferroday_cage::host::overlay_blocker(scratch),
        "overlay-rooted sandboxes are unavailable",
    )
}

/// Whether `/dev/net/tun` is present and openable, the additional host
/// requirement of the native network stack.
#[track_caller]
pub fn tun() -> bool {
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun");
    match opened {
        Ok(_) => true,
        Err(err) => {
            TUN.skip(format!("/dev/net/tun is unavailable: {err}"));
            false
        }
    }
}

/// Whether the kernel offers Landlock, given what `host::landlock_abi`
/// reported.
#[track_caller]
pub fn landlock(abi: Option<i32>) -> bool {
    LANDLOCK.holds(abi.is_some(), "the kernel offers no Landlock support")
}

/// Whether the kernel's Landlock ABI grants network rights (ABI 4), given what
/// `host::landlock_abi` reported.
#[track_caller]
pub fn landlock_net(abi: Option<i32>) -> bool {
    match abi {
        None => landlock(abi),
        Some(abi) => LANDLOCK.holds(
            abi >= 4,
            format!("Landlock ABI {abi} predates network rights (needs 4)"),
        ),
    }
}

/// Whether the kernel's Landlock ABI has scopes (ABI 6), given what
/// `host::landlock_abi` reported.
///
/// A kernel with no Landlock at all is missing Landlock before it is missing
/// scopes, so its skip is [`landlock`]'s, which [`LANDLOCK`] turns into a
/// failure as it does for every Landlock test. [`LANDLOCK_SCOPE`] still demands
/// the test there too, since scopes are among what that kernel lacks.
#[track_caller]
pub fn landlock_scope(abi: Option<i32>) -> bool {
    match abi {
        None => {
            LANDLOCK_SCOPE.insist("the kernel offers no Landlock support");
            landlock(abi)
        }
        Some(abi) => LANDLOCK_SCOPE.holds(
            abi >= 6,
            format!("Landlock ABI {abi} predates scopes (needs 6)"),
        ),
    }
}

/// Whether the kernel offers seccomp filtering, given what
/// `host::seccomp_available` reported.
#[track_caller]
pub fn seccomp(available: bool) -> bool {
    SECCOMP.holds(available, "the kernel offers no seccomp support")
}

/// Whether a network suite runs: `gate` opts into it, and without it the suite
/// skips, unless [`NETWORK_TEST`] says it must run. `suite` names what the
/// skip line tells the reader to set the gate for.
#[track_caller]
pub fn network_suite(gate: &str, suite: &str) -> bool {
    let opted = std::env::var_os(gate).is_some();
    NETWORK_TEST.holds(opted, format!("set {gate}=1 to run {suite}"))
}
