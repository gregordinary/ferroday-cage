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
//! A skip line on stderr is captured with the rest of a passing test's output,
//! so a green summary does not say how many of its passes were skips. Naming a
//! file in [`SKIP_LOG`] appends every skip to it as well, one line each, for a
//! run to be audited after it ends.
//!
//! The probes themselves stay with the tests where they need a library feature
//! (`host::landlock_abi` and the `host::landlock_enforces_*` questions are the
//! hardening layer's), and their results are handed in. The probes a
//! featureless library answers are here.

use std::fmt::Display;
use std::io::Write;
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

/// A delegated cgroup v2 directory the run has to itself and can divide, as a
/// scope from `systemd-run --user --scope -p Delegate=yes` is, which the
/// cgroup suite places its sandboxes' cgroups beneath, and the limit files the
/// suite sets: a kernel with swap accounting off has no `memory.swap.max`.
pub const CGROUP: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_CGROUP");

/// What the filesystem a test's scratch directory is on holds, for the tests
/// that copy, extract and export a tree: named pipes, POSIX access control
/// lists, `user.` attributes, and a sparse file's holes; and a second
/// filesystem, at `/dev/shm`, for a work directory placed apart from its upper.
pub const FILESYSTEM: Requirement = Requirement::named("FERRODAY_CAGE_REQUIRE_FILESYSTEM");

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
        report_skip(self.variable, &reason);
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

/// Reports a skip that no variable governs: the test's premise is not a
/// facility a host is asked to provide.
///
/// - A test of what happens *without* a facility, a delegate or Landlock,
///   cannot run on the runner that has it.
/// - One that needs a caller other than root, a controlling terminal, a limit
///   not already raised, a host with a `resolv.conf`, a scratch directory off
///   `/dev/shm`'s filesystem, or a host that is not a container masking its
///   procfs depends on how the run was started.
/// - One whose subject a kernel can be built without has nothing to test on
///   such a kernel: the 32-bit x86 entry points a network filter closes and an
///   i386 root runs through, or a refusal a filter test needs the kernel not
///   to make itself.
/// - One whose facility is newer than the kernels CI runs on has no variable
///   until they carry it: Landlock's unix-socket right, from ABI 9.
///
/// None of those is a host that failed to provide what a run asked of it.
#[track_caller]
pub fn premise_unmet(reason: impl Display) {
    report_skip("premise", &reason);
}

/// Whether the test runs as a caller other than root, which its premise needs:
/// root is bound by no directory's mode and refused no `chown`, so a test of
/// what those refuse has nothing to test as root. Where the caller is root,
/// [`premise_unmet`] reports the skip, with `why`.
///
/// Root is the effective uid, the one the kernel checks a permission against.
#[track_caller]
pub fn not_root(why: impl Display) -> bool {
    let root = rustix::process::geteuid().is_root();
    if root {
        premise_unmet(why);
    }
    !root
}

/// The variable naming a file every skip is appended to, besides the line
/// printed on stderr.
///
/// Each skip is one line of four tab-separated fields: the source location
/// that called for the skip, the running test's name, the variable that
/// governs it (or `premise` for [`premise_unmet`]'s), and the reason. The test
/// binaries a run starts all append to the one file, so it is removed before a
/// run whose skips it is to hold alone:
///
/// ```sh
/// rm -f target/skips.log
/// FERRODAY_CAGE_SKIP_LOG=$PWD/target/skips.log cargo test --workspace --all-features
/// cut -f3 target/skips.log | sort | uniq -c
/// ```
///
/// A log that cannot be written fails the skipping test, since a run asked
/// for an account of its skips and would otherwise come back with a partial
/// one.
pub const SKIP_LOG: &str = "FERRODAY_CAGE_SKIP_LOG";

/// Reports a skip governed by `governed_by`: on stderr, and in the file
/// [`SKIP_LOG`] names, where one is named.
///
/// # Panics
///
/// When the skip log is named and cannot be appended to.
#[track_caller]
fn report_skip(governed_by: &str, reason: &dyn Display) {
    eprintln!("skipping: {reason}");
    let Some(log) = std::env::var_os(SKIP_LOG) else {
        return;
    };
    let caller = std::panic::Location::caller();
    let thread = std::thread::current();
    // A reason can carry an error's own text, which keeps the line one line
    // only once its separators are spaces.
    let reason = reason.to_string().replace(['\t', '\n', '\r'], " ");
    let line = format!(
        "{}:{}\t{}\t{governed_by}\t{reason}\n",
        caller.file(),
        caller.line(),
        thread.name().unwrap_or("unnamed"),
    );
    // One write to a file opened for appending, so the lines of tests skipping
    // at once on their own threads, or in other binaries, do not interleave.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .unwrap_or_else(|err| {
            panic!(
                "the skip log {} cannot be appended to: {err}",
                Path::new(&log).display()
            )
        });
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

/// Whether the kernel's Landlock enforces network rights, given what
/// `host::landlock_abi` reported and what `host::landlock_enforces_net`
/// answered.
#[track_caller]
pub fn landlock_net(abi: Option<i32>, enforced: bool) -> bool {
    match abi {
        None => landlock(abi),
        Some(abi) => LANDLOCK.holds(
            enforced,
            format!("Landlock ABI {abi} predates network rights"),
        ),
    }
}

/// Whether the kernel's Landlock enforces scopes, given what
/// `host::landlock_abi` reported and what `host::landlock_enforces_scope`
/// answered.
///
/// A kernel with no Landlock at all is missing Landlock before it is missing
/// scopes, so its skip is [`landlock`]'s, which [`LANDLOCK`] turns into a
/// failure as it does for every Landlock test. [`LANDLOCK_SCOPE`] still demands
/// the test there too, since scopes are among what that kernel lacks.
#[track_caller]
pub fn landlock_scope(abi: Option<i32>, enforced: bool) -> bool {
    match abi {
        None => {
            LANDLOCK_SCOPE.insist("the kernel offers no Landlock support");
            landlock(abi)
        }
        Some(abi) => LANDLOCK_SCOPE.holds(enforced, format!("Landlock ABI {abi} predates scopes")),
    }
}

/// Whether the kernel offers seccomp filtering, which a hardening policy and
/// every sandbox with a network namespace of its own install.
#[track_caller]
pub fn seccomp() -> bool {
    SECCOMP.holds(
        ferroday_cage::host::seccomp_available(),
        "the kernel offers no seccomp support",
    )
}

/// Whether a network suite runs: `gate` opts into it, and without it the suite
/// skips, unless [`NETWORK_TEST`] says it must run. `suite` names what the
/// skip line tells the reader to set the gate for.
#[track_caller]
pub fn network_suite(gate: &str, suite: &str) -> bool {
    let opted = std::env::var_os(gate).is_some();
    NETWORK_TEST.holds(opted, format!("set {gate}=1 to run {suite}"))
}
