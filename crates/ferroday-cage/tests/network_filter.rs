//! Integration tests for the filter a sandbox with a network namespace of its
//! own carries, which refuses the routes out that a network namespace does not
//! cover: vsock, io_uring, and on x86 the socket creation `socketcall` hides.
//!
//! The probe is this test binary, run again inside a sandbox on an empty root
//! holding the host's own userland, bound read-only, so the calls under test
//! are made directly rather than through a tool that might not make them. A probe run
//! prints one line per route. Each test compares a sandbox under
//! [`Network::Host`], which carries no filter, with the postures that do, so a
//! refusal the host's kernel would have made anyway is told apart from one the
//! filter made. Each also holds the cage's provenance record to what the probe
//! saw: the record states the refusals a command observes, and none where it
//! observes none.

#![allow(unsafe_code)]

mod common;

use std::collections::BTreeMap;

use ferroday_cage::{Network, ResolvedNetworkFilter};

/// Set inside the sandbox to make a probe test probe rather than return.
const PROBE: &str = "FERRODAY_CAGE_TEST_NETWORK_FILTER_PROBE";

/// Where the test binary is bound inside the sandbox.
const PROBE_PATH: &str = "/probe";

/// What a route reported: success, or the errno it failed with.
type Outcome = Result<(), i32>;

/// One probe run's routes, by name, or `None` where the probe was killed by a
/// signal before it reported them all.
type Report = Option<BTreeMap<String, Outcome>>;

/// Whether this run is the probe inside the sandbox, rather than the test
/// outside it. A probe's routes start on a line of their own: under
/// `--nocapture` the harness has printed `test <name> ... ` without ending
/// the line.
fn probing() -> bool {
    let probing = std::env::var_os(PROBE).is_some();
    if probing {
        println!();
    }
    probing
}

/// Prints a route's outcome on the line the outer test reads.
///
/// `allow` rather than `expect`: a long is an int on a 32-bit target, where the
/// narrowing cannot fail and the pattern is irrefutable, and on no other.
#[allow(irrefutable_let_patterns)]
fn report(route: &str, result: libc::c_long) {
    if result < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        println!("route {route} errno {errno}");
    } else {
        println!("route {route} ok");
        if let Ok(fd) = libc::c_int::try_from(result) {
            // SAFETY: closing the descriptor the call just returned, which
            // nothing else holds.
            unsafe { libc::close(fd) };
        }
    }
}

/// Creates a socket of `domain` through the build's own `socket`, the whole
/// register passed as the family.
fn socket(domain: libc::c_long) -> libc::c_long {
    // SAFETY: socket takes three integers and touches no memory of ours.
    unsafe { libc::syscall(libc::SYS_socket, domain, libc::SOCK_STREAM, 0) }
}

// `allow` rather than `expect`: widening an int to a long is the identity on a
// 32-bit target, where the conversion lint fires, and on no other.
#[test]
#[allow(clippy::useless_conversion)]
fn probe_native() {
    if !probing() {
        return;
    }
    report("vsock", socket(libc::AF_VSOCK.into()));
    // The kernel reads the family as an int, so this is AF_VSOCK too.
    #[cfg(target_pointer_width = "64")]
    report(
        "vsock-high-bits",
        socket(1 << 32 | libc::c_long::from(libc::AF_VSOCK)),
    );
    report("unix", socket(libc::AF_UNIX.into()));
    report("inet", socket(libc::AF_INET.into()));
    let mut params = [0u8; 120];
    // SAFETY: io_uring_setup reads and writes a 120-byte io_uring_params,
    // which `params` is, zeroed as the call requires.
    let ring = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, params.as_mut_ptr()) };
    report("io_uring", ring);
    println!("probe done");
}

/// Reports whether the host probe finds a seccomp filter installable from
/// inside the sandbox.
#[test]
fn probe_seccomp_available() {
    if !probing() {
        return;
    }
    println!(
        "seccomp-available {}",
        ferroday_cage::host::seccomp_available()
    );
    println!("probe done");
}

/// A mirror nothing listens on: a bootstrap that reaches its first download
/// fails there, fetching from it.
#[cfg(any(feature = "debian", feature = "alpine"))]
const DEAD_MIRROR: &str = "http://127.0.0.1:9/";

/// Reports how a Debian bootstrap from [`DEAD_MIRROR`] fails inside the
/// sandbox.
#[test]
#[cfg(feature = "debian")]
fn probe_debian_preflight() {
    if !probing() {
        return;
    }
    let mut debian = ferroday_cage::provision::debian::Debian::builder("trixie")
        .mirror(DEAD_MIRROR)
        .build()
        .expect("a valid provisioner");
    let failure = ferroday_cage::provision::ensure("/tmp/debian", &mut debian)
        .expect_err("nothing can be fetched");
    println!("debian {}", ferroday_cage::ErrorChain::new(&failure));
    println!("probe done");
}

/// Reports how an Alpine bootstrap from [`DEAD_MIRROR`] fails inside the
/// sandbox.
#[test]
#[cfg(feature = "alpine")]
fn probe_alpine_preflight() {
    if !probing() {
        return;
    }
    let mut alpine = ferroday_cage::provision::alpine::Alpine::builder("v3.22")
        .mirror(DEAD_MIRROR)
        .include(["alpine-baselayout"])
        .build()
        .expect("a valid provisioner");
    let failure = ferroday_cage::provision::ensure("/tmp/alpine", &mut alpine)
        .expect_err("nothing can be fetched");
    println!("alpine {}", ferroday_cage::ErrorChain::new(&failure));
    println!("probe done");
}

/// A 32-bit x86 syscall from this 64-bit process, through `int 0x80`, which
/// takes its arguments in `ebx`, `ecx`, and `edx`.
///
/// `rbx` cannot be an operand, so the first argument is swapped through it.
/// The kernel restores no more than the 32-bit ABI promises, so `r8` through
/// `r15` are given up.
#[cfg(target_arch = "x86_64")]
fn int80(nr: u32, a: u32, b: u32, c: u32) -> libc::c_long {
    let ret: u64;
    // SAFETY: the instruction makes one syscall whose arguments are the
    // integers given, and pointers into memory this process owns where the
    // call reads any; every register it can change is declared.
    unsafe {
        std::arch::asm!(
            "xchg {a}, rbx",
            "int 0x80",
            "xchg {a}, rbx",
            a = inout(reg) u64::from(a) => _,
            inlateout("rax") u64::from(nr) => ret,
            in("rcx") u64::from(b),
            in("rdx") u64::from(c),
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            options(nostack),
        );
    }
    // The 32-bit result, sign-extended: a failure is -errno.
    let ret = libc::c_long::from(ret as u32 as i32);
    if ret < 0 && ret > -4096 {
        // SAFETY: writing this thread's errno, so `report` reads the call's.
        unsafe { *libc::__errno_location() = (-ret) as libc::c_int };
        return -1;
    }
    ret
}

#[test]
#[cfg(target_arch = "x86_64")]
fn probe_compat() {
    if !probing() {
        return;
    }
    /// 32-bit x86's `socket`.
    const SOCKET: u32 = 359;
    /// 32-bit x86's `socketcall`, and its call number for creating a socket.
    const SOCKETCALL: u32 = 102;
    const SYS_SOCKET: u32 = 1;
    let vsock = libc::AF_VSOCK as u32;
    let unix = libc::AF_UNIX as u32;
    let stream = libc::SOCK_STREAM as u32;

    report("i386-socket-vsock", int80(SOCKET, vsock, stream, 0));
    report("i386-socket-unix", int80(SOCKET, unix, stream, 0));

    // socketcall reads its arguments through a pointer a 32-bit call can
    // carry, so they live in memory below 4 GiB.
    // SAFETY: an anonymous private mapping, which aliases nothing.
    let low = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
            -1,
            0,
        )
    };
    assert_ne!(low, libc::MAP_FAILED, "a mapping below 4 GiB");
    let args = low.cast::<u32>();
    let address = u32::try_from(low.addr()).expect("MAP_32BIT maps below 4 GiB");
    for (route, domain) in [
        ("i386-socketcall-unix", unix),
        ("i386-socketcall-vsock", vsock),
    ] {
        // SAFETY: three u32 writes into the page just mapped.
        unsafe {
            args.write(domain);
            args.add(1).write(stream);
            args.add(2).write(0);
        }
        report(route, int80(SOCKETCALL, SYS_SOCKET, address, 0));
    }
    println!("probe done");
}

/// Runs the probe test `test` in a sandbox under `network`, returning what it
/// reported and what the sandbox's provenance record says its network filter
/// refuses.
fn probe(network: Network, test: &str) -> (Report, Option<ResolvedNetworkFilter>) {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let cage = common::host_userland()
        .command(PROBE_PATH)
        .args(common::rerun_args(test))
        .env(PROBE, "1")
        .network(network)
        .resolv_conf(false)
        .bind_ro(&exe, PROBE_PATH)
        .build()
        .expect("a valid sandbox configuration");
    let recorded = cage.resolved_inputs().network_filter;
    let output = cage.output().expect("the sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.signal().is_some() || !stdout.contains("probe done") {
        assert!(
            output.status.signal().is_some(),
            "the probe failed without reporting:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        return (None, recorded);
    }
    let routes = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("route "))
        .map(|line| {
            let (route, outcome) = line.split_once(' ').expect("a route and its outcome");
            let outcome = match outcome.strip_prefix("errno ") {
                Some(errno) => Err(errno.parse().expect("an errno number")),
                None => Ok(()),
            };
            (route.to_string(), outcome)
        })
        .collect();
    (Some(routes), recorded)
}

/// Whether this host can build a sandbox that installs the filter, reporting
/// the skip where it cannot.
fn host_runs_the_filter() -> bool {
    common::require::userns() && common::require::seccomp()
}

/// The outcome `route` reported, failing the test where the probe did not
/// report it.
fn outcome(report: &BTreeMap<String, Outcome>, route: &str) -> Outcome {
    *report
        .get(route)
        .unwrap_or_else(|| panic!("the probe reported no {route} route: {report:?}"))
}

/// The errno the record says `syscall` answers with where its first argument
/// is `first_argument`, failing the test where the record states no such
/// refusal.
fn recorded_errno(
    filter: Option<&ResolvedNetworkFilter>,
    syscall: &str,
    first_argument: Option<u32>,
) -> i32 {
    let filter = filter.expect("a filtered sandbox records its network filter");
    let refusal = filter
        .refusals
        .iter()
        .find(|refusal| refusal.syscall == syscall && refusal.first_argument == first_argument)
        .unwrap_or_else(|| panic!("the record states no refusal of {syscall}: {filter:?}"));
    i32::from(refusal.errno)
}

#[test]
fn an_isolated_network_refuses_vsock_and_io_uring() {
    if !host_runs_the_filter() {
        return;
    }
    let (host, unfiltered) = probe(Network::Host, "probe_native");
    let host = host.expect("the host-network probe reports");
    assert_eq!(unfiltered, None, "the host network records no filter");
    let vsock = u32::try_from(libc::AF_VSOCK).expect("a family fits a u32");
    for network in [Network::Isolated, Network::None] {
        let (filtered, recorded) = probe(network, "probe_native");
        let filtered = filtered.expect("the filtered probe reports");
        assert_eq!(
            outcome(&filtered, "vsock"),
            Err(libc::EAFNOSUPPORT),
            "{network:?}"
        );
        // The record states the answers the command saw.
        assert_eq!(
            outcome(&filtered, "vsock"),
            Err(recorded_errno(recorded.as_ref(), "socket", Some(vsock))),
            "{network:?}"
        );
        assert_eq!(
            outcome(&filtered, "io_uring"),
            Err(recorded_errno(recorded.as_ref(), "io_uring_setup", None)),
            "{network:?}"
        );
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            outcome(&filtered, "vsock-high-bits"),
            Err(libc::EAFNOSUPPORT),
            "{network:?}"
        );
        assert_eq!(
            outcome(&filtered, "io_uring"),
            Err(libc::ENOSYS),
            "{network:?}"
        );
        // Every other family is the namespace's to govern, and is created.
        assert_eq!(outcome(&filtered, "unix"), Ok(()), "{network:?}");
        assert_eq!(outcome(&filtered, "inet"), Ok(()), "{network:?}");
    }
    // Where the host's own kernel refuses the same calls, the refusals above
    // are not evidence of the filter. Say so rather than pass quietly.
    if outcome(&host, "vsock").is_err() {
        common::require::premise_unmet(format!(
            "this host refuses a vsock socket itself ({:?}), so the vsock check \
             cannot tell the filter from the kernel",
            outcome(&host, "vsock")
        ));
    }
    if outcome(&host, "io_uring") == Err(libc::ENOSYS) {
        common::require::premise_unmet(
            "this host's kernel has no io_uring, so the io_uring check cannot tell \
             the filter from the kernel",
        );
    }
}

#[test]
#[cfg(target_arch = "x86_64")]
fn an_isolated_network_closes_the_32_bit_entry_points() {
    if !host_runs_the_filter() {
        return;
    }
    // Without the 32-bit entry point there is nothing to close: a kernel
    // built without IA32 emulation, or booted with it off, faults the probe or
    // refuses its calls.
    let Some(host) = probe(Network::Host, "probe_compat").0 else {
        common::require::premise_unmet("this host offers no 32-bit x86 entry point");
        return;
    };
    if outcome(&host, "i386-socket-unix").is_err() {
        common::require::premise_unmet(format!(
            "this host refuses a 32-bit x86 socket ({:?})",
            outcome(&host, "i386-socket-unix")
        ));
        return;
    }
    for network in [Network::Isolated, Network::None] {
        let (filtered, recorded) = probe(network, "probe_compat");
        let filtered = filtered.expect("the filtered probe reports");
        assert_eq!(
            outcome(&filtered, "i386-socket-vsock"),
            Err(libc::EAFNOSUPPORT),
            "{network:?}"
        );
        // SYS_SOCKET, the call number socketcall creates a socket under.
        assert_eq!(
            outcome(&filtered, "i386-socketcall-unix"),
            Err(recorded_errno(recorded.as_ref(), "socketcall", Some(1))),
            "{network:?}"
        );
        // socketcall hides the family, so no socket is created through it,
        // and each family reads as one the kernel does not offer.
        assert_eq!(
            outcome(&filtered, "i386-socketcall-vsock"),
            Err(libc::EAFNOSUPPORT),
            "{network:?}"
        );
        assert_eq!(
            outcome(&filtered, "i386-socketcall-unix"),
            Err(libc::EAFNOSUPPORT),
            "{network:?}"
        );
        // The direct 32-bit call still creates every other family.
        assert_eq!(
            outcome(&filtered, "i386-socket-unix"),
            Ok(()),
            "{network:?}"
        );
    }
    // The host network carries no filter, and socketcall works there.
    assert_eq!(outcome(&host, "i386-socketcall-unix"), Ok(()));
}

/// Runs the probe test `test` in a sandbox under `policy`, or under no policy
/// of its own where `None`, and returns what it reported on its line starting
/// with `key`.
#[cfg(all(feature = "hardening", target_pointer_width = "64"))]
fn report_under(test: &str, key: &str, policy: Option<ferroday_cage::SeccompPolicy>) -> String {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let mut builder = common::host_userland()
        .command(PROBE_PATH)
        .args(common::rerun_args(test))
        .env(PROBE, "1")
        .resolv_conf(false)
        .bind_ro(&exe, PROBE_PATH);
    if let Some(policy) = policy {
        builder = builder.seccomp(policy);
    }
    let output = builder
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let prefix = format!("{key} ");
    let report = stdout
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| {
            panic!(
                "the probe reported no {key}:\n{stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    report.to_string()
}

/// A policy refusing the `seccomp` syscall, as a container runtime's profile
/// can.
///
/// It and the tests that launch under it build for a 64-bit target alone:
/// libc's syscall numbers are the `i64` a rule takes only there, and a policy
/// compiles for a 64-bit host alone.
#[cfg(all(feature = "hardening", target_pointer_width = "64"))]
fn refusing_seccomp() -> Option<ferroday_cage::SeccompPolicy> {
    let rules = ferroday_cage::SeccompRules::denying([libc::SYS_seccomp]);
    Some(ferroday_cage::SeccompPolicy::Rules(rules))
}

/// What the host probe answers inside a sandbox under `policy`.
#[cfg(all(feature = "hardening", target_pointer_width = "64"))]
fn seccomp_available_under(policy: Option<ferroday_cage::SeccompPolicy>) -> bool {
    report_under("probe_seccomp_available", "seccomp-available", policy)
        .parse()
        .expect("the probe reports a boolean")
}

/// The host probe answers what a launch would meet rather than what the kernel
/// was built with: inside a sandbox whose seccomp policy refuses the `seccomp`
/// syscall, as a container runtime's profile can, no filter can be installed,
/// and the probe says so.
#[test]
#[cfg(all(feature = "hardening", target_pointer_width = "64"))]
fn the_seccomp_probe_reports_a_policy_that_refuses_the_install() {
    if !host_runs_the_filter() {
        return;
    }
    assert!(
        seccomp_available_under(None),
        "a sandbox under no policy of its own can install a filter",
    );
    assert!(
        !seccomp_available_under(refusing_seccomp()),
        "a policy refusing seccomp leaves no filter installable",
    );
}

/// A bootstrap runs the target's binaries in sandboxes that carry the network
/// filter, so on a host that cannot install one it is refused before its first
/// download, naming the filter. Where the filter installs, the same bootstrap
/// reaches the download, which is what makes the refusal the preflight's.
#[test]
#[cfg(all(
    feature = "hardening",
    feature = "debian",
    feature = "alpine",
    target_pointer_width = "64"
))]
fn a_bootstrap_refuses_a_host_without_seccomp_before_downloading() {
    if !host_runs_the_filter() {
        return;
    }
    for (test, key) in [
        ("probe_debian_preflight", "debian"),
        ("probe_alpine_preflight", "alpine"),
    ] {
        let refused = report_under(test, key, refusing_seccomp());
        assert!(
            refused.contains("network filter") && !refused.contains("127.0.0.1"),
            "{key}: {refused}"
        );
        let reached = report_under(test, key, None);
        assert!(
            !reached.contains("network filter") && reached.contains("127.0.0.1"),
            "{key}: {reached}"
        );
    }
}
