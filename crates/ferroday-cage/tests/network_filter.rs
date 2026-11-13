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
//! filter made.

#![allow(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::path::Path;

use ferroday_cage::{Cage, CageBuilder, Network};

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

#[test]
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

/// An empty root holding the host's userland: bound in read-only, with the
/// merged-`/usr` links made as the host has them, so this test binary runs
/// inside as it runs outside.
fn host_userland() -> CageBuilder {
    let mut builder = Cage::builder().empty_rootfs().bind_ro("/usr", "/usr");
    for top in ["/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"] {
        let path = Path::new(top);
        let Ok(meta) = path.symlink_metadata() else {
            continue;
        };
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path).expect("a readable host link");
            builder = builder.symlink(target, top);
        } else if meta.is_dir() {
            builder = builder.bind_ro(top, top);
        }
    }
    builder
}

/// Runs the probe test `test` in a sandbox under `network`.
fn probe(network: Network, test: &str) -> Report {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let output = host_userland()
        .command(PROBE_PATH)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(PROBE, "1")
        .network(network)
        .resolv_conf(false)
        .bind_ro(&exe, PROBE_PATH)
        .build()
        .expect("a valid sandbox configuration")
        .output()
        .expect("the sandbox launches");
    let stdout = String::from_utf8_lossy(&output.stdout);
    if output.status.signal().is_some() || !stdout.contains("probe done") {
        assert!(
            output.status.signal().is_some(),
            "the probe failed without reporting:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        return None;
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
    Some(routes)
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

#[test]
fn an_isolated_network_refuses_vsock_and_io_uring() {
    if !host_runs_the_filter() {
        return;
    }
    let host = probe(Network::Host, "probe_native").expect("the host-network probe reports");
    for network in [Network::Isolated, Network::None] {
        let filtered = probe(network, "probe_native").expect("the filtered probe reports");
        assert_eq!(
            outcome(&filtered, "vsock"),
            Err(libc::EAFNOSUPPORT),
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
    let Some(host) = probe(Network::Host, "probe_compat") else {
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
        let filtered = probe(network, "probe_compat").expect("the filtered probe reports");
        assert_eq!(
            outcome(&filtered, "i386-socket-vsock"),
            Err(libc::EAFNOSUPPORT),
            "{network:?}"
        );
        // socketcall hides the family, so no socket is created through it.
        assert_eq!(
            outcome(&filtered, "i386-socketcall-vsock"),
            Err(libc::ENOSYS),
            "{network:?}"
        );
        assert_eq!(
            outcome(&filtered, "i386-socketcall-unix"),
            Err(libc::ENOSYS),
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
