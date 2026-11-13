//! Integration tests for the session keyring a sandbox is given in place of
//! the caller's.
//!
//! A key is read by whoever *possesses* it, and a process possesses every key
//! reachable from its session keyring, which a forked process inherits. Each
//! test here gives a thread a private session keyring and adds a key to it that
//! only a possessor may even view. Credentials are per thread, so the private
//! keyring touches neither the other tests nor the login session the suite runs
//! in, and it is released when the thread exits.
//!
//! Where the launch gives the command a keyring of its own, the command looks
//! for the key in `/proc/keys`. The listing shows a key exactly when the reader
//! may view it, so a key that stays out of the command's listing is one the
//! command does not possess.
//!
//! Where a seccomp policy the caller runs under refuses the launch's join, the
//! command keeps the caller's keyring and is refused the key syscalls instead.
//! Those tests install each policy on a thread of their own, since a filter is
//! per thread and inherited by every process the thread starts, and have the
//! command read the key by its serial number. The command is this test binary,
//! run again: [`probe_keys`] is the test that reads, when [`PROBE`] is set.

#![allow(unsafe_code)]

mod common;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::io;
use std::time::Duration;

use ferroday_cage::Cage;

/// Set in a launched command's environment to the serial of the key
/// [`probe_keys`] reads, which makes that test probe rather than return.
const PROBE: &str = "FERRODAY_CAGE_TEST_KEYRING_PROBE";

/// Where a sandbox binds this test binary.
const PROBE_PATH: &str = "/probe";

/// The payload of every private key, which no launched command may print.
const PAYLOAD: &str = "a secret the sandbox must not reach";

/// `KEYCTL_GET_KEYRING_ID`, from `linux/keyctl.h`.
const KEYCTL_GET_KEYRING_ID: libc::c_long = 0;
/// `KEYCTL_JOIN_SESSION_KEYRING`.
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
/// `KEYCTL_SETPERM`.
const KEYCTL_SETPERM: libc::c_long = 5;
/// `KEYCTL_READ`.
const KEYCTL_READ: libc::c_long = 11;
/// `KEYCTL_INVALIDATE`.
const KEYCTL_INVALIDATE: libc::c_long = 21;
/// `KEY_SPEC_SESSION_KEYRING`.
const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
/// `KEY_POS_ALL`: every right, for a possessor and for no one else. Without
/// `KEY_USR_VIEW` the owner cannot so much as list the key unless it possesses
/// it, which is what makes `/proc/keys` a test of possession.
const KEY_POS_ALL: libc::c_long = 0x3f00_0000;

/// A key in a private session keyring of the calling thread's own.
struct PrivateKey {
    /// The key's serial, for invalidating it when the test ends.
    serial: libc::c_long,
    /// The key's description, unique to this test run.
    description: String,
}

impl PrivateKey {
    /// Gives the calling thread a fresh session keyring and adds a key to it
    /// that only a possessor may view, or returns `None` where this process
    /// cannot use the kernel keyring at all.
    fn add(label: &str) -> Option<PrivateKey> {
        // SAFETY: an integer-only keyctl operation; the null name asks for an
        // anonymous keyring and no pointer is passed.
        let joined = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_JOIN_SESSION_KEYRING,
                std::ptr::null::<libc::c_char>(),
            )
        };
        if joined < 0 {
            // A premise rather than a facility: a process that cannot reach
            // the keyring starts no sandbox that could, so there is no
            // possession to test.
            let error = io::Error::last_os_error();
            common::require::premise_unmet(format!(
                "the kernel keyring is unavailable to this process: {error}"
            ));
            return None;
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is past the epoch")
            .as_nanos();
        let description = format!("ferroday-cage-{label}-{}-{nonce}", std::process::id());
        let kind = CString::new("user").expect("no interior NUL");
        let name = CString::new(description.clone()).expect("no interior NUL");
        let payload = PAYLOAD.as_bytes();
        // SAFETY: the type and description are NUL-terminated strings that
        // outlive the call, and the payload pointer and length describe one
        // readable buffer.
        let serial = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                kind.as_ptr(),
                name.as_ptr(),
                payload.as_ptr(),
                payload.len(),
                KEY_SPEC_SESSION_KEYRING,
            )
        };
        assert!(
            serial >= 0,
            "the key is addable: {}",
            io::Error::last_os_error()
        );
        // SAFETY: an integer-only keyctl operation on the serial just returned.
        let set = unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, serial, KEY_POS_ALL) };
        assert!(
            set == 0,
            "the key's permissions are settable: {}",
            io::Error::last_os_error()
        );

        let key = PrivateKey {
            serial,
            description,
        };
        // The premise the sandbox's half rests on: a possessor sees the key in
        // the listing. Read from this thread, whose credentials are the ones
        // holding the private keyring.
        assert!(
            key.listed_here(),
            "a key the reader possesses is listed in /proc/keys",
        );
        Some(key)
    }

    /// Whether the calling thread's `/proc/keys` lists this key.
    fn listed_here(&self) -> bool {
        std::fs::read_to_string("/proc/keys")
            .expect("/proc/keys is readable")
            .contains(&self.description)
    }

    /// A shell script that exits 0 when `/proc/keys` is readable, lists at
    /// least the reader's own keyring, and does not list this key.
    fn absence_script(&self) -> String {
        format!(
            "grep -q . /proc/keys || exit 2; grep -F -q '{}' /proc/keys && exit 1; exit 0",
            self.description,
        )
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Under a policy refusing every keyctl operation this is refused too,
        // and the key goes with the thread's keyring instead, when the thread
        // exits.
        // SAFETY: an integer-only keyctl operation on this key's own serial.
        unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_INVALIDATE, self.serial) };
    }
}

#[test]
fn a_sandbox_does_not_possess_the_callers_session_keys() {
    let Some(rootfs) = common::fixture_rootfs() else {
        return;
    };
    let Some(key) = PrivateKey::add("cage") else {
        return;
    };
    let status = Cage::builder()
        .rootfs(rootfs)
        .command("/bin/sh")
        .args(["-c", &key.absence_script()])
        .build()
        .expect("a valid sandbox configuration")
        .run()
        .expect("the sandbox launches");
    assert_eq!(
        status.code(),
        Some(0),
        "the command must not possess a key in the caller's session keyring",
    );
}

#[cfg(feature = "hardening")]
#[test]
fn a_restriction_does_not_possess_the_callers_session_keys() {
    use ferroday_cage::{FsAccess, Restriction};

    if !common::landlock() {
        return;
    }
    let Some(key) = PrivateKey::add("restriction") else {
        return;
    };
    // A restriction has to confine something; read and execute beneath the
    // system trees and read beneath `/proc` is what a host shell and its
    // listing need.
    let builder = Restriction::builder()
        .command("/bin/sh")
        .args(["-c", &key.absence_script()])
        .landlock_fs(FsAccess::READ, "/proc");
    let status = common::grant_system_trees(builder)
        .build()
        .expect("a valid restriction configuration")
        .run()
        .expect("the restriction launches");
    assert_eq!(
        status.code(),
        Some(0),
        "the restricted command must not possess a key in the caller's session keyring",
    );
}

/// A seccomp policy refusing some of `keyctl` with `EPERM`, as a policy a
/// caller runs under can, installed on the launching thread.
///
/// The policy reads the syscall number without the architecture: it stands for
/// a caller's policy over the calls this suite makes, all of them through the
/// native entry point.
#[derive(Debug, Clone, Copy)]
enum Inherited {
    /// Refuses `KEYCTL_JOIN_SESSION_KEYRING` alone.
    Join,
    /// Refuses the join and `KEYCTL_GET_KEYRING_ID`, and allows every other
    /// operation, `KEYCTL_READ` among them.
    JoinAndQuery,
    /// Refuses every `keyctl` operation.
    Keyctl,
}

impl Inherited {
    const ALL: [Inherited; 3] = [Inherited::Join, Inherited::JoinAndQuery, Inherited::Keyctl];

    /// The operations refused, or `None` where every one is.
    fn refused_operations(self) -> Option<&'static [libc::c_long]> {
        match self {
            Inherited::Join => Some(&[KEYCTL_JOIN_SESSION_KEYRING]),
            Inherited::JoinAndQuery => Some(&[KEYCTL_GET_KEYRING_ID, KEYCTL_JOIN_SESSION_KEYRING]),
            Inherited::Keyctl => None,
        }
    }

    /// The policy's program, where only some operations are refused:
    ///
    /// ```text
    ///   [0]   A = nr
    ///   [1]   keyctl: on; anything else: to allow
    ///   [2]   A = the low half of args[0]     keyctl's operation
    ///   [3..] each refused operation: to refuse
    ///         allow
    ///         return EPERM
    /// ```
    ///
    /// Where every one is, `[1]` sends `keyctl` straight to the refusal, and
    /// the operation is neither loaded nor checked.
    fn program(self) -> Vec<libc::sock_filter> {
        const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
        const JEQ_K: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        const RET_K: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
        /// `seccomp_data.nr`.
        const OFF_NR: u32 = 0;
        /// The low half of `seccomp_data.args[0]`, a 64-bit field in the
        /// kernel's byte order.
        const OFF_ARG0_LOW: u32 = if cfg!(target_endian = "little") {
            16
        } else {
            20
        };
        let insn = |code, k, jt, jf| libc::sock_filter { code, jt, jf, k };
        // The forward distance of a jump from `from` to `to`.
        let to = |from: usize, to: usize| u8::try_from(to - from - 1).expect("a short program");

        let keyctl = u32::try_from(libc::SYS_keyctl).expect("a syscall number fits a u32");
        let operations = self.refused_operations();
        let checks = operations.map_or(0, |operations| 1 + operations.len());
        let allow = 2 + checks;
        let refuse = allow + 1;
        let on_keyctl = if operations.is_some() {
            0
        } else {
            to(1, refuse)
        };
        let mut program = vec![
            insn(LD_W_ABS, OFF_NR, 0, 0),
            insn(JEQ_K, keyctl, on_keyctl, to(1, allow)),
        ];
        if let Some(operations) = operations {
            program.push(insn(LD_W_ABS, OFF_ARG0_LOW, 0, 0));
            for (index, &operation) in operations.iter().enumerate() {
                let operation = u32::try_from(operation).expect("an operation fits a u32");
                program.push(insn(JEQ_K, operation, to(3 + index, refuse), 0));
            }
        }
        program.push(insn(RET_K, libc::SECCOMP_RET_ALLOW, 0, 0));
        program.push(insn(
            RET_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            0,
            0,
        ));
        program
    }

    /// Installs the policy on the calling thread, for it and every process it
    /// starts, under no-new-privileges.
    fn install(self) {
        let program = self.program();
        let fprog = libc::sock_fprog {
            len: u16::try_from(program.len()).expect("a short program"),
            filter: program.as_ptr().cast_mut(),
        };
        rustix::thread::set_no_new_privs(true).expect("no-new-privileges can be set");
        // SAFETY: the fprog points at a program that outlives the call, with
        // its own length; the kernel copies the program and writes through
        // neither pointer.
        let installed = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER as libc::c_long,
                0 as libc::c_long,
                &raw const fprog,
            )
        };
        assert_eq!(
            installed,
            0,
            "the {self:?} policy installs: {}",
            io::Error::last_os_error()
        );
    }
}

/// What each key syscall the probe made answered: `Ok` with what it printed
/// after `ok`, or the errno.
type Report = BTreeMap<String, Result<String, i32>>;

/// Reads a probe run's standard output, failing the test where the probe did
/// not finish.
fn report(stdout: &[u8], stderr: &[u8]) -> Report {
    let stdout = String::from_utf8_lossy(stdout);
    assert!(
        stdout.contains("probe done"),
        "the probe failed without reporting:\n{stdout}\n{}",
        String::from_utf8_lossy(stderr),
    );
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("key "))
        .map(|line| {
            let (call, outcome) = line.split_once(' ').expect("a call and its outcome");
            let outcome = match outcome.strip_prefix("errno ") {
                Some(errno) => Err(errno.parse().expect("an errno number")),
                None => Ok(outcome
                    .strip_prefix("ok")
                    .expect("ok or an errno")
                    .trim()
                    .to_string()),
            };
            (call.to_string(), outcome)
        })
        .collect()
}

/// Prints one key syscall's outcome on the line the outer test reads.
fn print_outcome(call: &str, result: libc::c_long, shown: &str) {
    if result < 0 {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        println!("key {call} errno {errno}");
    } else {
        println!("key {call} ok {shown}");
    }
}

/// Reads the key whose serial [`PROBE`] names, then adds a key and requests
/// one, printing what each call answered. It runs as the command of a launch,
/// and returns at once anywhere else.
#[test]
fn probe_keys() {
    let Some(serial) = std::env::var_os(PROBE) else {
        return;
    };
    // The harness has printed `test probe_keys ... ` without ending the line.
    println!();
    let serial: libc::c_long = serial
        .to_str()
        .and_then(|serial| serial.parse().ok())
        .expect("a key serial");
    let mut payload = [0u8; 128];
    // SAFETY: KEYCTL_READ writes at most the buffer's length into it.
    let read = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_READ,
            serial,
            payload.as_mut_ptr(),
            payload.len(),
        )
    };
    let length = usize::try_from(read).map_or(0, |length| length.min(payload.len()));
    print_outcome("read", read, &String::from_utf8_lossy(&payload[..length]));

    let kind = c"user";
    let description = c"ferroday-cage-keyring-probe";
    // SAFETY: the type and description are NUL-terminated strings that outlive
    // the call, and the payload pointer and length describe one readable byte.
    let added = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            kind.as_ptr(),
            description.as_ptr(),
            b"x".as_ptr(),
            1usize,
            KEY_SPEC_SESSION_KEYRING,
        )
    };
    print_outcome("add_key", added, "");
    // SAFETY: the type and description are NUL-terminated strings that outlive
    // the call; a null callout asks for a search of the caller's keyrings
    // alone.
    let requested = unsafe {
        libc::syscall(
            libc::SYS_request_key,
            kind.as_ptr(),
            description.as_ptr(),
            std::ptr::null::<libc::c_char>(),
            0 as libc::c_long,
        )
    };
    print_outcome("request_key", requested, "");
    println!("probe done");
}

/// Gives a thread of its own a private key and `policy`, runs the probe there
/// directly and then under `launch`, and holds both runs to what the policy
/// and the launch allow.
///
/// Run directly, the probe is the policy's alone to govern: it reads the key
/// wherever the policy allows `KEYCTL_READ`. Under the launch, whose keyring
/// join the policy refuses, every key syscall answers `ENOSYS`, whatever the
/// policy allows.
fn assert_keys_unreadable_under(
    label: &str,
    policy: Inherited,
    launch: impl FnOnce(&str) -> (Option<i32>, Vec<u8>, Vec<u8>) + Send + 'static,
) {
    let label = format!("{label}-{policy:?}");
    let thread = std::thread::spawn(move || {
        let Some(key) = PrivateKey::add(&label) else {
            return;
        };
        policy.install();
        let serial = key.serial.to_string();

        let exe = std::env::current_exe().expect("the test binary has a path");
        let direct = common::run_bounded(
            std::process::Command::new(&exe)
                .args(common::rerun_args("probe_keys"))
                .env(PROBE, &serial)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped()),
            Duration::from_secs(60),
        );
        let direct = report(&direct.stdout, &direct.stderr);
        let expected = match policy.refused_operations() {
            Some(_) => Ok(PAYLOAD.to_string()),
            None => Err(libc::EPERM),
        };
        assert_eq!(
            direct.get("read"),
            Some(&expected),
            "{policy:?}: the probe run directly reads what the policy allows: {direct:?}",
        );

        let (code, stdout, stderr) = launch(&serial);
        assert!(
            !String::from_utf8_lossy(&stdout).contains(PAYLOAD),
            "{policy:?}: the launched command read the caller's key",
        );
        let launched = report(&stdout, &stderr);
        assert_eq!(code, Some(0), "{policy:?}: the probe exits cleanly");
        for call in ["read", "add_key", "request_key"] {
            assert_eq!(
                launched.get(call),
                Some(&Err(libc::ENOSYS)),
                "{policy:?}: the launched command is denied {call}: {launched:?}",
            );
        }
    });
    thread
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[test]
fn a_sandbox_under_a_policy_refusing_the_join_cannot_read_the_callers_keys() {
    if !(common::require::userns() && common::require::seccomp()) {
        return;
    }
    for policy in Inherited::ALL {
        assert_keys_unreadable_under("cage", policy, |serial| {
            let exe = std::env::current_exe().expect("the test binary has a path");
            let output = common::host_userland()
                .command(PROBE_PATH)
                .args(common::rerun_args("probe_keys"))
                .env(PROBE, serial)
                .resolv_conf(false)
                .bind_ro(&exe, PROBE_PATH)
                .build()
                .expect("a valid sandbox configuration")
                .output()
                .expect("the sandbox launches under a policy refusing its keyring join");
            (output.status.code(), output.stdout, output.stderr)
        });
    }
}

#[cfg(feature = "hardening")]
#[test]
fn a_restriction_under_a_policy_refusing_the_join_cannot_read_the_callers_keys() {
    use std::path::Path;

    use ferroday_cage::{FsAccess, Restriction};

    if !(common::landlock() && common::require::seccomp()) {
        return;
    }
    for policy in Inherited::ALL {
        assert_keys_unreadable_under("restriction", policy, |serial| {
            let exe = std::env::current_exe().expect("the test binary has a path");
            let mut builder = Restriction::builder()
                .command(&exe)
                .args(common::rerun_args("probe_keys"))
                .env(PROBE, serial)
                .landlock_fs(
                    FsAccess::READ | FsAccess::EXECUTE,
                    exe.parent().expect("the test binary is in a directory"),
                );
            for tree in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
                if Path::new(tree).exists() {
                    builder = builder.landlock_fs(FsAccess::READ | FsAccess::EXECUTE, tree);
                }
            }
            let output = builder
                .build()
                .expect("a valid restriction configuration")
                .output()
                .expect("the restriction launches under a policy refusing its keyring join");
            (output.status.code(), output.stdout, output.stderr)
        });
    }
}
