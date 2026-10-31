//! Integration tests for the session keyring a sandbox is given in place of
//! the caller's.
//!
//! A key is read by whoever *possesses* it, and a process possesses every key
//! reachable from its session keyring, which a forked process inherits. Each
//! test here gives its own thread a private session keyring, adds a key that
//! only a possessor may even view, and has the sandboxed command look for it in
//! `/proc/keys`. The listing shows a key exactly when the reader may view it,
//! so a key that stays out of the command's listing is one the command does not
//! possess.
//!
//! Credentials are per thread, so the private keyring touches neither the other
//! tests nor the login session the suite runs in, and it is released when the
//! test's thread exits.

#![allow(unsafe_code)]

mod common;

use std::ffi::CString;
use std::io;

use ferroday_cage::Cage;

/// `KEYCTL_JOIN_SESSION_KEYRING`, from `linux/keyctl.h`.
const KEYCTL_JOIN_SESSION_KEYRING: libc::c_long = 1;
/// `KEYCTL_SETPERM`.
const KEYCTL_SETPERM: libc::c_long = 5;
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
            let error = io::Error::last_os_error();
            eprintln!("skipping: the kernel keyring is unavailable to this process: {error}");
            return None;
        }

        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is past the epoch")
            .as_nanos();
        let description = format!("ferroday-cage-{label}-{}-{nonce}", std::process::id());
        let kind = CString::new("user").expect("no interior NUL");
        let name = CString::new(description.clone()).expect("no interior NUL");
        let payload = b"a secret the sandbox must not reach";
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
    use std::path::Path;

    use ferroday_cage::{FsAccess, Restriction};

    if ferroday_cage::host::landlock_abi().is_none() {
        assert!(
            std::env::var_os("FERRODAY_CAGE_REQUIRE_LANDLOCK").is_none(),
            "Landlock is required but the kernel offers none",
        );
        eprintln!("skipping: the kernel offers no Landlock support");
        return;
    }
    let Some(key) = PrivateKey::add("restriction") else {
        return;
    };
    // A restriction has to confine something; read and execute beneath the
    // system trees and read beneath `/proc` is what a host shell and its
    // listing need.
    let mut builder = Restriction::builder()
        .command("/bin/sh")
        .args(["-c", &key.absence_script()])
        .landlock_fs(FsAccess::READ, "/proc");
    for tree in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if Path::new(tree).exists() {
            builder = builder.landlock_fs(FsAccess::READ | FsAccess::EXECUTE, tree);
        }
    }
    let status = builder
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
