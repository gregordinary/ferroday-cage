//! Architecture handling: the host mapping, the merged-usr symlink farm, and
//! the foreign-architecture binfmt preflight.

use std::path::Path;

/// The Debian architecture name for the host, from `uname`.
///
/// Returns the raw machine name when it is not one this table knows, so a
/// caller on an unusual host can still proceed by naming the architecture
/// explicitly.
pub(crate) fn host_architecture() -> String {
    let uname = rustix::system::uname();
    let machine = uname.machine().to_string_lossy();
    match machine.as_ref() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "armv7l" | "armv6l" => "armhf",
        "i686" | "i586" | "i386" => "i386",
        "ppc64le" => "ppc64el",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        other => other,
    }
    .to_string()
}

/// The merged-usr top-level directories for `architecture`: `bin`, `sbin`,
/// and `lib` on every architecture, plus that architecture's multilib
/// directories.
///
/// Each becomes a symlink `<dir> -> usr/<dir>` created before extraction, so
/// packages that ship `/usr`-native paths and the `base-files` package's own
/// symlink entries agree, and any package shipping a legacy top-level path
/// resolves through the symlink.
pub(crate) fn merged_usr_dirs(architecture: &str) -> Vec<&'static str> {
    let mut dirs = vec!["bin", "sbin", "lib"];
    dirs.extend(match architecture {
        "amd64" => &["lib32", "lib64", "libx32"][..],
        "i386" => &["lib64", "libx32"][..],
        "ppc64el" => &["lib64"][..],
        "s390x" => &["lib32"][..],
        _ => &[][..],
    });
    dirs
}

/// The `qemu-user` interpreter name for `architecture`, or `None` when it is
/// not one that a qemu binfmt handler covers.
fn qemu_interpreter(architecture: &str) -> Option<&'static str> {
    Some(match architecture {
        "amd64" => "x86_64",
        "arm64" => "aarch64",
        "armhf" => "arm",
        "i386" => "i386",
        "ppc64el" => "ppc64le",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        _ => return None,
    })
}

/// Whether a `host` CPU executes `target` binaries with no emulation.
///
/// Identical architectures always do. Beyond that, an amd64 host runs i386
/// binaries through the near-universal IA-32 compatibility mode
/// (`CONFIG_IA32_EMULATION`), so a full i386 bootstrap on amd64 needs no qemu.
/// The relation is directional: a 32-bit i386 host cannot run amd64. Other
/// nominally-compatible pairs — arm64 running armhf, say — depend on optional
/// kernel support (AArch32 at EL0) that is absent on many hosts, so they are
/// treated as foreign and left to require an explicit binfmt handler.
fn runs_natively(host: &str, target: &str) -> bool {
    host == target || matches!((host, target), ("amd64", "i386"))
}

/// Checks that a full bootstrap for `target` can execute on `host`.
///
/// A bootstrap the host runs natively needs nothing (see [`runs_natively`]). A
/// foreign one runs the target's `dpkg` and maintainer scripts through a
/// `qemu-user` binfmt handler, which must be registered with the fix-binary
/// (`F`) flag so the interpreter is preloaded and no binary is copied into the
/// rootfs. The `F` flag makes the kernel open and hold the interpreter at
/// registration time, so it keeps working after the cage pivots into the target
/// rootfs, where the interpreter's own path no longer resolves; the launch path
/// never touches the binfmt registration. A clear, actionable message names the
/// remedy and points at extract-only as the alternative.
pub(crate) fn preflight_foreign(host: &str, target: &str) -> Result<(), String> {
    if runs_natively(host, target) {
        return Ok(());
    }
    let Some(interpreter) = qemu_interpreter(target) else {
        return Err(format!(
            "a full bootstrap for {target} on a {host} host needs a qemu-user binfmt \
             handler, and {target} is not a known qemu target; use extract-only instead"
        ));
    };
    let path = format!("/proc/sys/fs/binfmt_misc/qemu-{interpreter}");
    let registration = std::fs::read_to_string(&path).map_err(|_| {
        format!(
            "a full bootstrap for {target} on a {host} host needs the qemu-{interpreter} \
             binfmt handler registered (install qemu-user-static and binfmt support); \
             use extract-only to lay out the rootfs without running target binaries"
        )
    })?;
    check_registration(&registration).map_err(|reason| {
        format!(
            "the qemu-{interpreter} binfmt handler is registered but {reason}; a foreign \
             bootstrap needs it enabled and registered with the fix-binary (F) flag"
        )
    })
}

/// Validates a binfmt_misc registration: enabled, with the `F` flag.
fn check_registration(registration: &str) -> Result<(), &'static str> {
    let mut lines = registration.lines();
    match lines.next().map(str::trim) {
        Some("enabled") => {}
        _ => return Err("it is disabled"),
    }
    let flags = registration
        .lines()
        .find_map(|line| line.trim().strip_prefix("flags:"))
        .unwrap_or("");
    if flags.contains('F') {
        Ok(())
    } else {
        Err("it lacks the fix-binary (F) flag")
    }
}

/// Whether `path` names an existing entry (following no symlink at the leaf).
pub(crate) fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merged_usr_dirs_include_multilib() {
        assert_eq!(
            merged_usr_dirs("amd64"),
            ["bin", "sbin", "lib", "lib32", "lib64", "libx32"]
        );
        assert_eq!(merged_usr_dirs("arm64"), ["bin", "sbin", "lib"]);
        assert_eq!(merged_usr_dirs("ppc64el"), ["bin", "sbin", "lib", "lib64"]);
    }

    #[test]
    fn native_bootstrap_needs_no_binfmt() {
        assert!(preflight_foreign("amd64", "amd64").is_ok());
    }

    #[test]
    fn amd64_runs_i386_without_qemu() {
        // IA-32 compatibility mode: an amd64 host runs i386 binaries natively,
        // so a full i386 bootstrap needs no binfmt handler.
        assert!(preflight_foreign("amd64", "i386").is_ok());
        // The relation is directional: a 32-bit i386 host cannot run amd64,
        // and an unrelated pair stays foreign.
        assert!(!runs_natively("i386", "amd64"));
        assert!(!runs_natively("arm64", "armhf"));
    }

    #[test]
    fn registration_requires_enabled_and_fix_binary() {
        let good = "enabled\ninterpreter /usr/bin/qemu-aarch64-static\nflags: OCF\n";
        assert!(check_registration(good).is_ok());
        let disabled = "disabled\nflags: OCF\n";
        assert!(check_registration(disabled).is_err());
        let no_fix = "enabled\nflags: OC\n";
        assert_eq!(
            check_registration(no_fix),
            Err("it lacks the fix-binary (F) flag")
        );
    }
}
