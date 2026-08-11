//! Architecture handling: the host mapping, the merged-usr symlink farm, and
//! the foreign-architecture binfmt preflight.

use std::path::{Path, PathBuf};

use crate::provision::binfmt;

/// The Debian architecture name for the host.
///
/// This is what [`DebianBuilder::architecture`] and [`Pool::architecture`]
/// default to when a caller names none, and it is exposed so a caller composing
/// its own defaults — a pool path, a cache key, an artifact record — reaches the
/// same answer the bootstrap will.
///
/// The name comes from `uname`, not from `std::env::consts::ARCH`. The two are
/// not interchangeable: `ARCH` reports the architecture the *calling binary* was
/// compiled for, and it reports `powerpc64` for both endiannesses, so it cannot
/// tell `ppc64` from `ppc64el` — which are different Debian architectures with
/// incompatible binaries. The machine name distinguishes them.
///
/// Returns the raw machine name when it is not one this table knows, so a
/// caller on an unusual host can still proceed by naming the architecture
/// explicitly.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::provision::debian::{Debian, host_architecture};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let architecture = host_architecture();
/// let pool = format!("/var/cache/myapp/pool-{architecture}");
/// let debian = Debian::builder("trixie").architecture(&architecture).build()?;
/// # let _ = (pool, debian);
/// # Ok(())
/// # }
/// ```
///
/// [`DebianBuilder::architecture`]: super::DebianBuilder::architecture
/// [`Pool::architecture`]: super::Pool::architecture
pub fn host_architecture() -> String {
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
    binfmt::ready(interpreter).map_err(|reason| match reason {
        binfmt::Missing::Unregistered => format!(
            "a full bootstrap for {target} on a {host} host needs the qemu-{interpreter} \
             binfmt handler registered (install qemu-user-static and binfmt support); \
             use extract-only to lay out the rootfs without running target binaries"
        ),
        binfmt::Missing::Unusable(reason) => format!(
            "the qemu-{interpreter} binfmt handler is registered but {reason}; a foreign \
             bootstrap needs it enabled and registered with the fix-binary (F) flag"
        ),
    })
}

/// The `qemu-user` interpreter the kernel will execute `architecture` binaries
/// through, or `None` when no interpreter is involved.
///
/// `None` covers three cases, and all three are the honest answer rather than a
/// failure: the host runs `architecture` natively, so nothing is emulated; the
/// architecture is not one a `qemu-user` binfmt handler covers; or no handler is
/// registered for it. A caller folding the interpreter into an artifact
/// signature wants a missing value there, not an empty string.
///
/// The value comes from the kernel's own registration under
/// `/proc/sys/fs/binfmt_misc`, which is the path binaries are actually executed
/// through. That matters: the kernel reaches the interpreter through the
/// registration and not through `PATH`, so a caller deriving the interpreter by
/// looking one up in `PATH` can record something other than what ran, and will
/// record nothing at all under a harness that strips `PATH`.
///
/// # Hashing, not probing
///
/// The registered path is good for identity and not for interrogation. qemu
/// refuses to run under its binfmt wrapper name:
///
/// ```text
/// $ /usr/libexec/qemu-binfmt/aarch64-binfmt-P --version
/// qemu: /usr/libexec/qemu-binfmt/aarch64-binfmt-P has to be run using kernel
/// binfmt-misc subsystem
/// ```
///
/// So a caller that wants to identify the interpreter should hash
/// [`path`](Interpreter::path) rather than ask the binary about itself: `open`
/// follows the symlink, so a digest of the registered path is a digest of the
/// interpreter's bytes and needs no canonicalization. A version string is a
/// claim the binary makes about itself; a digest is what it is. Only *executing*
/// the interpreter needs [`resolved`](Interpreter::resolved).
///
/// The digest is the caller's to take, and deliberately not this crate's. The
/// `F` flag means the kernel opened and holds the interpreter at *registration*
/// time, so the file at that path may have been replaced since: a digest taken
/// now may be of something that never ran. Handing back a digest that can be
/// quietly wrong is worse than handing back none, so the crate reports the path
/// and states the caveat.
///
/// # Example
///
/// ```no_run
/// use ferroday_cage::provision::debian::foreign_interpreter;
///
/// match foreign_interpreter("arm64") {
///     Some(interpreter) => println!(
///         "emulated by {} (enabled: {})",
///         interpreter.path.display(),
///         interpreter.enabled,
///     ),
///     None => println!("no interpreter: run natively, or none registered"),
/// }
/// ```
pub fn foreign_interpreter(architecture: &str) -> Option<Interpreter> {
    if runs_natively(&host_architecture(), architecture) {
        return None;
    }
    let name = qemu_interpreter(architecture)?;
    let registration = binfmt::parse(&binfmt::read(name)?);
    let path = registration.interpreter?;
    Some(Interpreter {
        name: name.to_string(),
        resolved: std::fs::canonicalize(&path).ok(),
        path,
        enabled: registration.enabled,
        flags: registration.flags,
    })
}

/// The `qemu-user` interpreter a foreign-architecture binary is executed
/// through, as the kernel has it registered.
///
/// Returned by [`foreign_interpreter`], which documents what to do with it: a
/// changed interpreter silently changes compiled output, so it belongs in an
/// artifact signature, and the way to identify it is to hash
/// [`path`](Self::path) rather than to ask the binary about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Interpreter {
    /// The qemu target name the handler is registered under: `aarch64` for the
    /// Debian architecture `arm64`, and so on.
    pub name: String,
    /// The interpreter exactly as the kernel recorded it.
    ///
    /// This is the provenance-faithful value, and the one to hash: it is what
    /// the registration names, and `open` follows any symlink along it. It is
    /// not, however, a path that can be executed — see [`foreign_interpreter`].
    pub path: PathBuf,
    /// [`path`](Self::path) canonicalized, or `None` when it does not resolve.
    ///
    /// The two are different facts and both are worth recording. On the common
    /// Debian layout the registration names a wrapper —
    /// `/usr/libexec/qemu-binfmt/aarch64-binfmt-P` — that is a symlink to the
    /// real binary, and repointing that symlink changes the interpreter without
    /// changing the registration, which a record carrying one path alone could
    /// not show. A path that does not resolve is a fact rather than an error, so
    /// everything else is still reported.
    pub resolved: Option<PathBuf>,
    /// Whether the handler is enabled.
    ///
    /// A registered handler that is switched off is reported as present and not
    /// enabled, rather than as absent: the registration exists, and the
    /// distinction is the difference between "turn it on" and "install it".
    pub enabled: bool,
    /// The registration's flag letters, as written — `POF` on a Debian host.
    ///
    /// A foreign bootstrap needs `F`, the fix-binary flag, which is what makes
    /// the interpreter keep working after the cage pivots into the target
    /// rootfs where its own path no longer resolves.
    pub flags: String,
}

/// Whether `path` names an existing entry (following no symlink at the leaf).
pub(crate) fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch::Scratch;

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
    fn a_native_architecture_has_no_interpreter() {
        // Nothing is emulated, so there is no interpreter to name. An empty
        // string here would fold into a caller's artifact signature as though
        // it meant something.
        let host = host_architecture();
        assert!(foreign_interpreter(&host).is_none());
    }

    #[test]
    fn an_architecture_qemu_does_not_cover_has_no_interpreter() {
        assert!(qemu_interpreter("m68k").is_none());
        assert!(foreign_interpreter("m68k").is_none());
    }

    #[test]
    fn a_registered_symlink_reports_the_registration_and_its_target_apart() {
        // The common Debian layout: the kernel records a wrapper name that is a
        // symlink to the real binary. Repointing the symlink changes the
        // interpreter without changing the registration, which a record
        // carrying one path alone could not show.
        let scratch = Scratch::new("interpreter");
        let real = scratch.join("qemu-aarch64-static");
        std::fs::write(&real, b"not really qemu").expect("the stand-in is writable");
        let wrapper = scratch.join("aarch64-binfmt-P");
        std::os::unix::fs::symlink(&real, &wrapper).expect("the wrapper symlink is creatable");

        let registration = binfmt::parse(&format!(
            "enabled\ninterpreter {}\nflags: POF\n",
            wrapper.display()
        ));
        let path = registration.interpreter.expect("the interpreter is named");
        let resolved = std::fs::canonicalize(&path).ok();
        assert_eq!(path, wrapper, "the registered path is reported as written");
        assert_eq!(
            resolved.as_deref().map(Path::to_path_buf),
            std::fs::canonicalize(&real).ok(),
            "and the target it resolves to as a second, distinct fact",
        );
        assert_ne!(Some(path), resolved);
    }

    #[test]
    fn an_unresolvable_registration_still_reports_everything_else() {
        // A path that does not resolve is a fact, not an error: the handler is
        // registered and enabled, and only the target is unknowable.
        let registration =
            binfmt::parse("enabled\ninterpreter /nonexistent/qemu-aarch64\nflags: POF\n");
        let path = registration.interpreter.expect("the interpreter is named");
        assert_eq!(std::fs::canonicalize(&path).ok(), None);
        assert!(registration.enabled);
        assert_eq!(registration.flags, "POF");
    }
}
