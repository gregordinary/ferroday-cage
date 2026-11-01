//! What the kernel has registered for running foreign binaries.
//!
//! A bootstrap for an architecture the host cannot execute runs the target's
//! own binaries — `dpkg` and its maintainer scripts, `busybox` and its install
//! scripts — through a `qemu-user` handler the kernel dispatches to. Whether
//! that works is a property of `/proc/sys/fs/binfmt_misc` rather than of any
//! distribution, so it is asked once here and each layer maps its own
//! architecture names onto the interpreter names below.
//!
//! The handler must carry the fix-binary (`F`) flag. That flag makes the kernel
//! open and hold the interpreter when the handler is registered, so it keeps
//! working after a cage pivots into the target rootfs, where the interpreter's
//! own path no longer resolves. Without it a foreign bootstrap would need the
//! interpreter copied into the tree being built, which the launch path never
//! does.
//!
//! The registrations live in the kernel, and the `binfmt_misc` filesystem is
//! only where they are read. A container that has not mounted it still runs
//! foreign binaries through the host's handlers, so a missing mount is a
//! question the preflight cannot answer rather than a missing handler.

use std::path::PathBuf;

/// Where `binfmt_misc` keeps its host-wide switch.
const STATUS: &str = "/proc/sys/fs/binfmt_misc/status";

/// Why a handler cannot run a foreign binary.
#[derive(Debug, PartialEq, Eq)]
enum Missing {
    /// The kernel has no handler for the interpreter at all.
    Unregistered,
    /// A handler is registered, and this is what is wrong with it.
    Unusable(&'static str),
    /// `binfmt_misc` is switched off host-wide, so no handler runs whatever is
    /// registered.
    Disabled,
}

/// What `binfmt_misc`'s own status file says, where it could be read.
#[derive(Debug, PartialEq, Eq)]
enum Interface {
    /// Mounted, and handing foreign binaries to their handlers.
    Enabled,
    /// Mounted, and switched off host-wide.
    Disabled,
    /// Not mounted where this process looks. That says nothing about the
    /// registrations, which the kernel holds whether or not it is mounted.
    Unmounted,
}

/// Why a full bootstrap for `target` cannot run on a `host` host, as the
/// message a caller is shown, or nothing where it can.
///
/// The caller has decided already that the host does not run `target` natively,
/// which is a question asked in its own architecture names. `interpreter` is
/// the `qemu-user` interpreter it maps `target` onto, or `None` where no qemu
/// target covers it. What follows is the same for every layer: `binfmt_misc`
/// must be enabled, and the handler registered, enabled, and carrying the
/// fix-binary flag. A refusal names the remedy and the builder's
/// `extract_only` as the alternative.
///
/// Where `binfmt_misc` is not mounted, nothing here can be inspected, and the
/// run proceeds. A handler the host lacks then fails the first foreign binary
/// the bootstrap runs, with `ENOEXEC`, rather than this check refusing a run
/// the host's registrations would carry.
pub(crate) fn preflight(host: &str, target: &str, interpreter: Option<&str>) -> Result<(), String> {
    let Some(interpreter) = interpreter else {
        return Err(format!(
            "a full bootstrap for {target} on a {host} host needs a qemu-user binfmt handler, and \
             {target} is not a known qemu target; use extract_only instead"
        ));
    };
    ready(interpreter).map_err(|missing| refusal(host, target, interpreter, missing))
}

/// The message a caller is shown for `missing`.
fn refusal(host: &str, target: &str, interpreter: &str, missing: Missing) -> String {
    match missing {
        Missing::Unregistered => format!(
            "a full bootstrap for {target} on a {host} host needs the qemu-{interpreter} binfmt \
             handler registered (install qemu-user-static and binfmt support); use extract_only \
             to lay out the root filesystem without running its binaries"
        ),
        Missing::Unusable(reason) => format!(
            "the qemu-{interpreter} binfmt handler is registered but {reason}; a foreign \
             bootstrap needs it enabled and registered with the fix-binary (F) flag"
        ),
        Missing::Disabled => format!(
            "a full bootstrap for {target} on a {host} host needs binfmt_misc enabled, and {STATUS} \
             reads disabled (writing 1 to it as root enables it); use extract_only to lay out the \
             root filesystem without running its binaries"
        ),
    }
}

/// Whether the `qemu-<interpreter>` handler can run a foreign binary from a
/// cage, as far as this host lets it be seen.
fn ready(interpreter: &str) -> Result<(), Missing> {
    judge(interface(), read(interpreter))
}

/// The preflight's decision, from what `binfmt_misc` reported: its status,
/// `None` where that could not be read, and the handler's registration as
/// [`read`] returns it.
///
/// A status that could not be read decides nothing, and the registration is
/// judged as it stands.
fn judge(
    interface: Option<Interface>,
    registration: std::io::Result<Option<String>>,
) -> Result<(), Missing> {
    match interface {
        Some(Interface::Unmounted) => return Ok(()),
        Some(Interface::Disabled) => return Err(Missing::Disabled),
        Some(Interface::Enabled) | None => {}
    }
    let registration = registration
        .map_err(|_| Missing::Unusable("its registration could not be read"))?
        .ok_or(Missing::Unregistered)?;
    check(&parse(&registration)).map_err(Missing::Unusable)
}

/// What `binfmt_misc`'s status file says, or `None` where it could not be
/// read or says something other than `enabled` or `disabled`.
fn interface() -> Option<Interface> {
    match std::fs::read_to_string(STATUS) {
        Ok(status) => match status.trim() {
            "enabled" => Some(Interface::Enabled),
            "disabled" => Some(Interface::Disabled),
            _ => None,
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Some(Interface::Unmounted),
        Err(_) => None,
    }
}

/// The kernel's registration for the `qemu-<name>` handler, or `Ok(None)` when
/// none can be seen: none is registered, or `binfmt_misc` is not mounted. The
/// preflight tells the two apart through the status file.
///
/// A read that fails for any other reason is not "none is registered", and is
/// reported rather than folded into it: `binfmt_misc` can be mounted with a
/// registration present and unreadable — a restrictive mount, an LSM — and
/// answering `None` there advises a caller to register a handler the kernel
/// already holds.
pub(crate) fn read(name: &str) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(format!("/proc/sys/fs/binfmt_misc/qemu-{name}")) {
        Ok(registration) => Ok(Some(registration)),
        // Both the registration and the directory it would live in: neither
        // present is the same answer, since the filesystem is not mounted.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// What a `binfmt_misc` registration file says, as fields.
///
/// The file is a line-oriented listing: a bare `enabled` or `disabled`, then
/// `interpreter <path>`, `flags: <letters>`, and the magic and mask this does
/// not read.
pub(crate) struct Registration {
    /// Whether the handler is enabled. A registered-but-disabled handler is a
    /// distinct state from an absent one: the registration exists and can be
    /// switched back on.
    pub(crate) enabled: bool,
    /// The interpreter path the kernel recorded, absent from a malformed
    /// registration.
    ///
    /// Read only where a layer reports the interpreter a foreign build ran
    /// through, which is the Debian layer's `foreign_interpreter`; the preflight
    /// above never needs it.
    #[cfg_attr(not(feature = "debian"), allow(dead_code))]
    pub(crate) interpreter: Option<PathBuf>,
    /// The flag letters, as written.
    pub(crate) flags: String,
}

/// Reads a `binfmt_misc` registration into its fields.
pub(crate) fn parse(registration: &str) -> Registration {
    let mut lines = registration.lines().map(str::trim);
    let enabled = lines.next() == Some("enabled");
    let mut interpreter = None;
    let mut flags = String::new();
    for line in registration.lines().map(str::trim) {
        if let Some(path) = line.strip_prefix("interpreter ") {
            interpreter = Some(PathBuf::from(path.trim()));
        } else if let Some(letters) = line.strip_prefix("flags:") {
            flags = letters.trim().to_string();
        }
    }
    Registration {
        enabled,
        interpreter,
        flags,
    }
}

/// Validates a registration: enabled, with the `F` flag.
pub(crate) fn check(registration: &Registration) -> Result<(), &'static str> {
    if !registration.enabled {
        return Err("it is disabled");
    }
    if registration.flags.contains('F') {
        Ok(())
    } else {
        Err("it lacks the fix-binary (F) flag")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registration_is_usable_only_when_enabled_and_fixed() {
        let good = "enabled\ninterpreter /usr/bin/qemu-aarch64-static\nflags: OCF\n";
        assert!(check(&parse(good)).is_ok());

        let disabled = "disabled\ninterpreter /usr/bin/qemu-aarch64-static\nflags: OCF\n";
        assert_eq!(check(&parse(disabled)), Err("it is disabled"));

        let no_fix = "enabled\ninterpreter /usr/bin/qemu-aarch64\nflags: OC\n";
        assert_eq!(
            check(&parse(no_fix)),
            Err("it lacks the fix-binary (F) flag")
        );
    }

    #[test]
    fn a_registration_reports_the_path_the_kernel_holds() {
        let registration = parse(
            "enabled\ninterpreter /usr/libexec/qemu-binfmt/aarch64-binfmt-P\n\
             flags: POCF\noffset 0\n",
        );
        assert!(registration.enabled);
        assert_eq!(
            registration.interpreter.as_deref(),
            Some(std::path::Path::new(
                "/usr/libexec/qemu-binfmt/aarch64-binfmt-P"
            )),
        );
        assert_eq!(registration.flags, "POCF");
    }

    #[test]
    fn an_interpreter_no_kernel_registers_is_unregistered() {
        let mounted = Some(Interface::Enabled);
        assert_eq!(
            judge(mounted, read("an-architecture-no-kernel-has")),
            Err(Missing::Unregistered),
        );
        // A name the read cannot even attempt is not "no handler is
        // registered": the preflight would advise registering one, and what is
        // true is that nothing here could look. A NUL makes the read fail for a
        // reason that is not absence, whatever the host has mounted.
        assert!(read("a\0name").is_err());
        assert_eq!(
            judge(Some(Interface::Enabled), read("a\0name")),
            Err(Missing::Unusable("its registration could not be read")),
        );
    }

    #[test]
    fn binfmt_misc_unmounted_lets_the_run_proceed_and_disabled_refuses_it() {
        let usable = || Ok(Some("enabled\ninterpreter /q\nflags: F\n".to_string()));
        // Unmounted, nothing is visible and nothing is refused: the host's
        // registrations still run foreign binaries for this process.
        assert_eq!(judge(Some(Interface::Unmounted), Ok(None)), Ok(()));
        // Switched off host-wide, even a usable handler runs nothing.
        assert_eq!(
            judge(Some(Interface::Disabled), usable()),
            Err(Missing::Disabled)
        );
        // A status that could not be read leaves the registration to decide.
        assert_eq!(judge(None, usable()), Ok(()));
        assert_eq!(judge(None, Ok(None)), Err(Missing::Unregistered));
    }

    #[test]
    fn a_foreign_bootstrap_is_refused_with_the_remedy_and_the_alternative() {
        // One message for every layer: the architectures are each layer's own
        // names, and what is wrong and what to do about it is the kernel's.
        let unknown = preflight("x86_64", "vax", None).expect_err("qemu has no vax target");
        assert!(
            unknown.contains("vax is not a known qemu target") && unknown.contains("extract_only"),
            "{unknown}",
        );

        let unregistered = refusal(
            "x86_64",
            "imaginary",
            "an-interpreter-no-kernel-has",
            Missing::Unregistered,
        );
        assert!(
            unregistered.contains("needs the qemu-an-interpreter-no-kernel-has binfmt handler")
                && unregistered.contains("on a x86_64 host")
                && unregistered.contains("extract_only"),
            "{unregistered}",
        );

        let unreadable = refusal(
            "x86_64",
            "imaginary",
            "aarch64",
            Missing::Unusable("its registration could not be read"),
        );
        assert!(
            unreadable.contains("registered but its registration could not be read"),
            "{unreadable}",
        );

        let disabled = refusal("x86_64", "arm64", "aarch64", Missing::Disabled);
        assert!(
            disabled.contains("needs binfmt_misc enabled")
                && disabled.contains("/proc/sys/fs/binfmt_misc/status reads disabled")
                && disabled.contains("extract_only"),
            "{disabled}",
        );
    }
}
