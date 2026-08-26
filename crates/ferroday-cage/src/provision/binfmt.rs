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

use std::path::PathBuf;

/// Why a handler cannot run a foreign binary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Missing {
    /// The kernel has no handler for the interpreter at all.
    Unregistered,
    /// A handler is registered, and this is what is wrong with it.
    Unusable(&'static str),
}

/// Whether the `qemu-<interpreter>` handler can run a foreign binary from a
/// cage.
pub(crate) fn ready(interpreter: &str) -> Result<(), Missing> {
    let registration = read(interpreter)
        .map_err(|_| Missing::Unusable("its registration could not be read"))?
        .ok_or(Missing::Unregistered)?;
    check(&parse(&registration)).map_err(Missing::Unusable)
}

/// The kernel's registration for the `qemu-<name>` handler, or `Ok(None)` when
/// none is registered.
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
        assert_eq!(
            ready("an-architecture-no-kernel-has"),
            Err(Missing::Unregistered),
        );
        // A name the read cannot even attempt is not "no handler is
        // registered": the preflight would advise registering one, and what is
        // true is that nothing here could look. A NUL makes the read fail for a
        // reason that is not absence, whatever the host has mounted.
        assert!(read("a\0name").is_err());
        assert_eq!(
            ready("a\0name"),
            Err(Missing::Unusable("its registration could not be read")),
        );
    }
}
