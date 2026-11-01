//! The two halves of how an error reports a failure: the constructors an error
//! type carries an OS failure through, and the rendering that reads a failure
//! back out whole.
//!
//! `CONTRIBUTING.md` states the rule: an OS failure is carried as an
//! `io::Error` and returned from `source()`, never as a raw errno, and a
//! failure reports what it was doing and what it was operating on. Every error
//! type here that can meet one therefore has the same `Io { op, path, source }`
//! variant and the same pair of constructors -- `io`, which takes the cause
//! now, and `at`, which names the operation and the path now and takes the
//! cause when a `map_err` hands it over.
//!
//! Written out, that is the same two bodies and the same two doc comments per
//! error type, differing in the type name. [`path_io_error`] declares them
//! once instead. The vocabulary table lists "each error type's `io` and `at`
//! constructors" as one answer per type, which records the convention; this is
//! the convention as code.
//!
//! The same rule keeps a cause out of the message of the error that carries
//! it. Each error's `Display` says what failed and on what, and a cause is
//! reached through `source()` alone, so a renderer that walks the chain prints
//! each layer once. [`ErrorChain`] is that renderer, for every place the crate
//! or one of its consumers turns an error into text.

use std::error::Error as StdError;
use std::fmt;

/// An error rendered on one line with every cause beneath it, as
/// `error: cause: cause`.
///
/// Every error type in this crate states what failed and what it was operating
/// on in its own [`Display`](fmt::Display), and leaves the cause underneath,
/// such as the OS error a syscall returned, to
/// [`source`](StdError::source). Printing an error with `{}` therefore prints
/// one layer of it. This prints them all, which is what a diagnostic for a
/// person wants.
///
/// A cause whose message the rendering already ends with is not repeated. An
/// error from outside this crate, such as one a caller's
/// [`Provisioner`](crate::provision::Provisioner) returns, may carry its cause
/// in its own message as well as in `source()`.
///
/// # Example
///
/// ```
/// use ferroday_cage::{Cage, ErrorChain};
///
/// let error = Cage::builder()
///     .rootfs("/nonexistent/rootfs")
///     .command("/bin/true")
///     .build()
///     .unwrap_err();
/// let rendered = ErrorChain::new(&error).to_string();
/// assert!(rendered.starts_with("invalid sandbox configuration: cannot use"));
/// assert!(rendered.ends_with("No such file or directory (os error 2)"));
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ErrorChain<'a> {
    /// The outermost error, whose `source()` chain is walked from here.
    error: &'a (dyn StdError + 'static),
}

impl<'a> ErrorChain<'a> {
    /// Renders `error` together with its causes.
    pub fn new(error: &'a (dyn StdError + 'static)) -> ErrorChain<'a> {
        ErrorChain { error }
    }
}

impl fmt::Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut last_written = self.error.to_string();
        f.write_str(&last_written)?;
        let mut next = self.error.source();
        while let Some(cause) = next {
            let message = cause.to_string();
            if !last_written.ends_with(&message) {
                write!(f, ": {message}")?;
                last_written = message;
            }
            next = cause.source();
        }
        Ok(())
    }
}

/// Declares an error type's `io` and `at` constructors.
///
/// The type must be an enum with an
/// `Io { op: &'static str, path: PathBuf, source: io::Error }` variant, and
/// `io::Error` and `PathBuf` must be in scope where the macro is invoked.
///
/// Documentation written after the type name is appended to `at`'s, which is
/// where a type has something of its own to say about the form its callers
/// reach for:
///
/// ```ignore
/// path_io_error! {
///     DebianError,
///     /// This is the form the bootstrap's host-side steps use, where the
///     /// path is composed from a contained tree.
/// }
/// ```
macro_rules! path_io_error {
    (
        $name:ident
        $(, $(#[$at_meta:meta])* )?
        $(,)?
    ) => {
        impl $name {
            /// A host I/O failure, naming what the operation was doing and the
            /// path it concerned.
            ///
            /// Arguments run operation, then locator, then cause, which is the
            /// order every constructor in the crate takes them in.
            pub fn io(
                op: &'static str,
                path: impl Into<PathBuf>,
                source: io::Error,
            ) -> $name {
                $name::Io {
                    op,
                    path: path.into(),
                    source,
                }
            }

            /// The same failure as a [`map_err`](Result::map_err) argument:
            /// names the operation and the path now, and takes the cause when
            /// it arrives.
            $($(#[$at_meta])*)?
            pub fn at(
                op: &'static str,
                path: impl Into<PathBuf>,
            ) -> impl FnOnce(io::Error) -> $name {
                let path = path.into();
                move |source| $name::Io { op, path, source }
            }
        }
    };
}

pub(crate) use path_io_error;

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use super::*;
    use crate::error::{ConfigError, Error, OverlayLayer, SetupStep};
    use crate::idmap::IdMapError;
    use crate::provision::ProvisionError;

    /// The OS error every representative carries at the bottom of its chain,
    /// with a message no layer above it would write on its own.
    fn os_error() -> io::Error {
        io::Error::from_raw_os_error(13)
    }

    /// Holds one error to the convention: no layer's message contains the
    /// message of any layer beneath it, and the rendered chain names the OS
    /// error exactly once.
    fn holds(error: &(dyn StdError + 'static)) {
        let mut layers = Vec::new();
        let mut next = Some(error);
        while let Some(layer) = next {
            layers.push(layer.to_string());
            next = layer.source();
        }
        for (depth, outer) in layers.iter().enumerate() {
            for inner in &layers[depth + 1..] {
                assert!(
                    !outer.contains(inner.as_str()),
                    "{outer:?} repeats its cause {inner:?}",
                );
            }
        }
        let rendered = ErrorChain::new(error).to_string();
        let os = os_error().to_string();
        assert_eq!(
            rendered.matches(os.as_str()).count(),
            1,
            "{rendered:?} names the OS error once",
        );
        assert_eq!(rendered, layers.join(": "));
    }

    /// Representatives of every variant that carries a cause, of every error
    /// type the crate defines, built through the crate's constructors where it
    /// has them.
    ///
    /// A variant added with a cause belongs here. Its `Display` is where the
    /// cause is easiest to repeat by accident, and this is what notices.
    fn representatives() -> Vec<Box<dyn StdError + 'static>> {
        let delegate_refusal = || IdMapError::helper_spawn("newuidmap", Some(os_error()));
        let mut all: Vec<Box<dyn StdError + 'static>> = Vec::new();
        all.extend([
            Box::new(delegate_refusal()) as Box<dyn StdError>,
            Box::new(IdMapError::map_write("uid_map", os_error())),
            Box::new(ConfigError::RootfsUnusable {
                path: PathBuf::from("/srv/rootfs"),
                source: os_error(),
            }),
            Box::new(ConfigError::BindSourceUnusable {
                path: PathBuf::from("/srv/data"),
                source: os_error(),
            }),
            Box::new(ConfigError::OverlayDirUnusable {
                layer: OverlayLayer::Upper,
                path: PathBuf::from("/srv/upper"),
                source: os_error(),
            }),
            Box::new(ConfigError::IdentityMapUnavailable {
                reason: ErrorChain::new(&delegate_refusal()).to_string(),
                source: Some(delegate_refusal()),
            }),
            Box::new(Error::Config(ConfigError::RootfsUnusable {
                path: PathBuf::from("/srv/rootfs"),
                source: os_error(),
            })),
            Box::new(Error::UsernsUnavailable {
                blocker: None,
                source: os_error(),
            }),
            Box::new(Error::UsernsUnavailable {
                blocker: Some(crate::host::UsernsBlocker::MaxUserNamespacesIsZero),
                source: os_error(),
            }),
            Box::new(Error::NamespaceLimitReached {
                step: SetupStep::NestedUnshare,
                source: os_error(),
            }),
            Box::new(Error::KeyQuotaExhausted { source: os_error() }),
            Box::new(Error::Setup {
                step: SetupStep::BindMount,
                source: os_error(),
                detail: Some("/srv/data at /data".to_string()),
            }),
            Box::new(Error::Setup {
                step: SetupStep::PivotRoot,
                source: os_error(),
                detail: None,
            }),
            Box::new(Error::Spawn { source: os_error() }),
            Box::new(Error::Wait { source: os_error() }),
            Box::new(Error::Signal { source: os_error() }),
            Box::new(Error::KillHandle { source: os_error() }),
            Box::new(Error::IdentityMap(IdMapError::map_write(
                "gid_map",
                os_error(),
            ))),
            Box::new(Error::Terminal { source: os_error() }),
            Box::new(Error::TerminalsExhausted { source: os_error() }),
            Box::new(ProvisionError::io("opening", "/srv/rootfs.tar", os_error())),
            Box::new(ProvisionError::other(ProvisionError::io(
                "opening",
                "/srv/rootfs.tar",
                os_error(),
            ))),
            Box::new(ProvisionError::RemoveUnprivileged {
                path: PathBuf::from("/srv/rootfs"),
                source: os_error(),
                reason: "no delegate".to_string(),
            }),
            Box::new(crate::relay::RelayError::io("polling", os_error())),
            Box::new(crate::relay::RelayError::Cage(Error::Spawn {
                source: os_error(),
            })),
        ]);
        #[cfg(feature = "netstack")]
        {
            use crate::netstack::NetStackError;
            let host = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
            all.extend([
                Box::new(NetStackError::Publish {
                    host,
                    source: os_error(),
                }) as Box<dyn StdError>,
                Box::new(NetStackError::NamespaceJoin {
                    which: "opening the namespace",
                    source: Some(os_error()),
                }),
                Box::new(NetStackError::TapOpen { source: os_error() }),
                Box::new(NetStackError::TapCreate {
                    name: "tap0".to_string(),
                    source: os_error(),
                }),
                Box::new(NetStackError::TapConfigure {
                    detail: "setting the MTU",
                    source: os_error(),
                }),
                Box::new(NetStackError::TapHandoff { source: os_error() }),
                Box::new(NetStackError::Spawn { source: os_error() }),
                Box::new(NetStackError::Pump {
                    op: "reading the tap",
                    source: Some(os_error()),
                }),
            ]);
        }
        #[cfg(any(feature = "debian", feature = "alpine", feature = "gentoo"))]
        {
            use crate::provision::FetchError;
            let fetch = || FetchError::io("connecting", "http://mirror.invalid/x", os_error());
            all.push(Box::new(fetch()));
            #[cfg(feature = "debian")]
            {
                use crate::provision::debian::DebianError;
                all.extend([
                    Box::new(DebianError::Fetch(fetch())) as Box<dyn StdError>,
                    Box::new(DebianError::Launch(Error::Spawn { source: os_error() })),
                    Box::new(DebianError::Overlay(ProvisionError::io(
                        "copying",
                        "/srv/overlay",
                        os_error(),
                    ))),
                    Box::new(DebianError::io("reading", "/srv/staging", os_error())),
                    Box::new(DebianError::Index {
                        subject: "http://mirror.invalid/Packages.xz".to_string(),
                        reason: "it does not decompress".to_string(),
                        source: Some(os_error()),
                    }),
                    Box::new(ProvisionError::other(DebianError::Fetch(fetch()))),
                ]);
            }
            #[cfg(feature = "alpine")]
            {
                use crate::provision::alpine::AlpineError;
                all.extend([
                    Box::new(AlpineError::Fetch(fetch())) as Box<dyn StdError>,
                    Box::new(AlpineError::Launch(Error::Spawn { source: os_error() })),
                    Box::new(AlpineError::io("reading", "/srv/staging", os_error())),
                    Box::new(AlpineError::unreadable(
                        "http://mirror.invalid/x",
                        "its signature segment is unreadable",
                        os_error(),
                    )),
                ]);
            }
            #[cfg(feature = "gentoo")]
            {
                use crate::provision::gentoo::GentooError;
                all.extend([
                    Box::new(GentooError::Fetch(fetch())) as Box<dyn StdError>,
                    Box::new(GentooError::io("reading", "/srv/staging", os_error())),
                ]);
            }
        }
        all
    }

    #[test]
    fn no_message_repeats_its_cause() {
        for error in representatives() {
            holds(error.as_ref());
        }
    }

    #[test]
    fn a_chain_is_rendered_layer_by_layer() {
        let error =
            ProvisionError::other(ProvisionError::io("opening", "/srv/rootfs.tar", os_error()));
        assert_eq!(
            ErrorChain::new(&error).to_string(),
            "provisioning failed: provisioning failed while opening /srv/rootfs.tar: \
             Permission denied (os error 13)",
        );
        assert_eq!(
            ErrorChain::new(&os_error()).to_string(),
            "Permission denied (os error 13)"
        );
    }

    /// An error outside the crate that carries its cause in its own message as
    /// well as in `source()`.
    #[derive(Debug)]
    struct Embeds(io::Error);

    impl fmt::Display for Embeds {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "the helper failed: {}", self.0)
        }
    }

    impl StdError for Embeds {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_cause_the_message_already_ends_with_is_not_repeated() {
        let error = ProvisionError::other(Embeds(os_error()));
        assert_eq!(
            ErrorChain::new(&error).to_string(),
            "provisioning failed: the helper failed: Permission denied (os error 13)",
        );
    }
}
