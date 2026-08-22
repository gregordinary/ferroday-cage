//! The constructors an error type carries an OS failure through.
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
