//! The constructors and conversions every archive layer's error declares.
//!
//! Each layer's error is its own type, naming that layer's failures in its own
//! terms, and its `Display` is written out by hand for the same reason. What
//! surrounds the type is the same for all three, and is declared once here by
//! [`layer_error!`].

/// Declares a layer error's shared constructors and conversions.
///
/// The type must be an enum with `Io { op, path, source }`,
/// `Config { reason }`, `PlanDocument { reason }`, `Fetch(FetchError)` and
/// `Cancelled` variants, and `io::Error` and `PathBuf` must be in scope where
/// the macro is invoked, as [`path_io_error!`](crate::failure::path_io_error)
/// requires. Declared:
///
/// - the `io` and `at` constructors, through `path_io_error!`, with the
///   documentation written after the type name appended to `at`'s;
/// - `config(reason)` and `plan_document(reason)`, a configuration the layer
///   refuses and a plan document it cannot read;
/// - [`Failover`](super::Failover), reaching through `Fetch` to the transport's
///   answer, since a failure that is not a transport one, a digest or a
///   signature refused over bytes that did arrive, never advances a walk;
/// - the conversion from [`FetchError`](super::FetchError);
/// - the conversion into [`ProvisionError`](super::ProvisionError), which
///   surfaces a cancellation as the shared variant a caller matches on
///   whichever provisioner they drove, and boxes everything else as the
///   layer's own.
///
/// With `accounts` after the type, the conversion from an accounts step's
/// failure, as this layer's `Io`, is declared too.
///
/// ```ignore
/// layer_error! {
///     DebianError,
///     accounts,
///     /// Documentation appended to `at`'s.
/// }
/// ```
macro_rules! layer_error {
    (
        $name:ident,
        accounts
        $(, $(#[$at_meta:meta])* )?
        $(,)?
    ) => {
        layer_error! {
            $name
            $(, $(#[$at_meta])*)?
        }

        impl From<$crate::provision::accounts::Failure> for $name {
            /// An accounts step's failure, as this layer's own host failure.
            fn from(failure: $crate::provision::accounts::Failure) -> $name {
                $name::io(failure.op, failure.path, failure.source)
            }
        }
    };
    (
        $name:ident
        $(, $(#[$at_meta:meta])* )?
        $(,)?
    ) => {
        $crate::failure::path_io_error! {
            $name
            $(, $(#[$at_meta])*)?
        }

        impl $name {
            /// A configuration this layer refuses, and why.
            pub(crate) fn config(reason: impl Into<String>) -> $name {
                $name::Config {
                    reason: reason.into(),
                }
            }

            /// A plan document this layer cannot read, and why.
            pub(crate) fn plan_document(reason: impl Into<String>) -> $name {
                $name::PlanDocument {
                    reason: reason.into(),
                }
            }
        }

        impl $crate::provision::Failover for $name {
            /// Reaches through the wrapper this layer carries a transport
            /// failure in. A failure that is not a `Fetch` one at all, a
            /// signature or digest mismatch over bytes that did arrive, never
            /// advances a walk.
            fn is_failover(&self) -> bool {
                matches!(self, $name::Fetch(fetch) if fetch.is_failover())
            }
        }

        impl From<$crate::provision::FetchError> for $name {
            fn from(err: $crate::provision::FetchError) -> $name {
                $name::Fetch(err)
            }
        }

        impl From<$name> for $crate::provision::ProvisionError {
            /// A cancellation is the run's own outcome rather than a layer
            /// failure, so it surfaces as the shared variant a caller matches
            /// on whichever provisioner they drove; everything else is this
            /// layer's, boxed as a provisioner outside the core boxes its own.
            fn from(err: $name) -> $crate::provision::ProvisionError {
                match err {
                    $name::Cancelled => $crate::provision::ProvisionError::Cancelled,
                    other => $crate::provision::ProvisionError::other(other),
                }
            }
        }
    };
}

pub(crate) use layer_error;
