//! The step enums a forked helper reports its failures through.
//!
//! Every helper process this crate forks — the launch stage, the copy-in
//! child, the export child, the removal child, the network stack's tap helper —
//! reports a failure the same way: a small integer naming the step it was on,
//! and the errno the kernel gave. The step is an enum on both sides of the
//! pipe, and each such enum needs four things that must agree: the variants
//! with their wire values, a decoder, a phrase describing each step, and a list
//! of every variant for the round-trip test.
//!
//! Written out, those are four parallel lists per enum, kept in step by hand
//! and watched only by a test. [`wire_enum`] declares them once instead. The
//! decoder's match arms are the same literals the variants are declared with,
//! so a value used twice is a compile error rather than a test failure: the
//! enum refuses the duplicate discriminant, and the decoder's match refuses the
//! duplicate pattern.
//!
//! Three of these helpers — the copy-in child, the export child, the removal
//! child — begin with the same seven steps, because each takes a forked child
//! into a mapped user namespace before it does its own work. `child::MapStep`
//! is that sequence; what differs between the three is only the noun each
//! phrase uses, so each declares the seven in a `map` block and gets its own
//! wire values, its own phrases, and the `From<MapStep>` that names them.

/// Declares a wire-encoded step enum.
///
/// The body is one line per step — a doc comment, the variant, its wire value,
/// and the phrase that describes it — and the macro generates the enum,
/// [`wire`](#method.wire), [`from_wire`](#method.from_wire),
/// [`describe`](#method.describe), a [`Display`](std::fmt::Display) impl, and
/// (under `cfg(test)`) `ALL`.
///
/// Attributes and visibility on the enum pass through, so a public enum keeps
/// its `#[non_exhaustive]` and its own documentation. The generated methods are
/// always `pub(crate)`: the wire values are an encoding between two ends of one
/// build, never a promise to a consumer.
///
/// ```ignore
/// wire_enum! {
///     /// What the widget child was doing when a syscall failed.
///     pub(crate) enum WidgetStep {
///         /// Forking the widget process.
///         Spawn = 1 => "forking the widget process",
///         /// Opening the widget.
///         Open = 2 => "opening the widget",
///     }
/// }
/// ```
///
/// A helper that takes its forked child into a mapped user namespace first
/// declares those seven steps in a `map` block, ahead of its own. The block
/// gives each its wire value and its phrase — the phrase is the only thing
/// that differs between the three helpers, since it names the helper — and the
/// macro supplies the variants, their documentation, and
/// `From<child::MapStep>`:
///
/// ```ignore
/// wire_enum! {
///     pub(crate) enum WidgetStep {
///         map {
///             ResetSignals = 1 => "resetting the widget process's signal dispositions",
///             SweepFds = 2 => "closing the widget process's inherited descriptors",
///             Unshare = 3 => "unsharing the widget namespace",
///             DenySetgroups = 4 => "denying setgroups in the widget namespace",
///             WriteGidMap = 5 => "writing the widget gid map",
///             WriteUidMap = 6 => "writing the widget uid map",
///             AwaitMap = 7 => "establishing the widget identity map",
///         }
///         /// Forking the widget process.
///         Spawn = 8 => "forking the widget process",
///     }
/// }
/// ```
///
/// The seven names are matched literally, so the set, its order and its
/// completeness belong to the macro rather than to each helper: one left out
/// does not match the rule and does not compile.
macro_rules! wire_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            map {
                ResetSignals = $reset:literal => $reset_says:literal,
                SweepFds = $sweep:literal => $sweep_says:literal,
                Unshare = $unshare:literal => $unshare_says:literal,
                DenySetgroups = $deny:literal => $deny_says:literal,
                WriteGidMap = $gid:literal => $gid_says:literal,
                WriteUidMap = $uid:literal => $uid_says:literal,
                AwaitMap = $await_map:literal => $await_says:literal,
            }
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:literal => $describe:literal,
            )+
        }
    ) => {
        wire_enum! {
            $(#[$enum_meta])*
            $vis enum $name {
                /// The child could not reset its inherited signal dispositions.
                ResetSignals = $reset => $reset_says,
                /// The child could not close the descriptors it inherited.
                SweepFds = $sweep => $sweep_says,
                /// The child could not unshare its user namespace.
                Unshare = $unshare => $unshare_says,
                /// The child could not deny `setgroups` in its own user
                /// namespace.
                DenySetgroups = $deny => $deny_says,
                /// The child could not write its own gid map.
                WriteGidMap = $gid => $gid_says,
                /// The child could not write its own uid map.
                WriteUidMap = $uid => $uid_says,
                /// The child died or was abandoned at the map gate.
                AwaitMap = $await_map => $await_says,
                $(
                    $(#[$variant_meta])*
                    $variant = $value => $describe,
                )+
            }
        }

        impl From<crate::mechanism::child::MapStep> for $name {
            /// This helper's own name for a step of the shared map sequence,
            /// one for one.
            fn from(step: crate::mechanism::child::MapStep) -> $name {
                use crate::mechanism::child::MapStep;

                match step {
                    MapStep::ResetSignals => $name::ResetSignals,
                    MapStep::SweepFds => $name::SweepFds,
                    MapStep::Unshare => $name::Unshare,
                    MapStep::DenySetgroups => $name::DenySetgroups,
                    MapStep::WriteGidMap => $name::WriteGidMap,
                    MapStep::WriteUidMap => $name::WriteUidMap,
                    MapStep::AwaitMap => $name::AwaitMap,
                }
            }
        }
    };

    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:literal => $describe:literal,
            )+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u32)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value,
            )+
        }

        impl $name {
            /// Every step, in declaration order. Used by the wire-protocol
            /// tests.
            #[cfg(test)]
            #[allow(dead_code)]
            pub(crate) const ALL: &'static [$name] = &[$($name::$variant,)+];

            /// One past the largest wire value any step carries: the smallest
            /// value above the set that the decoder must refuse.
            ///
            /// Derived rather than written down, because the values need not be
            /// contiguous — a step that splits into several leaves its own
            /// value behind and the new ones take the next free values.
            #[cfg(test)]
            #[allow(dead_code)]
            pub(crate) fn past_the_last() -> u32 {
                let mut highest: u32 = 0;
                $(
                    if $name::$variant.wire() > highest {
                        highest = $name::$variant.wire();
                    }
                )+
                highest + 1
            }

            /// The wire value the failure record carries.
            #[allow(dead_code)]
            pub(crate) fn wire(self) -> u32 {
                self as u32
            }

            /// Decodes a wire value, or `None` for one no step carries.
            ///
            /// Both ends of the record are the same build, so an unrecognized
            /// value is a malformed record rather than a step from another
            /// version. It is reported as one instead of being read as a step
            /// the helper did not name.
            #[allow(dead_code)]
            pub(crate) fn from_wire(value: u32) -> Option<$name> {
                Some(match value {
                    $($value => $name::$variant,)+
                    _ => return None,
                })
            }

            /// The step as prose: what the helper was doing.
            ///
            /// `&'static str` rather than only a
            /// [`Display`](std::fmt::Display) rendering, because the phrase
            /// also becomes the `op` field of an error that stores one.
            #[allow(dead_code)]
            pub(crate) fn describe(self) -> &'static str {
                match self {
                    $($name::$variant => $describe,)+
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.describe())
            }
        }
    };
}

pub(crate) use wire_enum;
