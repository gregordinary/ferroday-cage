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
macro_rules! wire_enum {
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
