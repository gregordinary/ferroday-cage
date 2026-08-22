//! Enums that are also a roster of themselves.
//!
//! Several enums here are a closed set a caller can be shown, parse a name
//! against, or iterate: a capability keep-list, the script kinds an apk package
//! can carry. Each needs the variants, a name per variant, sometimes a value
//! per variant, and an `ALL` holding every one of them.
//!
//! Three of those four the compiler checks. A name or a value left out of its
//! match is a non-exhaustive-patterns error. `ALL` is the one it cannot see: it
//! is an ordinary array, and a variant left out of it is simply absent from
//! whatever reads it — unparseable where a parser searches the roster, unlisted
//! where a help text renders it. [`roster_enum`] declares the list once and
//! derives `ALL` from it, so the omission cannot be written.

/// Declares an enum together with the roster of its own variants.
///
/// The body is the accessors first, each with its documentation and its
/// visibility, and then one line per variant: the variant's documentation, its
/// name, and — where the enum has a value accessor — the value it stands for.
/// The macro generates the enum, `ALL` in declaration order, and each declared
/// accessor.
///
/// The enum's own attributes pass through, so it keeps its derives, its
/// documentation, and its `#[non_exhaustive]`. `ALL` takes the enum's
/// visibility, since a roster reaches exactly as far as the type it lists.
///
/// With a value and a name:
///
/// ```ignore
/// roster_enum! {
///     /// A named widget.
///     #[derive(Debug, Clone, Copy)]
///     pub enum Widget {
///         /// The bit this widget stands for.
///         fn bit -> u32;
///         /// The canonical kebab-case name.
///         fn as_str;
///
///         /// The small one.
///         Small = 1 << 0 => "small",
///         /// The large one.
///         Large = 1 << 1 => "large",
///     }
/// }
/// ```
///
/// With a name alone, the `= value` is left out of every line and the value
/// accessor is not declared.
macro_rules! roster_enum {
    // A value accessor and a name accessor.
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $(#[$value_meta:meta])*
            $value_vis:vis fn $value_fn:ident -> $value_ty:ty;
            $(#[$label_meta:meta])*
            $label_vis:vis fn $label_fn:ident;

            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:expr => $label:literal,
            )+
        }
    ) => {
        roster_enum! {
            @enum
            $(#[$enum_meta])*
            $vis enum $name { $($(#[$variant_meta])* $variant,)+ }
        }

        impl $name {
            roster_enum! { @all $vis $name { $($variant,)+ } }

            $(#[$value_meta])*
            $value_vis const fn $value_fn(self) -> $value_ty {
                match self {
                    $($name::$variant => $value,)+
                }
            }

            $(#[$label_meta])*
            $label_vis const fn $label_fn(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }
        }
    };

    // A name accessor alone.
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $(#[$label_meta:meta])*
            $label_vis:vis fn $label_fn:ident;

            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $label:literal,
            )+
        }
    ) => {
        roster_enum! {
            @enum
            $(#[$enum_meta])*
            $vis enum $name { $($(#[$variant_meta])* $variant,)+ }
        }

        impl $name {
            roster_enum! { @all $vis $name { $($variant,)+ } }

            $(#[$label_meta])*
            $label_vis const fn $label_fn(self) -> &'static str {
                match self {
                    $($name::$variant => $label,)+
                }
            }
        }
    };

    // The enum itself, shared by both forms.
    (
        @enum
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$variant_meta:meta])* $variant:ident,)+
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }
    };

    // The roster, shared by both forms.
    (@all $vis:vis $name:ident { $($variant:ident,)+ }) => {
        /// Every variant, in declaration order.
        ///
        /// Derived from the declaration rather than written beside it, so a
        /// variant cannot be absent from it.
        $vis const ALL: &'static [$name] = &[$($name::$variant,)+];
    };
}

pub(crate) use roster_enum;
