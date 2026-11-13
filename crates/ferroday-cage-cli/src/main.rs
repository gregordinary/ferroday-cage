//! The ferroday-cage command-line interface.
//!
//! `fcage` runs a command inside an unprivileged Linux sandbox built by the
//! ferroday-cage library: fresh namespaces, the given root filesystem
//! presented at `/` with the default mount profile assembled over it, and
//! the calling user mapped to root inside. Almost every flag maps onto a call
//! on the library's builder, and `--profile` loads a TOML sandbox
//! specification through the library's `serde` feature; the binary contains
//! no sandboxing logic of its own. `--restrict` selects the library's
//! restriction fallback instead: Landlock and seccomp confinement of a
//! plain process, for hosts without unprivileged user namespaces.
//!
//! Not every flag configures a launch. The `--provision-*` family publishes a
//! rootfs before the command runs, and given without a command provisions and
//! exits. `--remove-rootfs` deletes a provisioned rootfs and `--export-rootfs`
//! writes one to a tar archive, each a mode of its own that accepts no other
//! option. All three carry the library's `provision` calls to a shell prompt,
//! which is the whole lifecycle of a rootfs: make it, ship it, delete it.
//!
//! The binary is built with every library feature enabled, so any profile the
//! library accepts loads here, and every capability of the launch builder --
//! `CageBuilder`, and the `RestrictionBuilder` behind `--restrict` -- has a
//! flag. Two library seams have no command-line form, because neither is
//! expressible as an argument: `Stdio::Fd`, which hands the command an open
//! descriptor, and `CageBuilder::id_mapper`, which supplies an identity-map
//! delegate as code. `--stdin` therefore offers the two dispositions a profile
//! can name, and `--identity-map` the delegates the library bundles. The output
//! pair has no flag at all: a shell already spells both of its dispositions,
//! and a profile carries `stdout` and `stderr` where they belong. `fcage` does
//! reach for `Stdio::Fd` itself, for one purpose: a standard stream that is a
//! file is relayed through a pipe rather than handed to the command, which
//! [`streams`] explains.
//!
//! The same holds for the native network stack: every `NetStackBuilder` setting
//! has a `--netstack-*` flag. The provisioners are narrower, and deliberately:
//! each one's bootstrap surface has flags, including the plan and pin documents
//! that make an install reproducible, but a *layered* build has none. A
//! provisioner given a base layer produces an increment in a disposable overlay
//! upper rather than a published rootfs, which is a mode `fcage` does not have;
//! and only Gentoo has read-only inspection modes, because only its archive
//! publishes the enumerations they print. `tools/parity.toml` records the whole
//! comparison, setting by setting, and a check holds it to the code.

mod output;
mod streams;
mod terminal;

use std::ffi::{OsStr, OsString};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ferroday_cage::provision::alpine::KeySet as AlpineKeySet;
use ferroday_cage::provision::debian::{Priority, Repository};
use ferroday_cage::provision::{ProvisionError, ProvisionEvent, Provisioned, Provisioner};
use ferroday_cage::relay::{Escalation, RelayError, Signals};
use ferroday_cage::{
    Bind, Cage, CageBuilder, Capability, Error, ErrorChain, ExitStatus, FsAccess, IdRange,
    Identity, IdentityMap, LandlockScope, Limit, Mount, NetAccess, NetStack, Network, Overlay,
    PresentedIdentity, RawMount, Resource, RestrictedProfile, Restriction, RestrictionBuilder,
    Running, SeccompArg, SeccompArgLen, SeccompCompare, SeccompPolicy, SeccompRules, Stdio,
    Symlink,
};
use serde::Deserialize as _;

/// The exit code of a command line `fcage` cannot understand.
const USAGE: u8 = 2;

/// `timeout(1)`'s exit code for an expired `--timeout`, whatever became of the
/// command afterwards.
const TIMED_OUT: u8 = 124;

/// The exit code of a failure of `fcage`'s own: a sandbox it could not build or
/// launch, a root filesystem it could not provision, a stream it refused or
/// could not relay.
///
/// [`Error::shell_code`] answers 125 for every launch failure but the exec
/// step's. This is the same code for the failures that are not an [`Error`], so
/// a script reads one code for "`fcage` failed" whatever part of it failed.
const FAILED: u8 = 125;

/// Reports a failure of `fcage`'s own on standard error, and returns
/// [`FAILED`].
fn fail(diagnostic: impl Into<Diagnostic>) -> ExitCode {
    output::report(format_args!("fcage: {}", diagnostic.into().0));
    ExitCode::from(FAILED)
}

/// What [`fail`] reports: a message of `fcage`'s own, or an error rendered with
/// every cause beneath it.
///
/// The library's errors, and the OS errors `fcage` meets on its own, keep their
/// causes out of their messages and return them from `source()`. Printing one
/// with `{}` would therefore drop the OS error underneath it, so each converts
/// through [`ErrorChain`] instead. The conversions name each error type rather
/// than covering every type at once, so an error type without one is refused as
/// an argument to [`fail`] at compile time, rather than accepted as a message
/// that has lost its cause.
struct Diagnostic(String);

impl From<String> for Diagnostic {
    fn from(message: String) -> Diagnostic {
        Diagnostic(message)
    }
}

impl From<std::fmt::Arguments<'_>> for Diagnostic {
    fn from(message: std::fmt::Arguments<'_>) -> Diagnostic {
        Diagnostic(message.to_string())
    }
}

/// Declares the conversion of each error type `fcage` reports into a
/// [`Diagnostic`], rendered through [`ErrorChain`].
macro_rules! diagnostic_from_errors {
    ($($error:ty),+ $(,)?) => {
        $(
            impl From<$error> for Diagnostic {
                fn from(error: $error) -> Diagnostic {
                    Diagnostic(ErrorChain::new(&error).to_string())
                }
            }
        )+
    };
}

diagnostic_from_errors!(
    Error,
    ferroday_cage::NetStackError,
    ferroday_cage::provision::ProvisionError,
    ferroday_cage::provision::alpine::AlpineError,
    ferroday_cage::provision::debian::DebianError,
    ferroday_cage::provision::gentoo::GentooError,
    RelayError,
    streams::StartError,
);

/// What follows a flag's name on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arity {
    /// Nothing: the flag is the whole argument.
    Bare,
    /// One value, written `--flag VALUE` or `--flag=VALUE`.
    One,
    /// Two, written `--flag FIRST SECOND`. Only the bind, environment, and
    /// publication flags take a pair, and none of them has a joined form:
    /// `--bind=A B` would put one of the two on the wrong side of the `=`.
    Two,
}

/// The invocation a flag belongs to.
///
/// `fcage` is several programs behind one name, and each mode's parser accepts
/// only its own flags. What the modes share is where the command begins, which
/// is why every flag is here whether a launch takes it or not: the pre-scan
/// that routes an invocation has to walk past a flag's value to find the first
/// positional argument, and it can only do that if it knows what each flag
/// takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The ordinary invocation: build a sandbox and run a command in it.
    Launch,
    /// `--remove-rootfs`.
    Remove,
    /// `--export-rootfs`.
    Export,
    /// `--gentoo-variants`.
    GentooVariants,
    /// `--gentoo-packages`.
    GentooPackages,
    /// `--gentoo-installed`.
    GentooInstalled,
    /// `--gentoo-keyring-horizon`.
    GentooKeyring,
    /// `--help`.
    Help,
    /// `--version`.
    Version,
}

/// Where `--help` lists a flag.
///
/// The order here is the order the sections are printed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Provisioning,
    Profiles,
    Identity,
    Command,
    Networking,
    Hardening,
    Off,
    Help,
    /// Named in the closing prose rather than listed: the counterpart toggles,
    /// each of which overrides a profile in the direction its named partner
    /// does not.
    Counterpart,
}

impl Section {
    /// Every section, in the order `--help` prints them.
    const ALL: &'static [Section] = &[
        Section::Provisioning,
        Section::Profiles,
        Section::Identity,
        Section::Command,
        Section::Networking,
        Section::Hardening,
        Section::Off,
        Section::Help,
        Section::Counterpart,
    ];

    /// The heading `--help` prints above it, or `None` for the flags the
    /// closing prose names instead of listing.
    const fn heading(self) -> Option<&'static str> {
        match self {
            Section::Provisioning => Some("Provisioning the root filesystem"),
            Section::Profiles => Some("Profiles, overlays, and mounts"),
            Section::Identity => Some("Identity and limits"),
            Section::Command => Some("The command and its process"),
            Section::Networking => Some("Networking"),
            Section::Hardening => Some("Hardening"),
            Section::Off => Some("Turning off what is on by default"),
            Section::Help => Some("Help and version"),
            Section::Counterpart => None,
        }
    }
}

/// What a launch does with a flag, and what the flag takes.
///
/// The two are one field rather than two, so that a flag's arity is the shape
/// of the function that applies it and cannot disagree with it.
#[derive(Clone, Copy)]
enum Take {
    /// A flag with nothing after it.
    Bare(fn(&mut Options)),
    /// A flag taking one value.
    One(fn(&mut Options, &'static str, OsString) -> Result<(), String>),
    /// A flag taking two.
    Two(fn(&mut Options, &'static str, OsString, OsString) -> Result<(), String>),
    /// A flag a launch refuses, because it belongs to another mode. The arity
    /// is still recorded: the pre-scan walks past such a flag's value like any
    /// other's, since reading that value as the command would end the scan
    /// before a mode flag after it.
    Refused(Arity),
}

/// One flag `fcage` accepts, wherever it accepts it.
///
/// This is the parser's vocabulary, the help's contents, and the suggester's
/// candidate list, declared once. None of the three is derived from another by
/// reading text, where a pattern that stopped matching would produce an empty
/// list that every check over it passes.
#[derive(Clone, Copy)]
struct Flag {
    /// The name, with its leading dashes.
    long: &'static str,
    /// A one-letter alias, where the flag has one.
    short: Option<&'static str>,
    /// What `--help` writes after the name: `DIR`, `SRC DEST`, or nothing.
    placeholder: &'static str,
    /// Where `--help` lists it.
    section: Section,
    /// What `--help` says about it, one entry per line of the entry's body.
    ///
    /// Held as written rather than as a paragraph to wrap: the help is prose
    /// broken where it reads well rather than at a column, and re-wrapping it
    /// would move a line break the person who wrote the sentence chose.
    help: &'static [&'static str],
    /// Whether a roster generated from the library follows the entry.
    roster: bool,
    /// The invocation it belongs to.
    mode: Mode,
    /// Whether naming this flag is what selects its mode.
    selects: bool,
    /// What a missing value is reported as: `--flag requires {needs}`.
    needs: &'static str,
    /// What a launch does with it, and what it takes.
    take: Take,
}

impl Flag {
    /// The fields most flags share, so an entry states only what is its own.
    const DEFAULTS: Flag = Flag {
        long: "",
        short: None,
        placeholder: "",
        section: Section::Command,
        help: &[],
        roster: false,
        mode: Mode::Launch,
        selects: false,
        needs: "a value",
        take: Take::Refused(Arity::Bare),
    };

    /// What follows this flag's name.
    const fn arity(&self) -> Arity {
        match self.take {
            Take::Bare(_) => Arity::Bare,
            Take::One(_) => Arity::One,
            Take::Two(_) => Arity::Two,
            Take::Refused(arity) => arity,
        }
    }

    /// The name and its placeholder, as `--help` writes them.
    fn spelled(&self) -> String {
        let mut out = String::new();
        if let Some(short) = self.short {
            out.push_str(short);
            out.push_str(", ");
        }
        out.push_str(self.long);
        if !self.placeholder.is_empty() {
            out.push(' ');
            out.push_str(self.placeholder);
        }
        out
    }
}

/// Every flag `fcage` accepts, in the order `--help` lists them.
const FLAGS: &[Flag] = &[
    Flag {
        long: "--rootfs",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &["Directory to present as the sandbox root filesystem"],
        take: Take::One(|options, _flag, value| {
            options.rootfs = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--empty-rootfs",
        section: Section::Provisioning,
        help: &[
            "Root the sandbox on an empty filesystem of its own,",
            "composed with --ro-bind, --bind and --symlink and made",
            "read-only once they are in place. Nothing is written",
            "on the host. Alternative to --rootfs",
        ],
        take: Take::Bare(|options| {
            options.empty_rootfs = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--provision-tar",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Provision --rootfs from a tar archive (plain, gzip,",
            "xz, or zstd). Runs only when the directory does not",
            "exist yet: an existing one is reused as it stands,",
            "whatever it holds",
        ],
        take: Take::One(|options, _flag, value| {
            options.provision_tar = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--provision-debian",
        section: Section::Provisioning,
        placeholder: "SUITE",
        help: &[
            "Bootstrap --rootfs as a Debian SUITE (e.g. trixie)",
            "from the archive; given without a command, provision",
            "and exit. Runs only when the directory does not exist",
            "yet: an existing one is reused as it stands, whatever",
            "it holds",
        ],
        take: Take::One(|options, flag, value| {
            options.provision_debian = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-arch",
        section: Section::Provisioning,
        placeholder: "ARCH",
        help: &[
            "Target architecture for --provision-debian (default:",
            "the host architecture)",
        ],
        take: Take::One(|options, flag, value| {
            options.debian_arch = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-mirror",
        section: Section::Provisioning,
        placeholder: "URL",
        help: &["Archive mirror (default: http://deb.debian.org/debian)"],
        take: Take::One(|options, flag, value| {
            options.debian_mirror = Some(fetchable_mirror(flag, into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-components",
        section: Section::Provisioning,
        placeholder: "L",
        help: &["Comma-separated components (default: main; repeatable)"],
        take: Take::One(|options, flag, value| {
            extend_comma(&mut options.debian_components, &into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-include",
        section: Section::Provisioning,
        placeholder: "L",
        help: &[
            "Extra packages to install (comma-separated, repeatable).",
            "NAME/RELEASE installs NAME from the repository",
            "configured with suite RELEASE",
        ],
        take: Take::One(|options, flag, value| {
            extend_comma(&mut options.debian_include, &into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-exclude",
        section: Section::Provisioning,
        placeholder: "L",
        help: &[
            "Packages to keep out of the resolution, with their",
            "dependents (comma-separated, repeatable)",
        ],
        take: Take::One(|options, flag, value| {
            extend_comma(&mut options.debian_exclude, &into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-plan",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Install exactly the packages FILE names, resolving",
            "nothing. FILE is a plan document a previous resolution",
            "wrote. The flags that shape a resolution",
            "(--debian-include, --debian-exclude,",
            "--debian-base-priority, --debian-pin) cannot be given",
            "with it",
        ],
        take: Take::One(|options, _flag, value| {
            options.debian_plan = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-pin",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Hold the resolution to the versions the plan document",
            "FILE records, resolving everything it does not name.",
            "Where --debian-plan replaces a resolution, this",
            "constrains one",
        ],
        take: Take::One(|options, _flag, value| {
            options.debian_pin = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-extract-only",
        section: Section::Provisioning,
        help: &[
            "Lay out files without configuring them (runs no",
            "maintainer scripts; for a foreign architecture)",
        ],
        take: Take::Bare(|options| {
            options.debian_extract_only = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-cache",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &["Cache downloaded packages in DIR, reused across runs"],
        take: Take::One(|options, _flag, value| {
            options.debian_cache = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-keyring",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &["Verify the archive with FILE, not the embedded keyring"],
        take: Take::One(|options, _flag, value| {
            options.debian_keyring = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-mirror-fallback",
        section: Section::Provisioning,
        placeholder: "URL",
        help: &[
            "A further URL for the same archive, tried when the",
            "primary mirror does not serve a resource (repeatable,",
            "in order)",
        ],
        take: Take::One(|options, flag, value| {
            options
                .debian_mirror_fallback
                .push(fetchable_mirror(flag, into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-base-priority",
        section: Section::Provisioning,
        placeholder: "P",
        help: &[
            "The priority floor the base set is drawn from:",
            "required (default), important, standard, optional,",
            "or extra",
        ],
        take: Take::One(|options, flag, value| {
            options.debian_base_priority = Some(parse_priority(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-trust-unsigned",
        section: Section::Provisioning,
        help: &[
            "Accept the archive without verifying its signature.",
            "Every mirror must then be file://: an unsigned archive",
            "is taken only over a transport that authenticates what",
            "it serves, and fcage fetches nothing over https://",
        ],
        take: Take::Bare(|options| {
            options.debian_trust_unsigned = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-allow-stale-release",
        section: Section::Provisioning,
        help: &["Accept a signed release whose validity has expired"],
        take: Take::Bare(|options| {
            options.debian_allow_stale_release = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-pre-configure-overlay",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &[
            "Overlay DIR onto the root after the packages are",
            "unpacked and before the configure wave runs",
        ],
        take: Take::One(|options, _flag, value| {
            options.debian_pre_configure_overlay = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-source-date-epoch",
        section: Section::Provisioning,
        placeholder: "EPOCH",
        help: &[
            "Give every maintainer script SOURCE_DATE_EPOCH, a",
            "Unix timestamp in seconds, so the accounts the",
            "install creates are dated by EPOCH rather than by",
            "the day the bootstrap ran",
        ],
        take: Take::One(|options, flag, value| {
            options.debian_source_date_epoch =
                Some(parse_source_date_epoch(flag, &into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-identity-map",
        section: Section::Provisioning,
        placeholder: "M",
        help: &[
            "Identity map for the bootstrap's own cages, in the",
            "form --identity-map takes; a range map records real",
            "ownership instead of the single-map stubs",
        ],
        take: Take::One(|options, flag, value| {
            options.debian_identity_map =
                Some(parse_identity_map(flag, &into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--debian-repository",
        section: Section::Provisioning,
        placeholder: "SPEC",
        help: &[
            "An additional archive source, merged into the same",
            "resolution. SPEC is space-separated key=value fields:",
            "'suite=S mirror=URL [mirror-fallback=URL]",
            "[components=a,b] [keyring=PATH] [name=NAME]",
            "[trust-unsigned] [allow-stale-release]'. Repeatable",
        ],
        take: Take::One(|options, flag, value| {
            options
                .debian_repositories
                .push(parse_repository(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--provision-alpine",
        section: Section::Provisioning,
        placeholder: "RELEASE",
        help: &[
            "Bootstrap --rootfs as an Alpine RELEASE (e.g. v3.23)",
            "from the archive; given without a command, provision",
            "and exit. Runs only when the directory does not exist",
            "yet: an existing one is reused as it stands, whatever",
            "it holds",
        ],
        take: Take::One(|options, flag, value| {
            options.provision_alpine = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-arch",
        section: Section::Provisioning,
        placeholder: "ARCH",
        help: &[
            "Target architecture for --provision-alpine (default:",
            "the host architecture)",
        ],
        take: Take::One(|options, flag, value| {
            options.alpine_arch = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-mirror",
        section: Section::Provisioning,
        placeholder: "URL",
        help: &[
            "Archive mirror (default:",
            "http://dl-cdn.alpinelinux.org/alpine)",
        ],
        take: Take::One(|options, flag, value| {
            options.alpine_mirror = Some(fetchable_mirror(flag, into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-components",
        section: Section::Provisioning,
        placeholder: "L",
        help: &["Comma-separated components (default: main; repeatable)"],
        take: Take::One(|options, flag, value| {
            extend_comma(&mut options.alpine_components, &into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-include",
        section: Section::Provisioning,
        placeholder: "L",
        help: &[
            "Packages to install (comma-separated, repeatable).",
            "apk has no priority band, so nothing is installed that",
            "was not named here or required by something that was",
        ],
        take: Take::One(|options, flag, value| {
            extend_comma(&mut options.alpine_include, &into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-exclude",
        section: Section::Provisioning,
        placeholder: "L",
        help: &[
            "Packages to keep out of the resolution (comma-separated,",
            "repeatable)",
        ],
        take: Take::One(|options, flag, value| {
            extend_comma(&mut options.alpine_exclude, &into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-plan",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Install exactly the packages FILE names, resolving",
            "nothing. FILE is a plan document a previous resolution",
            "wrote. The flags that shape a resolution",
            "(--alpine-include, --alpine-exclude, --alpine-pin)",
            "cannot be given with it",
        ],
        take: Take::One(|options, _flag, value| {
            options.alpine_plan = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-pin",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Hold the resolution to the versions the plan document",
            "FILE records, resolving everything it does not name.",
            "Where --alpine-plan replaces a resolution, this",
            "constrains one",
        ],
        take: Take::One(|options, _flag, value| {
            options.alpine_pin = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-extract-only",
        section: Section::Provisioning,
        help: &[
            "Lay out files and register them without running any",
            "install script (for a foreign architecture)",
        ],
        take: Take::Bare(|options| {
            options.alpine_extract_only = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-cache",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &["Cache downloaded packages in DIR, reused across runs"],
        take: Take::One(|options, _flag, value| {
            options.alpine_cache = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-keys",
        section: Section::Provisioning,
        placeholder: "SOURCE",
        help: &[
            "The keys the archive is verified against: 'alpine' (the",
            "bundled set for the target architecture, the default),",
            "'postmarketos', or a directory of PEM public keys named",
            "as the repository publishes them",
        ],
        take: Take::One(|options, flag, value| {
            options.alpine_keys = Some(parse_alpine_keys(flag, &into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-mirror-fallback",
        section: Section::Provisioning,
        placeholder: "URL",
        help: &[
            "A further URL for the same archive, tried when the",
            "primary mirror does not serve a resource (repeatable,",
            "in order)",
        ],
        take: Take::One(|options, flag, value| {
            options
                .alpine_mirror_fallback
                .push(fetchable_mirror(flag, into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-pre-configure-overlay",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &[
            "Overlay DIR onto the root after the files are laid",
            "out and before any install script runs",
        ],
        take: Take::One(|options, _flag, value| {
            options.alpine_pre_configure_overlay = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-identity-map",
        section: Section::Provisioning,
        placeholder: "M",
        help: &[
            "Identity map for the bootstrap's own cages, in the",
            "form --identity-map takes",
        ],
        take: Take::One(|options, flag, value| {
            options.alpine_identity_map =
                Some(parse_identity_map(flag, &into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-source-date-epoch",
        section: Section::Provisioning,
        placeholder: "EPOCH",
        help: &[
            "Give every install script SOURCE_DATE_EPOCH, a",
            "Unix timestamp in seconds, and date the accounts",
            "the install creates by EPOCH rather than by the",
            "day the bootstrap ran",
        ],
        take: Take::One(|options, flag, value| {
            options.alpine_source_date_epoch =
                Some(parse_source_date_epoch(flag, &into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--alpine-repository",
        section: Section::Provisioning,
        placeholder: "SPEC",
        help: &[
            "An additional archive source, merged into the same",
            "resolution. SPEC is space-separated key=value fields:",
            "'release=R mirror=URL keys=SOURCE [mirror-fallback=URL]",
            "[components=a,b]'. Naming no components selects the",
            "<release>/<architecture> layout postmarketOS publishes.",
            "Repeatable",
        ],
        take: Take::One(|options, flag, value| {
            options
                .alpine_repositories
                .push(parse_alpine_repository(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--provision-gentoo",
        section: Section::Provisioning,
        placeholder: "ARCH",
        help: &[
            "Bootstrap --rootfs from a signed Gentoo stage3 for",
            "ARCH (e.g. amd64); given without a command, provision",
            "and exit. Gentoo publishes one tree per architecture",
            "rather than a release, so ARCH is the coordinate.",
            "Runs only when the directory does not exist yet: an",
            "existing one is reused as it stands, whatever it holds",
        ],
        take: Take::One(|options, flag, value| {
            options.provision_gentoo = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-variant",
        section: Section::Provisioning,
        placeholder: "NAME",
        help: &[
            "The stage3 to install, as the archive spells it:",
            "'amd64-openrc', 'amd64-hardened-systemd', 'x32-openrc'.",
            "--gentoo-variants lists what an architecture offers",
        ],
        take: Take::One(|options, flag, value| {
            options.gentoo_variant = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-build-id",
        section: Section::Provisioning,
        placeholder: "ID",
        help: &[
            "Install the build in directory ID (e.g.",
            "20260810T204554Z) rather than the current one. The",
            "archive keeps about five weeks of builds, so a pinned",
            "id resolves against it for roughly a month, and after",
            "that from the digest document a provision kept in",
            "--gentoo-cache. It resolves only while the key that",
            "signed that document is in force, since every",
            "signature is checked at the current time",
        ],
        take: Take::One(|options, flag, value| {
            options.gentoo_build_id = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-binhost",
        section: Section::Provisioning,
        placeholder: "SUBARCH",
        help: &[
            "Install binary packages from the binhost tree for",
            "SUBARCH ('x86-64', 'x86-64-v3', 'x86-64_hardened',",
            "'x32'). There is no default: nothing signed enumerates",
            "the trees, so a wrong one is a 404 rather than a",
            "silently different userland",
        ],
        take: Take::One(|options, flag, value| {
            options.gentoo_binhost = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-install",
        section: Section::Provisioning,
        placeholder: "ATOM",
        help: &[
            "Install ATOM and its runtime dependencies from the",
            "binhost, in Gentoo's own dependency grammar:",
            "'dev-vcs/git', '>=dev-lang/python-3.12',",
            "'dev-libs/openssl:0'. Repeatable. A USE dependency in",
            "an atom is a constraint -- 'dev-vcs/git[keyring]'",
            "refuses to install a build without the flag",
        ],
        take: Take::One(|options, flag, value| {
            options.gentoo_install.push(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-prefer-use",
        section: Section::Provisioning,
        placeholder: "FLAGS",
        help: &[
            "Prefer builds carrying these space-separated USE flags,",
            "and builds without the ones written '-flag'. A",
            "preference, not a constraint: it reorders the candidate",
            "builds and cannot make an atom unsatisfiable. Repeatable",
        ],
        take: Take::One(|options, flag, value| {
            options.gentoo_prefer_use.extend(
                into_string(flag, value)?
                    .split_ascii_whitespace()
                    .map(str::to_string),
            );
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-plan",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Install the packages FILE names, resolving nothing.",
            "FILE is a plan document a previous run wrote. The",
            "flags that shape a resolution (--gentoo-install,",
            "--gentoo-prefer-use) cannot be given with it. A",
            "package the root has at the planned version is",
            "skipped, and one whose slot the root already holds",
            "is refused",
        ],
        take: Take::One(|options, _flag, value| {
            options.gentoo_plan = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-mirror",
        section: Section::Provisioning,
        placeholder: "URL",
        help: &["Archive mirror (default:", "http://distfiles.gentoo.org)"],
        take: Take::One(|options, flag, value| {
            options.gentoo_mirror = Some(fetchable_mirror(flag, into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-mirror-fallback",
        section: Section::Provisioning,
        placeholder: "URL",
        help: &[
            "A further URL for the same archive, tried when the",
            "primary mirror does not serve a resource (repeatable,",
            "in order)",
        ],
        take: Take::One(|options, flag, value| {
            options
                .gentoo_mirror_fallback
                .push(fetchable_mirror(flag, into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-cache",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &[
            "Cache the downloaded stage3, its digest document and",
            "the binary packages in DIR, reused across runs",
        ],
        take: Take::One(|options, _flag, value| {
            options.gentoo_cache = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-max-pointer-age",
        section: Section::Provisioning,
        placeholder: "DAYS",
        help: &[
            "Refuse a signed pointer document regenerated more than",
            "DAYS ago (default: 30), or 'none' to accept one of any",
            "age. Gentoo publishes no expiry of any kind, so this",
            "timestamp is the only thing that says when a document",
            "stopped being current; clearing the bound accepts a",
            "replayed one, which is what an archived mirror needs.",
            "The key that signed it must still be in force",
        ],
        take: Take::One(|options, flag, value| {
            options.gentoo_max_pointer_age = Some(parse_pointer_age(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-variants",
        section: Section::Provisioning,
        placeholder: "ARCH",
        help: &[
            "Print the stage3 variants ARCH publishes, from the",
            "signed enumeration, and exit. Takes --gentoo-mirror,",
            "--gentoo-mirror-fallback and --gentoo-max-pointer-age",
        ],
        mode: Mode::GentooVariants,
        selects: true,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-packages",
        section: Section::Provisioning,
        placeholder: "ARCH",
        help: &[
            "Print what the binhost publishes for ARCH: every",
            "package name and its versions, and exit. Takes",
            "--gentoo-binhost, --gentoo-mirror and",
            "--gentoo-mirror-fallback",
        ],
        mode: Mode::GentooPackages,
        selects: true,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-installed",
        section: Section::Provisioning,
        placeholder: "ROOT",
        help: &[
            "Print what the Gentoo root at ROOT already has",
            "installed, from its own package database, and exit.",
            "Reaches no network",
        ],
        mode: Mode::GentooInstalled,
        selects: true,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--gentoo-keyring-horizon",
        section: Section::Provisioning,
        help: &[
            "Print the vendored Gentoo keyring: every certificate,",
            "whether it can still sign, and when its authority",
            "lapses. Reaches no network",
        ],
        mode: Mode::GentooKeyring,
        selects: true,
        take: Take::Refused(Arity::Bare),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--remove-rootfs",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &[
            "Delete the provisioned rootfs at DIR and exit,",
            "including one a range-mapped sandbox wrote and a plain",
            "'rm -rf' cannot remove. Give the --identity-map the",
            "tree was provisioned under; the default is",
            "'subordinate'. The sibling lock file DIR.lock goes with",
            "it, since provisioning wrote that file; --keep-lock",
            "leaves it. Removing a path that is not there succeeds,",
            "so the call is repeatable. Takes no other option: it",
            "removes a rootfs rather than running a command in one",
        ],
        mode: Mode::Remove,
        selects: true,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--keep-lock",
        section: Section::Provisioning,
        help: &[
            "Leave the DIR.lock sibling in place when",
            "--remove-rootfs deletes DIR. Use it where DIR merely",
            "contains rootfs trees rather than being one, so that",
            "DIR.lock is an unrelated file the command never named",
        ],
        mode: Mode::Remove,
        take: Take::Refused(Arity::Bare),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--remove-overlay-upper",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &[
            "Delete the overlay upper at DIR and the work directory",
            "kept beside it, and exit: how a run on --overlay-upper",
            "is reverted. Give the --identity-map the sandbox ran",
            "under; the default is 'subordinate'. A work directory",
            "named with --overlay-work is removed with",
            "--remove-rootfs and --keep-lock. Removing a path that",
            "is not there succeeds. Takes no other option",
        ],
        mode: Mode::Remove,
        selects: true,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--export-rootfs",
        section: Section::Provisioning,
        placeholder: "DIR",
        help: &[
            "Write the provisioned rootfs at DIR to a tar archive",
            "and exit, preserving the ownership the tree intends",
            "and the extended attributes a host-side 'tar' cannot",
            "read. Give the --identity-map the tree was provisioned",
            "under; the default is 'subordinate'. Takes no other",
            "option: it exports a rootfs rather than running a",
            "command in one",
        ],
        mode: Mode::Export,
        selects: true,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--export-to",
        section: Section::Provisioning,
        placeholder: "FILE",
        help: &[
            "Where --export-rootfs writes. The default is standard",
            "output, so the archive pipes into a compressor without",
            "a temporary file; writing one to a terminal is refused",
        ],
        mode: Mode::Export,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--clamp-mtime",
        section: Section::Provisioning,
        placeholder: "EPOCH",
        help: &[
            "Cap every modification time --export-rootfs records at",
            "EPOCH, a Unix timestamp in seconds. With it the archive",
            "is byte-reproducible given the tree",
        ],
        mode: Mode::Export,
        take: Take::Refused(Arity::One),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--profile",
        section: Section::Profiles,
        placeholder: "FILE",
        help: &[
            "Load a TOML sandbox profile; flags given alongside",
            "override its settings, binds and variables extend it,",
            "and any [hardening] table it carries takes effect. A",
            "profile is trusted like a script: it can bind any host",
            "path, issue raw mounts, share the host network, and",
            "share the host PID namespace. Load only a profile you",
            "trust, or use --restricted-profile",
        ],
        take: Take::One(|options, _flag, value| {
            let path = PathBuf::from(value);
            set_profile(options, path, false)?;
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--restricted-profile",
        section: Section::Profiles,
        placeholder: "FILE",
        help: &[
            "Load a TOML profile from an untrusted source: like",
            "--profile, but the operations that map host resources",
            "into the sandbox or share a host namespace (binds, raw",
            "mounts, host networking, the host PID namespace, an",
            "overlay root) are refused. The rootfs it names still",
            "grants access to that host subtree, so pass a rootfs",
            "you control",
        ],
        take: Take::One(|options, _flag, value| {
            let path = PathBuf::from(value);
            set_profile(options, path, true)?;
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--overlay-lower",
        section: Section::Profiles,
        placeholder: "DIR",
        help: &[
            "Root the sandbox on an overlay whose base is DIR",
            "(repeatable and ordered: the first is the base, each",
            "later one is laid over it). Alternative to --rootfs",
        ],
        take: Take::One(|options, _flag, value| {
            options.overlay_lowers.push(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--overlay-upper",
        section: Section::Profiles,
        placeholder: "DIR",
        help: &[
            "Where the overlay's writes land; DIR persists after",
            "the sandbox exits, so discarding it with",
            "--remove-overlay-upper reverts the run. Required with",
            "--overlay-lower",
        ],
        take: Take::One(|options, _flag, value| {
            options.overlay_upper = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--overlay-work",
        section: Section::Profiles,
        placeholder: "DIR",
        help: &[
            "Override the overlay's work directory, which must sit",
            "on the same filesystem as the upper",
        ],
        take: Take::One(|options, _flag, value| {
            options.overlay_work = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--bind",
        section: Section::Profiles,
        placeholder: "SRC DEST",
        help: &["Bind-mount host path SRC read-write at DEST"],
        needs: "a source and a target",
        take: Take::Two(|options, _flag, value, second| {
            let source = value;
            let target = second;
            options.mounts.push(Mount::Bind(
                Bind::new(PathBuf::from(source), PathBuf::from(target)).read_only(false),
            ));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--ro-bind",
        section: Section::Profiles,
        placeholder: "SRC DEST",
        help: &["Bind-mount host path SRC read-only at DEST"],
        needs: "a source and a target",
        take: Take::Two(|options, _flag, value, second| {
            let source = value;
            let target = second;
            options.mounts.push(Mount::Bind(
                Bind::new(PathBuf::from(source), PathBuf::from(target)).read_only(true),
            ));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--symlink",
        section: Section::Profiles,
        placeholder: "TARGET PATH",
        help: &[
            "Create a symbolic link at PATH inside the sandbox,",
            "pointing at TARGET, in its place among the mounts",
        ],
        needs: "a target and a path",
        take: Take::Two(|options, _flag, target, path| {
            options.mounts.push(Mount::Symlink(Symlink::new(
                PathBuf::from(target),
                PathBuf::from(path),
            )));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--raw-mount",
        section: Section::Profiles,
        placeholder: "SPEC",
        help: &[
            "A mount the typed options do not model, passed to the",
            "kernel as given. SPEC is space-separated key=value",
            "fields: 'target=/sys fstype=sysfs flags=0xE",
            "[source=...] [data=...]'. Only the target is validated",
            "and confined. Repeatable.",
            "Mounts apply in the order these flags appear, so a",
            "--raw-mount tmpfs followed by --bind flags into it",
            "builds a directory the sandbox owns outright",
        ],
        take: Take::One(|options, flag, value| {
            options
                .mounts
                .push(Mount::Raw(parse_raw_mount(&into_string(flag, value)?)?));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--identity-map",
        section: Section::Identity,
        placeholder: "M",
        help: &[
            "How the user namespace maps identities: 'single'",
            "(default: root inside is you outside, and no other id",
            "exists), 'subordinate' (root plus your whole",
            "subordinate allocation, through newuidmap/newgidmap),",
            "or explicit extents,",
            "'uid=IN:OUT:COUNT[,...] gid=IN:OUT:COUNT[,...]'",
        ],
        take: Take::One(|options, flag, value| {
            options.identity_map = Some(parse_identity_map(flag, &into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--run-as",
        section: Section::Identity,
        placeholder: "UID:GID[:G,...]",
        help: &[
            "Run the command as a non-root identity inside the",
            "sandbox, with optional supplementary groups. Every id",
            "must be contained in the identity map; groups need a",
            "gid map wider than the caller's own gid",
        ],
        take: Take::One(|options, flag, value| {
            options.run_as = Some(parse_run_as(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--present-as",
        section: Section::Identity,
        placeholder: "UID:GID|own",
        help: &[
            "Under the single identity map, show yourself to the",
            "command as UID:GID rather than as root, or as your own",
            "ids with 'own'. The command runs as that identity and",
            "holds no capability, but on the host it is still you",
        ],
        take: Take::One(|options, flag, value| {
            let text = into_string(flag, value)?;
            options.present_as = Some(
                text.parse::<PresentedIdentity>()
                    .map_err(|error| format!("{flag}: {error}"))?,
            );
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--rlimit",
        section: Section::Identity,
        placeholder: "RES=SOFT[:HARD]",
        help: &[
            "Set a resource limit on the command, inherited by",
            "every process it starts. A value may be 'unlimited',",
            "and an omitted hard limit repeats the soft one.",
            "Repeatable (e.g. --rlimit processes=64 --rlimit",
            "address-space=536870912). RES is one of:",
        ],
        roster: true,
        take: Take::One(|options, flag, value| {
            options
                .rlimits
                .push(parse_rlimit(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--path-lookup",
        section: Section::Command,
        help: &[
            "Resolve a command with no slash against the sandbox's",
            "PATH, the way a shell does",
        ],
        take: Take::Bare(|options| {
            options.path_lookup = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--setenv",
        section: Section::Command,
        placeholder: "NAME VALUE",
        help: &["Set an environment variable for the command"],
        needs: "a name and a value",
        take: Take::Two(|options, flag, value, second| {
            // Validated here so a bad name is the usage error it is (exit 2),
            // rather than deferring to the library's build-time rejection
            // (exit 125). The rule matches the library's.
            if value.is_empty() || value.as_bytes().contains(&b'=') {
                return Err(format!(
                    "{flag}: {value:?} is not a valid environment variable name \
                     (it is empty or contains '=')"
                ));
            }
            options.setenv.push((value, second));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--hostname",
        section: Section::Command,
        placeholder: "NAME",
        help: &["Set the hostname inside the sandbox"],
        take: Take::One(|options, _flag, value| {
            options.hostname = Some(value);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--chdir",
        section: Section::Command,
        placeholder: "DIR",
        help: &["Working directory inside the sandbox (default /)"],
        take: Take::One(|options, _flag, value| {
            options.chdir = Some(PathBuf::from(value));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--stdin",
        section: Section::Command,
        placeholder: "MODE",
        help: &[
            "Standard input: inherit (default) or null. With null",
            "the command also runs in a session of its own, so the",
            "terminal fcage was started from is not its controlling",
            "terminal; an interrupt there stops fcage, which stops",
            "the sandbox. Standard output and standard error still",
            "reach that terminal unless redirected, which a shell",
            "already spells and a profile carries as stdout/stderr",
        ],
        take: Take::One(|options, _flag, value| {
            options.stdin = Some(parse_stdin(&value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--terminal",
        section: Section::Command,
        help: &[
            "Give the sandbox a pseudoterminal of its own and relay",
            "this terminal to it: interactive programs work, and the",
            "sandbox reaches nothing of the terminal fcage was",
            "started from. TERM passes through as ever unless",
            "--no-base-env is given, and --setenv TERM overrides it.",
            "From a script, where fcage's own input is not a",
            "terminal, this degrades to a plain byte relay around a",
            "sandbox that still has a real terminal of its own, at",
            "80x24",
        ],
        take: Take::Bare(|options| {
            options.terminal = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--timeout",
        section: Section::Command,
        placeholder: "SECS",
        help: &[
            "Terminate the command after SECS seconds, kill it",
            "--kill-after seconds later, and exit 124",
        ],
        take: Take::One(|options, flag, value| {
            options.timeout = Some(parse_seconds(flag, &value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--kill-after",
        section: Section::Command,
        placeholder: "SECS",
        help: &["Grace between terminate and kill (default 10)"],
        take: Take::One(|options, flag, value| {
            options.kill_after = parse_seconds(flag, &value)?;
            options.kill_after_given = true;
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--stop-with-caller",
        section: Section::Command,
        help: &[
            "Stop the sandbox when fcage itself exits (the default;",
            "--no-stop-with-caller leaves it running)",
        ],
        take: Take::Bare(|options| {
            options.stop_with_caller = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--share-net",
        section: Section::Networking,
        help: &["Share the host network (default: isolated loopback)"],
        take: Take::Bare(|options| {
            options.network = Some(Network::Host);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--deny-net",
        section: Section::Networking,
        help: &[
            "Isolated network with loopback left down (no",
            "connectivity at all, not even 127.0.0.1)",
        ],
        take: Take::Bare(|options| {
            options.network = Some(Network::None);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack",
        section: Section::Networking,
        help: &[
            "Attach the native userspace network stack: IPv4 and",
            "IPv6 for the isolated network, outbound and to any",
            "--netstack-publish port, carried over host sockets",
            "with no external helper. Binds the host's resolv.conf",
            "when it names a nameserver the stack forwards to,",
            "unless --no-resolv-conf or --no-managed-mounts is",
            "given or a mount of the run's own claims the file; a",
            "host whose nameservers are all loopback or link-local",
            "composes nothing, leaving the rootfs's own resolv.conf",
            "in place",
        ],
        take: Take::Bare(|options| {
            options.netstack = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-cidr",
        section: Section::Networking,
        placeholder: "V4/LEN",
        help: &[
            "IPv4 network for --netstack (default 10.0.2.0/24; the",
            "gateway is host 2, the guest host 15)",
        ],
        take: Take::One(|options, flag, value| {
            options.netstack_cidr = Some(parse_cidr(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-cidr6",
        section: Section::Networking,
        placeholder: "V6/LEN",
        help: &[
            "IPv6 network for --netstack (default fd00::/64; the",
            "gateway is host 2, the guest host 15)",
        ],
        take: Take::One(|options, flag, value| {
            options.netstack_cidr6 = Some(parse_cidr6(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-no-ipv4",
        section: Section::Networking,
        help: &[
            "Run the stack without IPv4, for a workload or a host",
            "where it is unwanted. The guest is then given no IPv4",
            "address and the stack answers no IPv4 traffic",
        ],
        take: Take::Bare(|options| {
            options.netstack_no_ipv4 = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-no-ipv6",
        section: Section::Networking,
        help: &[
            "Run the stack without IPv6, for a host that offers no",
            "IPv6 connectivity. The guest is then given no IPv6",
            "address and the stack answers no IPv6 traffic",
        ],
        take: Take::Bare(|options| {
            options.netstack_no_ipv6 = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-interface",
        section: Section::Networking,
        placeholder: "NAME",
        help: &[
            "Name the stack's interface inside the sandbox (default",
            "tap0; 1 to 15 bytes, free of '/', ':', and whitespace)",
        ],
        take: Take::One(|options, flag, value| {
            options.netstack_interface = Some(into_string(flag, value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-mtu",
        section: Section::Networking,
        placeholder: "N",
        help: &[
            "Interface MTU for --netstack (default 1500; the minimum",
            "is 576, or 1280 while IPv6 is enabled)",
        ],
        take: Take::One(|options, flag, value| {
            options.netstack_mtu = Some(parse_mtu(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-host-loopback",
        section: Section::Networking,
        help: &[
            "Map connections to the gateway address onto the host's",
            "loopback, 127.0.0.1 or ::1, port preserved, to reach a",
            "service bound there (off by default; every other loopback",
            "destination stays blocked, including a resolver on",
            "another loopback address such as systemd-resolved's",
            "127.0.0.53 stub)",
        ],
        take: Take::Bare(|options| {
            options.netstack_host_loopback = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-host-port",
        section: Section::Networking,
        placeholder: "PORT",
        help: &[
            "Map connections to the gateway address on PORT alone",
            "onto the host's loopback, the narrower form of",
            "--netstack-host-loopback (repeatable; TCP and UDP)",
        ],
        take: Take::One(|options, flag, value| {
            let port = parse_port(flag, &into_string(flag, value)?)?;
            options.netstack_host_ports.push(port);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--netstack-publish",
        section: Section::Networking,
        placeholder: "HOST GUEST_PORT",
        help: &[
            "Listen on HOST, an ADDRESS:PORT or a bare PORT on",
            "127.0.0.1, and carry each TCP connection to the",
            "sandbox's GUEST_PORT (repeatable). HOST decides who",
            "can connect: 0.0.0.0 admits the network. Port 0",
            "picks a free port, which fcage reports on stderr",
        ],
        needs: "a host address and a guest port",
        take: Take::Two(|options, flag, value, second| {
            let host = parse_publish_host(&into_string(flag, value)?)?;
            let guest_port = parse_port(flag, &into_string(flag, second)?)?;
            // The library refuses it at build; refused here, it is the usage
            // error it is. Port 0 on the host side asks the kernel for a free
            // port, and the guest side has no such meaning.
            if guest_port == 0 {
                return Err(format!(
                    "{flag}: the guest port must not be 0; it names the port the \
                     sandbox's service listens on"
                ));
            }
            options.netstack_publish.push((host, guest_port));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--restrict",
        section: Section::Hardening,
        help: &[
            "Confine the command with Landlock and seccomp only:",
            "no namespaces, no root filesystem swap, and paths are",
            "host paths. The fallback for hosts without",
            "unprivileged user namespaces; requires a Landlock",
            "grant (--landlock-ro, --landlock-rw, --landlock-bind,",
            "--landlock-connect) or a seccomp flag, and accepts",
            "only those, --landlock-scope, --setenv,",
            "--no-base-env, --chdir, --stdin, --terminal,",
            "--timeout, --kill-after, --rlimit, and",
            "--stop-with-caller, with their counterparts",
        ],
        take: Take::Bare(|options| {
            options.restrict = true;
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--landlock-ro",
        section: Section::Hardening,
        placeholder: "PATH",
        help: &[
            "Grant the command read and execute beneath PATH under",
            "a Landlock ruleset (repeatable; enrolling any grant",
            "denies all filesystem access not granted)",
        ],
        take: Take::One(|options, _flag, value| {
            let path = value;
            options.landlock.push((PathBuf::from(path), false));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--landlock-rw",
        section: Section::Hardening,
        placeholder: "PATH",
        help: &[
            "Grant read, write, and execute beneath PATH",
            "(repeatable)",
        ],
        take: Take::One(|options, _flag, value| {
            let path = value;
            options.landlock.push((PathBuf::from(path), true));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--landlock-bind",
        section: Section::Hardening,
        placeholder: "PORT",
        help: &[
            "Allow binding a TCP socket to PORT under a Landlock",
            "ruleset (repeatable; enrolling any network grant denies",
            "every bind and connect not granted; port 0 permits a",
            "kernel-assigned ephemeral port; needs Landlock ABI 4)",
        ],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            options
                .landlock_net
                .push((parse_port(flag, &value)?, NetAccess::BIND));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--landlock-connect",
        section: Section::Hardening,
        placeholder: "PORT",
        help: &["Allow connecting a TCP socket to PORT (repeatable)"],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            options
                .landlock_net
                .push((parse_port(flag, &value)?, NetAccess::CONNECT));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--landlock-scope",
        section: Section::Hardening,
        placeholder: "LIST",
        help: &[
            "Deny the command signals to, and abstract-socket",
            "connections with, processes outside its Landlock",
            "domain: LIST is comma-separated, from signal and",
            "abstract-unix-socket, or empty for none. Default: none,",
            "or both with --restrict. Needs Landlock ABI 6",
        ],
        take: Take::One(|options, flag, value| {
            options.landlock_scope = Some(parse_scopes(&into_string(flag, value)?)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--seccomp",
        section: Section::Hardening,
        placeholder: "curated",
        help: &[
            "Apply the curated seccomp deny-list of dangerous",
            "syscalls to the command",
        ],
        take: Take::One(|options, flag, value| {
            parse_seccomp(&into_string(flag, value)?, &mut options.seccomp_curated)?;
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--seccomp-allow",
        section: Section::Hardening,
        placeholder: "LIST",
        help: &[
            "Allow only these syscalls, denying the rest with EPERM",
            "(comma-separated names, repeatable; must name every",
            "syscall the command needs)",
        ],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            parse_seccomp_names(flag, &value, &mut options.seccomp_allow)?;
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--seccomp-deny",
        section: Section::Hardening,
        placeholder: "LIST",
        help: &[
            "Deny these syscalls with EPERM, allowing the rest",
            "(comma-separated names, repeatable)",
        ],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            parse_seccomp_names(flag, &value, &mut options.seccomp_deny)?;
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--seccomp-allow-rule",
        section: Section::Hardening,
        placeholder: "RULE",
        help: &[
            "Allow a syscall only when its arguments match; RULE is",
            "a syscall name and comma-separated conditions, each of",
            "the form 'arg=N len=dword|qword op=OP value=V', with",
            "op one of eq, ne, ge, gt, le, lt, or masked-eq (which",
            "also takes mask=M). Repeatable; repeating a syscall",
            "accepts any of the rules. Example:",
            "'ioctl arg=1 len=dword op=eq value=0x5413'",
        ],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            options
                .seccomp_allow_rules
                .push(parse_seccomp_rule(flag, &value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--seccomp-deny-rule",
        section: Section::Hardening,
        placeholder: "RULE",
        help: &[
            "Deny a syscall only when its arguments match, in the",
            "same form as --seccomp-allow-rule",
        ],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            options
                .seccomp_deny_rules
                .push(parse_seccomp_rule(flag, &value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--seccomp-errno",
        section: Section::Hardening,
        placeholder: "SYSCALL=ERRNO",
        help: &[
            "Answer every call of SYSCALL with ERRNO, by name or",
            "number (1 to 4095), ahead of every other seccomp rule.",
            "Joins the policy the other seccomp flags or a profile",
            "set rather than replacing it (repeatable; e.g.",
            "clone3=ENOSYS, which the C library answers by falling",
            "back to clone)",
        ],
        take: Take::One(|options, flag, value| {
            let value = into_string(flag, value)?;
            options
                .seccomp_errno
                .push(parse_seccomp_errno(flag, &value)?);
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--drop-caps",
        section: Section::Hardening,
        help: &["Drop every capability from the command"],
        take: Take::Bare(|options| {
            options.caps = Some(CapsChoice::DropAll);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--keep-caps",
        section: Section::Hardening,
        placeholder: "LIST",
        help: &[
            "Drop every capability except LIST (comma-separated,",
            "e.g. net-bind-service,sys-chroot)",
        ],
        take: Take::One(|options, flag, value| {
            options.caps = Some(CapsChoice::Keep(parse_caps(&into_string(flag, value)?)?));
            Ok(())
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--share-pid",
        section: Section::Off,
        help: &["Share the host PID namespace (default: isolated)"],
        take: Take::Bare(|options| {
            options.pid_namespace = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-proc",
        section: Section::Off,
        help: &[
            "Do not mount /proc. A cage needs a procfs from",
            "somewhere -- the nested user namespace that locks its",
            "mount flags establishes its identity map through one --",
            "so a run that sets this supplies its own with --bind",
        ],
        take: Take::Bare(|options| {
            options.mount_proc = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-dev",
        section: Section::Off,
        help: &["Do not assemble the minimal /dev"],
        take: Take::Bare(|options| {
            options.mount_dev = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-tmp",
        section: Section::Off,
        help: &["Do not mount a tmpfs on /tmp"],
        take: Take::Bare(|options| {
            options.mount_tmp = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-resolv-conf",
        section: Section::Off,
        help: &[
            "Do not bind the host resolv.conf: neither the bind",
            "--share-net makes nor the one --netstack composes",
        ],
        take: Take::Bare(|options| {
            options.resolv_conf = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-managed-mounts",
        section: Section::Off,
        help: &[
            "Establish no mount of the library's own, so the sandbox",
            "carries exactly the --bind and --raw-mount flags given.",
            "Unlike the individual --no-* toggles this also excludes",
            "any managed mount a later release adds. One of the flags",
            "given must supply a procfs; see --no-proc",
        ],
        take: Take::Bare(|options| {
            options.managed_mounts = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-base-env",
        section: Section::Off,
        help: &[
            "Give the command only the variables --setenv and a",
            "profile name, with no PATH, HOME, or host TERM",
            "supplied underneath them",
        ],
        take: Take::Bare(|options| {
            options.base_env = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--isolate-net",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.network = Some(Network::Isolated);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--pid-ns",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.pid_namespace = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--proc",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.mount_proc = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--dev",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.mount_dev = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--tmp",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.mount_tmp = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--resolv-conf",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.resolv_conf = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--managed-mounts",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.managed_mounts = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--base-env",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.base_env = Some(true);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-path-lookup",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.path_lookup = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--no-stop-with-caller",
        section: Section::Counterpart,
        take: Take::Bare(|options| {
            options.stop_with_caller = Some(false);
        }),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--help",
        section: Section::Help,
        short: Some("-h"),
        help: &["Print this help"],
        mode: Mode::Help,
        take: Take::Refused(Arity::Bare),
        ..Flag::DEFAULTS
    },
    Flag {
        long: "--version",
        section: Section::Help,
        short: Some("-V"),
        help: &["Print the fcage and library versions"],
        mode: Mode::Version,
        take: Take::Refused(Arity::Bare),
        ..Flag::DEFAULTS
    },
];

/// What `--help` prints above the option sections.
const SYNOPSIS: &str = "\
Run a command inside an unprivileged Linux sandbox.

Usage: fcage [--rootfs DIR | --empty-rootfs | --overlay-lower DIR | --profile FILE | --restricted-profile FILE | --restrict] [OPTIONS] [--] [COMMAND [ARGS...]]
       fcage --remove-rootfs DIR [--identity-map M] [--keep-lock]
       fcage --remove-overlay-upper DIR [--identity-map M]
       fcage --export-rootfs DIR [--export-to FILE] [--identity-map M] [--clamp-mtime EPOCH]
       fcage --gentoo-variants ARCH [--gentoo-mirror URL] [--gentoo-mirror-fallback URL] [--gentoo-max-pointer-age DAYS]
       fcage --gentoo-packages ARCH --gentoo-binhost SUBARCH [--gentoo-mirror URL] [--gentoo-mirror-fallback URL]
       fcage --gentoo-installed ROOT
       fcage --gentoo-keyring-horizon
";

/// What `--help` prints below them.
///
/// Prose rather than entries, so it stays written out: it names flags in
/// sentences, and the ten counterpart toggles are documented here rather
/// than listed above. A test holds every name it uses to [`FLAGS`], which is
/// what stops it drifting from the vocabulary it describes.
const CLOSING: &str = "\
Each toggle has a counterpart to override a profile in the other direction:
--isolate-net, --pid-ns, --proc, --dev, --tmp, --resolv-conf,
--managed-mounts, --base-env, --stop-with-caller, and --no-path-lookup.
A profile's [hardening] table composes with the hardening flags:
--landlock-ro, --landlock-rw, --landlock-bind, and --landlock-connect add
grants to it, while --landlock-scope, --drop-caps, --keep-caps, and the
seccomp flags that set a posture replace its scopes, capability posture, or
seccomp policy. Those seccomp flags are mutually constrained: --seccomp
curated stands alone, and an allow side (--seccomp-allow,
--seccomp-allow-rule) cannot be mixed with a deny side (--seccomp-deny,
--seccomp-deny-rule). --seccomp-errno joins whichever policy stands, the
flags' or else the profile's, and with neither denies only what it names; a
curated posture takes none.

The command path is interpreted inside the sandbox (with --restrict, on the
host) and must be absolute, unless --path-lookup resolves a name with no
slash against the sandbox's PATH; a command given on the command line
replaces one named by the profile. The command runs with inherited standard
streams and a clean environment: PATH and HOME, the host TERM when set,
profile variables, and the --setenv values. With --restrict the base is PATH
alone, there being no sandbox root for HOME to name. --no-base-env drops the
base, and the host TERM with it, either way.

A standard stream that is a regular file or a block device is not handed
to the command. It gets a pipe instead, and fcage copies between the pipe
and the file, so the command cannot reopen the file through /proc/self/fd
with more access than the stream carried. The command cannot seek such a
stream or read its size. Input it does not read stays in the file for the
next reader, and a relayed standard input puts the command in a session
of its own, as --stdin null does. A pipe, a socket, or a character device
is handed over as it is, and any other kind of stream, such as a
directory, is refused.

Exit status: the command's own exit code, or 128 plus the signal number
when it is terminated by a signal, or 124 when --timeout expires. fcage
itself exits 125 when the sandbox cannot be built or launched, when a
standard stream is refused, or when a relayed stream could not be read or
delivered; 126 when the command exists but cannot be executed; 127 when
the command does not exist; 141 when a reader of fcage's own output or
diagnostics goes away before fcage is done; and 2 on usage errors.
";

/// A parsed command line.
enum Invocation {
    /// Launch a sandbox.
    Run(Box<Options>),
    /// Delete a provisioned rootfs or an overlay upper, under the identity map
    /// it was written under.
    Remove {
        dest: PathBuf,
        map: IdentityMap,
        /// What the tree at `dest` is, which decides what goes with it.
        removal: Removal,
    },
    /// Print the stage3 variants an architecture publishes.
    GentooVariants {
        architecture: String,
        /// The archive to read, or `None` for the library's default.
        ///
        /// Kept apart from the backstops, as a provisioning run keeps them, so
        /// that the two flags mean the same thing in both modes.
        mirror: Option<String>,
        fallbacks: Vec<String>,
        max_pointer_age: Option<Option<u64>>,
    },
    /// Print what the binhost publishes for an architecture.
    GentooPackages {
        architecture: String,
        /// The sub-architecture tree, which has no default: nothing signed
        /// enumerates them.
        binhost: Option<String>,
        mirror: Option<String>,
        fallbacks: Vec<String>,
    },
    /// Print what a Gentoo root already has installed, from its own database.
    GentooInstalled {
        root: PathBuf,
    },
    /// Print what each certificate of the vendored Gentoo keyring can still be
    /// trusted to do, and until when.
    GentooKeyring,
    /// Write a provisioned rootfs to a tar archive, under the identity map it
    /// was written under.
    Export {
        source: PathBuf,
        /// Where the archive goes; standard output when absent.
        dest: Option<PathBuf>,
        map: IdentityMap,
        /// The `SOURCE_DATE_EPOCH` ceiling that makes the archive
        /// byte-reproducible, when given.
        clamp_mtime: Option<i64>,
    },
    Help,
    Version,
}

/// Everything a `Run` invocation configures. Toggles are three-state:
/// `None` leaves the profile's (or library's) value in place.
struct Options {
    profile: Option<PathBuf>,
    /// Whether the profile is loaded under the restricted policy
    /// (`--restricted-profile`) rather than fully trusted (`--profile`).
    profile_restricted: bool,
    rootfs: Option<PathBuf>,
    /// `--empty-rootfs`.
    empty_rootfs: bool,
    provision_tar: Option<PathBuf>,
    provision_debian: Option<String>,
    debian_arch: Option<String>,
    debian_mirror: Option<String>,
    debian_components: Vec<String>,
    debian_include: Vec<String>,
    debian_exclude: Vec<String>,
    debian_plan: Option<PathBuf>,
    debian_pin: Option<PathBuf>,
    debian_extract_only: bool,
    debian_cache: Option<PathBuf>,
    debian_keyring: Option<PathBuf>,
    debian_mirror_fallback: Vec<String>,
    debian_base_priority: Option<Priority>,
    debian_trust_unsigned: bool,
    debian_allow_stale_release: bool,
    debian_pre_configure_overlay: Option<PathBuf>,
    debian_source_date_epoch: Option<i64>,
    debian_identity_map: Option<IdentityMap>,
    debian_repositories: Vec<Repository>,
    provision_alpine: Option<String>,
    alpine_arch: Option<String>,
    alpine_mirror: Option<String>,
    alpine_components: Vec<String>,
    alpine_include: Vec<String>,
    alpine_exclude: Vec<String>,
    alpine_plan: Option<PathBuf>,
    alpine_pin: Option<PathBuf>,
    alpine_extract_only: bool,
    alpine_cache: Option<PathBuf>,
    alpine_keys: Option<AlpineKeys>,
    alpine_mirror_fallback: Vec<String>,
    alpine_pre_configure_overlay: Option<PathBuf>,
    alpine_identity_map: Option<IdentityMap>,
    alpine_source_date_epoch: Option<i64>,
    alpine_repositories: Vec<AlpineRepositorySpec>,
    provision_gentoo: Option<String>,
    gentoo_variant: Option<String>,
    gentoo_binhost: Option<String>,
    gentoo_install: Vec<String>,
    gentoo_prefer_use: Vec<String>,
    gentoo_plan: Option<PathBuf>,
    gentoo_build_id: Option<String>,
    gentoo_mirror: Option<String>,
    gentoo_mirror_fallback: Vec<String>,
    gentoo_cache: Option<PathBuf>,
    gentoo_max_pointer_age: Option<Option<u64>>,
    command_line: Vec<OsString>,
    path_lookup: Option<bool>,
    /// Binds and raw mounts in one sequence, so `--bind` and `--raw-mount`
    /// apply in the order they appear on the command line — the same
    /// declaration-order rule the library's `[[mount]]` array follows.
    mounts: Vec<Mount>,
    overlay_lowers: Vec<PathBuf>,
    overlay_upper: Option<PathBuf>,
    overlay_work: Option<PathBuf>,
    identity_map: Option<IdentityMap>,
    run_as: Option<Identity>,
    present_as: Option<PresentedIdentity>,
    rlimits: Vec<(Resource, Limit, Limit)>,
    setenv: Vec<(OsString, OsString)>,
    hostname: Option<OsString>,
    chdir: Option<PathBuf>,
    stdin: Option<Stdio>,
    /// Whether to allocate a pseudoterminal for the sandbox and relay it.
    terminal: bool,
    timeout: Option<Duration>,
    kill_after: Duration,
    /// Whether `--kill-after` was given explicitly, to reject it without a
    /// `--timeout` to hang the grace period on.
    kill_after_given: bool,
    network: Option<Network>,
    pid_namespace: Option<bool>,
    mount_proc: Option<bool>,
    mount_dev: Option<bool>,
    mount_tmp: Option<bool>,
    resolv_conf: Option<bool>,
    managed_mounts: Option<bool>,
    base_env: Option<bool>,
    stop_with_caller: Option<bool>,
    landlock: Vec<(PathBuf, bool)>,
    landlock_net: Vec<(u16, NetAccess)>,
    landlock_scope: Option<Vec<LandlockScope>>,
    seccomp: Option<SeccompPolicy>,
    /// The seccomp flags as they were given, reconciled into
    /// [`seccomp`](Self::seccomp) once the whole command line has been read.
    ///
    /// The curated posture and the allow and deny sides are mutually
    /// constrained, so they are gathered rather than applied: which of them is
    /// legal depends on what else was given, and the flag that decides can come
    /// last. They live here rather than beside the argument loop because a
    /// flag's own applier reaches exactly one value, and that value is this.
    seccomp_curated: bool,
    seccomp_allow: Vec<i64>,
    seccomp_deny: Vec<i64>,
    seccomp_allow_rules: Vec<(i64, Vec<SeccompArg>)>,
    seccomp_deny_rules: Vec<(i64, Vec<SeccompArg>)>,
    /// The `--seccomp-errno` answers, kept apart from [`seccomp`](Self::seccomp)
    /// until the launch: they join whichever policy stands, and with a profile
    /// that is not known until the profile is loaded.
    seccomp_errno: Vec<(i64, u16)>,
    caps: Option<CapsChoice>,
    restrict: bool,
    netstack: bool,
    netstack_cidr: Option<(Ipv4Addr, u8)>,
    netstack_cidr6: Option<(Ipv6Addr, u8)>,
    netstack_no_ipv4: bool,
    netstack_no_ipv6: bool,
    netstack_interface: Option<String>,
    netstack_mtu: Option<u16>,
    netstack_host_loopback: bool,
    netstack_host_ports: Vec<u16>,
    netstack_publish: Vec<(SocketAddr, u16)>,
}

/// The capability posture requested on the command line.
enum CapsChoice {
    /// Drop every capability.
    DropAll,
    /// Keep only these, dropping the rest.
    Keep(Vec<Capability>),
}

/// The help text, with its generated sections filled in.
///
/// The resource-limit names come from the library's own roster rather than a
/// second copy here, so a resource the library gains is offered by `--help` as
/// soon as `--rlimit` accepts it.
fn usage() -> String {
    /// The column an entry's description starts in, and the widest name that
    /// still shares a line with it.
    const DESCRIPTION: usize = 24;
    const NAME_ROOM: usize = DESCRIPTION - 2 - 1;

    let mut out = String::from(SYNOPSIS);
    for section in Section::ALL {
        let Some(heading) = section.heading() else {
            continue;
        };
        out.push('\n');
        out.push_str(heading);
        out.push_str(":\n");
        for flag in FLAGS.iter().filter(|flag| flag.section == *section) {
            let name = flag.spelled();
            let mut body = flag.help.iter();
            // A name too wide to leave room takes a line of its own, and the
            // description begins on the next.
            if name.len() <= NAME_ROOM
                && let Some(first) = body.next()
            {
                out.push_str(&format!(
                    "  {name:<width$}{first}\n",
                    width = DESCRIPTION - 2
                ));
            } else {
                out.push_str(&format!("  {name}\n"));
            }
            for line in body {
                out.push_str(&format!("{:DESCRIPTION$}{line}\n", ""));
            }
            if flag.roster {
                // The resource names come from the library's own roster rather
                // than a second copy here, so a resource the library gains is
                // offered by --help as soon as --rlimit accepts it.
                let names: Vec<&str> = Resource::ALL.iter().map(|r| r.spelling()).collect();
                out.push_str(&wrapped(&names));
                out.push('\n');
            }
        }
    }
    out.push('\n');
    out.push_str(CLOSING);
    out
}

/// The usage error for an option the launch parser does not know, offering the
/// nearest flag the help documents when one is close.
///
/// The message may span two lines: the report, then the suggestion, which
/// [`main`] prints above its own `Try 'fcage --help'`. Nothing is offered when
/// nothing is close, so a string that resembles no flag is reported plainly
/// rather than answered with an arbitrary one.
fn unrecognized_option(arg: &OsStr) -> String {
    let given = arg.to_string_lossy();
    // A `--flag=value` argument names its flag before the `=`; matching the
    // whole of it would weigh a value against a roster of flags and find
    // nothing near.
    let name = flag_name(&given);
    // A flag of another mode is not a misspelling. Suggesting it would offer
    // the spelling just refused; naming the mode that accepts it will not.
    if let Some(owner) = owning_mode_flag(name) {
        return format!(
            "unrecognized option {given}\n{name} is an option of {owner}, which is a mode of \
             its own.",
        );
    }
    // The candidates are the table itself, which the help is rendered from, so
    // the roster and the vocabulary are one list rather than two that have to
    // agree.
    let candidates: Vec<&str> = FLAGS
        .iter()
        .map(|flag| flag.long)
        .filter(|flag| owning_mode_flag(flag).is_none())
        .collect();
    match nearest_flag(name, &candidates) {
        Some(flag) => format!("unrecognized option {given}\nTry 'fcage {flag}'."),
        None => format!("unrecognized option {given}"),
    }
}

/// The flag an argument names: everything before a `=`, so the joined and
/// separated spellings of one option compare alike.
fn flag_name(arg: &str) -> &str {
    arg.split_once('=').map_or(arg, |(name, _)| name)
}

/// The mode flag that owns `flag`, when `flag` belongs to a mode of its own
/// rather than to a launch.
///
/// A flag of another mode is not a misspelling, so the suggester never offers
/// one; naming the flag that selects the owning mode is the useful answer.
fn owning_mode_flag(flag: &str) -> Option<&'static str> {
    let entry = FLAGS.iter().find(|entry| entry.long == flag)?;
    // A flag that *selects* its mode is not an option of another mode: it is
    // the mode, and typing it is how a caller asks for one. Only a flag that
    // belongs to a mode without selecting it -- `--export-to`, `--keep-lock`
    // -- is the case this answers.
    if entry.mode == Mode::Launch || entry.selects {
        return None;
    }
    FLAGS
        .iter()
        .find(|other| other.selects && other.mode == entry.mode)
        .map(|other| other.long)
}

/// The usage error for an argument a mode's parser does not accept.
///
/// A mode takes only its own options, so an unexpected one is usually a launch
/// flag given to the wrong invocation — reported as the conflict it is. A near
/// miss of one of the mode's own flags is a misspelling instead, and is answered
/// like any other: the launch parser's suggestion machinery, over this mode's
/// vocabulary.
fn mode_conflict(arg: &OsStr, mode: &str, vocabulary: &[&'static str]) -> String {
    let given = arg.to_string_lossy();
    match nearest_flag(flag_name(&given), vocabulary) {
        Some(flag) => format!("unrecognized option {given}\nTry 'fcage {flag}'."),
        None => format!("{given} cannot be used with {mode}"),
    }
}

/// The documented flag nearest `given`, or `None` when none is near enough to
/// be worth offering.
///
/// A candidate qualifies on a small edit distance or on a prefix relationship.
/// The prefix rule carries the cases the distance bound misses on a long name:
/// a flag typed short, and one typed with something appended. Ties break on the
/// flag's own spelling, so the suggestion for a given input never depends on
/// the order the help happens to list its options in.
fn nearest_flag<'a>(given: &str, flags: &[&'a str]) -> Option<&'a str> {
    /// Two edits is a transposition, a doubled letter, or a wrong one — the
    /// typos worth guessing at. Beyond it a suggestion is noise.
    const FURTHEST: usize = 2;

    // A run of dashes with nothing after it is every flag's prefix and names
    // none of them. The prefix rule below is about a flag typed short, and this
    // is not one typed at all: without this a mode parser meeting a bare `--`
    // answers it with whichever flag happens to sort first.
    if given.trim_start_matches('-').is_empty() {
        return None;
    }

    flags
        .iter()
        .filter_map(|flag| {
            let distance = edit_distance(given, flag);
            // An abbreviation of a flag outranks any small distance: `--net`
            // names `--netstack`, and answering it with the two-edit `--dev`
            // is worse than useless. A flag typed with something appended is
            // the weaker signal — `--seccomp-alow` extends `--seccomp` and
            // misspells `--seccomp-allow` — so it merely qualifies a
            // candidate, leaving the distance to choose.
            let abbreviates = flag.starts_with(given);
            let extends = given.starts_with(flag);
            (abbreviates || extends || distance <= FURTHEST).then_some((
                usize::from(!abbreviates),
                distance,
                *flag,
            ))
        })
        .min()
        .map(|(_, _, flag)| flag)
}

/// The Levenshtein distance between two strings: the fewest single-character
/// insertions, deletions, and substitutions that turn one into the other.
///
/// Two rows rather than the full matrix, since only the previous one is ever
/// read. Both inputs are short — a flag and something someone typed instead of
/// one — so this runs once, against a couple of hundred candidates, on a path
/// that is about to exit.
fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    // Row zero: turning an empty prefix of `left` into each prefix of `right`
    // costs one insertion per character.
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (row, from) in left.chars().enumerate() {
        current[0] = row + 1;
        for (column, to) in right.iter().enumerate() {
            let substitute = previous[column] + usize::from(from != *to);
            let delete = previous[column + 1] + 1;
            let insert = current[column] + 1;
            current[column + 1] = substitute.min(delete).min(insert);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

/// Renders `items` as a comma-separated list, wrapped to the option-help
/// column and indented to it.
fn wrapped(items: &[&str]) -> String {
    /// The column option descriptions start in, and the width they wrap at.
    const INDENT: usize = 24;
    const WIDTH: usize = 78;

    let mut lines = vec![String::new()];
    for (position, item) in items.iter().enumerate() {
        let separator = if position + 1 == items.len() { "" } else { "," };
        let line = lines.last_mut().expect("the first line is always present");
        if !line.is_empty() && INDENT + line.len() + 1 + item.len() + separator.len() > WIDTH {
            lines.push(String::new());
        }
        let line = lines.last_mut().expect("a line was just ensured");
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(item);
        line.push_str(separator);
    }
    lines
        .iter()
        .map(|line| format!("{:INDENT$}{line}", ""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The mode an invocation selects, and where the command begins.
///
/// A mode flag chooses the invocation, so it has to be found before the launch
/// vocabulary is parsed. What "before" means is the whole of this function: an
/// argument past the command belongs to the command, so a tool with an
/// `--export-rootfs` flag of its own must still be runnable inside a sandbox.
///
/// The command begins at `--`, or at the first argument that is neither an
/// option nor the value of one. Deciding the second half is why every flag is
/// in [`FLAGS`] whether a launch takes it or not: without each flag's arity
/// this walk would read `--export-to /tmp/out` as the command `/tmp/out` and
/// stop, or read a launch's command as a flag and go on.
fn selected_mode(args: &[OsString]) -> Option<Mode> {
    let mut selected = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--" {
            break;
        }
        let Some(flag) = named(arg) else {
            if arg.as_bytes().starts_with(b"-") && arg != "-" {
                // An option this does not know: not a mode, and the launch
                // parser is where it is reported.
                continue;
            }
            // The command.
            break;
        };
        if flag.selects && selected.is_none() {
            selected = Some(flag.mode);
        }
        // A separated value is the flag's, not the command.
        if flag.arity() != Arity::Bare && !joined(arg) {
            let count = if flag.arity() == Arity::Two { 2 } else { 1 };
            for _ in 0..count {
                if rest.next().is_none() {
                    break;
                }
            }
        }
    }
    selected
}

/// Whether `arg` is a flag written with its value joined on.
fn joined(arg: &OsStr) -> bool {
    arg.as_bytes().contains(&b'=')
}

/// The flag `arg` names, whether it is written joined or separated.
///
/// A joined value is only split off for a flag that takes one value: `--bind=A`
/// would leave the pair's second half on the wrong side of the `=`, and
/// `--no-proc=1` names a flag that takes nothing. Both stay unrecognized, which
/// is what they were.
fn named(arg: &OsStr) -> Option<&'static Flag> {
    let text = arg.to_str()?;
    if let Some(flag) = FLAGS.iter().find(|flag| flag.long == text) {
        return Some(flag);
    }
    let (name, _) = text.split_once('=')?;
    FLAGS
        .iter()
        .find(|flag| flag.long == name && flag.arity() == Arity::One)
}

/// Applies one flag to the options a launch is being built from.
///
/// `joined` is the value written after an `=`, where it was; the lookup only
/// splits one off for a flag that takes exactly one value.
fn apply_flag(
    flag: &Flag,
    options: &mut Options,
    joined: Option<OsString>,
    args: &mut dyn Iterator<Item = OsString>,
) -> Result<(), String> {
    match flag.take {
        Take::Bare(set) => {
            set(options);
            Ok(())
        }
        Take::One(set) => {
            let value = match joined {
                Some(value) => value,
                None => value_for(flag.long, flag.needs, Arity::One, args)?,
            };
            set(options, flag.long, value)
        }
        Take::Two(set) => {
            let first = value_for(flag.long, flag.needs, Arity::Two, args)?;
            let second = value_for(flag.long, flag.needs, Arity::Two, args)?;
            set(options, flag.long, first, second)
        }
        // A flag of another mode, written before the command of a launch. The
        // pre-scan routed nothing here, so it is one that belongs to a mode
        // without selecting it -- and the message names the mode rather than
        // suggesting the spelling that was just refused.
        Take::Refused(_) => Err(unrecognized_option(OsStr::new(flag.long))),
    }
}

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            output::print_stdout("the help", |out| out.write_all(usage().as_bytes()))
        }
        Ok(Invocation::Version) => output::print_stdout("the version", |out| {
            // Both numbers, because they move independently: one `fcage`
            // release can be built against several library releases, and the
            // library is where a containment defect would be.
            writeln!(
                out,
                "fcage {} (ferroday-cage {})",
                env!("CARGO_PKG_VERSION"),
                ferroday_cage::VERSION,
            )
        }),
        Ok(Invocation::Run(options)) => run(*options),
        Ok(Invocation::Remove { dest, map, removal }) => remove_tree(&dest, map, removal),
        Ok(Invocation::GentooVariants {
            architecture,
            mirror,
            fallbacks,
            max_pointer_age,
        }) => gentoo_variants(
            &architecture,
            mirror.as_deref(),
            &fallbacks,
            max_pointer_age,
        ),
        Ok(Invocation::GentooPackages {
            architecture,
            binhost,
            mirror,
            fallbacks,
        }) => gentoo_packages(
            &architecture,
            binhost.as_deref(),
            mirror.as_deref(),
            &fallbacks,
        ),
        Ok(Invocation::GentooInstalled { root }) => gentoo_installed(&root),
        Ok(Invocation::GentooKeyring) => gentoo_keyring_horizon(),
        Ok(Invocation::Export {
            source,
            dest,
            map,
            clamp_mtime,
        }) => export_rootfs(&source, dest.as_deref(), map, clamp_mtime),
        Err(message) => usage_error(format_args!("{message}")),
    }
}

/// Parses the command line, excluding the program name.
fn parse(args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let args: Vec<OsString> = args.collect();
    // A mode is a program of its own behind the same name, so it is recognized
    // before the launch vocabulary is parsed and its parser accepts only its
    // own flags. Splitting it this way is what keeps the two in step: a flag
    // added to a launch is refused alongside --remove-rootfs by the same `else`
    // that refuses every other one, rather than being silently accepted and
    // then ignored by a removal that never reads it.
    match selected_mode(&args) {
        Some(Mode::GentooVariants) => return parse_gentoo_variants(args),
        Some(Mode::GentooPackages) => return parse_gentoo_packages(args),
        Some(Mode::GentooInstalled) => return parse_gentoo_installed(args),
        Some(Mode::GentooKeyring) => return parse_gentoo_keyring(args),
        Some(Mode::Remove) => return parse_removal(args),
        Some(Mode::Export) => return parse_export(args),
        _ => {}
    }
    let mut args = args.into_iter();
    // The flags the loop below applied, in order, for the no-effect check at
    // the end. A value is the flag's, whatever it looks like, so only what the
    // loop took as a flag is a flag here.
    let mut applied: Vec<&'static str> = Vec::new();

    let mut options = Options {
        profile: None,
        profile_restricted: false,
        rootfs: None,
        empty_rootfs: false,
        provision_tar: None,
        provision_debian: None,
        debian_arch: None,
        debian_mirror: None,
        debian_components: Vec::new(),
        debian_include: Vec::new(),
        debian_exclude: Vec::new(),
        debian_plan: None,
        debian_pin: None,
        debian_extract_only: false,
        debian_cache: None,
        debian_keyring: None,
        debian_mirror_fallback: Vec::new(),
        debian_base_priority: None,
        debian_trust_unsigned: false,
        debian_allow_stale_release: false,
        debian_pre_configure_overlay: None,
        debian_source_date_epoch: None,
        debian_identity_map: None,
        debian_repositories: Vec::new(),
        provision_alpine: None,
        alpine_arch: None,
        alpine_mirror: None,
        alpine_components: Vec::new(),
        alpine_include: Vec::new(),
        alpine_exclude: Vec::new(),
        alpine_plan: None,
        alpine_pin: None,
        alpine_extract_only: false,
        alpine_cache: None,
        alpine_keys: None,
        alpine_mirror_fallback: Vec::new(),
        provision_gentoo: None,
        gentoo_variant: None,
        gentoo_binhost: None,
        gentoo_install: Vec::new(),
        gentoo_prefer_use: Vec::new(),
        gentoo_plan: None,
        gentoo_build_id: None,
        gentoo_mirror: None,
        gentoo_mirror_fallback: Vec::new(),
        gentoo_cache: None,
        gentoo_max_pointer_age: None,
        alpine_pre_configure_overlay: None,
        alpine_identity_map: None,
        alpine_source_date_epoch: None,
        alpine_repositories: Vec::new(),
        command_line: Vec::new(),
        path_lookup: None,
        mounts: Vec::new(),
        overlay_lowers: Vec::new(),
        overlay_upper: None,
        overlay_work: None,
        identity_map: None,
        run_as: None,
        present_as: None,
        rlimits: Vec::new(),
        setenv: Vec::new(),
        hostname: None,
        chdir: None,
        stdin: None,
        terminal: false,
        timeout: None,
        kill_after: Duration::from_secs(10),
        kill_after_given: false,
        network: None,
        pid_namespace: None,
        mount_proc: None,
        mount_dev: None,
        mount_tmp: None,
        resolv_conf: None,
        managed_mounts: None,
        base_env: None,
        // `None` like every other toggle, so a profile's setting survives. The
        // default is applied where the profile is known rather than here: see
        // `stop_with_caller_default`.
        stop_with_caller: None,
        landlock: Vec::new(),
        landlock_net: Vec::new(),
        landlock_scope: None,
        seccomp: None,
        seccomp_curated: false,
        seccomp_allow: Vec::new(),
        seccomp_deny: Vec::new(),
        seccomp_allow_rules: Vec::new(),
        seccomp_deny_rules: Vec::new(),
        seccomp_errno: Vec::new(),
        caps: None,
        restrict: false,
        netstack: false,
        netstack_cidr: None,
        netstack_cidr6: None,
        netstack_no_ipv4: false,
        netstack_no_ipv6: false,
        netstack_interface: None,
        netstack_mtu: None,
        netstack_host_loopback: false,
        netstack_host_ports: Vec::new(),
        netstack_publish: Vec::new(),
    };

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        }
        if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        }
        if arg == "--" {
            options.command_line.extend(args);
            break;
        }
        if let Some(flag) = named(&arg) {
            // The joined form's value, where the argument carries one. The
            // lookup only matches a joined argument against a flag that takes
            // exactly one value, so this is `Some` for those and nothing else.
            let joined = flag_value(&arg, format!("{}=", flag.long).as_bytes());
            apply_flag(flag, &mut options, joined, &mut args)?;
            applied.push(flag.long);
            continue;
        }
        if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(unrecognized_option(&arg));
        }
        // The first positional argument is the command; everything after it
        // belongs to the command, dashes included.
        options.command_line.push(arg);
        options.command_line.extend(args);
        break;
    }

    // Reconciled after the loop: the curated posture and the allow and deny
    // sides are mutually constrained, and the flag that decides can come last.
    options.seccomp = assemble_seccomp(
        options.seccomp_curated,
        std::mem::take(&mut options.seccomp_allow),
        std::mem::take(&mut options.seccomp_deny),
        std::mem::take(&mut options.seccomp_allow_rules),
        std::mem::take(&mut options.seccomp_deny_rules),
    )?;
    // The curated posture is a whole policy and takes no errno. A profile's own
    // posture is checked when the profile is loaded; this one is the command
    // line's, so it is the usage error it looks like now.
    if matches!(options.seccomp, Some(SeccompPolicy::Curated)) && !options.seccomp_errno.is_empty()
    {
        return Err("--seccomp curated cannot be combined with --seccomp-errno".to_string());
    }

    // --kill-after is the grace period before the SIGKILL that follows a
    // --timeout; without a timeout it has nothing to hang on and would be
    // silently ignored.
    if options.kill_after_given && options.timeout.is_none() {
        return Err("--kill-after requires --timeout".to_string());
    }

    // A terminal is all three of the command's standard streams, so a stated
    // disposition for any of them means two different things were asked for.
    // The library refuses the same combination at the launch; naming it here
    // makes it the usage error it is, and names both flags.
    if options.terminal && matches!(options.stdin, Some(Stdio::Null)) {
        return Err("--terminal cannot be used with --stdin null".to_string());
    }

    if options.restrict {
        // A restriction knows nothing of a rootfs or namespaces; every flag
        // that configures one is a contradiction, named explicitly.
        let conflicts = [
            (options.rootfs.is_some(), "--rootfs"),
            (options.empty_rootfs, "--empty-rootfs"),
            (
                options.profile.is_some(),
                "--profile or --restricted-profile",
            ),
            (options.provision_tar.is_some(), "--provision-tar"),
            (options.provision_debian.is_some(), "--provision-debian"),
            (has_debian_modifiers(&options), "the --debian-* options"),
            (options.provision_alpine.is_some(), "--provision-alpine"),
            (has_alpine_modifiers(&options), "the --alpine-* options"),
            (options.provision_gentoo.is_some(), "--provision-gentoo"),
            (has_gentoo_modifiers(&options), "the --gentoo-* options"),
            (
                options
                    .mounts
                    .iter()
                    .any(|mount| matches!(mount, Mount::Bind(_))),
                "--bind and --ro-bind",
            ),
            (options.hostname.is_some(), "--hostname"),
            (options.network.is_some(), "the network options"),
            (options.pid_namespace.is_some(), "the PID-namespace options"),
            (
                options.mount_proc.is_some()
                    || options.mount_dev.is_some()
                    || options.mount_tmp.is_some()
                    || options.managed_mounts.is_some(),
                "the mount toggles",
            ),
            (options.resolv_conf.is_some(), "the resolv.conf options"),
            (options.caps.is_some(), "the capability options"),
            (
                options
                    .mounts
                    .iter()
                    .any(|mount| matches!(mount, Mount::Raw(_))),
                "--raw-mount",
            ),
            (
                options
                    .mounts
                    .iter()
                    .any(|mount| matches!(mount, Mount::Symlink(_))),
                "--symlink",
            ),
            (
                !options.overlay_lowers.is_empty()
                    || options.overlay_upper.is_some()
                    || options.overlay_work.is_some(),
                "the --overlay-* options",
            ),
            (options.identity_map.is_some(), "--identity-map"),
            (options.run_as.is_some(), "--run-as"),
            (options.present_as.is_some(), "--present-as"),
            (options.path_lookup.is_some(), "the path-lookup options"),
            (options.netstack, "--netstack"),
            (has_netstack_modifiers(&options), "the --netstack-* options"),
        ];
        for (given, name) in conflicts {
            if given {
                return Err(format!("{name} cannot be used with --restrict"));
            }
        }
        if options.command_line.is_empty() {
            return Err("no command given".to_string());
        }
        // A restriction with nothing to enforce would run a plain host process
        // while appearing to sandbox it. The library rejects that too, but as a
        // launch error; catching it here makes it the usage error it is.
        if options.landlock.is_empty()
            && options.landlock_net.is_empty()
            && options.seccomp.is_none()
            && options.seccomp_errno.is_empty()
        {
            return Err(
                "--restrict requires at least one grant: a --landlock-ro, --landlock-rw, \
                 --landlock-bind or --landlock-connect rule, or a seccomp filter; \
                 --landlock-scope alone leaves the filesystem and the network open"
                    .to_string(),
            );
        }
        return Ok(Invocation::Run(Box::new(options)));
    }

    // The native stack configures the isolated network; sharing the host
    // network is the opposite request, and the stack's sub-flags mean
    // nothing without it.
    if options.netstack && options.network == Some(Network::Host) {
        return Err("--netstack cannot be used with --share-net".to_string());
    }
    if !options.netstack && has_netstack_modifiers(&options) {
        return Err("the --netstack-* options require --netstack".to_string());
    }

    // A plain rootfs, an overlay root, and an empty root are alternatives; the
    // last builder call would silently win, so name the contradiction here
    // instead.
    let overlay_given = !options.overlay_lowers.is_empty()
        || options.overlay_upper.is_some()
        || options.overlay_work.is_some();
    if overlay_given {
        if options.overlay_lowers.is_empty() {
            return Err("the --overlay-* options require at least one --overlay-lower".to_string());
        }
        if options.overlay_upper.is_none() {
            return Err("the --overlay-* options require --overlay-upper".to_string());
        }
        if options.rootfs.is_some() {
            return Err("--rootfs and the --overlay-* options are alternatives".to_string());
        }
    }
    if options.empty_rootfs {
        if options.rootfs.is_some() {
            return Err("--rootfs and --empty-rootfs are alternatives".to_string());
        }
        if overlay_given {
            return Err("--empty-rootfs and the --overlay-* options are alternatives".to_string());
        }
    }
    if options.rootfs.is_none()
        && options.profile.is_none()
        && !overlay_given
        && !options.empty_rootfs
    {
        return Err(
            "--rootfs, --empty-rootfs, --overlay-lower, --profile, --restricted-profile, \
                    or --restrict is required"
                .to_string(),
        );
    }
    // One rootfs is provisioned one way, and by something that was told where
    // to put it. Both refusals name the flag rather than reporting "a
    // provisioner", so the two are enumerated once here.
    let provisioners: Vec<&str> = [
        (options.provision_tar.is_some(), "--provision-tar"),
        (options.provision_debian.is_some(), "--provision-debian"),
        (options.provision_alpine.is_some(), "--provision-alpine"),
        (options.provision_gentoo.is_some(), "--provision-gentoo"),
    ]
    .into_iter()
    .filter_map(|(given, flag)| given.then_some(flag))
    .collect();
    if let [first, second, ..] = provisioners[..] {
        return Err(format!("{first} and {second} are mutually exclusive"));
    }
    if let [only] = provisioners[..]
        && options.rootfs.is_none()
    {
        return Err(format!("{only} requires --rootfs to name the destination"));
    }
    if options.provision_debian.is_none() && has_debian_modifiers(&options) {
        return Err("the --debian-* options require --provision-debian".to_string());
    }
    if options.provision_alpine.is_none() && has_alpine_modifiers(&options) {
        return Err("the --alpine-* options require --provision-alpine".to_string());
    }
    if options.provision_gentoo.is_none() && has_gentoo_modifiers(&options) {
        return Err("the --gentoo-* options require --provision-gentoo".to_string());
    }
    // A plan is a resolution that already happened, so a flag that shapes a
    // resolution has nothing to shape beside one. Every layer refuses such a
    // pair when it is built. Refused here as well, each is the usage error it
    // is, named by its flag rather than by the builder method it reaches.
    plan_alone(
        "--debian-plan",
        options.debian_plan.is_some(),
        &[
            (!options.debian_include.is_empty(), "--debian-include"),
            (!options.debian_exclude.is_empty(), "--debian-exclude"),
            (
                options.debian_base_priority.is_some(),
                "--debian-base-priority",
            ),
            (options.debian_pin.is_some(), "--debian-pin"),
        ],
    )?;
    plan_alone(
        "--alpine-plan",
        options.alpine_plan.is_some(),
        &[
            (!options.alpine_include.is_empty(), "--alpine-include"),
            (!options.alpine_exclude.is_empty(), "--alpine-exclude"),
            (options.alpine_pin.is_some(), "--alpine-pin"),
        ],
    )?;
    plan_alone(
        "--gentoo-plan",
        options.gentoo_plan.is_some(),
        &[
            (!options.gentoo_install.is_empty(), "--gentoo-install"),
            (!options.gentoo_prefer_use.is_empty(), "--gentoo-prefer-use"),
        ],
    )?;
    // A variant is what a bootstrap installs, and the archive publishes dozens
    // per architecture with no default among them. Refusing here rather than
    // letting the library refuse after two fetches is what makes the message
    // "name one" instead of "the resolution failed".
    if options.provision_gentoo.is_some()
        && options.gentoo_variant.is_none()
        && options.rootfs.is_some()
    {
        return Err(
            "--provision-gentoo requires --gentoo-variant; --gentoo-variants lists what an \
             architecture offers"
                .to_string(),
        );
    }
    // A provisioning run without a command provisions and exits; otherwise a
    // command (or a profile that names one) is required.
    let provisioning = options.provision_tar.is_some()
        || options.provision_debian.is_some()
        || options.provision_alpine.is_some()
        || options.provision_gentoo.is_some();
    if options.command_line.is_empty() && options.profile.is_none() && !provisioning {
        return Err("no command given".to_string());
    }
    // Nothing is launched, so a flag that configures a launch has nothing to
    // configure. Every other no-effect combination is refused above, and
    // silently dropping this one leaves a caller believing a sandbox was shaped
    // the way the command line said.
    if options.command_line.is_empty()
        && options.profile.is_none()
        && let Some(flag) = applied.into_iter().find(|flag| !provisions(flag))
    {
        return Err(format!(
            "{flag} configures a launch, and a provisioning run without a command does not \
             launch one",
        ));
    }
    Ok(Invocation::Run(Box::new(options)))
}

/// Refuses `plan`, where it was given, beside any flag in `shaping` that was
/// given too: each shapes a resolution, which a plan replaces.
fn plan_alone(plan: &str, given: bool, shaping: &[(bool, &str)]) -> Result<(), String> {
    match shaping.iter().find(|(set, _)| given && *set) {
        Some((_, flag)) => Err(format!(
            "{plan} installs what a resolution already chose, so {flag}, which shapes a \
             resolution, has nothing to shape; give one of the two"
        )),
        None => Ok(()),
    }
}

/// Whether `flag` configures the provisioning rather than the launch.
///
/// The provisioning vocabulary is short enough to name; everything else shapes a
/// sandbox, which a provision-and-exit run never builds.
fn provisions(flag: &str) -> bool {
    matches!(
        flag,
        "--rootfs"
            | "--provision-tar"
            | "--provision-debian"
            | "--provision-alpine"
            | "--provision-gentoo"
    ) || flag.starts_with("--debian-")
        || flag.starts_with("--alpine-")
        || flag.starts_with("--gentoo-")
}

/// Records the profile to load, refusing a mix of the two trust models.
///
/// Repeating one flag takes the last value, as repeating any other value option
/// does. Naming both is refused instead: the two load a file under different
/// trust, and there is no sensible way to choose between them.
fn set_profile(options: &mut Options, path: PathBuf, restricted: bool) -> Result<(), String> {
    if options.profile.is_some() && options.profile_restricted != restricted {
        return Err("--profile and --restricted-profile are alternatives".to_string());
    }
    options.profile = Some(path);
    options.profile_restricted = restricted;
    Ok(())
}

/// The help or version request `args` carries, wherever it appears.
///
/// A mode takes no positional argument, so nothing in one can legitimately be
/// the word `--help`. Answering it up front is what stops the destination arm
/// from consuming it: `fcage --remove-rootfs --help` would otherwise take it as
/// the tree to delete.
fn help_or_version(args: &[OsString]) -> Option<Invocation> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Some(Invocation::Help);
    }
    if args.iter().any(|arg| arg == "-V" || arg == "--version") {
        return Some(Invocation::Version);
    }
    None
}

/// What a removal deletes, besides the tree it is named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removal {
    /// A published rootfs, with its `<dest>.lock` sibling unless `--keep-lock`
    /// declines it.
    Rootfs { remove_lock: bool },
    /// An overlay upper, with the work directory the library keeps beside it.
    OverlayUpper,
}

/// The flags that select a removal, each with what it removes. Exactly one
/// names the tree.
const REMOVALS: [(&str, Removal); 2] = [
    ("--remove-rootfs", Removal::Rootfs { remove_lock: true }),
    ("--remove-overlay-upper", Removal::OverlayUpper),
];

/// The removal flag `arg` is, in either form, with the value it carries when
/// it is written joined.
fn removal_flag(arg: &OsStr) -> Option<(&'static str, Removal, Option<OsString>)> {
    REMOVALS.into_iter().find_map(|(flag, removal)| {
        if arg == flag {
            return Some((flag, removal, None));
        }
        let joined = flag_value(arg, format!("{flag}=").as_bytes())?;
        Some((flag, removal, Some(joined)))
    })
}

/// Parses a `--remove-rootfs` or `--remove-overlay-upper` command line,
/// excluding the program name.
///
/// A removal takes the tree, the identity map it was written under, and for a
/// rootfs whether the lock sibling goes with it. Every other flag configures a
/// launch that does not happen here, so naming one is a usage error rather than
/// a setting with no effect. So is `--keep-lock` beside an overlay upper, whose
/// removal never takes a lock.
fn parse_removal(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    // Named in a refusal: the flag that selected the mode, wherever it sits.
    let mode = args
        .iter()
        .find_map(|arg| removal_flag(arg))
        .map_or("--remove-rootfs", |(flag, _, _)| flag);
    let mut target: Option<(&'static str, Removal, PathBuf)> = None;
    // The same default the library's own removal carries: a tree written by a
    // bundled-delegate sandbox is the case that needs the escalation at all.
    let mut map = IdentityMap::Subordinate;
    // The library's default is to take the lock. Provisioning wrote
    // `<dest>.lock`, so for the published rootfs `--remove-rootfs` is named on,
    // the two round-trip together; `--keep-lock` is for the `dest` that merely
    // holds such trees.
    let mut keep_lock = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if let Some((flag, removal, joined)) = removal_flag(&arg) {
            let dest = match joined {
                Some(value) => value,
                None => value_for(flag, "a value", Arity::One, &mut args)?,
            };
            if let Some((named, _, _)) = target
                && named != flag
            {
                return Err(format!("{named} and {flag} are alternatives"));
            }
            target = Some((flag, removal, removal_target(flag, dest)?));
        } else if arg == "--identity-map" {
            map = parse_identity_map(
                "--identity-map",
                &string_value("--identity-map", &mut args)?,
            )?;
        } else if let Some(value) = flag_value(&arg, b"--identity-map=") {
            map = parse_identity_map("--identity-map", &into_string("--identity-map", value)?)?;
        } else if arg == "--keep-lock" {
            keep_lock = true;
        } else {
            return Err(mode_conflict(
                &arg,
                mode,
                &[
                    "--remove-rootfs",
                    "--remove-overlay-upper",
                    "--identity-map",
                    "--keep-lock",
                ],
            ));
        }
    }

    // The caller established that a removal flag is present, so this is a
    // guard rather than a live path: the only value-taking flag here would
    // reject a removal flag as a map spelling before reaching it. It stays a
    // usage error rather than an `expect` because what upholds it is the shape
    // of the argument vector, not an invariant of this module.
    let (flag, removal, dest) = target.ok_or_else(|| format!("{mode} requires a value"))?;
    let removal = match removal {
        Removal::Rootfs { .. } => Removal::Rootfs {
            remove_lock: !keep_lock,
        },
        Removal::OverlayUpper if keep_lock => {
            return Err(format!(
                "--keep-lock cannot be used with {flag}, which leaves any lock beside the upper \
                 in place"
            ));
        }
        Removal::OverlayUpper => Removal::OverlayUpper,
    };
    Ok(Invocation::Remove { dest, map, removal })
}

/// The tree a mode flag names, refusing an empty value.
///
/// An empty value is almost always a variable that was never set, as in
/// `--remove-rootfs "$ROOT"`, and names no tree the caller meant. It is a usage
/// error here, reported before the mode runs, for a removal and a listing
/// alike.
fn tree_value(flag: &str, value: OsString) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err(format!(
            "{flag} requires a directory, and was given an empty value, which is what an \
             unset variable expands to"
        ));
    }
    Ok(PathBuf::from(value))
}

/// The tree a removal flag names, refusing a value that names none.
///
/// Beyond [`tree_value`]'s refusal, a path with no final component, such as
/// `.`, `..` or `/`, names no tree of its own to remove from its parent, and no
/// lock file beside one. The library's removal refuses both shapes too, as
/// [`ProvisionError::RemoveDestInvalid`]; checking them here makes them usage
/// errors, reported before anything runs, as every other malformed flag value
/// is.
fn removal_target(flag: &str, value: OsString) -> Result<PathBuf, String> {
    let dest = tree_value(flag, value)?;
    if dest.file_name().is_none() {
        return Err(format!(
            "{flag}: {} names no directory of its own; name the tree itself, as in \
             /srv/roots/trixie",
            dest.display(),
        ));
    }
    Ok(dest)
}

/// Parses a `--gentoo-variants` command line, excluding the program name.
///
/// A listing reads the signed enumeration and prints it, so it takes the
/// architecture, where to read it from, and how old it may be. As with a removal
/// and an export, every other flag configures a launch that does not happen
/// here, and parsing the mode separately is what keeps that true of a flag added
/// to a launch later.
fn parse_gentoo_variants(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    let mut architecture: Option<String> = None;
    // The primary and its backstops are separate settings here exactly as they
    // are on a provisioning command line: repeating the primary takes the last
    // value, and a backstop given alone backs the default archive rather than
    // replacing it.
    let mut mirror: Option<String> = None;
    let mut fallbacks: Vec<String> = Vec::new();
    let mut max_pointer_age: Option<Option<u64>> = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--gentoo-variants" {
            architecture = Some(string_value("--gentoo-variants", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-variants=") {
            architecture = Some(into_string("--gentoo-variants", value)?);
        } else if arg == "--gentoo-mirror" {
            let url = string_value("--gentoo-mirror", &mut args)?;
            mirror = Some(fetchable_mirror("--gentoo-mirror", url)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-mirror=") {
            let url = into_string("--gentoo-mirror", value)?;
            mirror = Some(fetchable_mirror("--gentoo-mirror", url)?);
        } else if arg == "--gentoo-mirror-fallback" {
            let url = string_value("--gentoo-mirror-fallback", &mut args)?;
            fallbacks.push(fetchable_mirror("--gentoo-mirror-fallback", url)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-mirror-fallback=") {
            let url = into_string("--gentoo-mirror-fallback", value)?;
            fallbacks.push(fetchable_mirror("--gentoo-mirror-fallback", url)?);
        } else if arg == "--gentoo-max-pointer-age" {
            max_pointer_age = Some(parse_pointer_age(&string_value(
                "--gentoo-max-pointer-age",
                &mut args,
            )?)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-max-pointer-age=") {
            max_pointer_age = Some(parse_pointer_age(&into_string(
                "--gentoo-max-pointer-age",
                value,
            )?)?);
        } else {
            return Err(mode_conflict(
                &arg,
                "--gentoo-variants",
                &[
                    "--gentoo-variants",
                    "--gentoo-mirror",
                    "--gentoo-mirror-fallback",
                    "--gentoo-max-pointer-age",
                ],
            ));
        }
    }

    // As for a removal, the caller established that the flag is present, so
    // this is a guard rather than a live path.
    let architecture =
        architecture.ok_or_else(|| "--gentoo-variants requires a value".to_string())?;
    Ok(Invocation::GentooVariants {
        architecture,
        mirror,
        fallbacks,
        max_pointer_age,
    })
}

/// Parses a `--gentoo-keyring-horizon` command line, excluding the program name.
///
/// It reads the keyring the crate vendors and nothing else, so it takes no
/// settings at all: there is no mirror to name and no network to reach.
fn parse_gentoo_keyring(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    for arg in args {
        if arg != "--gentoo-keyring-horizon" {
            return Err(mode_conflict(
                &arg,
                "--gentoo-keyring-horizon",
                &["--gentoo-keyring-horizon"],
            ));
        }
    }
    Ok(Invocation::GentooKeyring)
}

/// Parses a `--gentoo-packages` command line, excluding the program name.
///
/// A listing reads the binhost index and prints it, so it takes the
/// architecture, the sub-architecture tree, and where to read them from. As
/// with the other listing modes, every other flag configures a launch that does
/// not happen here.
fn parse_gentoo_packages(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    let mut architecture: Option<String> = None;
    let mut binhost: Option<String> = None;
    let mut mirror: Option<String> = None;
    let mut fallbacks: Vec<String> = Vec::new();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--gentoo-packages" {
            architecture = Some(string_value("--gentoo-packages", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-packages=") {
            architecture = Some(into_string("--gentoo-packages", value)?);
        } else if arg == "--gentoo-binhost" {
            binhost = Some(string_value("--gentoo-binhost", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-binhost=") {
            binhost = Some(into_string("--gentoo-binhost", value)?);
        } else if arg == "--gentoo-mirror" {
            let url = string_value("--gentoo-mirror", &mut args)?;
            mirror = Some(fetchable_mirror("--gentoo-mirror", url)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-mirror=") {
            let url = into_string("--gentoo-mirror", value)?;
            mirror = Some(fetchable_mirror("--gentoo-mirror", url)?);
        } else if arg == "--gentoo-mirror-fallback" {
            let url = string_value("--gentoo-mirror-fallback", &mut args)?;
            fallbacks.push(fetchable_mirror("--gentoo-mirror-fallback", url)?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-mirror-fallback=") {
            let url = into_string("--gentoo-mirror-fallback", value)?;
            fallbacks.push(fetchable_mirror("--gentoo-mirror-fallback", url)?);
        } else {
            return Err(mode_conflict(
                &arg,
                "--gentoo-packages",
                &[
                    "--gentoo-packages",
                    "--gentoo-binhost",
                    "--gentoo-mirror",
                    "--gentoo-mirror-fallback",
                ],
            ));
        }
    }
    match architecture {
        Some(architecture) => Ok(Invocation::GentooPackages {
            architecture,
            binhost,
            mirror,
            fallbacks,
        }),
        None => Err("--gentoo-packages requires a value".to_string()),
    }
}

/// Parses a `--gentoo-installed` command line, excluding the program name.
///
/// It reads a root's own package database and reaches nothing else, so it takes
/// a path and no other flag.
fn parse_gentoo_installed(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    let mut root: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--gentoo-installed" {
            root = Some(tree_value(
                "--gentoo-installed",
                value_for("--gentoo-installed", "a value", Arity::One, &mut args)?,
            )?);
        } else if let Some(value) = flag_value(&arg, b"--gentoo-installed=") {
            root = Some(tree_value("--gentoo-installed", value)?);
        } else {
            return Err(mode_conflict(
                &arg,
                "--gentoo-installed",
                &["--gentoo-installed"],
            ));
        }
    }
    match root {
        Some(root) => Ok(Invocation::GentooInstalled { root }),
        None => Err("--gentoo-installed requires a value".to_string()),
    }
}

/// Parses an `--export-rootfs` command line, excluding the program name.
///
/// An export takes the tree to read, where to write it, the identity map the
/// tree was written under, and the modification-time ceiling. As with a
/// removal, every other flag configures a launch that does not happen here, so
/// naming one is a usage error rather than a setting with no effect — and
/// parsing the mode separately is what keeps that true of a flag added to a
/// launch later, since the vocabulary is closed by exhaustion rather than by a
/// list kept in step by hand.
fn parse_export(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    let mut source: Option<PathBuf> = None;
    let mut dest: Option<PathBuf> = None;
    // The map a bundled-delegate sandbox writes under, as removal defaults to.
    let mut map = IdentityMap::Subordinate;
    let mut clamp_mtime: Option<i64> = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--export-rootfs" {
            source = Some(PathBuf::from(value_for(
                "--export-rootfs",
                "a value",
                Arity::One,
                &mut args,
            )?));
        } else if let Some(value) = flag_value(&arg, b"--export-rootfs=") {
            source = Some(PathBuf::from(value));
        } else if arg == "--export-to" {
            dest = Some(PathBuf::from(value_for(
                "--export-to",
                "a value",
                Arity::One,
                &mut args,
            )?));
        } else if let Some(value) = flag_value(&arg, b"--export-to=") {
            dest = Some(PathBuf::from(value));
        } else if arg == "--identity-map" {
            map = parse_identity_map(
                "--identity-map",
                &string_value("--identity-map", &mut args)?,
            )?;
        } else if let Some(value) = flag_value(&arg, b"--identity-map=") {
            map = parse_identity_map("--identity-map", &into_string("--identity-map", value)?)?;
        } else if arg == "--clamp-mtime" {
            clamp_mtime = Some(parse_epoch(
                "--clamp-mtime",
                &string_value("--clamp-mtime", &mut args)?,
            )?);
        } else if let Some(value) = flag_value(&arg, b"--clamp-mtime=") {
            clamp_mtime = Some(parse_epoch(
                "--clamp-mtime",
                &into_string("--clamp-mtime", value)?,
            )?);
        } else {
            return Err(mode_conflict(
                &arg,
                "--export-rootfs",
                &[
                    "--export-rootfs",
                    "--export-to",
                    "--identity-map",
                    "--clamp-mtime",
                ],
            ));
        }
    }

    // As for a removal, the caller established that the flag is present, so
    // this is a guard rather than a live path.
    let source = source.ok_or_else(|| "--export-rootfs requires a value".to_string())?;
    Ok(Invocation::Export {
        source,
        dest,
        map,
        clamp_mtime,
    })
}

/// Parses the Unix timestamp in seconds that `flag` takes: `--clamp-mtime`'s
/// ceiling, or the date a bootstrap's `--*-source-date-epoch` gives it.
///
/// Signed, because the ceiling is a plain timestamp rather than a duration and
/// a tree may legitimately be pinned to an instant before the epoch.
fn parse_epoch(flag: &str, value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|_| format!("{flag}: {value:?} is not a Unix timestamp in whole seconds"))
}

/// Parses the date a `--debian-source-date-epoch` or `--alpine-source-date-epoch`
/// gives a bootstrap: a timestamp, as [`parse_epoch`] reads one, that is not
/// negative.
///
/// Each bootstrap refuses a negative date when it is built, because the account
/// tools read `SOURCE_DATE_EPOCH` as an unsigned count. Refused here too, so the
/// mistake is the usage error it is rather than a bootstrap that cannot be
/// built.
fn parse_source_date_epoch(flag: &str, value: &str) -> Result<i64, String> {
    let epoch = parse_epoch(flag, value)?;
    if epoch < 0 {
        return Err(format!(
            "{flag}: {epoch} is before 1970, and the tools that read SOURCE_DATE_EPOCH \
             take it as an unsigned count of seconds"
        ));
    }
    Ok(epoch)
}

/// Whether any `--debian-*` modifier flag was given.
fn has_debian_modifiers(options: &Options) -> bool {
    options.debian_arch.is_some()
        || options.debian_mirror.is_some()
        || !options.debian_components.is_empty()
        || !options.debian_include.is_empty()
        || !options.debian_exclude.is_empty()
        || options.debian_plan.is_some()
        || options.debian_pin.is_some()
        || options.debian_extract_only
        || options.debian_cache.is_some()
        || options.debian_keyring.is_some()
        || !options.debian_mirror_fallback.is_empty()
        || options.debian_base_priority.is_some()
        || options.debian_trust_unsigned
        || options.debian_allow_stale_release
        || options.debian_pre_configure_overlay.is_some()
        || options.debian_source_date_epoch.is_some()
        || options.debian_identity_map.is_some()
        || !options.debian_repositories.is_empty()
}

/// Whether any `--alpine-*` modifier flag was given.
fn has_alpine_modifiers(options: &Options) -> bool {
    options.alpine_arch.is_some()
        || options.alpine_mirror.is_some()
        || !options.alpine_components.is_empty()
        || !options.alpine_include.is_empty()
        || !options.alpine_exclude.is_empty()
        || options.alpine_plan.is_some()
        || options.alpine_pin.is_some()
        || options.alpine_extract_only
        || options.alpine_cache.is_some()
        || options.alpine_keys.is_some()
        || !options.alpine_mirror_fallback.is_empty()
        || options.alpine_pre_configure_overlay.is_some()
        || options.alpine_identity_map.is_some()
        || options.alpine_source_date_epoch.is_some()
        || !options.alpine_repositories.is_empty()
}

/// Whether any `--gentoo-*` modifier flag was given.
fn has_gentoo_modifiers(options: &Options) -> bool {
    options.gentoo_variant.is_some()
        || options.gentoo_binhost.is_some()
        || !options.gentoo_install.is_empty()
        || !options.gentoo_prefer_use.is_empty()
        || options.gentoo_plan.is_some()
        || options.gentoo_build_id.is_some()
        || options.gentoo_mirror.is_some()
        || !options.gentoo_mirror_fallback.is_empty()
        || options.gentoo_cache.is_some()
        || options.gentoo_max_pointer_age.is_some()
}

/// Parses `--gentoo-max-pointer-age`: a count of days, or `none` for no bound.
fn parse_pointer_age(value: &str) -> Result<Option<u64>, String> {
    if value == "none" {
        return Ok(None);
    }
    let days: u64 = value.parse().map_err(|_| {
        format!("--gentoo-max-pointer-age expects a number of days or 'none', not {value:?}")
    })?;
    Ok(Some(days))
}

/// Whether any `--netstack-*` modifier flag was given.
fn has_netstack_modifiers(options: &Options) -> bool {
    options.netstack_cidr.is_some()
        || options.netstack_cidr6.is_some()
        || options.netstack_no_ipv4
        || options.netstack_no_ipv6
        || options.netstack_interface.is_some()
        || options.netstack_mtu.is_some()
        || options.netstack_host_loopback
        || !options.netstack_host_ports.is_empty()
        || !options.netstack_publish.is_empty()
}

/// Parses the host half of `--netstack-publish`: an `ADDRESS:PORT`, with an
/// IPv6 address in brackets, or a bare `PORT`, which listens on `127.0.0.1`.
///
/// The bare form is the loopback because a published port is reachable by
/// whatever reaches its address, and the address that reaches least is the one
/// to fall back on. Anything wider is spelled out.
fn parse_publish_host(value: &str) -> Result<SocketAddr, String> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    value.parse::<SocketAddr>().map_err(|_| {
        format!(
            "--netstack-publish expects ADDRESS:PORT or a bare PORT for the host side, \
             not {value:?}"
        )
    })
}

/// Parses an IPv4 `address/prefix` for `--netstack-cidr`.
fn parse_cidr(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, len) = value
        .split_once('/')
        .ok_or_else(|| format!("--netstack-cidr expects ADDRESS/LEN, not {value:?}"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("--netstack-cidr: {address:?} is not an IPv4 address"))?;
    let len = len
        .parse::<u8>()
        .map_err(|_| format!("--netstack-cidr: {len:?} is not a prefix length"))?;
    if len > 32 {
        return Err(format!(
            "--netstack-cidr: {len} is not an IPv4 prefix length (0-32)"
        ));
    }
    Ok((address, len))
}

/// Parses an IPv6 `address/prefix` for `--netstack-cidr6`.
///
/// A second answer to the question above, because the two address families are
/// two types with two parsers and two prefix ceilings, and a shared one would
/// take the family as a parameter only to branch on it throughout. The library
/// splits [`ipv4_cidr`] from [`ipv6_cidr`] the same way.
///
/// [`ipv4_cidr`]: ferroday_cage::NetStackBuilder::ipv4_cidr
/// [`ipv6_cidr`]: ferroday_cage::NetStackBuilder::ipv6_cidr
fn parse_cidr6(value: &str) -> Result<(Ipv6Addr, u8), String> {
    let (address, len) = value
        .split_once('/')
        .ok_or_else(|| format!("--netstack-cidr6 expects ADDRESS/LEN, not {value:?}"))?;
    let address = address
        .parse::<Ipv6Addr>()
        .map_err(|_| format!("--netstack-cidr6: {address:?} is not an IPv6 address"))?;
    let len = len
        .parse::<u8>()
        .map_err(|_| format!("--netstack-cidr6: {len:?} is not a prefix length"))?;
    if len > 128 {
        return Err(format!(
            "--netstack-cidr6: {len} is not an IPv6 prefix length (0-128)"
        ));
    }
    Ok((address, len))
}

/// Parses an interface MTU for `--netstack-mtu`.
fn parse_mtu(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("--netstack-mtu: {value:?} is not a valid MTU"))
}

/// Splits a space-separated `key=value` specification into its pairs.
///
/// The shape `--seccomp-allow-rule` already uses, shared by `--raw-mount`,
/// `--debian-repository`, and the range form of `--identity-map`. A bare word
/// with no `=` is a flag, reported with an empty value.
fn spec_pairs<'a>(flag: &str, spec: &'a str) -> Result<Vec<(&'a str, &'a str)>, String> {
    let mut pairs = Vec::new();
    for field in spec.split_whitespace() {
        match field.split_once('=') {
            Some((key, value)) if !key.is_empty() => pairs.push((key, value)),
            Some(_) => return Err(format!("{flag}: {field:?} has an empty key")),
            None => pairs.push((field, "")),
        }
    }
    if pairs.is_empty() {
        return Err(format!("{flag} requires at least one key=value field"));
    }
    Ok(pairs)
}

/// Reads a field whose presence is the whole of its meaning, refusing one
/// written with a value.
///
/// A value cannot be honoured by a field that has no off state, and reading
/// `trust-unsigned=false` as the field being present turns archive signature
/// verification off — the opposite of what it says. Refused rather than
/// interpreted: `trust-unsigned` and `allow-stale-release` are spelled bare,
/// and a caller who wants the setting off leaves the field out.
fn bare_field(flag: &str, key: &str, value: &str) -> Result<bool, String> {
    if value.is_empty() {
        Ok(true)
    } else {
        Err(format!(
            "{flag}: {key} takes no value, and {key}={value} does not turn it off; write {key} on \
             its own, or leave it out"
        ))
    }
}

/// Parses a `--raw-mount` specification:
/// `target=/sys fstype=sysfs flags=0xE [source=...] [data=...]`.
fn parse_raw_mount(spec: &str) -> Result<RawMount, String> {
    let mut target = None;
    let mut source = None;
    let mut fstype = None;
    let mut data = None;
    let mut flags = 0u64;
    for (key, value) in spec_pairs("--raw-mount", spec)? {
        match key {
            "target" => target = Some(PathBuf::from(value)),
            "source" => source = Some(PathBuf::from(value)),
            "fstype" => fstype = Some(value.to_string()),
            "data" => data = Some(value.to_string()),
            "flags" => flags = parse_u64_literal("--raw-mount", "flags", value)?,
            other => {
                return Err(format!(
                    "--raw-mount: unknown field {other:?}; expected target, source, fstype, \
                     flags, or data"
                ));
            }
        }
    }
    let target = target.ok_or("--raw-mount requires a target= field".to_string())?;
    let mut mount = RawMount::new(target).flags(flags);
    if let Some(source) = source {
        mount = mount.source(source);
    }
    if let Some(fstype) = fstype {
        mount = mount.fstype(fstype);
    }
    if let Some(data) = data {
        mount = mount.data(data);
    }
    Ok(mount)
}

/// Parses an identity-map selector: `single`, `subordinate`, or the explicit
/// range form `uid=IN:OUT:COUNT[,...] gid=IN:OUT:COUNT[,...]`.
fn parse_identity_map(flag: &str, spec: &str) -> Result<IdentityMap, String> {
    match spec.trim() {
        "single" => return Ok(IdentityMap::Single),
        "subordinate" => return Ok(IdentityMap::Subordinate),
        _ => {}
    }
    let mut uid = Vec::new();
    let mut gid = Vec::new();
    for (key, value) in spec_pairs(flag, spec)? {
        let target = match key {
            "uid" => &mut uid,
            "gid" => &mut gid,
            other => {
                return Err(format!(
                    "{flag}: expected 'single', 'subordinate', or uid=/gid= extents, not {other:?}"
                ));
            }
        };
        for extent in value.split(',').filter(|extent| !extent.is_empty()) {
            target.push(parse_id_range(flag, extent)?);
        }
    }
    if uid.is_empty() || gid.is_empty() {
        return Err(format!(
            "{flag}: an explicit range map needs both uid= and gid= extents"
        ));
    }
    Ok(IdentityMap::ranges(uid, gid))
}

/// Parses one `INSIDE:OUTSIDE:COUNT` extent of an explicit range map.
fn parse_id_range(flag: &str, extent: &str) -> Result<IdRange, String> {
    let parts: Vec<&str> = extent.split(':').collect();
    let [inside, outside, count] = parts.as_slice() else {
        return Err(format!(
            "{flag}: {extent:?} is not an INSIDE:OUTSIDE:COUNT extent"
        ));
    };
    let field = |name: &str, text: &str| {
        text.parse::<u32>()
            .map_err(|_| format!("{flag}: {text:?} is not a valid {name}"))
    };
    Ok(IdRange {
        inside: field("inside id", inside)?,
        outside: field("outside id", outside)?,
        count: field("count", count)?,
    })
}

/// Parses a `--run-as` identity: `UID:GID[:GROUP[,GROUP...]]`.
fn parse_run_as(spec: &str) -> Result<Identity, String> {
    let mut fields = spec.splitn(3, ':');
    let id = |name: &str, text: Option<&str>| match text {
        Some(text) => text
            .parse::<u32>()
            .map_err(|_| format!("--run-as: {text:?} is not a valid {name}")),
        None => Err(format!("--run-as requires UID:GID, not {spec:?}")),
    };
    let uid = id("uid", fields.next().filter(|field| !field.is_empty()))?;
    let gid = id("gid", fields.next())?;
    let identity = Identity::new(uid, gid);
    match fields.next().filter(|groups| !groups.is_empty()) {
        None => Ok(identity),
        Some(groups) => {
            let groups = groups
                .split(',')
                .filter(|group| !group.is_empty())
                .map(|group| {
                    group
                        .parse::<u32>()
                        .map_err(|_| format!("--run-as: {group:?} is not a valid group id"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(identity.groups(groups))
        }
    }
}

/// Parses a `--rlimit` setting: `RESOURCE=SOFT[:HARD]`, where a value of
/// `unlimited` is the kernel's `RLIM_INFINITY` and an omitted hard limit
/// repeats the soft one.
fn parse_rlimit(spec: &str) -> Result<(Resource, Limit, Limit), String> {
    let (name, values) = spec
        .split_once('=')
        .ok_or_else(|| format!("--rlimit expects RESOURCE=SOFT[:HARD], not {spec:?}"))?;
    // Resolved through the library's own `Deserialize`, which is the same name
    // table a profile's `[rlimit]` keys use. A resource added to the library is
    // then spelled identically here without a change, and its rejection message
    // lists the accepted names.
    let resource = Resource::deserialize(serde::de::value::StrDeserializer::<
        serde::de::value::Error,
    >::new(name.trim()))
    .map_err(|error| format!("--rlimit: {error}"))?;
    let limit = |text: &str| -> Result<Limit, String> {
        if text == "unlimited" {
            return Ok(Limit::UNLIMITED);
        }
        text.parse::<u64>()
            .map(Limit::of)
            .map_err(|_| format!("--rlimit: {text:?} is not a limit value or 'unlimited'"))
    };
    let (soft, hard) = match values.split_once(':') {
        Some((soft, hard)) => (limit(soft)?, limit(hard)?),
        None => {
            let both = limit(values)?;
            (both, both)
        }
    };
    Ok((resource, soft, hard))
}

/// Parses a Debian priority floor for `--debian-base-priority`.
///
/// The library owns the name table — it is the same one that reads a
/// `Priority:` field out of an index — so this only prefixes the flag onto the
/// refusal.
fn parse_priority(value: &str) -> Result<Priority, String> {
    value
        .parse()
        .map_err(|err| format!("--debian-base-priority: {err}"))
}

/// The mirrors a repository specification names: its primary, and its backstops
/// in the order they were given.
///
/// The two fields are held apart rather than as one list, because neither a
/// repeated `mirror=` nor a lone `mirror-fallback=` is a spelling of something
/// the caller could have meant. One list read positionally makes both of them
/// mean something: a lone backstop becomes the primary, and a second `mirror=`
/// demotes the first to a backstop ahead of the declared ones. The first is the
/// one that matters — a repository's primary mirror is written into the finished
/// root, as `/etc/apk/repositories` or `sources.list`, so a typo-dropped
/// `mirror=` would leave that root permanently fetching from what the caller
/// meant as a fetch-time backstop.
#[derive(Debug, Default)]
struct MirrorSpec {
    primary: Option<String>,
    fallbacks: Vec<String>,
}

impl MirrorSpec {
    /// Records a `mirror=` field, refusing a second one.
    fn primary(&mut self, flag: &str, url: &str) -> Result<(), String> {
        if let Some(first) = &self.primary {
            return Err(format!(
                "{flag}: mirror= is given twice, as {first:?} and {url:?}; a repository has one \
                 primary mirror, and the rest are mirror-fallback="
            ));
        }
        self.primary = Some(fetchable_mirror(flag, url.to_string())?);
        Ok(())
    }

    /// Records a `mirror-fallback=` field.
    fn fallback(&mut self, flag: &str, url: &str) -> Result<(), String> {
        self.fallbacks
            .push(fetchable_mirror(flag, url.to_string())?);
        Ok(())
    }

    /// The primary and its backstops, refusing a spec that names only backstops.
    fn finish(self, flag: &str) -> Result<(Option<String>, Vec<String>), String> {
        if self.primary.is_none() && !self.fallbacks.is_empty() {
            return Err(format!(
                "{flag}: mirror-fallback= names a backstop for a mirror= that was not given; a \
                 repository is fetched from its primary mirror first"
            ));
        }
        Ok((self.primary, self.fallbacks))
    }
}

/// A mirror URL `fcage` can fetch from, refusing an `https://` one.
///
/// The library's own client speaks plain HTTP and reads `file://`, and an
/// `https://` mirror needs a fetcher that a program supplies as code, which a
/// command line cannot carry. Refused here, the mistake is a usage error naming
/// the flag, rather than a failure partway through a run that names a library
/// setting `fcage` has no flag for. Plain HTTP costs a signed archive nothing:
/// the signature authenticates whatever the transport delivers.
fn fetchable_mirror(flag: &str, url: String) -> Result<String, String> {
    if url
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
    {
        return Err(format!(
            "{flag}: {url:?} is an https:// mirror, which fcage cannot fetch from; name the \
             archive over http://, which its signature authenticates, or a local copy over \
             file://"
        ));
    }
    Ok(url)
}

/// Parses a `--debian-repository` specification:
/// `suite=S mirror=URL [mirror-fallback=URL] [components=a,b] [keyring=PATH]
/// [name=NAME] [trust-unsigned] [allow-stale-release]`.
fn parse_repository(spec: &str) -> Result<Repository, String> {
    let mut suite = None;
    let mut mirrors = MirrorSpec::default();
    let mut components: Vec<String> = Vec::new();
    let mut keyring = None;
    let mut name = None;
    let mut trust_unsigned = false;
    let mut allow_stale = false;
    for (key, value) in spec_pairs("--debian-repository", spec)? {
        match key {
            "suite" => suite = Some(value.to_string()),
            "mirror" => mirrors.primary("--debian-repository", value)?,
            "mirror-fallback" => mirrors.fallback("--debian-repository", value)?,
            "components" => extend_comma(&mut components, value),
            "keyring" => keyring = Some(PathBuf::from(value)),
            "name" => name = Some(value.to_string()),
            "trust-unsigned" => trust_unsigned = bare_field("--debian-repository", key, value)?,
            "allow-stale-release" => allow_stale = bare_field("--debian-repository", key, value)?,
            other => {
                return Err(format!(
                    "--debian-repository: unknown field {other:?}; expected suite, mirror, \
                     mirror-fallback, components, keyring, name, trust-unsigned, or \
                     allow-stale-release"
                ));
            }
        }
    }
    let suite = suite.ok_or("--debian-repository requires a suite= field".to_string())?;
    let (primary, fallbacks) = mirrors.finish("--debian-repository")?;
    let mut builder = Repository::builder(suite)
        .trust_unsigned(trust_unsigned)
        .allow_stale_release(allow_stale);
    if let Some(primary) = primary {
        builder = builder.mirror(primary);
    }
    for fallback in fallbacks {
        builder = builder.mirror_fallback(fallback);
    }
    if !components.is_empty() {
        builder = builder.components(components);
    }
    if let Some(keyring) = keyring {
        builder = builder.keyring(keyring);
    }
    if let Some(name) = name {
        builder = builder.name(name);
    }
    builder
        .build()
        .map_err(|error| format!("--debian-repository: {}", ErrorChain::new(&error)))
}

/// Where an apk repository's trusted keys come from.
///
/// Resolved after the whole command line is read rather than as the flag is
/// parsed, because the bundled Alpine set is per architecture and
/// `--alpine-arch` may come later. The spelling is checked here; only the
/// lookup waits.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AlpineKeys {
    /// The bundled Alpine set for the bootstrap's architecture.
    Alpine,
    /// The bundled postmarketOS key, which serves every architecture it
    /// publishes.
    PostmarketOs,
    /// A directory of PEM public keys, each held under its file name.
    Dir(PathBuf),
}

/// A `--alpine-repository` specification, read but not yet built.
///
/// Held in this shape for the same reason [`AlpineKeys`] is: a repository is
/// built once the architecture its keys are chosen by is known.
#[derive(Debug, Clone)]
struct AlpineRepositorySpec {
    release: String,
    /// The primary mirror, absent where the spec named none — which the library
    /// refuses, and is left to it so the refusal reads the same however the
    /// repository was configured.
    mirror: Option<String>,
    /// The backstops, in the order they were given.
    fallbacks: Vec<String>,
    components: Vec<String>,
    keys: AlpineKeys,
}

/// Reads a key-set selector: `alpine`, `postmarketos`, or a directory path.
///
/// A path is accepted without being examined, since whether a directory holds
/// usable keys is [`alpine_key_set`]'s question and its answer names the file.
/// An empty selector is not a path, though: read as one it names the working
/// directory, and the run ends at an io failure about a directory the caller
/// never typed rather than at the usage error it is.
fn parse_alpine_keys(flag: &str, value: &str) -> Result<AlpineKeys, String> {
    Ok(match value {
        "alpine" => AlpineKeys::Alpine,
        "postmarketos" => AlpineKeys::PostmarketOs,
        "" => {
            return Err(format!(
                "{flag}: keys= names no key set; write 'alpine', 'postmarketos', or a directory \
                 of PEM public keys"
            ));
        }
        path => AlpineKeys::Dir(PathBuf::from(path)),
    })
}

/// Builds the key set `keys` names, for a bootstrap targeting `architecture`.
///
/// A directory is read as `/etc/apk/keys` is: every regular file in it is a PEM
/// public key held under its own file name, which is the name a signature spells
/// its key by. The directory is read in name order so that two runs over one
/// directory report the same first failure.
fn alpine_key_set(
    flag: &str,
    keys: &AlpineKeys,
    architecture: &str,
) -> Result<AlpineKeySet, String> {
    let directory = match keys {
        AlpineKeys::Alpine => {
            return AlpineKeySet::alpine(architecture)
                .map_err(|err| format!("{flag}: {}", ErrorChain::new(&err)));
        }
        AlpineKeys::PostmarketOs => return Ok(AlpineKeySet::postmarketos()),
        AlpineKeys::Dir(directory) => directory,
    };

    let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|err| {
            format!(
                "{flag}: reading {}: {}",
                directory.display(),
                ErrorChain::new(&err)
            )
        })?
        .map(|entry| {
            entry.map(|entry| entry.path()).map_err(|err| {
                format!(
                    "{flag}: reading {}: {}",
                    directory.display(),
                    ErrorChain::new(&err)
                )
            })
        })
        .collect::<Result<_, _>>()?;
    entries.sort();

    let mut set = AlpineKeySet::new();
    for path in entries {
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(format!(
                "{flag}: {} is not a usable key name; a signature names its key by exactly the \
                 file name the repository publishes it under",
                path.display(),
            ));
        };
        let pem = std::fs::read_to_string(&path).map_err(|err| {
            format!(
                "{flag}: reading {}: {}",
                path.display(),
                ErrorChain::new(&err)
            )
        })?;
        set.insert(name, &pem)
            .map_err(|err| format!("{flag}: {}", ErrorChain::new(&err)))?;
    }
    if set.is_empty() {
        return Err(format!(
            "{flag}: {} holds no keys, so nothing the repository serves could be verified",
            directory.display(),
        ));
    }
    Ok(set)
}

/// Parses an `--alpine-repository` specification:
/// `release=R mirror=URL keys=SOURCE [mirror-fallback=URL] [components=a,b]`.
fn parse_alpine_repository(spec: &str) -> Result<AlpineRepositorySpec, String> {
    let mut release = None;
    let mut mirrors = MirrorSpec::default();
    let mut components: Vec<String> = Vec::new();
    let mut keys = None;
    for (key, value) in spec_pairs("--alpine-repository", spec)? {
        match key {
            "release" => release = Some(value.to_string()),
            "mirror" => mirrors.primary("--alpine-repository", value)?,
            "mirror-fallback" => mirrors.fallback("--alpine-repository", value)?,
            "components" => extend_comma(&mut components, value),
            "keys" => keys = Some(parse_alpine_keys("--alpine-repository", value)?),
            other => {
                return Err(format!(
                    "--alpine-repository: unknown field {other:?}; expected release, mirror, \
                     mirror-fallback, components, or keys"
                ));
            }
        }
    }
    let (primary, fallbacks) = mirrors.finish("--alpine-repository")?;
    Ok(AlpineRepositorySpec {
        release: release.ok_or("--alpine-repository requires a release= field".to_string())?,
        mirror: primary,
        fallbacks,
        components,
        // Unlike the primary, an additional repository has no default: its
        // signing key is its own, and the library refuses one without keys.
        keys: keys.ok_or(
            "--alpine-repository requires a keys= field, one of 'alpine', 'postmarketos', or a \
             directory of PEM public keys"
                .to_string(),
        )?,
    })
}

/// Consumes the next argument as the value a flag needs, or reports which flag
/// needed one.
///
/// A free function rather than a closure inside the main parser, because the
/// mode parsers are functions of their own and need the same message.
///
/// A value that names another flag is refused rather than consumed. `fcage
/// --remove-rootfs --identity-map=subordinate` would otherwise take the map's
/// spelling as the tree to delete, and report success having removed a path of
/// that name in the working directory instead. Every flag taking a separated
/// value has that shape, which is why the refusal is here rather than at any
/// one flag.
///
/// Only a name [`FLAGS`] holds is refused, so a value that merely begins with a
/// dash is still the caller's: `--gentoo-prefer-use -systemd` states a
/// preference against a flag and means what it looks like. A value that
/// genuinely is a flag's spelling is written joined, as `--export-to=--odd`.
/// `arity` decides whether the refusal offers that: a flag taking two values
/// has no joined form, so its refusal does not suggest one.
fn value_for(
    name: &str,
    needs: &str,
    arity: Arity,
    args: &mut dyn Iterator<Item = OsString>,
) -> Result<OsString, String> {
    let value = args
        .next()
        .ok_or_else(|| format!("{name} requires {needs}"))?;
    if named(&value).is_some() {
        let value = value.to_string_lossy();
        return Err(match arity {
            Arity::Two => format!(
                "{name} requires {needs}, and {value} names a flag; {name} has no joined \
                 form, so neither of its values can be spelled as a flag"
            ),
            Arity::Bare | Arity::One => format!(
                "{name} requires {needs}, and {value} names a flag; write it joined as \
                 {name}=VALUE where it is the value"
            ),
        });
    }
    Ok(value)
}

/// Consumes the next argument as a required UTF-8 string value.
///
/// The library's examples carry helpers answering the same three questions —
/// this, [`into_string`], and [`flag_value`] — and keep them because a crate's
/// examples cannot reach another crate's code, so sharing four
/// argument-parsing functions would mean publishing a crate for them. Each side
/// owns the wording of its own diagnostics.
fn string_value(name: &str, args: &mut dyn Iterator<Item = OsString>) -> Result<String, String> {
    into_string(name, value_for(name, "a value", Arity::One, args)?)
}

/// Converts a flag value to a `String`, requiring UTF-8.
fn into_string(name: &str, value: OsString) -> Result<String, String> {
    value
        .into_string()
        .map_err(|_| format!("{name} requires a valid UTF-8 value"))
}

/// Appends comma-separated items to `target`, trimming and dropping empties.
fn extend_comma(target: &mut Vec<String>, value: &str) {
    target.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_string),
    );
}

/// Splits `--flag=value` syntax, preserving non-UTF-8 values.
fn flag_value(arg: &OsStr, prefix: &[u8]) -> Option<OsString> {
    arg.as_bytes()
        .strip_prefix(prefix)
        .map(|value| OsString::from_vec(value.to_vec()))
}

/// Parses a `--stdin` mode.
fn parse_stdin(value: &OsStr) -> Result<Stdio, String> {
    if value == "inherit" {
        Ok(Stdio::Inherit)
    } else if value == "null" {
        Ok(Stdio::Null)
    } else {
        Err(format!(
            "--stdin accepts 'inherit' or 'null', not {}",
            value.to_string_lossy()
        ))
    }
}

/// Parses a `--seccomp` value, which selects the curated posture.
fn parse_seccomp(value: &str, curated: &mut bool) -> Result<(), String> {
    match value {
        "curated" => {
            *curated = true;
            Ok(())
        }
        other => Err(format!(
            "--seccomp accepts 'curated', not {other:?}; name syscalls with \
             --seccomp-allow/--seccomp-deny or condition them with \
             --seccomp-allow-rule/--seccomp-deny-rule"
        )),
    }
}

/// Appends the comma-separated syscall names in `value` to `target`, resolved
/// to their numbers for the host architecture.
fn parse_seccomp_names(flag: &str, value: &str, target: &mut Vec<i64>) -> Result<(), String> {
    for name in value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        target.push(resolve_syscall_name(flag, name)?);
    }
    Ok(())
}

/// Parses one `--seccomp-*-rule` value into a syscall number and its argument
/// conditions.
///
/// The value is a syscall name followed by comma-separated conditions, each a
/// space-separated set of `key=value` pairs mirroring a profile's `arg` entry:
/// `arg` (0 through 5), `len` (`dword` or `qword`), `op` (`eq`, `ne`, `ge`,
/// `gt`, `le`, `lt`, or `masked-eq`), `value`, and `mask` (required only for
/// `masked-eq`). Values are decimal or `0x`-prefixed hexadecimal. A rule
/// without conditions lists the syscall unconditionally.
fn parse_seccomp_rule(flag: &str, value: &str) -> Result<(i64, Vec<SeccompArg>), String> {
    let value = value.trim();
    let (name, rest) = match value.split_once(char::is_whitespace) {
        Some((name, rest)) => (name, rest.trim()),
        None => (value, ""),
    };
    if name.is_empty() {
        return Err(format!("{flag} requires a syscall name"));
    }
    let syscall = resolve_syscall_name(flag, name)?;
    let conditions = rest
        .split(',')
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .map(|clause| parse_seccomp_condition(flag, clause))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((syscall, conditions))
}

/// Parses one `key=value` condition clause into a [`SeccompArg`].
fn parse_seccomp_condition(flag: &str, clause: &str) -> Result<SeccompArg, String> {
    let mut index: Option<u8> = None;
    let mut len: Option<SeccompArgLen> = None;
    let mut op: Option<String> = None;
    let mut value: Option<u64> = None;
    let mut mask: Option<u64> = None;

    for field in clause.split_whitespace() {
        let (key, raw) = field
            .split_once('=')
            .ok_or_else(|| format!("{flag}: expected key=value, not {field:?}"))?;
        match key {
            "arg" => {
                // A syscall has six argument registers; the library rejects a
                // larger index at build, but a parse-time check reports it
                // where the other usage errors are reported.
                let parsed = raw
                    .parse::<u8>()
                    .ok()
                    .filter(|index| *index <= 5)
                    .ok_or_else(|| format!("{flag}: arg must be 0 through 5, not {raw:?}"))?;
                index = Some(parsed);
            }
            "len" => {
                len = Some(match raw {
                    "dword" => SeccompArgLen::Dword,
                    "qword" => SeccompArgLen::Qword,
                    other => {
                        return Err(format!("{flag}: len must be dword or qword, not {other:?}"));
                    }
                });
            }
            "op" => op = Some(raw.to_string()),
            "value" => value = Some(parse_u64_literal(flag, "value", raw)?),
            "mask" => mask = Some(parse_u64_literal(flag, "mask", raw)?),
            other => return Err(format!("{flag}: unknown condition key {other:?}")),
        }
    }

    let index = index.ok_or_else(|| format!("{flag}: a condition needs arg="))?;
    let len = len.ok_or_else(|| format!("{flag}: a condition needs len= (dword or qword)"))?;
    let op = op.ok_or_else(|| format!("{flag}: a condition needs op="))?;
    let value = value.ok_or_else(|| format!("{flag}: a condition needs value="))?;

    // The mask belongs to masked-eq alone: required there, rejected elsewhere,
    // the same rule the profile applies.
    let compare = match op.as_str() {
        "masked-eq" => SeccompCompare::MaskedEq(
            mask.ok_or_else(|| format!("{flag}: op=masked-eq needs mask="))?,
        ),
        simple => {
            if mask.is_some() {
                return Err(format!("{flag}: mask= is only valid with op=masked-eq"));
            }
            match simple {
                "eq" => SeccompCompare::Eq,
                "ne" => SeccompCompare::Ne,
                "ge" => SeccompCompare::Ge,
                "gt" => SeccompCompare::Gt,
                "le" => SeccompCompare::Le,
                "lt" => SeccompCompare::Lt,
                other => {
                    return Err(format!(
                        "{flag}: op must be eq, ne, ge, gt, le, lt, or masked-eq, not {other:?}"
                    ));
                }
            }
        }
    };

    Ok(SeccompArg::new(index, len, compare, value))
}

/// Parses a decimal or `0x`-prefixed hexadecimal `u64` for a condition field.
fn parse_u64_literal(flag: &str, field: &str, raw: &str) -> Result<u64, String> {
    let parsed = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse::<u64>(),
    };
    parsed.map_err(|_| format!("{flag}: {field} must be a number (decimal or 0x hex), not {raw:?}"))
}

/// Resolves a syscall name to its number for the host architecture, through
/// [`SeccompRules::syscall`], the table a profile's names resolve through.
fn resolve_syscall_name(flag: &str, name: &str) -> Result<i64, String> {
    SeccompRules::syscall(name).ok_or_else(|| format!("{flag}: unknown syscall {name:?}"))
}

/// Reconciles the seccomp flags into a single policy, or `None` when none were
/// given.
///
/// The curated posture is a whole policy on its own, so it cannot be combined
/// with named rules. An allow-list and a deny-list are opposite postures and
/// cannot be combined either, the same constraint a profile enforces.
fn assemble_seccomp(
    curated: bool,
    allow: Vec<i64>,
    deny: Vec<i64>,
    allow_rules: Vec<(i64, Vec<SeccompArg>)>,
    deny_rules: Vec<(i64, Vec<SeccompArg>)>,
) -> Result<Option<SeccompPolicy>, String> {
    let allow_side = !allow.is_empty() || !allow_rules.is_empty();
    let deny_side = !deny.is_empty() || !deny_rules.is_empty();

    if curated && (allow_side || deny_side) {
        return Err(
            "--seccomp curated cannot be combined with --seccomp-allow/--seccomp-deny rules"
                .to_string(),
        );
    }
    if curated {
        return Ok(Some(SeccompPolicy::Curated));
    }
    if allow_side && deny_side {
        return Err(
            "--seccomp-allow/--seccomp-allow-rule cannot be combined with \
             --seccomp-deny/--seccomp-deny-rule"
                .to_string(),
        );
    }

    let (bare, rules) = if allow_side {
        (SeccompRules::allowing(allow), allow_rules)
    } else if deny_side {
        (SeccompRules::denying(deny), deny_rules)
    } else {
        return Ok(None);
    };
    let policy = rules
        .into_iter()
        .fold(bare, |rules, (syscall, conditions)| {
            rules.rule(syscall, conditions)
        });
    Ok(Some(SeccompPolicy::Rules(policy)))
}

/// The seccomp policy a launch sets, or `None` to leave the one it has.
///
/// `flags` is the policy the allow, deny and curated flags assembled, which
/// replaces a profile's as every flag given beside a profile overrides it.
/// `errnos` joins whichever policy then stands: the flags', or else the
/// profile's, `beneath`. An errno beside a profile's allow-list therefore
/// answers its syscall without discarding the list. With neither policy, the
/// errnos make a deny side of their own, refusing only what they name. The
/// curated posture is a whole policy and takes none, and a policy that is not
/// a rule set cannot be extended by one.
fn compose_seccomp(
    flags: Option<SeccompPolicy>,
    errnos: Vec<(i64, u16)>,
    beneath: Option<&SeccompPolicy>,
) -> Result<Option<SeccompPolicy>, String> {
    if errnos.is_empty() {
        return Ok(flags);
    }
    let rules = match (flags, beneath) {
        (Some(SeccompPolicy::Rules(rules)), _) => rules,
        (None, Some(SeccompPolicy::Rules(rules))) => rules.clone(),
        (None, None) => SeccompRules::denying([]),
        (Some(_), _) => {
            return Err("--seccomp curated cannot be combined with --seccomp-errno".to_string());
        }
        (None, Some(_)) => {
            return Err(
                "--seccomp-errno cannot be added to the profile's seccomp policy, which is the \
                 curated posture rather than a set of rules; add the errno to a rule set, or \
                 replace the profile's policy with --seccomp-allow or --seccomp-deny"
                    .to_string(),
            );
        }
    };
    let rules = errnos.into_iter().fold(rules, |rules, (syscall, errno)| {
        rules.errno_for(syscall, errno)
    });
    Ok(Some(SeccompPolicy::Rules(rules)))
}

/// Parses one `--seccomp-errno` value, `SYSCALL=ERRNO`, into the syscall's
/// number and the errno's.
///
/// The errno is read by [`SeccompRules::errno`]: a name such as `ENOSYS`, in
/// any letter case, through the table a profile's `errno` entries resolve
/// through, or a number a failed syscall can report. Zero is refused, since the
/// command would read it as a success the syscall never performed.
fn parse_seccomp_errno(flag: &str, value: &str) -> Result<(i64, u16), String> {
    let (name, errno) = value
        .split_once('=')
        .ok_or_else(|| format!("{flag} expects SYSCALL=ERRNO, not {value:?}"))?;
    let syscall = resolve_syscall_name(flag, name.trim())?;
    let errno = errno.trim();
    let number = SeccompRules::errno(errno).ok_or_else(|| {
        format!(
            "{flag}: {errno:?} is not an errno a syscall can fail with; name one, such as \
             ENOSYS, or give its number, from 1 to 4095"
        )
    })?;
    Ok((syscall, number))
}

/// Parses a comma-separated `--landlock-scope` list into scopes; an empty
/// list is no scope at all.
fn parse_scopes(value: &str) -> Result<Vec<LandlockScope>, String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.parse::<LandlockScope>().map_err(|err| err.to_string()))
        .collect()
}

/// Parses a port number: a `--landlock-bind` or `--landlock-connect` grant's
/// TCP port, a `--netstack-host-port` mapping's TCP and UDP port, or the guest
/// side of a `--netstack-publish`.
///
/// The value is a decimal port in `0..=65535`. What port 0 means is each flag's
/// own: with `--landlock-bind` it permits binding to a kernel-assigned
/// ephemeral port.
fn parse_port(flag: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{flag} requires a port in 0..=65535, not {value:?}"))
}

/// Parses a comma-separated `--keep-caps` list into capabilities.
///
/// Each name is parsed by the library's [`Capability`] `FromStr`, which
/// accepts the kebab or snake form with or without a `cap-`/`cap_` prefix
/// (`net-bind-service`, `CAP_SYS_ADMIN`).
fn parse_caps(value: &str) -> Result<Vec<Capability>, String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.parse::<Capability>().map_err(|err| err.to_string()))
        .collect()
}

/// Parses a positive decimal duration in seconds.
fn parse_seconds(name: &str, value: &OsStr) -> Result<Duration, String> {
    let seconds: f64 = value
        .to_str()
        .and_then(|value| value.parse().ok())
        .ok_or(format!("{name} requires a number of seconds"))?;
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(format!("{name} requires a positive number of seconds"));
    }
    let duration =
        Duration::try_from_secs_f64(seconds).map_err(|_| format!("{name} is too large"))?;
    // A positive number below a nanosecond rounds to no time at all, which
    // would expire before the command started.
    if duration.is_zero() {
        return Err(format!("{name} requires at least a nanosecond"));
    }
    Ok(duration)
}

/// What the CLI needs to know about a loaded profile beyond the builder itself.
struct ProfileMeta {
    /// The profile sets a `TERM` variable, so the host `TERM` is not applied as
    /// a fallback beneath it.
    sets_term: bool,
    /// The profile requests host networking, which `--netstack` cannot attach
    /// a stack to.
    network_host: bool,
    /// The profile states `stop-with-caller`, so `fcage`'s own default for it
    /// is not applied over the answer the profile gave.
    sets_stop_with_caller: bool,
}

/// Whether to set the caller tie, and to what: the flag where one was given,
/// `fcage`'s own default where neither the command line nor a profile said.
///
/// The tie is on by default here, unlike in the library: `fcage` waits for the
/// command and exits with it, so a sandbox that outlived the process is never
/// what a shell or a supervisor meant. Without it a SIGTERM to `fcage` —
/// `timeout(1)` is the everyday source — kills the waiter and orphans the
/// sandbox.
///
/// A default is not a setting, though, so it is applied only where nothing else
/// answers. Seeding the option with it would make every run state the tie, and
/// a profile's `stop-with-caller = false` would be overridden by a value its
/// author never wrote, leaving a documented profile key unreachable through
/// `fcage`.
fn stop_with_caller_default(flag: Option<bool>, profile_states_it: bool) -> Option<bool> {
    flag.or((!profile_states_it).then_some(true))
}

/// A `toml` error rendered as the body of one `fcage:` diagnostic.
///
/// The crate's `Display` ends with a newline of its own, and every diagnostic
/// here goes out as a line of its own, so formatting one verbatim leaves a blank
/// line behind the message. Only trailing whitespace is dropped: a parse
/// diagnostic keeps its span, its caret, and the line breaks between them, and
/// a single-line refusal -- an `unknown field`, or one of the restricted
/// policy's -- becomes the one line it reads as.
fn toml_diagnostic(error: &impl std::fmt::Display) -> String {
    error.to_string().trim_end().to_string()
}

/// Loads a profile into a builder, alongside the metadata the CLI reconciles
/// against its own flags.
///
/// With `override_command`, the profile's command and arguments are dropped
/// before it is deserialized: when the command line names a command of its own,
/// it overrides the profile's as a unit, never mixed with the profile's
/// arguments.
///
/// With `restricted`, the profile is deserialized under the library's
/// [`RestrictedProfile`] policy, which refuses the operations that map host
/// resources into the sandbox or share a host namespace; otherwise it is
/// trusted as code-equivalent configuration.
fn load_profile(
    path: &Path,
    override_command: bool,
    restricted: bool,
) -> Result<(CageBuilder, ProfileMeta), String> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        format!(
            "cannot read profile {}: {}",
            path.display(),
            ErrorChain::new(&err)
        )
    })?;
    let mut table: toml::Table = text.parse().map_err(|err| {
        format!(
            "cannot parse profile {}: {}",
            path.display(),
            toml_diagnostic(&err)
        )
    })?;
    if override_command {
        table.remove("command");
        table.remove("args");
    }
    let meta = ProfileMeta {
        sets_term: table
            .get("env")
            .and_then(|env| env.as_table())
            .is_some_and(|env| env.contains_key("TERM")),
        network_host: table.get("network").and_then(|value| value.as_str()) == Some("host"),
        sets_stop_with_caller: table.contains_key("stop-with-caller"),
    };
    let builder = if restricted {
        let profile: RestrictedProfile = table.try_into().map_err(|err| {
            format!(
                "cannot load profile {}: {}",
                path.display(),
                toml_diagnostic(&err)
            )
        })?;
        profile.into_builder()
    } else {
        table.try_into().map_err(|err| {
            format!(
                "cannot load profile {}: {}",
                path.display(),
                toml_diagnostic(&err)
            )
        })?
    };
    Ok((builder, meta))
}

/// Deletes the provisioned rootfs or the overlay upper at `dest`, under the
/// identity map it was written under.
///
/// A tree a range-mapped sandbox wrote carries subordinate ownership that a
/// plain `rm -rf` cannot delete; the library re-enters the same map to remove
/// it. A failure exits 125, the code every other setup failure uses: nothing
/// ran, so there is no command status to report.
///
/// A rootfs removal's `remove_lock` carries `--keep-lock` through to the
/// library's own setting. Deleting `<dest>.lock` is right for the published
/// rootfs this command is usually named on, and a deletion outside what the
/// caller named for a `dest` that merely holds such trees, which is a
/// distinction only the caller can make. An overlay upper's removal is
/// [`Remove::overlay_upper`](ferroday_cage::provision::Remove::overlay_upper),
/// which takes the work directory the library manages beside the upper with
/// it.
fn remove_tree(dest: &Path, map: IdentityMap, removal: Removal) -> ExitCode {
    use ferroday_cage::provision::Remove;

    let remove = match removal {
        Removal::Rootfs { remove_lock } => Remove::new(dest).remove_lock(remove_lock),
        Removal::OverlayUpper => Remove::overlay_upper(dest),
    };
    match remove.identity_map(map).run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error),
    }
}

/// Writes a provisioned rootfs to a tar archive, to a file or to standard
/// output.
///
/// A named destination appears complete or not at all: the library stages the
/// archive beside it and renames, so a run that fails part-way leaves whatever
/// archive was already there. Standard output has no such staging, and a
/// pipeline that consumes a partial stream is the caller's to arrange.
///
/// The terminal refusal is here rather than in the parser, so that parsing a
/// command line stays a function of the command line: whether standard output
/// is a terminal is a property of how `fcage` was invoked, not of what was
/// typed, and a parser that consulted it would answer differently under a test
/// harness than at a prompt. It is still the usage error it looks like, exit
/// code and all.
///
/// Both paths are checked before the walk begins, for the reason a launch
/// checks its rootfs before building anything: without it a typo surfaces from
/// wherever the walk happened to meet it, described in the walk's own
/// vocabulary ("while opening an entry in the exported tree"), which names the
/// step rather than the mistake.
fn export_rootfs(
    source: &Path,
    dest: Option<&Path>,
    map: IdentityMap,
    clamp_mtime: Option<i64>,
) -> ExitCode {
    use std::io::IsTerminal as _;

    if dest.is_none() && std::io::stdout().is_terminal() {
        output::report(format_args!(
            "fcage: refusing to write an archive to the terminal"
        ));
        output::report(format_args!(
            "Try '--export-to FILE', or pipe the output into a compressor."
        ));
        return ExitCode::from(USAGE);
    }

    match std::fs::metadata(source) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return fail(format_args!(
                "cannot export {}: it is not a directory",
                source.display(),
            ));
        }
        Err(error) => {
            return fail(format_args!(
                "cannot export {}: {}",
                source.display(),
                ErrorChain::new(&error),
            ));
        }
    }
    // Only a directory standing where the archive goes is refused here. Every
    // other destination failure belongs to the publish step, which stages beside
    // the destination and renames: it learns about a read-only parent or a full
    // filesystem by trying, and a check that raced it would report on a state
    // that no longer held.
    if let Some(path) = dest
        && std::fs::metadata(path).is_ok_and(|meta| meta.is_dir())
    {
        return fail(format_args!(
            "cannot write the archive to {}: it is a directory",
            path.display(),
        ));
    }

    let mut export = ferroday_cage::provision::Export::new(source).identity_map(map);
    if let Some(epoch) = clamp_mtime {
        export = export.clamp_mtime(epoch);
    }

    // To a file the library stages and renames, so a failed export leaves an
    // existing archive at the destination exactly as it found it; to standard
    // output there is nothing to stage onto, and the library buffers the writer
    // itself, so neither arm wraps it again.
    let written = match dest {
        Some(path) => export.write_to_path(path),
        None => export.write_to(std::io::stdout().lock()),
    };

    match written {
        Ok(()) => ExitCode::SUCCESS,
        // A reader that stopped early — `fcage --export-rootfs X | head -c 512`
        // — is not a failure of the export. The conventional ending is a quiet
        // one, so it is reported as the signal a writer to a closed pipe would
        // ordinarily die of rather than as noise on stderr.
        Err(ProvisionError::Io { source, .. })
            if dest.is_none() && source.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            ExitCode::from(output::broken_pipe())
        }
        Err(error) => fail(error),
    }
}

/// Provisions the root filesystem where the run asks for one, then builds and
/// runs the sandbox, mapping the outcome onto the exit status.
///
/// Everything a launch can be refused for without its root filesystem is
/// settled before a provisioner runs: the provisioner's own configuration, the
/// profile, the network stack's configuration, and the standard streams. A
/// mistake in any of them is then reported at once rather than after a
/// bootstrap that took minutes, and a refused run provisions nothing.
fn run(options: Options) -> ExitCode {
    if options.restrict {
        return run_restricted(options);
    }
    let mut provisioner = match provisioner(&options) {
        Ok(provisioner) => provisioner,
        Err(code) => return code,
    };
    let rootfs = options.rootfs.clone();

    // A provisioning run with no command and no profile provisions and exits.
    if options.command_line.is_empty() && options.profile.is_none() {
        let rootfs = rootfs.as_deref().expect("checked at parse time");
        let provisioner = provisioner.as_deref_mut().expect("checked at parse time");
        return match provision(rootfs, provisioner) {
            // The one place reuse is worth saying out loud. Everywhere else the
            // flag is a standing instruction and silence is the point -- it can
            // sit in an invocation forever and cost nothing once the tree is
            // there. But a run whose whole purpose was to provision, and which
            // provisioned nothing, exits 0 having done nothing at all, and an
            // empty directory the caller just created is indistinguishable from
            // a finished rootfs.
            Ok(Provisioned::Existing) => {
                output::report(format_args!(
                    "fcage: {} already exists, so nothing was provisioned; remove it first to \
                     provision again",
                    rootfs.display(),
                ));
                ExitCode::SUCCESS
            }
            Ok(_) => ExitCode::SUCCESS,
            Err(code) => code,
        };
    }

    let launch = match Launch::prepare(options) {
        Ok(launch) => launch,
        Err(code) => return code,
    };
    if let Some(provisioner) = provisioner.as_deref_mut() {
        let rootfs = rootfs.as_deref().expect("checked at parse time");
        if let Err(code) = provision(rootfs, provisioner) {
            return code;
        }
    }
    launch.run()
}

/// A sandbox launch composed and checked, waiting only for its root
/// filesystem.
struct Launch {
    builder: CageBuilder,
    /// The native network stack, for a `--netstack` run.
    stack: Option<NetStack>,
    /// The standard streams the launch hands over, judged, or `None` where a
    /// pseudoterminal of the sandbox's own replaces all three.
    streams: Option<streams::Judged>,
    terminal: bool,
    timeout: Option<Duration>,
    kill_after: Duration,
    publications: Vec<(SocketAddr, u16)>,
}

impl Launch {
    /// Composes the launch `options` describe, and refuses whatever the launch
    /// would refuse that does not need the root filesystem to exist.
    ///
    /// The builder only records settings, so composing it before the root is
    /// provisioned changes nothing it does. What is checked here is what would
    /// otherwise surface after a bootstrap: the stack's configuration, the
    /// profile, the profile against the flags, and the standard streams.
    fn prepare(options: Options) -> Result<Launch, ExitCode> {
        let stack = if options.netstack {
            Some(netstack_from(&options).map_err(fail)?)
        } else {
            None
        };

        let mut profile_sets_term = false;
        let mut profile_network_host = false;
        let mut profile_sets_stop_with_caller = false;
        let mut builder = match &options.profile {
            Some(path) => {
                let (builder, meta) = load_profile(
                    path,
                    !options.command_line.is_empty(),
                    options.profile_restricted,
                )
                .map_err(fail)?;
                profile_sets_term = meta.sets_term;
                profile_network_host = meta.network_host;
                profile_sets_stop_with_caller = meta.sets_stop_with_caller;
                builder
            }
            None => Cage::builder(),
        };

        // The parse-time guard rejects --netstack with --share-net, but a
        // profile can request host networking without any CLI network flag,
        // leaving that check blind. Reconcile against the loaded profile:
        // attaching a stack to a host-network sandbox cannot work, and the
        // usage error belongs here.
        if options.netstack && options.network.is_none() && profile_network_host {
            return Err(usage_error(format_args!(
                "--netstack cannot be used with a profile that sets network = \"host\""
            )));
        }

        // The seccomp flags against the profile's own policy, which is known
        // only now. A conflict between the two is the usage error it is.
        let seccomp = compose_seccomp(
            options.seccomp,
            options.seccomp_errno,
            builder.get_seccomp(),
        )
        .map_err(|message| usage_error(format_args!("{message}")))?;

        if let Some(rootfs) = options.rootfs {
            builder = builder.rootfs(rootfs);
        }
        if options.empty_rootfs {
            builder = builder.empty_rootfs();
        }
        // An overlay root, when the run named one. Parse-time validation has
        // already established that a lower and an upper are both present and
        // that no --rootfs competes with them.
        if !options.overlay_lowers.is_empty() {
            let mut overlay = Overlay::new();
            for lower in options.overlay_lowers {
                overlay = overlay.lower(lower);
            }
            if let Some(upper) = options.overlay_upper {
                overlay = overlay.upper(upper);
            }
            if let Some(work) = options.overlay_work {
                overlay = overlay.work(work);
            }
            builder = builder.overlay(overlay);
        }
        let mut command_line = options.command_line.into_iter();
        if let Some(command) = command_line.next() {
            builder = builder.command(PathBuf::from(command)).args(command_line);
        }
        if let Some(base) = options.base_env {
            builder = builder.base_env(base);
        }
        // Since `envs` appends (last-wins), adding the host TERM
        // unconditionally would override the profile's, so it is added only
        // when neither the profile nor --setenv sets TERM.
        let mut env = options.setenv;
        let setenv_sets_term = env.iter().any(|(key, _)| key.to_str() == Some("TERM"));
        if let Some(term) = passed_term(
            builder.get_base_env(),
            profile_sets_term || setenv_sets_term,
            std::env::var_os("TERM"),
        ) {
            env.push((OsString::from("TERM"), term));
        }
        builder = builder.envs(env);
        // One sequence, so a `--raw-mount` written between two `--bind` flags
        // is applied between them.
        builder = builder.mounts(options.mounts);
        for (resource, soft, hard) in options.rlimits {
            builder = builder.rlimit(resource, soft, hard);
        }
        if let Some(map) = options.identity_map {
            builder = builder.identity_map(map);
        }
        if let Some(identity) = options.run_as {
            builder = builder.run_as(identity);
        }
        if let Some(identity) = options.present_as {
            builder = builder.present_as(identity);
        }
        if let Some(enabled) = options.path_lookup {
            builder = builder.path_lookup(enabled);
        }
        if let Some(hostname) = options.hostname {
            builder = builder.hostname(hostname);
        }
        if let Some(chdir) = options.chdir {
            builder = builder.current_dir(chdir);
        }
        if let Some(stdin) = options.stdin {
            builder = builder.stdin(stdin);
        }
        if let Some(network) = options.network {
            builder = builder.network(network);
        }
        if let Some(isolate) = options.pid_namespace {
            builder = builder.pid_namespace(isolate);
        }
        if let Some(mount) = options.mount_proc {
            builder = builder.mount_proc(mount);
        }
        if let Some(mount) = options.mount_dev {
            builder = builder.mount_dev(mount);
        }
        if let Some(mount) = options.mount_tmp {
            builder = builder.mount_tmp(mount);
        }
        if let Some(bind) = options.resolv_conf {
            builder = builder.resolv_conf(bind);
        }
        if let Some(managed) = options.managed_mounts {
            builder = builder.managed_mounts(managed);
        }
        if let Some(tie) =
            stop_with_caller_default(options.stop_with_caller, profile_sets_stop_with_caller)
        {
            builder = builder.stop_with_caller(tie);
        }
        for (path, writable) in options.landlock {
            builder = builder.landlock_fs(landlock_access(writable), path);
        }
        for (port, access) in options.landlock_net {
            builder = builder.landlock_net(access, port);
        }
        if let Some(scopes) = options.landlock_scope {
            builder = builder.landlock_scope(scopes);
        }
        if let Some(policy) = seccomp {
            builder = builder.seccomp(policy);
        }
        match options.caps {
            Some(CapsChoice::DropAll) => builder = builder.drop_all_capabilities(),
            Some(CapsChoice::Keep(caps)) => builder = builder.keep_capabilities(caps),
            None => {}
        }

        // The native stack composes the sandbox's DNS from the host's own,
        // where the stack forwards to one of its nameservers, unless the run
        // opts out. --no-managed-mounts opts out as surely as --no-resolv-conf
        // does: its promise is that the sandbox carries exactly the binds the
        // command line names, and this would be one it does not.
        //
        // The builder is asked rather than the flags, so that a profile
        // setting either toggle governs this composition exactly as the
        // matching flag does. Both have already been applied above.
        //
        // The same getter folds in the caller's own claim on the target: a
        // mount of theirs at `/etc/resolv.conf`, or a host tree of theirs over
        // `/etc`, which this composition yields to exactly as the library's own
        // bind for a host-network sandbox does.
        if let Some(stack) = &stack
            && builder.get_resolv_conf()
        {
            builder = compose_netstack_resolv_conf(builder, stack)
                .map_err(|output::ReaderGone| ExitCode::from(output::broken_pipe()))?;
        }

        // Every launch hands the sandbox `fcage`'s own standard streams, unless
        // a terminal replaces all three, so each is judged now and any that is a
        // file is relayed once the launch starts. A terminal without the
        // network stack is driven by the library's terminal launch, which
        // takes no stream of `fcage`'s at all.
        let streams = if options.terminal && stack.is_none() {
            None
        } else {
            Some(judge_streams(&builder, &CAGE_STREAMS, options.terminal)?)
        };

        Ok(Launch {
            builder,
            stack,
            streams,
            terminal: options.terminal,
            timeout: options.timeout,
            kill_after: options.kill_after,
            publications: options.netstack_publish,
        })
    }

    /// Starts the launch's stream relays, builds the sandbox, and runs it.
    fn run(self) -> ExitCode {
        let Launch {
            builder,
            stack,
            streams,
            terminal,
            timeout,
            kill_after,
            publications,
        } = self;
        let Some(judged) = streams else {
            return run_on_a_terminal(builder, timeout, kill_after);
        };
        let (builder, relay) = match route_streams(builder, judged, &CAGE_STREAMS) {
            Ok(routed) => routed,
            Err(code) => return code,
        };
        if let Some(stack) = stack {
            return run_with_netstack(
                builder,
                stack,
                &publications,
                terminal,
                timeout,
                kill_after,
                relay,
            );
        }
        let outcome = builder
            .build()
            .and_then(|cage| cage.spawn())
            .and_then(|running| wait_with_deadline(running, timeout, kill_after));
        finish(relay, outcome.map_err(Failure::from))
    }
}

/// The host's `TERM`, where a launch passes it to the command.
///
/// It passes through so an interactive command works at a prompt, as a
/// fallback beneath the base environment: `named` says a profile or `--setenv`
/// gives TERM a value of its own, which wins. A run without the base
/// environment asked for exactly the variables it names, so it gets none, and
/// a run meant to be hermetic does not vary with the caller's terminal.
fn passed_term(base_env: bool, named: bool, host: Option<OsString>) -> Option<OsString> {
    host.filter(|_| base_env && !named)
}

/// Reports a usage error found once a launch's inputs are read, such as a
/// profile that contradicts a flag, and returns [`USAGE`].
fn usage_error(message: std::fmt::Arguments<'_>) -> ExitCode {
    output::report(format_args!("fcage: {message}"));
    output::report(format_args!("Try 'fcage --help' for usage."));
    ExitCode::from(USAGE)
}

/// A launch builder's three standard-stream settings, in stream order: the
/// getter that reads each and the setter that replaces it.
///
/// [`CageBuilder`] and [`RestrictionBuilder`] spell the three alike, so one
/// wiring serves both.
struct StreamSettings<B> {
    /// Each stream's disposition as the builder holds it.
    get: [fn(&B) -> &Stdio; 3],
    /// Each stream's setter.
    set: [fn(B, Stdio) -> B; 3],
}

/// [`CageBuilder`]'s three standard-stream settings.
const CAGE_STREAMS: StreamSettings<CageBuilder> = StreamSettings {
    get: [
        CageBuilder::get_stdin,
        CageBuilder::get_stdout,
        CageBuilder::get_stderr,
    ],
    set: [CageBuilder::stdin, CageBuilder::stdout, CageBuilder::stderr],
};

/// [`RestrictionBuilder`]'s three standard-stream settings.
const RESTRICTION_STREAMS: StreamSettings<RestrictionBuilder> = StreamSettings {
    get: [
        RestrictionBuilder::get_stdin,
        RestrictionBuilder::get_stdout,
        RestrictionBuilder::get_stderr,
    ],
    set: [
        RestrictionBuilder::stdin,
        RestrictionBuilder::stdout,
        RestrictionBuilder::stderr,
    ],
};

/// Judges `fcage`'s standard streams for a launch, starting nothing.
///
/// A stream the builder leaves inherited is handed over as `fcage` holds it,
/// unless `terminal` says a pseudoterminal replaces all three. The builder is
/// asked rather than the flags, so a profile's stream settings count exactly as
/// `--stdin` does. A refused stream is reported here and ends the run with
/// [`FAILED`] before anything is provisioned or launched.
fn judge_streams<B>(
    builder: &B,
    streams: &StreamSettings<B>,
    terminal: bool,
) -> Result<streams::Judged, ExitCode> {
    let inherited = if terminal {
        [false; 3]
    } else {
        streams
            .get
            .map(|get| matches!(get(builder), Stdio::Inherit))
    };
    streams::Judged::streams(inherited).map_err(fail)
}

/// Starts the relays a judgement calls for, and routes each relayed stream of
/// `builder` through its relay. A relay that cannot start is reported here and
/// ends the run with [`FAILED`] before anything is launched.
fn route_streams<B>(
    builder: B,
    judged: streams::Judged,
    streams: &StreamSettings<B>,
) -> Result<(B, streams::StreamRelay), ExitCode> {
    let mut relay = judged.start().map_err(fail)?;
    let mut builder = builder;
    for (replacement, set) in relay.take_replacements().into_iter().zip(streams.set) {
        if let Some(stdio) = replacement {
            builder = set(builder, stdio);
        }
    }
    Ok((builder, relay))
}

/// Settles a run that relayed its streams: the relays first, then the outcome.
fn finish(relay: streams::StreamRelay, outcome: Result<Option<ExitStatus>, Failure>) -> ExitCode {
    let delivered = settle(relay);
    settled_code(outcome, delivered)
}

/// Stops the stream relays, and reports each one that failed. Returns whether
/// every relay delivered.
///
/// Called before `fcage` prints anything about how the run ended, so that its
/// own words land after the command's last bytes in a relayed file. A relay
/// that failed lost output the command believed delivered, or could not return
/// the input the command did not read, which is a failure of `fcage` rather
/// than of the command.
fn settle(relay: streams::StreamRelay) -> bool {
    let failures = relay.finish();
    for (streams, error) in &failures {
        output::report(format_args!(
            "fcage: relaying the command's {streams}: {}",
            ErrorChain::new(error)
        ));
    }
    failures.is_empty()
}

/// Maps a settled run onto the process exit status: the outcome's own, or
/// [`FAILED`] where a relay failed, whatever the command's status was.
fn settled_code(outcome: Result<Option<ExitStatus>, Failure>, delivered: bool) -> ExitCode {
    let code = conclude(outcome);
    if delivered {
        code
    } else {
        ExitCode::from(FAILED)
    }
}

/// Runs a sandbox on a pseudoterminal of its own and relays the caller's
/// terminal to it.
///
/// The signals the relay reads are blocked first, before anything else the run
/// may start, so no thread of this process is left able to take one; raw mode is
/// entered last, inside the relay, so every failure up to that point leaves the
/// caller's terminal untouched.
fn run_on_a_terminal(
    builder: CageBuilder,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> ExitCode {
    let signals = match Signals::install() {
        Ok(signals) => signals,
        Err(error) => return conclude(Err(error.into())),
    };
    let launched = builder
        .build()
        .and_then(|cage| cage.spawn_terminal(&terminal::terminal_for_caller()));
    let (running, pty) = match launched {
        Ok(launched) => launched,
        Err(error) => return conclude(Err(error.into())),
    };
    conclude(terminal::relay(running, pty, signals, timeout, kill_after).map_err(Failure::from))
}

/// Assembles the native network stack the `--netstack-*` flags describe.
///
/// Built before the sandbox is, so a configuration the stack refuses -- a
/// prefix outside its range, an MTU below the floor IPv6 raises, an interface
/// name the kernel would not take, both protocols turned off -- is reported
/// without a sandbox having been created and torn down for it. Building the
/// stack starts nothing: the pump thread is `attach`'s, and the relay's signal
/// mask has to be in place before it exists.
fn netstack_from(options: &Options) -> Result<NetStack, ferroday_cage::NetStackError> {
    let mut stack = NetStack::builder()
        .ipv4(!options.netstack_no_ipv4)
        .ipv6(!options.netstack_no_ipv6)
        .host_loopback(options.netstack_host_loopback);
    for port in &options.netstack_host_ports {
        stack = stack.host_loopback_port(*port);
    }
    for (host, guest_port) in &options.netstack_publish {
        stack = stack.publish(*host, *guest_port);
    }
    if let Some((network, prefix_len)) = options.netstack_cidr {
        stack = stack.ipv4_cidr(network, prefix_len);
    }
    if let Some((network, prefix_len)) = options.netstack_cidr6 {
        stack = stack.ipv6_cidr(network, prefix_len);
    }
    if let Some(name) = &options.netstack_interface {
        stack = stack.interface(name);
    }
    if let Some(mtu) = options.netstack_mtu {
        stack = stack.mtu(mtu);
    }
    stack.build()
}

/// Builds and runs a sandbox with the native network stack attached at the
/// pending seam: build, hold the command, attach the stack, then release it
/// so the network is up before the command's first instruction.
fn run_with_netstack(
    builder: CageBuilder,
    stack: NetStack,
    publications: &[(SocketAddr, u16)],
    terminal: bool,
    timeout: Option<Duration>,
    kill_after: Duration,
    relay: streams::StreamRelay,
) -> ExitCode {
    // Blocked before the stack's own thread exists, so that thread inherits the
    // mask and no process-directed signal can be delivered behind the relay's
    // back. Nothing is allocated for a run without a terminal.
    let signals = if terminal {
        match Signals::install() {
            Ok(signals) => Some(signals),
            Err(error) => return finish(relay, Err(error.into())),
        }
    } else {
        None
    };
    let cage = match builder.build() {
        Ok(cage) => cage,
        Err(error) => return finish(relay, Err(error.into())),
    };

    // Hold the command at the gate, attach the stack to the sandbox's
    // namespace, then release the command. A failed attach drops the
    // pending launch, which tears the sandbox down.
    //
    // With a terminal, the primary comes back here rather than out of
    // `proceed`: the sandbox allocates the pseudoterminal and sends its primary
    // before the command reaches the gate, so the stack is attached with the
    // primary already in hand.
    let held = if terminal {
        cage.spawn_pending_terminal(&terminal::terminal_for_caller())
            .map(|(pending, pty)| (pending, Some(pty)))
    } else {
        cage.spawn_pending().map(|pending| (pending, None))
    };
    let (pending, pty) = match held {
        Ok(held) => held,
        Err(error) => return finish(relay, Err(error.into())),
    };
    let handle = match stack.attach(&pending) {
        Ok(handle) => handle,
        Err(error) => return finish(relay, Err(Failure::Fcage(error.into()))),
    };
    // A publication that left the port to the kernel is useless until the
    // caller knows which one it got. Said before the command is released, and
    // before a terminal session takes the caller's terminal into raw mode. A
    // reader that has gone is told nothing, so the command is not released:
    // dropping the pending launch tears the sandbox down, and the stack stops
    // with it.
    for ((requested, guest_port), bound) in publications.iter().zip(handle.published()) {
        if requested.port() == 0
            && output::say(format_args!(
                "fcage: publishing the sandbox's port {guest_port} on {bound}"
            ))
            .is_err()
        {
            drop(pending);
            // A stack that does not stop cleanly has nowhere left to say so.
            let _ = handle.stop();
            return finish(relay, Err(Failure::ReaderGone));
        }
    }
    let running = match pending.proceed() {
        Ok(running) => running,
        Err(error) => return finish(relay, Err(error.into())),
    };

    // The relay when a terminal was allocated, the plain wait otherwise. Both
    // return the same outcome; only the driving differs.
    let outcome = match (pty, signals) {
        (Some(pty), Some(signals)) => {
            terminal::relay(running, pty, signals, timeout, kill_after).map_err(Failure::from)
        }
        _ => wait_with_deadline(running, timeout, kill_after).map_err(Failure::from),
    };
    let stopped = handle.stop();
    let delivered = settle(relay);
    // The stack is torn down after the command; a failure here loses no data,
    // so it is a warning, not the run's outcome. Printed after the stream
    // relays have delivered the command's output, so it lands after that
    // output, and after the terminal relay has restored the caller's terminal,
    // so it is not stair-stepped.
    if let Err(error) = stopped {
        output::report(format_args!(
            "fcage: the network stack did not stop cleanly: {}",
            ErrorChain::new(&error)
        ));
    }
    settled_code(outcome, delivered)
}

/// Composes the sandbox's `resolv.conf` for a native-stack run: binds the
/// host's `resolv.conf` read-only when it names a nameserver the stack forwards
/// to, and otherwise composes nothing and says so.
///
/// Called only where [`CageBuilder::get_resolv_conf`] holds, which folds in
/// both opt-outs and the caller's own claim on the target. A caller's mount at
/// `/etc/resolv.conf` or over `/etc` replaces this bind as it replaces the
/// library's own for a host-network sandbox.
///
/// A nameserver the stack refuses is unreachable from the sandbox, so binding a
/// file that names only such ones would produce nothing but silent DNS
/// failures. systemd-resolved's `127.0.0.53` stub is the common one, and a
/// cloud host's link-local resolver another; [`NetStack::forwards`] is the
/// stack's own answer for each.
///
/// Composing nothing leaves whatever `resolv.conf` the rootfs ships, which
/// may name a routable resolver and resolve perfectly well. The warning
/// therefore reports what was not composed; it does not predict that the
/// sandbox has no DNS, which is not this function's to know.
///
/// The warning is written before the launch, so a reader of it that has gone
/// stops the launch: [`output::ReaderGone`].
fn compose_netstack_resolv_conf(
    builder: CageBuilder,
    stack: &NetStack,
) -> Result<CageBuilder, output::ReaderGone> {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        // No host resolv.conf to compose from; leave the sandbox's as-is.
        return Ok(builder);
    };
    if names_a_forwarded_nameserver(&contents, stack) {
        return Ok(builder.bind_ro("/etc/resolv.conf", "/etc/resolv.conf"));
    }
    // The remedies are named as flags rather than as goals. This is the default
    // configuration on every systemd-resolved host, so it is the warning most
    // users of --netstack ever see, and "point it at a routable nameserver" is
    // not something anyone can type.
    output::say(format_args!(
        "fcage: the host's nameservers are all ones the network stack refuses, such as a \
         loopback or link-local address, so no resolv.conf was composed; the sandbox \
         resolves through whatever its rootfs ships"
    ))?;
    output::say(format_args!(
        "Try '--ro-bind FILE /etc/resolv.conf' with a file naming a routable nameserver, \
         which is taken in place of this composition; or '--netstack-host-loopback' with \
         the gateway address, which reaches a host resolver only when that resolver \
         listens on 127.0.0.1, not systemd-resolved's 127.0.0.53 stub; or \
         '--no-resolv-conf' to leave the rootfs's own and silence this."
    ))?;
    Ok(builder)
}

/// The port a `resolv.conf` nameserver is queried on: `resolv.conf` names no
/// port, and the resolver always asks 53.
const DNS_PORT: u16 = 53;

/// Whether a `resolv.conf` names at least one nameserver the network stack
/// forwards DNS to.
fn names_a_forwarded_nameserver(contents: &str, stack: &NetStack) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        let Some(address) = line.strip_prefix("nameserver") else {
            return false;
        };
        // The keyword and its value are separated by whitespace, and glibc
        // ignores a line that runs them together. Reading `nameserver8.8.8.8`
        // as a nameserver would count a line the resolver does not as the
        // reason this host is considered routable.
        if !address.starts_with([' ', '\t']) {
            return false;
        }
        match address.trim().parse::<std::net::IpAddr>() {
            Ok(address) => stack.forwards(SocketAddr::new(address, DNS_PORT)),
            Err(_) => false,
        }
    })
}

/// Builds and runs a restriction — the --restrict mode — mapping the outcome
/// onto the exit status exactly as the sandbox path does.
fn run_restricted(options: Options) -> ExitCode {
    if let Err(code) = withhold_from_restricted_command() {
        return code;
    }
    // The seccomp flags have no profile beneath them here, and the curated
    // posture beside an errno was refused when the command line was parsed.
    let seccomp = match compose_seccomp(options.seccomp, options.seccomp_errno, None) {
        Ok(seccomp) => seccomp,
        Err(message) => return usage_error(format_args!("{message}")),
    };
    let mut builder = Restriction::builder();
    let mut command_line = options.command_line.into_iter();
    if let Some(command) = command_line.next() {
        builder = builder.command(PathBuf::from(command)).args(command_line);
    }
    if let Some(base) = options.base_env {
        builder = builder.base_env(base);
    }
    // Set first, so a --setenv TERM overrides it.
    let mut env = options.setenv;
    if let Some(term) = passed_term(builder.get_base_env(), false, std::env::var_os("TERM")) {
        env.insert(0, (OsString::from("TERM"), term));
    }
    builder = builder.envs(env);
    if let Some(chdir) = options.chdir {
        builder = builder.current_dir(chdir);
    }
    if let Some(stdin) = options.stdin {
        builder = builder.stdin(stdin);
    }
    for (resource, soft, hard) in options.rlimits {
        builder = builder.rlimit(resource, soft, hard);
    }
    if let Some(tie) = stop_with_caller_default(options.stop_with_caller, false) {
        builder = builder.stop_with_caller(tie);
    }
    for (path, writable) in options.landlock {
        builder = builder.landlock_fs(landlock_access(writable), path);
    }
    for (port, access) in options.landlock_net {
        builder = builder.landlock_net(access, port);
    }
    if let Some(scopes) = options.landlock_scope {
        builder = builder.landlock_scope(scopes);
    }
    if let Some(policy) = seccomp {
        builder = builder.seccomp(policy);
    }

    if options.terminal {
        // The restriction's terminal comes from the host's own /dev/ptmx, the
        // one its command sees, so the fallback gets the same interactive
        // story a cage does.
        let signals = match Signals::install() {
            Ok(signals) => signals,
            Err(error) => return conclude(Err(error.into())),
        };
        let launched = builder
            .build()
            .and_then(|restriction| restriction.spawn_terminal(&terminal::terminal_for_caller()));
        let (running, pty) = match launched {
            Ok(launched) => launched,
            Err(error) => return conclude(Err(error.into())),
        };
        return conclude(
            terminal::relay(running, pty, signals, options.timeout, options.kill_after)
                .map_err(Failure::from),
        );
    }

    // As for a sandbox: each stream is judged, and one that is a file is relayed
    // rather than handed over.
    let relayed = judge_streams(&builder, &RESTRICTION_STREAMS, false)
        .and_then(|judged| route_streams(builder, judged, &RESTRICTION_STREAMS));
    let (builder, relay) = match relayed {
        Ok(relayed) => relayed,
        Err(code) => return code,
    };
    let outcome = builder
        .build()
        .and_then(|restriction| restriction.spawn())
        .and_then(|running| wait_with_deadline(running, options.timeout, options.kill_after));
    finish(relay, outcome.map_err(Failure::from))
}

/// Makes `fcage` non-dumpable for the rest of its life, ahead of a restricted
/// launch.
///
/// A restricted command runs beside `fcage`, as the same user and in the
/// host's user and PID namespaces. Reading another process's descriptors
/// through `/proc/<pid>/fd` is a ptrace read, which the kernel grants such a
/// process over a dumpable one, so the command could reopen whatever `fcage`
/// holds: the file a relayed stream copies, or the terminal a `--terminal` run
/// relays. A Landlock domain refuses that read on its own, and a seccomp-only
/// restriction does not. A non-dumpable process answers it only to a holder of
/// `CAP_SYS_PTRACE`.
///
/// The launch's own processes fork from `fcage` after this and inherit the
/// flag, which covers their copies of `fcage`'s descriptors as well. The
/// command's `execve` sets its own flag afresh.
///
/// A sandbox needs none of this, and its launch could not survive it. The
/// sandbox's command runs in a user namespace below `fcage`'s, and a ptrace read
/// of a process outside that namespace takes `CAP_SYS_PTRACE` in the target's.
/// And a non-dumpable process's identity map files belong to root, which
/// neither the launch stage writing its own map nor a `newuidmap` holding only
/// `CAP_SETUID` can open.
fn withhold_from_restricted_command() -> Result<(), ExitCode> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable).map_err(
        |errno| {
            fail(format_args!(
                "cannot withhold fcage's descriptors from a restricted command: {}",
                ErrorChain::new(&std::io::Error::from(errno)),
            ))
        },
    )
}

/// The Landlock access set a --landlock-ro or --landlock-rw grant confers.
fn landlock_access(writable: bool) -> FsAccess {
    if writable {
        FsAccess::READ | FsAccess::WRITE | FsAccess::EXECUTE
    } else {
        FsAccess::READ | FsAccess::EXECUTE
    }
}

/// Waits a launch out under the optional deadline, escalating as
/// [`Escalation`] says. `Ok(None)` means the deadline fired.
///
/// The blocking half of the two waits `fcage` has; the terminal relay drives
/// the same escalation from its poll loop.
fn wait_with_deadline(
    mut running: Running<'_>,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> Result<Option<ExitStatus>, Error> {
    let mut escalation = Escalation::new(timeout, kill_after);
    let status = loop {
        // No deadline left: either none was asked for, or the escalation has
        // run its course and only the outcome is outstanding.
        let Some(deadline) = escalation.deadline() else {
            break running.wait()?;
        };
        match running.wait_deadline(deadline)? {
            Some(status) => break status,
            None => escalation.expire(&mut running)?,
        }
    };
    Ok(escalation.outcome(status))
}

/// Why a run ended with no status of the command's to report.
enum Failure {
    /// The library failed, and its error says which exit code that is.
    Cage(Error),
    /// A part of `fcage`'s own failed, such as the network stack or the
    /// terminal relay's plumbing, which exits [`FAILED`].
    Fcage(Diagnostic),
    /// A reader of `fcage`'s own output went away before the run was done,
    /// which ends it as a writer to a closed pipe ends.
    ReaderGone,
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure::Cage(error)
    }
}

impl From<RelayError> for Failure {
    /// The sandbox failing under the terminal relay is the library's failure,
    /// so a launch that fails the same way with and without a terminal exits
    /// the same way. The relay's own plumbing failing is `fcage`'s.
    ///
    /// A relay whose write to the caller found no reader left has lost its
    /// reader, which ends the run as any write of `fcage`'s to a closed pipe
    /// does.
    fn from(error: RelayError) -> Failure {
        match error {
            RelayError::Cage(error) => Failure::Cage(error),
            RelayError::Io { source, .. } if source.kind() == std::io::ErrorKind::BrokenPipe => {
                Failure::ReaderGone
            }
            other => Failure::Fcage(other.into()),
        }
    }
}

impl Failure {
    /// Reports the failure on standard error and returns its exit code.
    fn report(self) -> ExitCode {
        match self {
            Failure::Cage(error) => {
                output::report(format_args!("fcage: {}", ErrorChain::new(&error)));
                ExitCode::from(error.shell_code())
            }
            Failure::Fcage(diagnostic) => fail(diagnostic),
            Failure::ReaderGone => ExitCode::from(output::broken_pipe()),
        }
    }
}

/// Maps a run's outcome onto the process exit status.
fn conclude(outcome: Result<Option<ExitStatus>, Failure>) -> ExitCode {
    match outcome {
        // The timeout(1) convention: 124 announces an expired timeout,
        // whatever became of the command afterwards.
        Ok(None) => ExitCode::from(TIMED_OUT),
        Ok(Some(status)) => ExitCode::from(status.shell_code()),
        Err(failure) => failure.report(),
    }
}

/// Reads the plan document a `--*-plan` or `--*-pin` flag names and parses it
/// with `parse`.
///
/// The parse is each userland's own -- three formats, three `Plan` types, three
/// `parse_document` functions -- but reading the file and saying what stopped it
/// is one question, and its answer names the path the caller typed rather than
/// the layer that could not read it. Both failures are environment failures, so
/// both are 125.
fn plan_from<P, E: std::error::Error + 'static>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<P, E>,
) -> Result<P, ExitCode> {
    let document = std::fs::read_to_string(path).map_err(|error| {
        fail(format_args!(
            "reading {}: {}",
            path.display(),
            ErrorChain::new(&error)
        ))
    })?;
    parse(&document).map_err(|error| {
        fail(format_args!(
            "{}: {}",
            path.display(),
            ErrorChain::new(&error)
        ))
    })
}

/// The provisioner a `--provision-*` flag configures, built, or `None` for a
/// run that provisions nothing.
///
/// Built before anything else a run does. A configuration the layer refuses, a
/// plan or pin document that does not read, and a key set this machine cannot
/// supply are each reported before a launch is composed, and before a
/// bootstrap spends minutes on a root that would then go unused.
fn provisioner(options: &Options) -> Result<Option<Box<dyn Provisioner>>, ExitCode> {
    if let Some(tarball) = &options.provision_tar {
        return Ok(Some(Box::new(ferroday_cage::provision::Tarball::new(
            tarball,
        ))));
    }
    if let Some(suite) = &options.provision_debian {
        return Ok(Some(Box::new(debian_provisioner(suite, options)?)));
    }
    if let Some(release) = &options.provision_alpine {
        return Ok(Some(Box::new(alpine_provisioner(release, options)?)));
    }
    if let Some(architecture) = &options.provision_gentoo {
        return Ok(Some(Box::new(gentoo_provisioner(architecture, options)?)));
    }
    Ok(None)
}

/// Publishes a root filesystem at `rootfs` through `provisioner`, reporting its
/// progress on standard error.
///
/// An existing directory is reused as it stands. A reader of the progress that
/// goes away stops the run at the provisioner's next clean point, which leaves
/// no destination behind, and the run exits 141. So does a run that finished
/// before it reached such a point, since the reader left before the run did.
fn provision(rootfs: &Path, provisioner: &mut dyn Provisioner) -> Result<Provisioned, ExitCode> {
    let mut progress = Progress::new(std::io::stderr());
    let published = ferroday_cage::provision::Provision::new(rootfs)
        .observe(&mut progress)
        .run(provisioner);
    match published {
        Ok(_) | Err(ProvisionError::Cancelled) if progress.gone => {
            Err(ExitCode::from(output::broken_pipe()))
        }
        Ok(provisioned) => Ok(provisioned),
        Err(error) => Err(fail(error)),
    }
}

/// What a provisioning run reports as it goes: each userland's progress, and
/// the output of the commands its bootstrap runs in a cage. Also whether the
/// run should stop, which it should once nothing reads what it reports.
///
/// Generic over where the report goes so that a test can hand it a pipe whose
/// reader has gone; a run hands it standard error.
struct Progress<W> {
    out: W,
    /// Whether a write found the reader gone. Nothing more is written once it
    /// has, and the run is asked to stop.
    gone: bool,
}

impl<W: std::io::Write> Progress<W> {
    fn new(out: W) -> Progress<W> {
        Progress { out, gone: false }
    }

    /// Writes one line of progress.
    fn line(&mut self, line: std::fmt::Arguments<'_>) -> Result<(), output::ReaderGone> {
        output::say_to(&mut self.out, line)
    }

    /// Reports a Debian bootstrap's step.
    fn debian(
        &mut self,
        event: &ferroday_cage::provision::debian::DebianEvent<'_>,
    ) -> Result<(), output::ReaderGone> {
        use ferroday_cage::provision::debian::DebianEvent;
        match event {
            DebianEvent::Fetching { url, .. } => self.line(format_args!("fcage: fetching {url}")),
            DebianEvent::Resolving => self.line(format_args!("fcage: resolving the package set")),
            DebianEvent::Unsatisfiable {
                requirement,
                required_by,
                reason,
                ..
            } => self.line(format_args!(
                "fcage: {required_by} requires {requirement}, and {reason}"
            )),
            DebianEvent::Downloading {
                package,
                index,
                total,
                ..
            } => self.line(format_args!(
                "fcage: downloading {package} ({index}/{total})"
            )),
            DebianEvent::Extracting { package, .. } => {
                self.line(format_args!("fcage: extracting {package}"))
            }
            // dpkg's own output passes straight through.
            DebianEvent::CommandOutput { bytes, .. } => output::pass_to(&mut self.out, bytes),
            _ => Ok(()),
        }
    }

    /// Reports an Alpine bootstrap's step, in the same shape as a Debian one's,
    /// which is the point of
    /// [`AlpineEvent`](ferroday_cage::provision::alpine::AlpineEvent) carrying
    /// the same progress.
    fn alpine(
        &mut self,
        event: &ferroday_cage::provision::alpine::AlpineEvent<'_>,
    ) -> Result<(), output::ReaderGone> {
        use ferroday_cage::provision::alpine::AlpineEvent;
        match event {
            AlpineEvent::Fetching { url, .. } => self.line(format_args!("fcage: fetching {url}")),
            AlpineEvent::Resolving => self.line(format_args!("fcage: resolving the package set")),
            AlpineEvent::Downloading {
                package,
                index,
                total,
                ..
            } => self.line(format_args!(
                "fcage: downloading {package} ({index}/{total})"
            )),
            AlpineEvent::Extracting { package, .. } => {
                self.line(format_args!("fcage: extracting {package}"))
            }
            AlpineEvent::Script {
                package, script, ..
            } => self.line(format_args!("fcage: {package}: {script}")),
            // An install script's own output passes straight through.
            AlpineEvent::CommandOutput { bytes, .. } => output::pass_to(&mut self.out, bytes),
            _ => Ok(()),
        }
    }
}

impl<W: std::io::Write> Progress<W> {
    /// Reports a Gentoo bootstrap's step, as the other layers do.
    fn gentoo(
        &mut self,
        event: &ferroday_cage::provision::gentoo::GentooEvent<'_>,
    ) -> Result<(), output::ReaderGone> {
        use ferroday_cage::provision::gentoo::GentooEvent;
        match event {
            GentooEvent::Fetching { url, .. } => self.line(format_args!("fcage: fetching {url}")),
            GentooEvent::Resolved { stage3, .. } => self.line(format_args!(
                "fcage: resolved {} to build {} ({} bytes), vouched for by {}",
                stage3.variant(),
                stage3.build_id(),
                stage3.size(),
                stage3.certificate(),
            )),
            GentooEvent::Verifying { path, .. } => {
                self.line(format_args!("fcage: verifying {}", path.display()))
            }
            GentooEvent::Extracting { path, .. } => {
                self.line(format_args!("fcage: extracting {}", path.display()))
            }
            GentooEvent::Index {
                builds,
                skipped,
                generated,
                ..
            } => self.line(format_args!(
                "fcage: the binhost index names {builds} builds{}{}",
                match skipped {
                    0 => String::new(),
                    skipped => format!(", {skipped} of which this layer cannot act on"),
                },
                generated.map_or_else(String::new, |at| format!(", generated at {at}")),
            )),
            GentooEvent::Planned {
                packages, bytes, ..
            } => self.line(format_args!(
                "fcage: installing {packages} packages ({bytes} bytes)"
            )),
            GentooEvent::Merging {
                package, version, ..
            } => self.line(format_args!("fcage: merging {package}-{version}")),
            GentooEvent::DependencyCycle { packages, .. } => self.line(format_args!(
                "fcage: a runtime dependency cycle among {} was broken to order the merge",
                packages.join(", "),
            )),
            // Reported before the run fails, so a caller fixing an install list
            // sees every atom the binhost cannot answer rather than the first.
            GentooEvent::Unsatisfiable {
                atom,
                wanted_by,
                reason,
                ..
            } => self.line(format_args!(
                "fcage: {wanted_by} requires {atom}, and no build {reason}"
            )),
            GentooEvent::Conflict {
                atom,
                stated_by,
                blocks,
                installed,
                ..
            } => self.line(format_args!(
                "fcage: {stated_by} blocks {blocks} with {atom}, which {}",
                if *installed {
                    "the root already has"
                } else {
                    "this same resolution would install"
                },
            )),
            _ => Ok(()),
        }
    }
}

impl<W: std::io::Write> ferroday_cage::provision::ProvisionObserver for Progress<W> {
    fn progress(&mut self, event: ProvisionEvent<'_>) {
        if self.gone {
            return;
        }
        let written = match event {
            ProvisionEvent::Debian(event) => self.debian(event),
            ProvisionEvent::Alpine(event) => self.alpine(event),
            ProvisionEvent::Gentoo(event) => self.gentoo(event),
            _ => Ok(()),
        };
        self.gone = written.is_err();
    }

    fn cancelled(&mut self) -> bool {
        self.gone
    }
}

/// The Debian bootstrap the `--debian-*` flags configure, built.
fn debian_provisioner(
    suite: &str,
    options: &Options,
) -> Result<ferroday_cage::provision::debian::Debian, ExitCode> {
    use ferroday_cage::provision::debian::{Debian, Plan};

    let mut builder = Debian::builder(suite).extract_only(options.debian_extract_only);
    if let Some(arch) = &options.debian_arch {
        builder = builder.architecture(arch.as_str());
    }
    if let Some(mirror) = &options.debian_mirror {
        builder = builder.mirror(mirror.as_str());
    }
    if !options.debian_components.is_empty() {
        builder = builder.components(options.debian_components.clone());
    }
    if !options.debian_include.is_empty() {
        builder = builder.include(options.debian_include.clone());
    }
    if !options.debian_exclude.is_empty() {
        builder = builder.exclude(options.debian_exclude.clone());
    }
    if let Some(path) = &options.debian_plan {
        builder = builder.plan(plan_from(path, Plan::parse_document)?);
    }
    if let Some(path) = &options.debian_pin {
        builder = builder.pin(plan_from(path, Plan::parse_document)?);
    }
    if let Some(cache) = &options.debian_cache {
        builder = builder.cache_dir(cache);
    }
    if let Some(keyring) = &options.debian_keyring {
        builder = builder.keyring(keyring);
    }
    for fallback in &options.debian_mirror_fallback {
        builder = builder.mirror_fallback(fallback.as_str());
    }
    if let Some(priority) = options.debian_base_priority {
        builder = builder.base_priority(priority);
    }
    if options.debian_trust_unsigned {
        builder = builder.trust_unsigned(true);
    }
    if options.debian_allow_stale_release {
        builder = builder.allow_stale_release(true);
    }
    if let Some(overlay) = &options.debian_pre_configure_overlay {
        builder = builder.pre_configure_overlay(overlay);
    }
    if let Some(epoch) = options.debian_source_date_epoch {
        builder = builder.source_date_epoch(epoch);
    }
    if let Some(map) = &options.debian_identity_map {
        builder = builder.identity_map(map.clone());
    }
    for repository in &options.debian_repositories {
        builder = builder.repository(repository.clone());
    }

    builder.build().map_err(fail)
}

/// The Alpine bootstrap the `--alpine-*` flags configure, built.
///
/// Mirrors [`debian_provisioner`] flag for flag where the two layers agree.
/// Where they do not, the difference is the archive's: apk publishes no
/// priority band, so there is no base-set floor and the install set is exactly
/// what `--alpine-include` names closed over its dependencies; and it has no
/// unsigned mode and no freshness window, so there is nothing for a
/// `--debian-*` counterpart of `trust-unsigned` or `allow-stale-release` to
/// relax.
fn alpine_provisioner(
    release: &str,
    options: &Options,
) -> Result<ferroday_cage::provision::alpine::Alpine, ExitCode> {
    use ferroday_cage::provision::alpine::{Alpine, Plan, Repository};

    let usage = |message: String| usage_error(format_args!("{message}"));
    // The architecture the key sets are chosen by: the one named, or the host's,
    // which is what the builder would default to.
    let architecture = options
        .alpine_arch
        .clone()
        .unwrap_or_else(ferroday_cage::provision::alpine::host_architecture);

    let mut builder = Alpine::builder(release)
        .architecture(&architecture)
        .extract_only(options.alpine_extract_only);
    if let Some(mirror) = &options.alpine_mirror {
        builder = builder.mirror(mirror);
    }
    for fallback in &options.alpine_mirror_fallback {
        builder = builder.mirror_fallback(fallback);
    }
    if !options.alpine_components.is_empty() {
        builder = builder.components(options.alpine_components.clone());
    }
    if !options.alpine_include.is_empty() {
        builder = builder.include(options.alpine_include.clone());
    }
    if !options.alpine_exclude.is_empty() {
        builder = builder.exclude(options.alpine_exclude.clone());
    }
    if let Some(path) = &options.alpine_plan {
        builder = builder.plan(plan_from(path, Plan::parse_document)?);
    }
    if let Some(path) = &options.alpine_pin {
        builder = builder.pin(plan_from(path, Plan::parse_document)?);
    }
    if let Some(cache) = &options.alpine_cache {
        builder = builder.cache_dir(cache);
    }
    // Reading a key set is not spelling: the selector was checked when the
    // command line was parsed, so what is left is whether this machine can
    // supply the keys — an unreadable directory, a file that is not a PEM key,
    // a bundle holding none for the architecture. Those fail, as the library
    // reports the same failures when it resolves the keys itself, where a
    // repository spelled wrong is a usage error. A script telling "fix my
    // command line" from "fix my machine" reads the two codes.
    if let Some(keys) = &options.alpine_keys {
        builder = builder.keys(alpine_key_set("--alpine-keys", keys, &architecture).map_err(fail)?);
    }
    if let Some(overlay) = &options.alpine_pre_configure_overlay {
        builder = builder.pre_configure_overlay(overlay);
    }
    if let Some(map) = &options.alpine_identity_map {
        builder = builder.identity_map(map.clone());
    }
    if let Some(epoch) = options.alpine_source_date_epoch {
        builder = builder.source_date_epoch(epoch);
    }
    for spec in &options.alpine_repositories {
        let mut repository = Repository::builder(&spec.release)
            .keys(alpine_key_set("--alpine-repository", &spec.keys, &architecture).map_err(fail)?);
        if let Some(primary) = &spec.mirror {
            repository = repository.mirror(primary);
        }
        for fallback in &spec.fallbacks {
            repository = repository.mirror_fallback(fallback);
        }
        if !spec.components.is_empty() {
            repository = repository.components(spec.components.clone());
        }
        builder =
            builder.repository(repository.build().map_err(|error| {
                usage(format!("--alpine-repository: {}", ErrorChain::new(&error)))
            })?);
    }

    builder.build().map_err(fail)
}

/// The Gentoo bootstrap the `--gentoo-*` flags configure, built.
///
/// A run is two waves where the other two layers have one of a different shape:
/// the stage3 is extracted, and then the binary packages `--gentoo-install`
/// names are resolved against the root that produced and merged into it. A
/// command line that names no package does exactly the first: a stage3
/// bootstrap and nothing more.
fn gentoo_provisioner(
    architecture: &str,
    options: &Options,
) -> Result<ferroday_cage::provision::gentoo::Gentoo, ExitCode> {
    use ferroday_cage::provision::gentoo::{Gentoo, Plan};

    let mut builder = Gentoo::builder(architecture);
    if let Some(variant) = &options.gentoo_variant {
        builder = builder.variant(variant);
    }
    if let Some(binhost) = &options.gentoo_binhost {
        builder = builder.binhost(binhost);
    }
    if !options.gentoo_install.is_empty() {
        builder = builder.install(&options.gentoo_install);
    }
    if !options.gentoo_prefer_use.is_empty() {
        builder = builder.prefer_use(&options.gentoo_prefer_use);
    }
    if let Some(path) = &options.gentoo_plan {
        builder = builder.plan(plan_from(path, Plan::parse_document)?);
    }
    if let Some(build_id) = &options.gentoo_build_id {
        builder = builder.build_id(build_id);
    }
    if let Some(mirror) = &options.gentoo_mirror {
        builder = builder.mirror(mirror);
    }
    for fallback in &options.gentoo_mirror_fallback {
        builder = builder.mirror_fallback(fallback);
    }
    if let Some(cache) = &options.gentoo_cache {
        builder = builder.cache_dir(cache);
    }
    if let Some(age) = options.gentoo_max_pointer_age {
        builder = builder.max_pointer_age(age.map(days));
    }

    builder.build().map_err(fail)
}

/// A count of days as a duration.
fn days(count: u64) -> std::time::Duration {
    std::time::Duration::from_secs(count.saturating_mul(24 * 60 * 60))
}

/// Prints the stage3 variants an architecture publishes, from the signed
/// enumeration.
fn gentoo_variants(
    architecture: &str,
    mirror: Option<&str>,
    fallbacks: &[String],
    max_pointer_age: Option<Option<u64>>,
) -> ExitCode {
    use ferroday_cage::provision::gentoo::Gentoo;

    // Configured exactly as a provisioning run configures the same layer, so a
    // command line that lists an architecture's variants and one that installs
    // one of them read the same archive.
    let mut builder = Gentoo::builder(architecture);
    if let Some(mirror) = mirror {
        builder = builder.mirror(mirror);
    }
    for fallback in fallbacks {
        builder = builder.mirror_fallback(fallback);
    }
    if let Some(age) = max_pointer_age {
        builder = builder.max_pointer_age(age.map(days));
    }
    let mut gentoo = match builder.build() {
        Ok(gentoo) => gentoo,
        Err(error) => return fail(error),
    };
    let variants = match gentoo.variants() {
        Ok(variants) => variants,
        Err(error) => return fail(error),
    };
    // The build id belongs beside the variant rather than in a heading: a
    // sub-architecture is built on its own cadence, so one document routinely
    // points different variants at different builds.
    output::print_stdout("the variant listing", |out| {
        for variant in variants.names() {
            let build = variants.build_id(variant).unwrap_or("");
            let size = variants.size(variant).unwrap_or(0);
            writeln!(out, "{variant}\t{build}\t{size}")?;
        }
        Ok(())
    })
}

/// Prints what the binhost publishes: every package name and its versions.
fn gentoo_packages(
    architecture: &str,
    binhost: Option<&str>,
    mirror: Option<&str>,
    fallbacks: &[String],
) -> ExitCode {
    use ferroday_cage::provision::gentoo::Gentoo;

    // Configured exactly as a provisioning run configures the same layer, so a
    // command line that lists what a binhost offers and one that installs from
    // it read the same archive.
    let mut builder = Gentoo::builder(architecture);
    if let Some(binhost) = binhost {
        builder = builder.binhost(binhost);
    }
    if let Some(mirror) = mirror {
        builder = builder.mirror(mirror);
    }
    for fallback in fallbacks {
        builder = builder.mirror_fallback(fallback);
    }
    let mut gentoo = match builder.build() {
        Ok(gentoo) => gentoo,
        Err(error) => return fail(error),
    };
    let catalogue = match gentoo.packages() {
        Ok(catalogue) => catalogue,
        Err(error) => return fail(error),
    };
    // One line per package, its versions after it: a name is what a caller
    // writes in an atom, and the versions are what tells them whether the one
    // they meant is on offer.
    output::print_stdout("the package listing", |out| {
        for name in catalogue.names() {
            let versions: Vec<&str> = catalogue.versions(name).collect();
            writeln!(out, "{name}\t{}", versions.join(" "))?;
        }
        Ok(())
    })
}

/// Prints what the Gentoo root at `root` already has installed.
///
/// An empty listing is reported on stderr rather than left as silence. The
/// library answers "no packages" for a root whose `/var/db/pkg` is absent,
/// which is a true answer about a directory that is not there and also exactly
/// what a mistyped path or a root of some other distribution produces. The
/// listing itself stays on stdout and the exit stays 0, because nothing failed;
/// what the note adds is that the reader learns the answer was empty rather
/// than inferring it from a blank screen.
fn gentoo_installed(root: &Path) -> ExitCode {
    let installed = match ferroday_cage::provision::gentoo::installed(root) {
        Ok(installed) => installed,
        Err(error) => return fail(error),
    };
    // Said before the listing, so a reader that has gone stops it there.
    if installed.is_empty()
        && output::say(format_args!(
            "fcage: no packages are installed at {}: its package database is empty or \
             absent, and an absent one is what a root that is not a Gentoo root looks like",
            root.display(),
        ))
        .is_err()
    {
        return ExitCode::from(output::broken_pipe());
    }
    output::print_stdout("the installed listing", |out| {
        for package in installed.packages() {
            writeln!(
                out,
                "{}-{}\t{}\t{}",
                package.name(),
                package.version(),
                package.slot(),
                package.use_flags().collect::<Vec<_>>().join(" "),
            )?;
        }
        Ok(())
    })
}

/// Prints what each certificate of the vendored Gentoo keyring can still be
/// trusted to do, and until when.
fn gentoo_keyring_horizon() -> ExitCode {
    use ferroday_cage::provision::gentoo::{Expiry, Gentoo};

    // The architecture is a coordinate the keyring knows nothing about, and a
    // listing reads no archive, so any well-formed one names the same keyring.
    let gentoo = match Gentoo::builder("amd64").build() {
        Ok(gentoo) => gentoo,
        Err(error) => return fail(error),
    };
    let horizon = gentoo.keyring_horizon();
    output::print_stdout("the keyring horizon", |out| {
        for held in &horizon {
            writeln!(
                out,
                "{}\t{}\t{}\t{}",
                held.fingerprint,
                if held.signs { "signs" } else { "cannot-sign" },
                match held.expires {
                    Expiry::At(at) => at.to_string(),
                    Expiry::Never => "never".to_string(),
                    // No date established, and any reading added later that
                    // is not one.
                    _ => "unknown".to_string(),
                },
                held.user_id.as_deref().unwrap_or(""),
            )?;
        }
        // The spread, and deliberately not a single date to act on. Every
        // certificate in the keyring is an equally trusted anchor, so which one
        // signs a given document is the archive's choice rather than a property
        // this command can read: reducing the list to its earliest expiry
        // reports the keyring as nearly stale whenever the keyring holds a
        // short-dated certificate nothing currently signs with. The per-
        // certificate lines above are the answer, and this says how far apart
        // they run so a reader knows whether reading them matters.
        let signing = horizon.iter().filter(|held| held.signs).count();
        let mut dated = horizon.iter().filter_map(|held| held.expires.epoch());
        let bounds = dated.next().map(|first| {
            dated.fold((first, first), |(low, high), at| {
                (low.min(at), high.max(at))
            })
        });
        writeln!(
            out,
            "{} certificates, {signing} can sign\t{}",
            horizon.len(),
            match bounds {
                Some((low, high)) if low == high => format!("all expiring {low}"),
                Some((low, high)) => format!("expiring between {low} and {high}"),
                None => "none carrying an expiry".to_string(),
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses an argument list given as string slices.
    fn parse_args(args: &[&str]) -> Result<Invocation, String> {
        parse(args.iter().map(OsString::from))
    }

    /// The usage error `args` produces, panicking if it is accepted instead.
    fn parse_error(args: &[&str]) -> String {
        match parse_args(args) {
            Err(message) => message,
            Ok(_) => panic!("{args:?} should be refused"),
        }
    }

    #[test]
    fn a_misspelled_flag_suggests_the_one_it_was_meant_to_be() {
        // With this many flags, several sharing long prefixes, a report that
        // says only that an option is unrecognized leaves the reader to find
        // the difference by eye.
        for (typed, meant) in [
            ("--rootsf", "--rootfs"),
            ("--seccomp-alow", "--seccomp-allow"),
            ("--no-prc", "--no-proc"),
            ("--bnid", "--bind"),
            ("--debian-includ", "--debian-include"),
            // A flag typed short: too far in edit distance on a long name,
            // caught by the prefix rule instead.
            ("--netstack-host-loop", "--netstack-host-loopback"),
            // A counterpart named only in the closing prose is still offered,
            // because the candidates come from the whole help text.
            ("--managed-mount", "--managed-mounts"),
        ] {
            let error = parse_error(&[typed]);
            assert!(
                error.contains(&format!("Try 'fcage {meant}'.")),
                "{typed} should have suggested {meant}, got {error:?}",
            );
            assert!(error.contains(typed), "the report drops what was typed");
        }
    }

    #[test]
    fn a_joined_value_does_not_hide_the_flag_it_misspells() {
        // `--flag=value` names its flag before the `=`. Weighing the whole
        // argument against the roster compares a value against flag names and
        // finds nothing near, so the one form of an option draws a suggestion
        // and the other does not.
        let error = parse_error(&["--rootsf=/srv/alpine"]);
        assert!(
            error.contains("Try 'fcage --rootfs'."),
            "the joined form drew no suggestion: {error:?}",
        );
    }

    #[test]
    fn an_option_of_another_mode_names_that_mode() {
        // The candidates come from the whole help, which documents every mode,
        // so a launch would otherwise answer `--export-to` with `--export-to`.
        for typed in ["--export-to", "--export-to=out.tar", "--clamp-mtime"] {
            let error = parse_error(&["--rootfs", "/srv/alpine", typed, "/bin/sh"]);
            assert!(
                error.contains("is an option of --export-rootfs"),
                "{typed} was not attributed to its mode: {error:?}",
            );
            assert!(
                !error.contains("Try 'fcage --export-to'."),
                "{typed} was answered with the spelling just refused: {error:?}",
            );
        }
    }

    #[test]
    fn a_mode_suggests_a_misspelling_of_its_own_vocabulary() {
        // A mode's parser refuses everything but its own options, so without
        // this a misspelling of one of them reads as a launch flag given to the
        // wrong invocation.
        let error = parse_error(&["--export-rootfs", "/roots/a", "--clamp-mtme", "5"]);
        assert!(
            error.contains("Try 'fcage --clamp-mtime'."),
            "the export mode did not answer its own misspelling: {error:?}",
        );
        let error = parse_error(&["--remove-rootfs", "/roots/a", "--identity-mp", "single"]);
        assert!(
            error.contains("Try 'fcage --identity-map'."),
            "the removal mode did not answer its own misspelling: {error:?}",
        );
        // A launch flag is still the conflict it is, not a near miss.
        let error = parse_error(&["--remove-rootfs", "/roots/a", "--hostname", "box"]);
        assert!(
            error.contains("cannot be used with --remove-rootfs"),
            "a launch flag stopped reading as a conflict: {error:?}",
        );
    }

    #[test]
    fn a_commands_own_flags_do_not_choose_the_mode() {
        // Past `--` every argument belongs to the command, including one spelled
        // like a mode of fcage's. Scanning the whole vector for a mode flag
        // makes a tool with an --export-rootfs option of its own unrunnable.
        let invocation = parse_args(&[
            "--rootfs",
            "/srv/alpine",
            "--",
            "/bin/mytool",
            "--export-rootfs",
            "/tmp/out",
        ])
        .expect("the launch parses");
        let Invocation::Run(options) = invocation else {
            panic!("the invocation is a launch, not a mode");
        };
        assert_eq!(
            options.command_line,
            ["/bin/mytool", "--export-rootfs", "/tmp/out"],
        );
    }

    #[test]
    fn a_commands_own_flags_do_not_choose_the_mode_without_a_separator() {
        // `--` is optional, and the synopsis says so: the command is the first
        // argument that is neither an option nor the value of one, and
        // everything after it is the command's. A pre-scan that stopped only at
        // `--` read a mode flag out of the command's own arguments, ran the
        // mode's parser, and reported the launch flag it then met as the
        // problem -- blaming --rootfs for an export nobody asked for.
        let invocation = parse_args(&[
            "--rootfs",
            "/srv/alpine",
            "/bin/mytool",
            "--export-rootfs",
            "/tmp/out",
        ])
        .expect("the launch parses");
        let Invocation::Run(options) = invocation else {
            panic!("the invocation is a launch, not a mode");
        };
        assert_eq!(
            options.command_line,
            ["/bin/mytool", "--export-rootfs", "/tmp/out"],
        );
    }

    #[test]
    fn a_mode_flag_after_another_flags_value_still_chooses_the_mode() {
        // The other half of the same rule: a flag's value is not the command,
        // so the walk goes past it. Reading `/tmp/out` as the command would
        // stop the scan before it reached the flag that selects the mode.
        let invocation = parse_args(&["--export-to", "/tmp/out", "--export-rootfs", "/roots/a"])
            .expect("the export parses");
        assert!(
            matches!(invocation, Invocation::Export { .. }),
            "the invocation is an export",
        );
    }

    #[test]
    fn a_two_value_flag_does_not_hide_the_command() {
        // A pair counts as two, so the argument after them is the command
        // rather than the second half of the pair.
        let invocation = parse_args(&["--rootfs", "/srv/a", "--setenv", "K", "V", "/bin/sh"])
            .expect("the launch parses");
        let Invocation::Run(options) = invocation else {
            panic!("the invocation is a launch, not a mode");
        };
        assert_eq!(options.command_line, ["/bin/sh"]);
        assert_eq!(options.setenv.len(), 1);
    }

    #[test]
    fn every_option_of_a_mode_is_refused_by_a_launch_and_taken_by_its_mode() {
        // The roster is the table's `mode`, so this is what keeps that honest:
        // every flag it files under a mode must be one a launch refuses and
        // that mode accepts, or the suggester attributes a flag to the wrong
        // mode.
        let options: Vec<&Flag> = FLAGS
            .iter()
            .filter(|flag| {
                !matches!(flag.mode, Mode::Launch | Mode::Help | Mode::Version) && !flag.selects
            })
            .collect();
        assert!(!options.is_empty(), "the roster is not empty");
        for flag in options {
            let long = flag.long;
            let owner = owning_mode_flag(long).expect("a mode's option names its mode");
            assert_eq!(
                FLAGS
                    .iter()
                    .find(|entry| entry.long == owner)
                    .map(|entry| entry.mode),
                Some(flag.mode),
                "{long} is attributed to {owner}, which selects another mode",
            );
            let launch = parse_error(&["--rootfs", "/srv/alpine", long, "/bin/sh"]);
            assert!(
                launch.contains("unrecognized option"),
                "a launch accepts {long}, which the roster calls {owner}'s: {launch:?}",
            );
            let mut args = vec![owner, "/roots/a", long];
            if flag.arity() != Arity::Bare {
                args.push("1700000000");
            }
            let taken = parse_args(&args);
            assert!(
                taken.is_ok(),
                "{owner} refuses {long}, which the roster calls its own: {:?}",
                taken.err(),
            );
        }
    }

    #[test]
    fn a_provision_and_exit_run_refuses_a_launch_flag() {
        // Nothing is launched, so a launch flag has nothing to configure. The
        // parser refuses every other no-effect combination; dropping this one
        // would leave a caller believing a sandbox was shaped as written.
        let error = parse_error(&[
            "--rootfs",
            "/roots/trixie",
            "--provision-debian",
            "trixie",
            "--hostname",
            "box",
        ]);
        assert!(
            error.contains("--hostname configures a launch"),
            "the dropped flag went unreported: {error:?}",
        );
        // The provisioning vocabulary itself is accepted, and so is anything at
        // all once a command is given.
        assert!(
            parse_args(&[
                "--rootfs",
                "/roots/trixie",
                "--provision-debian",
                "trixie",
                "--debian-arch",
                "amd64",
            ])
            .is_ok()
        );
        assert!(
            parse_args(&[
                "--rootfs",
                "/roots/trixie",
                "--provision-debian",
                "trixie",
                "--hostname",
                "box",
                "/bin/sh",
            ])
            .is_ok()
        );
        // A value is the flag's, whatever it looks like: a directory named
        // `--mydir` is a rootfs, not a launch flag nobody gave.
        let Invocation::Run(options) =
            parse_args(&["--rootfs", "--mydir", "--provision-tar", "t.tar"])
                .expect("a value spelled like an option is still a value")
        else {
            panic!("the invocation is a provisioning run");
        };
        assert_eq!(options.rootfs.as_deref(), Some(Path::new("--mydir")));
        // A trailing separator with nothing after it names no launch setting:
        // it introduces a command line rather than configuring one, and the run
        // it ends is the provisioning run it was already.
        assert!(
            parse_args(&[
                "--rootfs",
                "/roots/trixie",
                "--provision-debian",
                "trixie",
                "--"
            ])
            .is_ok()
        );
    }

    /// The options of a parsed invocation, or a panic naming what went wrong.
    fn run_options(args: &[&str]) -> Box<Options> {
        match parse_args(args) {
            Ok(Invocation::Run(options)) => options,
            Ok(_) => panic!("{args:?} should parse as a run"),
            Err(error) => panic!("{args:?} should parse: {error}"),
        }
    }

    #[test]
    fn the_alpine_options_reach_the_builder_they_mirror() {
        let options = run_options(&[
            "--rootfs",
            "/roots/alpine",
            "--provision-alpine",
            "v3.23",
            "--alpine-arch",
            "aarch64",
            "--alpine-include",
            "build-base,git",
            "--alpine-include",
            "curl",
            "--alpine-exclude",
            "docs",
            "--alpine-components",
            "main,community",
            "--alpine-cache",
            "/var/cache/apk",
            "--alpine-extract-only",
        ]);
        assert_eq!(options.provision_alpine.as_deref(), Some("v3.23"));
        assert_eq!(options.alpine_arch.as_deref(), Some("aarch64"));
        // Repeatable and comma-separated, as the Debian list flags are.
        assert_eq!(options.alpine_include, ["build-base", "git", "curl"]);
        assert_eq!(options.alpine_exclude, ["docs"]);
        assert_eq!(options.alpine_components, ["main", "community"]);
        assert!(options.alpine_extract_only);
    }

    #[test]
    fn every_userland_takes_a_plan_document_the_same_way() {
        // A plan replaces a resolution and a pin constrains one, and both are
        // documents a previous resolution wrote. Gentoo takes a plan; Debian
        // and Alpine take both, so a reproducible install is expressible at a
        // prompt for each of the three formats and not only from a program.
        for (userland, release) in [("debian", "trixie"), ("alpine", "v3.23")] {
            for document in ["plan", "pin"] {
                let flag = format!("--{userland}-{document}");
                let path = format!("/plans/{userland}.{document}");
                let options = run_options(&[
                    "--rootfs",
                    "/roots/r",
                    &format!("--provision-{userland}"),
                    release,
                    &flag,
                    &path,
                ]);
                let parsed = match (userland, document) {
                    ("debian", "plan") => options.debian_plan,
                    ("debian", _) => options.debian_pin,
                    (_, "plan") => options.alpine_plan,
                    _ => options.alpine_pin,
                };
                assert_eq!(parsed.as_deref(), Some(Path::new(&path)), "{flag}");
            }
        }

        // A plan is a resolution that already happened, so every flag that
        // shapes one is refused beside it, in each format alike, rather than
        // dropped or left to fail once the provisioner is built.
        for (provision, release, plan, shaping) in [
            (
                "--provision-debian",
                "trixie",
                "--debian-plan",
                &[
                    ["--debian-include", "curl"],
                    ["--debian-exclude", "curl"],
                    ["--debian-base-priority", "important"],
                    ["--debian-pin", "/plans/p"],
                ][..],
            ),
            (
                "--provision-alpine",
                "v3.23",
                "--alpine-plan",
                &[
                    ["--alpine-include", "curl"],
                    ["--alpine-exclude", "curl"],
                    ["--alpine-pin", "/plans/p"],
                ],
            ),
            (
                "--provision-gentoo",
                "amd64",
                "--gentoo-plan",
                &[
                    ["--gentoo-install", "dev-vcs/git"],
                    ["--gentoo-prefer-use", "keyring"],
                ],
            ),
        ] {
            for [flag, value] in shaping {
                let mut args = vec!["--rootfs", "/roots/r", provision, release];
                if provision == "--provision-gentoo" {
                    args.extend(["--gentoo-variant", "amd64-openrc"]);
                }
                args.extend([plan, "/plans/plan", flag, value]);
                let error = parse_error(&args);
                assert!(
                    error.contains(plan) && error.contains(flag),
                    "{plan} beside {flag}: {error}",
                );
            }
        }

        // And each belongs to its own provisioner, as the rest of its family
        // does.
        for flag in ["--debian-plan", "--debian-pin"] {
            let error = parse_error(&["--rootfs", "/roots/r", flag, "/plans/p"]);
            assert!(
                error.contains("require --provision-debian"),
                "{flag}: {error:?}",
            );
        }
        for flag in ["--alpine-plan", "--alpine-pin"] {
            let error = parse_error(&["--rootfs", "/roots/r", flag, "/plans/p"]);
            assert!(
                error.contains("require --provision-alpine"),
                "{flag}: {error:?}",
            );
        }
    }

    #[test]
    fn an_overlay_repository_is_spelled_by_naming_no_components() {
        // postmarketOS's layout, which is the whole of what the flag has to
        // express that the Debian one does not.
        let options = run_options(&[
            "--rootfs",
            "/roots/alpine",
            "--provision-alpine",
            "v3.23",
            "--alpine-repository",
            "release=v26.06 mirror=http://mirror.invalid/pmos keys=postmarketos",
        ]);
        let [overlay] = &options.alpine_repositories[..] else {
            panic!(
                "one repository was given: {:?}",
                options.alpine_repositories
            );
        };
        assert_eq!(overlay.release, "v26.06");
        assert_eq!(
            overlay.mirror.as_deref(),
            Some("http://mirror.invalid/pmos")
        );
        assert!(overlay.fallbacks.is_empty());
        assert!(overlay.components.is_empty(), "the shallower layout");
        assert_eq!(overlay.keys, AlpineKeys::PostmarketOs);
    }

    #[test]
    fn a_repository_spec_states_one_primary_mirror_and_names_it_mirror() {
        // A repository's primary mirror is written into the finished root, so a
        // spec that promoted a backstop would leave that root permanently
        // fetching from what the caller meant as a fetch-time backstop, and one
        // that demoted a repeated mirror= would quietly reorder the walk.
        for (flag, spec) in [
            (
                "--alpine-repository",
                "release=v26.06 keys=postmarketos mirror-fallback=http://backstop.invalid",
            ),
            (
                "--debian-repository",
                "suite=trixie mirror-fallback=http://backstop.invalid",
            ),
        ] {
            let error = parse_error(&[
                "--rootfs",
                "/roots/r",
                "--provision-alpine",
                "v3.23",
                flag,
                spec,
            ]);
            assert!(error.contains("mirror-fallback="), "{flag}: {error}");
            assert!(error.contains("was not given"), "{flag}: {error}");
        }

        for (flag, spec) in [
            (
                "--alpine-repository",
                "release=v26.06 keys=postmarketos mirror=http://one.invalid \
                 mirror=http://two.invalid",
            ),
            (
                "--debian-repository",
                "suite=trixie mirror=http://one.invalid mirror=http://two.invalid",
            ),
        ] {
            let error = parse_error(&[
                "--rootfs",
                "/roots/r",
                "--provision-alpine",
                "v3.23",
                flag,
                spec,
            ]);
            assert!(error.contains("given twice"), "{flag}: {error}");
        }
    }

    #[test]
    fn a_repository_without_keys_is_refused_where_it_is_written() {
        // An additional repository has no default trust anchor, so the refusal
        // belongs at the flag rather than at the first signature it cannot
        // check.
        let error = parse_error(&[
            "--rootfs",
            "/roots/alpine",
            "--provision-alpine",
            "v3.23",
            "--alpine-repository",
            "release=v26.06 mirror=http://mirror.invalid/pmos",
        ]);
        assert!(error.contains("keys="), "{error}");

        let error = parse_error(&[
            "--rootfs",
            "/roots/alpine",
            "--provision-alpine",
            "v3.23",
            "--alpine-repository",
            "release=v26.06 mirror=http://mirror.invalid/pmos keys=alpine suite=trixie",
        ]);
        assert!(
            error.contains("suite"),
            "an unknown field is named: {error}"
        );
    }

    #[test]
    fn the_gentoo_binhost_options_reach_the_builder_they_mirror() {
        let options = run_options(&[
            "--rootfs",
            "/roots/gentoo",
            "--provision-gentoo",
            "amd64",
            "--gentoo-variant",
            "amd64-openrc",
            "--gentoo-binhost",
            "x86-64",
            "--gentoo-install",
            "dev-vcs/git[keyring]",
            "--gentoo-install=app-editors/vim",
            // Space-separated, because a caller states a taste as a list
            // rather than one flag at a time.
            "--gentoo-prefer-use",
            "-X gtk",
            "--gentoo-prefer-use=keyring",
        ]);
        assert_eq!(options.gentoo_binhost.as_deref(), Some("x86-64"));
        assert_eq!(
            options.gentoo_install,
            ["dev-vcs/git[keyring]", "app-editors/vim"],
        );
        assert_eq!(options.gentoo_prefer_use, ["-X", "gtk", "keyring"]);
        let options = run_options(&[
            "--rootfs",
            "/roots/gentoo",
            "--provision-gentoo",
            "amd64",
            "--gentoo-variant",
            "amd64-openrc",
            "--gentoo-binhost",
            "x86-64",
            "--gentoo-plan",
            "/plans/binhost.plan",
        ]);
        assert_eq!(
            options.gentoo_plan.as_deref(),
            Some(Path::new("/plans/binhost.plan")),
        );
    }

    #[test]
    fn the_gentoo_binhost_listings_are_modes_of_their_own() {
        // Each reads and exits, so each parses on its own and refuses a flag
        // that configures a launch it will not perform.
        match parse_args(&["--gentoo-packages", "amd64", "--gentoo-binhost", "x86-64"])
            .expect("the listing parses")
        {
            Invocation::GentooPackages {
                architecture,
                binhost,
                ..
            } => {
                assert_eq!(architecture, "amd64");
                assert_eq!(binhost.as_deref(), Some("x86-64"));
            }
            _ => panic!("expected a binhost listing"),
        }
        match parse_args(&["--gentoo-installed=/roots/gentoo"]).expect("the listing parses") {
            Invocation::GentooInstalled { root } => assert_eq!(root, Path::new("/roots/gentoo")),
            _ => panic!("expected an installed listing"),
        }
        // A flag belonging to a launch is a conflict rather than something the
        // listing quietly ignores.
        let error = parse_error(&["--gentoo-packages", "amd64", "--rootfs", "/roots/x"]);
        assert!(error.contains("--gentoo-packages"), "{error}");
        let error = parse_error(&["--gentoo-installed", "/roots/x", "--gentoo-mirror", "u"]);
        assert!(error.contains("--gentoo-installed"), "{error}");
        // And each requires its value.
        assert!(parse_error(&["--gentoo-installed"]).contains("requires a value"));
    }

    #[test]
    fn the_gentoo_options_reach_the_builder_they_mirror() {
        let options = run_options(&[
            "--rootfs",
            "/roots/gentoo",
            "--provision-gentoo",
            "amd64",
            "--gentoo-variant",
            "amd64-hardened-openrc",
            "--gentoo-build-id",
            "20260810T204554Z",
            "--gentoo-mirror",
            "http://mirror.invalid/gentoo",
            "--gentoo-mirror-fallback",
            "http://backup.invalid/gentoo",
            "--gentoo-cache",
            "/var/cache/stage3",
            "--gentoo-max-pointer-age",
            "7",
        ]);
        // The architecture is the coordinate here rather than a release, since
        // Gentoo publishes one autobuilds tree per architecture and no suite.
        assert_eq!(options.provision_gentoo.as_deref(), Some("amd64"));
        assert_eq!(
            options.gentoo_variant.as_deref(),
            Some("amd64-hardened-openrc"),
        );
        assert_eq!(options.gentoo_build_id.as_deref(), Some("20260810T204554Z"));
        assert_eq!(
            options.gentoo_mirror.as_deref(),
            Some("http://mirror.invalid/gentoo"),
        );
        assert_eq!(
            options.gentoo_mirror_fallback,
            ["http://backup.invalid/gentoo"],
        );
        assert_eq!(options.gentoo_max_pointer_age, Some(Some(7)));

        // The bound is cleared by a word rather than by a number, since no
        // number means "no bound" and a very large one is not the same request.
        let cleared = run_options(&[
            "--rootfs",
            "/roots/gentoo",
            "--provision-gentoo",
            "amd64",
            "--gentoo-variant=amd64-openrc",
            "--gentoo-max-pointer-age=none",
        ]);
        assert_eq!(cleared.gentoo_max_pointer_age, Some(None));
        assert_eq!(cleared.gentoo_variant.as_deref(), Some("amd64-openrc"));

        let error = parse_error(&[
            "--rootfs",
            "/roots/gentoo",
            "--provision-gentoo",
            "amd64",
            "--gentoo-variant",
            "amd64-openrc",
            "--gentoo-max-pointer-age",
            "a-while",
        ]);
        assert!(error.contains("number of days or 'none'"), "{error}");
    }

    #[test]
    fn a_gentoo_bootstrap_names_the_variant_it_installs() {
        // The archive publishes twenty-one stage3s for amd64 alone with no
        // default among them, so the refusal belongs at the command line rather
        // than after two archive fetches.
        let error = parse_error(&["--rootfs", "/roots/gentoo", "--provision-gentoo", "amd64"]);
        assert!(error.contains("--gentoo-variant"), "{error}");
        assert!(error.contains("--gentoo-variants"), "{error}");
    }

    #[test]
    fn the_gentoo_listings_are_modes_of_their_own() {
        // Each reads and prints rather than launching anything, so each takes
        // its own vocabulary and refuses every launch flag -- the shape a
        // removal and an export already have.
        match parse_args(&[
            "--gentoo-variants",
            "arm64",
            "--gentoo-mirror",
            "http://mirror.invalid/gentoo",
            "--gentoo-mirror-fallback=http://backup.invalid/gentoo",
            "--gentoo-max-pointer-age=none",
        ])
        .expect("the listing parses")
        {
            Invocation::GentooVariants {
                architecture,
                mirror,
                fallbacks,
                max_pointer_age,
            } => {
                assert_eq!(architecture, "arm64");
                assert_eq!(mirror.as_deref(), Some("http://mirror.invalid/gentoo"));
                assert_eq!(fallbacks, ["http://backup.invalid/gentoo"]);
                assert_eq!(max_pointer_age, Some(None));
            }
            _ => panic!("expected a variant listing"),
        }

        // The two flags mean here what they mean on a provisioning command
        // line, which is what keeps one command line from reading an archive
        // the other would not. A backstop given alone backs the default archive
        // rather than replacing it, so nothing names the primary here.
        let listing = |args: &[&str]| match parse_args(args).expect("the listing parses") {
            Invocation::GentooVariants {
                mirror, fallbacks, ..
            } => (mirror, fallbacks),
            _ => panic!("expected a variant listing"),
        };
        assert_eq!(
            listing(&[
                "--gentoo-variants",
                "amd64",
                "--gentoo-mirror-fallback",
                "http://backup.invalid/gentoo",
            ]),
            (None, vec!["http://backup.invalid/gentoo".to_string()]),
        );
        // Repeating one flag takes the last value, as it does everywhere else
        // in the tool.
        assert_eq!(
            listing(&[
                "--gentoo-variants",
                "amd64",
                "--gentoo-mirror",
                "http://a.invalid",
                "--gentoo-mirror",
                "http://b.invalid",
            ]),
            (Some("http://b.invalid".to_string()), Vec::new()),
        );

        assert!(matches!(
            parse_args(&["--gentoo-keyring-horizon"]).expect("the horizon parses"),
            Invocation::GentooKeyring,
        ));

        // A launch flag alongside either is a usage error rather than a setting
        // with no effect.
        let error = parse_error(&["--gentoo-variants", "amd64", "--rootfs", "/roots/gentoo"]);
        assert!(error.contains("--rootfs"), "{error}");
        let error = parse_error(&["--gentoo-keyring-horizon", "--gentoo-mirror", "http://x"]);
        assert!(error.contains("--gentoo-mirror"), "{error}");
    }

    #[test]
    fn the_provisioners_are_mutually_exclusive_and_need_a_destination() {
        // One rootfs is provisioned one way. Every flag the refusal enumerates
        // is exercised, so a provisioner added to the list without being added
        // to the check fails here rather than in a caller's hands.
        let error = parse_error(&[
            "--rootfs",
            "/roots/mixed",
            "--provision-debian",
            "trixie",
            "--provision-alpine",
            "v3.23",
        ]);
        assert!(
            error.contains("--provision-debian and --provision-alpine"),
            "{error}",
        );
        let error = parse_error(&[
            "--rootfs",
            "/roots/mixed",
            "--provision-tar",
            "rootfs.tar",
            "--provision-gentoo",
            "amd64",
        ]);
        assert!(
            error.contains("--provision-tar and --provision-gentoo"),
            "{error}",
        );

        // And each of them names the destination it writes to. Alone, that is
        // the general refusal every command line without somewhere to run
        // meets; alongside a profile, which does say where the launch runs, it
        // is the provisioner's own -- and for the Gentoo one that refusal is
        // what makes the variant refusal reachable only where a destination was
        // named.
        for provisioner in [
            ["--provision-tar", "rootfs.tar"],
            ["--provision-debian", "trixie"],
            ["--provision-alpine", "v3.23"],
            ["--provision-gentoo", "amd64"],
        ] {
            let error = parse_error(&provisioner);
            assert!(error.contains("--rootfs"), "{provisioner:?}: {error}");

            let error = parse_error(&[
                "--profile",
                "/etc/fcage/profile.toml",
                provisioner[0],
                provisioner[1],
            ]);
            assert_eq!(
                error,
                format!(
                    "{} requires --rootfs to name the destination",
                    provisioner[0]
                ),
            );
        }
    }

    #[test]
    fn the_alpine_options_require_the_provisioner_they_configure() {
        let error = parse_error(&[
            "--rootfs",
            "/roots/alpine",
            "--alpine-include",
            "build-base",
            "/bin/sh",
        ]);
        assert!(
            error.contains("the --alpine-* options require --provision-alpine"),
            "{error}",
        );
    }

    #[test]
    fn the_gentoo_options_require_the_provisioner_they_configure() {
        let error = parse_error(&[
            "--rootfs",
            "/roots/gentoo",
            "--gentoo-variant",
            "amd64-openrc",
            "/bin/sh",
        ]);
        assert!(
            error.contains("the --gentoo-* options require --provision-gentoo"),
            "{error}",
        );
    }

    #[test]
    fn a_mode_answers_help_rather_than_taking_it_as_a_path() {
        // `--remove-rootfs` takes the next argument, so without an answer up
        // front `fcage --remove-rootfs --help` deletes a directory named
        // `--help` — or, finding none, exits 0 having printed nothing.
        for args in [
            ["--remove-rootfs", "--help"].as_slice(),
            ["--export-rootfs", "--help"].as_slice(),
            ["--remove-rootfs", "/roots/a", "--help"].as_slice(),
        ] {
            assert!(
                matches!(parse_args(args), Ok(Invocation::Help)),
                "{args:?} did not ask for help",
            );
        }
        assert!(matches!(
            parse_args(&["--export-rootfs", "--version"]),
            Ok(Invocation::Version)
        ));
    }

    #[test]
    fn the_sandbox_is_tied_to_fcage_unless_the_run_says_otherwise() {
        // fcage waits for the command and exits with it, so a sandbox that
        // outlived the process is never what was meant: a SIGTERM to fcage —
        // `timeout(1)` is the everyday source — would otherwise orphan it.
        //
        // The parse records only what the command line said, so that a profile
        // can be the thing that answers; the default is applied where the
        // profile is known.
        let options = parse_run(&["--rootfs", "/srv/alpine", "/bin/true"]).expect("it parses");
        assert_eq!(options.stop_with_caller, None);
        assert_eq!(
            stop_with_caller_default(options.stop_with_caller, false),
            Some(true)
        );
        let options = parse_run(&[
            "--rootfs",
            "/srv/alpine",
            "--no-stop-with-caller",
            "/bin/true",
        ])
        .expect("it parses");
        assert_eq!(options.stop_with_caller, Some(false));
        assert_eq!(
            stop_with_caller_default(options.stop_with_caller, false),
            Some(false),
        );
    }

    #[test]
    fn a_listing_whose_reader_stops_early_ends_quietly() {
        // Rust ignores SIGPIPE, so a write to a closed pipe returns EPIPE
        // rather than killing the process, and `println!` panics on it: exit
        // 101 and a panic message where a shell expects 141 and silence.
        // `fcage --gentoo-packages amd64 | head` is the everyday case.
        assert_eq!(
            output::stdout_status("a listing", Err(std::io::ErrorKind::BrokenPipe.into())),
            141,
        );
        // Any other write failure is a real one and says so.
        assert_eq!(
            output::stdout_status("a listing", Err(std::io::ErrorKind::StorageFull.into())),
            125,
        );
        assert_eq!(output::stdout_status("a listing", Ok(())), 0);
    }

    #[test]
    fn a_provisioning_run_whose_progress_reader_has_gone_stops() {
        use ferroday_cage::provision::ProvisionObserver as _;
        use ferroday_cage::provision::debian::DebianEvent;

        // The reader goes first, so the first line of progress finds the pipe
        // closed, as a `2>&1 | head` does once `head` has its lines.
        let (reader, writer) = std::io::pipe().expect("a pipe");
        drop(reader);
        let mut progress = Progress::new(writer);
        assert!(!progress.cancelled(), "nothing has been written yet");
        progress.progress(ProvisionEvent::Debian(&DebianEvent::Resolving));
        assert!(
            progress.cancelled(),
            "a run whose progress nobody reads goes on to the end",
        );

        // A reader still there sees the progress, and the run goes on.
        let (mut reader, writer) = std::io::pipe().expect("a pipe");
        let mut progress = Progress::new(writer);
        progress.progress(ProvisionEvent::Debian(&DebianEvent::Resolving));
        assert!(!progress.cancelled());
        drop(progress);
        let mut seen = String::new();
        std::io::Read::read_to_string(&mut reader, &mut seen).expect("the line arrives");
        assert_eq!(seen, "fcage: resolving the package set\n");
    }

    #[test]
    fn a_profiles_caller_tie_is_reachable_through_fcage() {
        // A default is not a setting. Seeding the option with fcage's own made
        // every run state the tie, so a profile's `stop-with-caller = false`
        // was overridden by a value its author never wrote and the documented
        // key could not be reached through fcage at all.
        assert_eq!(stop_with_caller_default(None, true), None);
        // A flag still wins over the profile, in both directions.
        assert_eq!(stop_with_caller_default(Some(false), true), Some(false));
        assert_eq!(stop_with_caller_default(Some(true), true), Some(true));

        // And the profile is read for the key, which is what tells "the
        // profile said so" from "nothing said".
        let dir = ferroday_cage_testkit::scratch::scratch_dir("fcage-profile-tie");
        let stated = dir.join("stated.toml");
        std::fs::write(
            &stated,
            "rootfs = \"/tmp\"\ncommand = \"/bin/true\"\nstop-with-caller = false\n",
        )
        .expect("the profile is written");
        let (_, meta) = load_profile(&stated, false, false).expect("the profile loads");
        assert!(meta.sets_stop_with_caller);

        let silent = dir.join("silent.toml");
        std::fs::write(&silent, "rootfs = \"/tmp\"\ncommand = \"/bin/true\"\n")
            .expect("the profile is written");
        let (_, meta) = load_profile(&silent, false, false).expect("the profile loads");
        assert!(!meta.sets_stop_with_caller);
    }

    #[test]
    fn a_string_resembling_no_flag_is_reported_without_a_guess() {
        // A suggestion is worth having only where it is likely to be right.
        for typed in ["--qqqzzz", "--", "-x", "--wildly-unlike-anything"] {
            let error = parse_error(&[typed]);
            assert!(
                !error.contains("Try 'fcage --"),
                "{typed} drew a suggestion out of nothing: {error:?}",
            );
        }
        // The mode parsers ask the same question of their own vocabularies, and
        // a run of dashes is every flag's prefix: the abbreviation rule would
        // otherwise answer a bare `--` with whichever flag sorts first.
        for typed in ["--", "-", "---"] {
            assert_eq!(
                nearest_flag(typed, &["--identity-map", "--remove-rootfs"]),
                None
            );
            let error = parse_error(&["--remove-rootfs=/roots/a", typed]);
            assert!(
                !error.contains("Try 'fcage --"),
                "{typed} drew a suggestion out of nothing: {error:?}",
            );
        }
        // And a flag genuinely typed short still draws one.
        assert_eq!(
            nearest_flag("--remove", &["--identity-map", "--remove-rootfs"]),
            Some("--remove-rootfs"),
        );
    }

    #[test]
    fn an_alpine_key_set_that_names_nothing_is_a_usage_error() {
        // Read as a path, an empty selector names the working directory: the
        // run then ends at an io failure about a directory the caller never
        // typed, exit 125, rather than at the usage error it is.
        let error = parse_error(&[
            "--rootfs",
            "/r",
            "--alpine-repository",
            "release=v3.23 mirror=http://dl-cdn.alpinelinux.org/alpine keys=",
            "/bin/true",
        ]);
        assert!(error.contains("names no key set"), "{error}");
        // The three forms it does take still parse.
        assert_eq!(
            parse_alpine_keys("--flag", "alpine"),
            Ok(AlpineKeys::Alpine)
        );
        assert_eq!(
            parse_alpine_keys("--flag", "postmarketos"),
            Ok(AlpineKeys::PostmarketOs)
        );
        assert_eq!(
            parse_alpine_keys("--flag", "keys"),
            Ok(AlpineKeys::Dir(PathBuf::from("keys")))
        );
    }

    #[test]
    fn every_flag_the_parser_accepts_is_in_the_help() {
        // The parser's vocabulary and the help's contents are one list, so an
        // entry cannot be missing from either. What is left to check is the
        // flags the help documents in prose rather than as an entry: the
        // counterpart toggles, each named in the closing paragraphs. A flag
        // filed there and then forgotten in the prose is documented nowhere,
        // and the suggester could never offer it.
        let usage = usage();
        for flag in FLAGS {
            if flag.section != Section::Counterpart {
                // Rendered from the table, so its presence is not a question.
                assert!(
                    usage.contains(&format!("  {}", flag.spelled())),
                    "the help does not list {}, which is not a prose entry",
                    flag.long,
                );
                continue;
            }
            assert!(
                usage.contains(flag.long),
                "the parser accepts {}, which --help never names",
                flag.long,
            );
        }
    }

    #[test]
    fn every_flag_the_help_names_in_prose_is_one_the_parser_accepts() {
        // The other direction over the same prose, and what keeps the closing
        // paragraphs from naming a flag that no longer exists. The entries
        // themselves come from the table and cannot.
        let usage = usage();
        let prose = usage
            .split_once("Each toggle")
            .expect("the closing prose")
            .1;
        for token in prose.split_whitespace() {
            let name = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
            if !name.starts_with("--") || name.len() <= 2 || name.ends_with('-') {
                continue;
            }
            assert!(
                FLAGS.iter().any(|flag| flag.long == name),
                "the closing prose names {name}, which no flag is",
            );
        }
    }

    #[test]
    fn every_flag_the_help_names_is_one_the_parser_accepts() {
        // A flag is offered to each mode's vocabulary in turn, since some
        // belong to one mode only -- `--clamp-mtime` is an export's -- and
        // trying all of them is what covers the whole table.
        for flag in FLAGS {
            if matches!(flag.mode, Mode::Help | Mode::Version) {
                continue;
            }
            let long = flag.long;
            let vocabularies: [Vec<&str>; 3] = [
                vec![long],
                vec!["--remove-rootfs", "/roots/a", long],
                vec!["--export-rootfs", "/roots/a", long],
            ];
            let recognized = vocabularies.iter().any(|args| match parse_args(args) {
                // A flag needing a value reports that, which is recognition.
                // Only being unknown, or belonging to another mode, is not.
                Err(error) => {
                    !error.contains("unrecognized option") && !error.contains("cannot be used with")
                }
                Ok(_) => true,
            });
            assert!(
                recognized,
                "the table holds {long}, which no mode's parser accepts",
            );
        }
    }

    #[test]
    fn the_help_files_every_option_under_a_section() {
        // The options are already ordered by subject; the sections name the
        // groups that ordering makes. An entry above the first header, or
        // after a header that no longer exists, is one a reader has to find by
        // scanning the whole list.
        let usage = usage();
        let mut section: Option<&str> = None;
        for line in usage.lines() {
            if line.ends_with(':') && !line.starts_with(' ') && !line.starts_with("Usage") {
                section = Some(line);
            } else if line.starts_with("  -") {
                assert!(
                    section.is_some(),
                    "the option {line:?} sits above the first section header",
                );
            }
        }
        // The groups themselves, so a section lost in an edit is caught rather
        // than silently folding its options into the one before it.
        for header in [
            "Provisioning the root filesystem:",
            "Profiles, overlays, and mounts:",
            "Identity and limits:",
            "The command and its process:",
            "Networking:",
            "Hardening:",
            "Turning off what is on by default:",
            "Help and version:",
        ] {
            assert!(
                usage.contains(header),
                "the help lost the section {header:?}"
            );
        }
    }

    #[test]
    fn edit_distance_counts_single_character_edits() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("--rootfs", "--rootfs"), 0);
        // One substitution, one deletion, one insertion.
        assert_eq!(edit_distance("--rootfs", "--roatfs"), 1);
        assert_eq!(edit_distance("--rootfs", "--rootf"), 1);
        assert_eq!(edit_distance("--rootfs", "--rootfss"), 1);
        // A transposition costs two: the distance does not model a swap, which
        // is why two is the bound worth offering a suggestion at.
        assert_eq!(edit_distance("--rootfs", "--rootsf"), 2);
        // Against an empty string the distance is the length, from either
        // side, so the two rows are indexed the same way round.
        assert_eq!(edit_distance("--bind", ""), 6);
        assert_eq!(edit_distance("", "--bind"), 6);
    }

    #[test]
    fn remove_rootfs_takes_a_destination_in_either_form() {
        for args in [
            ["--remove-rootfs", "/var/lib/roots/trixie"].as_slice(),
            ["--remove-rootfs=/var/lib/roots/trixie"].as_slice(),
        ] {
            match parse_args(args).expect("the removal should parse") {
                Invocation::Remove { dest, map, removal } => {
                    assert_eq!(dest, PathBuf::from("/var/lib/roots/trixie"));
                    assert_eq!(
                        map,
                        IdentityMap::Subordinate,
                        "the default is the map a bundled-delegate sandbox writes under"
                    );
                    assert_eq!(
                        removal,
                        Removal::Rootfs { remove_lock: true },
                        "the default takes the lock with the tree, as the library's own does"
                    );
                }
                _ => panic!("expected a removal for {args:?}"),
            }
        }
    }

    #[test]
    fn remove_rootfs_takes_the_identity_map_the_tree_was_written_under() {
        // A tree provisioned under the single-identity map is removed under it
        // too, whichever side of the destination the flag appears on.
        for args in [
            ["--identity-map", "single", "--remove-rootfs", "/roots/a"].as_slice(),
            ["--remove-rootfs", "/roots/a", "--identity-map=single"].as_slice(),
        ] {
            match parse_args(args).expect("the removal should parse") {
                Invocation::Remove { map, .. } => assert_eq!(map, IdentityMap::Single),
                _ => panic!("expected a removal for {args:?}"),
            }
        }
    }

    #[test]
    fn keep_lock_spares_the_sibling_the_caller_never_named() {
        // `<dest>.lock` is the file provisioning wrote beside a published
        // rootfs, so a removal takes it by default. Where `dest` merely holds
        // such trees it is an unrelated path, and deleting it is a deletion
        // outside what the command line named -- silent, and not undoable.
        for args in [
            ["--remove-rootfs", "/roots/cache", "--keep-lock"].as_slice(),
            ["--keep-lock", "--remove-rootfs", "/roots/cache"].as_slice(),
        ] {
            match parse_args(args).expect("the removal should parse") {
                Invocation::Remove { removal, .. } => assert_eq!(
                    removal,
                    Removal::Rootfs { remove_lock: false },
                    "--keep-lock should leave the sibling for {args:?}"
                ),
                _ => panic!("expected a removal for {args:?}"),
            }
        }
    }

    #[test]
    fn remove_overlay_upper_takes_an_upper_in_either_form() {
        for args in [
            ["--remove-overlay-upper", "/var/cache/run-42"].as_slice(),
            ["--remove-overlay-upper=/var/cache/run-42"].as_slice(),
            [
                "--identity-map",
                "single",
                "--remove-overlay-upper",
                "/var/cache/run-42",
            ]
            .as_slice(),
        ] {
            match parse_args(args).expect("the removal should parse") {
                Invocation::Remove { dest, removal, .. } => {
                    assert_eq!(dest, PathBuf::from("/var/cache/run-42"));
                    assert_eq!(removal, Removal::OverlayUpper, "{args:?}");
                }
                _ => panic!("expected a removal for {args:?}"),
            }
        }
        match parse_args(&["--remove-overlay-upper", "/up", "--identity-map=single"])
            .expect("the removal should parse")
        {
            Invocation::Remove { map, .. } => assert_eq!(map, IdentityMap::Single),
            _ => panic!("expected a removal"),
        }
    }

    #[test]
    fn remove_overlay_upper_refuses_what_does_not_apply_to_an_upper() {
        // An upper is not a published rootfs, so its removal takes no lock and
        // `--keep-lock` would be a setting with no effect.
        let error = parse_error(&["--remove-overlay-upper", "/up", "--keep-lock"]);
        assert!(
            error.contains("--keep-lock") && error.contains("--remove-overlay-upper"),
            "{error}"
        );
        // One removal names one tree, of one kind.
        for args in [
            ["--remove-overlay-upper", "/up", "--remove-rootfs", "/r"].as_slice(),
            ["--remove-rootfs=/r", "--remove-overlay-upper=/up"].as_slice(),
        ] {
            let error = parse_error(args);
            assert!(error.contains("are alternatives"), "{args:?}: {error}");
        }
        // A launch option is refused, named against the mode that was asked for.
        let error = parse_error(&["--remove-overlay-upper", "/up", "--rootfs", "/r"]);
        assert!(
            error.contains("--rootfs") && error.contains("--remove-overlay-upper"),
            "{error}"
        );
        assert!(parse_args(&["--remove-overlay-upper"]).is_err());
        assert!(parse_args(&["--remove-overlay-upper", "/up", "/bin/true"]).is_err());
    }

    #[test]
    fn remove_overlay_upper_takes_the_work_directory_beside_the_upper() {
        // The library keeps an overlay's work directory as a hidden sibling of
        // the upper, and this removal is how a caller at a shell prompt takes
        // both. A tree the calling user owns needs no map to be entered.
        let base = ferroday_cage_testkit::scratch::scratch_dir("fcage-remove-overlay-upper");
        let upper = base.join("run-42");
        let work = base.join(".run-42.work");
        std::fs::create_dir_all(upper.join("etc")).expect("the upper is laid out");
        std::fs::write(upper.join("etc/hostname"), b"run-42\n").expect("a file in the upper");
        std::fs::create_dir_all(work.join("work")).expect("the work directory is laid out");
        std::fs::write(base.join("run-42.lock"), b"").expect("a lock beside the upper");

        let code = remove_tree(&upper, IdentityMap::Single, Removal::OverlayUpper);
        assert_eq!(code, ExitCode::SUCCESS);
        assert!(!upper.exists(), "the upper is removed");
        assert!(!work.exists(), "the work directory goes with it");
        assert!(
            base.join("run-42.lock").exists(),
            "a lock beside an upper is not the removal's to take"
        );
        // Removing what is no longer there succeeds, so the call is repeatable.
        let code = remove_tree(&upper, IdentityMap::Single, Removal::OverlayUpper);
        assert_eq!(code, ExitCode::SUCCESS);
    }

    #[test]
    fn a_separated_value_is_never_another_flag() {
        // A flag written where a value belongs is a usage error, not the value.
        // `--remove-rootfs --identity-map=subordinate` took the map's spelling
        // as the tree to delete and removed a path of that name in the working
        // directory, reporting success. Every flag taking a separated value has
        // the shape, so the refusal is checked across the modes.
        for args in [
            ["--remove-rootfs", "--identity-map=subordinate"].as_slice(),
            ["--remove-rootfs", "/roots/a", "--identity-map", "--rootfs"].as_slice(),
            ["--rootfs", "--share-net", "/bin/true"].as_slice(),
            ["--bind", "--rootfs", "/target", "/r", "/bin/true"].as_slice(),
            ["--gentoo-variants", "--gentoo-mirror"].as_slice(),
            // An export's own two paths: `--export-to --clamp-mtime=0` wrote an
            // archive named `--clamp-mtime=0`, unclamped, and exited 0.
            [
                "--export-rootfs",
                "/roots/a",
                "--export-to",
                "--clamp-mtime=0",
            ]
            .as_slice(),
            ["--export-rootfs", "--export-to", "/tmp/out.tar"].as_slice(),
        ] {
            let error = parse_error(args);
            assert!(
                error.contains("names a flag"),
                "expected a refusal for {args:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn a_refused_value_suggests_only_the_form_its_flag_accepts() {
        // A one-value flag has a joined form, which is how a value spelled as
        // a flag is written; a two-value flag has none, so suggesting one sends
        // the caller to a spelling the parser then refuses.
        let error = parse_error(&["--remove-rootfs", "--identity-map=single"]);
        assert!(error.contains("--remove-rootfs=VALUE"), "{error}");
        for args in [
            [
                "--rootfs",
                "/r",
                "--bind",
                "--rootfs",
                "/target",
                "/bin/true",
            ]
            .as_slice(),
            [
                "--rootfs",
                "/r",
                "--setenv",
                "NAME",
                "--share-net",
                "/bin/true",
            ]
            .as_slice(),
        ] {
            let error = parse_error(args);
            assert!(error.contains("names a flag"), "{error}");
            assert!(
                !error.contains("=VALUE") && error.contains("no joined form"),
                "{error}"
            );
        }
    }

    #[test]
    fn a_value_that_merely_begins_with_a_dash_is_the_callers() {
        // A USE preference against a flag is written `-flag`, so the refusal
        // above keys on the names the flag table holds rather than on a leading
        // dash.
        let options = parse_run(&[
            "--rootfs",
            "/r",
            "--provision-gentoo",
            "amd64",
            "--gentoo-variant",
            "openrc",
            "--gentoo-prefer-use",
            "-systemd",
            "/bin/true",
        ])
        .expect("a valid command line");
        assert_eq!(options.gentoo_prefer_use, ["-systemd"]);
    }

    #[test]
    fn a_value_that_is_a_flags_spelling_is_written_joined() {
        // The escape hatch the refusal names, so a path that really is spelled
        // like a flag stays reachable.
        match parse_args(&["--remove-rootfs=--identity-map"]).expect("the removal should parse") {
            Invocation::Remove { dest, .. } => {
                assert_eq!(dest, PathBuf::from("--identity-map"));
            }
            _ => panic!("expected a removal"),
        }
    }

    #[test]
    fn remove_rootfs_refuses_every_launch_option() {
        // The removal vocabulary is closed, so a launch flag is a usage error
        // rather than a setting a removal would silently ignore. This holds for
        // flags added later too: the parser rejects by exhaustion, not by a
        // list kept in step by hand.
        for flag in [
            "--rootfs",
            "--restrict",
            "--share-net",
            "--provision-tar",
            "--profile",
            "--bind",
            "--seccomp",
        ] {
            let error = parse_error(&["--remove-rootfs", "/roots/a", flag]);
            assert!(
                error.contains(flag) && error.contains("--remove-rootfs"),
                "the error should name both flags, got {error:?}"
            );
        }
    }

    #[test]
    fn remove_rootfs_refuses_a_command() {
        let error = parse_error(&["--remove-rootfs", "/roots/a", "/bin/true"]);
        assert!(error.contains("/bin/true"), "{error}");
    }

    #[test]
    fn remove_rootfs_requires_a_destination() {
        assert!(parse_args(&["--remove-rootfs"]).is_err());
        // The map parser rejects the flag as a spelling before it can be
        // mistaken for the destination.
        assert!(parse_args(&["--identity-map", "--remove-rootfs"]).is_err());
    }

    #[test]
    fn a_launch_is_checked_before_its_root_is_provisioned() {
        // A typo in a profile, or a stack configuration the stack refuses, is
        // reported before a provisioner spends minutes on a root the launch
        // then cannot use, and the root is not provisioned at all.
        let dir = ferroday_cage_testkit::scratch::scratch_dir("fcage-checked-first");
        let tarball = dir.join("root.tar");
        std::fs::write(
            &tarball,
            ferroday_cage_testkit::tar::Tar::new()
                .dir("etc", 0o755)
                .file("etc/hostname", 0o644, b"root\n")
                .finish(),
        )
        .expect("the tarball is written");
        let profile = dir.join("typo.toml");
        std::fs::write(&profile, "rootfs = \"/tmp\"\nnot-a-key = 1\n")
            .expect("the profile is written");
        let path = |path: &Path| path.to_str().expect("a UTF-8 scratch path").to_string();
        for (case, extra) in [
            ("profile", vec!["--profile".to_string(), path(&profile)]),
            (
                "stack",
                vec![
                    "--netstack".to_string(),
                    "--netstack-no-ipv4".to_string(),
                    "--netstack-no-ipv6".to_string(),
                ],
            ),
        ] {
            let rootfs = dir.join(case);
            let mut args = vec![
                "--rootfs".to_string(),
                path(&rootfs),
                "--provision-tar".to_string(),
                path(&tarball),
            ];
            args.extend(extra);
            args.push("/bin/true".to_string());
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            assert_eq!(run(*run_options(&args)), ExitCode::from(FAILED), "{case}");
            assert!(
                !rootfs.exists(),
                "{case}: the root was provisioned for a launch that was refused",
            );
        }
    }

    #[test]
    fn the_host_term_passes_only_beneath_the_base_environment() {
        let term = || Some(OsString::from("xterm-256color"));
        assert_eq!(passed_term(true, false, term()), term());
        // A profile's or --setenv's own TERM wins.
        assert_eq!(passed_term(true, true, term()), None);
        // --no-base-env asks for exactly the variables the run names, so a
        // hermetic run does not vary with the caller's terminal.
        assert_eq!(passed_term(false, false, term()), None);
        assert_eq!(passed_term(true, false, None), None);
    }

    #[test]
    fn an_https_mirror_is_refused_where_it_is_written() {
        // The library's own client cannot fetch one, and its refusal names a
        // setting fcage has no flag for, so the mistake is caught as written.
        let https = "https://deb.debian.org/debian";
        let launch = |args: &[&str]| {
            let mut all = vec!["--rootfs", "/roots/r"];
            all.extend_from_slice(args);
            parse_error(&all)
        };
        for error in [
            launch(&["--provision-debian", "trixie", "--debian-mirror", https]),
            launch(&[
                "--provision-debian",
                "trixie",
                "--debian-mirror-fallback",
                https,
            ]),
            launch(&[
                "--provision-debian",
                "trixie",
                "--debian-repository",
                &format!("suite=trixie mirror={https}"),
            ]),
            launch(&[
                "--provision-debian",
                "trixie",
                "--debian-repository",
                &format!("suite=trixie mirror=http://a mirror-fallback={https}"),
            ]),
            launch(&["--provision-alpine", "v3.23", "--alpine-mirror", https]),
            launch(&[
                "--provision-alpine",
                "v3.23",
                "--alpine-mirror-fallback",
                https,
            ]),
            launch(&[
                "--provision-alpine",
                "v3.23",
                "--alpine-repository",
                &format!("release=v3.23 mirror={https} keys=alpine"),
            ]),
            launch(&[
                "--provision-gentoo",
                "amd64",
                "--gentoo-variant",
                "amd64-openrc",
                "--gentoo-mirror",
                "HTTPS://distfiles.gentoo.org",
            ]),
            parse_error(&["--gentoo-variants", "amd64", "--gentoo-mirror", https]),
            parse_error(&[
                "--gentoo-packages",
                "amd64",
                "--gentoo-mirror-fallback",
                https,
            ]),
        ] {
            assert!(error.contains("https:// mirror"), "{error}");
        }
        // Plain HTTP and a local copy are what fcage fetches.
        assert!(
            parse_args(&[
                "--rootfs",
                "/roots/r",
                "--provision-debian",
                "trixie",
                "--debian-mirror",
                "http://deb.debian.org/debian",
                "--debian-mirror-fallback",
                "file:///srv/mirror/debian",
            ])
            .is_ok()
        );
    }

    #[test]
    fn a_removal_names_a_tree_of_its_own() {
        // An empty value is an unset variable, refused as a usage error before
        // the removal runs.
        for args in [
            &["--remove-rootfs="][..],
            &["--remove-rootfs", ""],
            &["--remove-overlay-upper="],
            &["--remove-overlay-upper", ""],
        ] {
            let error = parse_error(args);
            assert!(error.contains("empty value"), "{args:?}: {error}");
        }
        // A path with no final component names no tree beside its parent.
        for dest in [".", "..", "/", "a/..", "./"] {
            let error = parse_error(&["--remove-rootfs", dest]);
            assert!(error.contains("no directory of its own"), "{dest}: {error}");
        }
        // A trailing `/.` still names the directory before it.
        assert!(parse_args(&["--remove-rootfs", "roots/a/."]).is_ok());
        // The library refuses the same values before it touches anything,
        // which is what makes asking it here harmless; the parse only reports
        // them earlier.
        for dest in ["", ".", "..", "/", "a/..", "./"] {
            assert!(
                matches!(
                    ferroday_cage::provision::Remove::new(dest).run(),
                    Err(ProvisionError::RemoveDestInvalid { .. })
                ),
                "{dest:?}"
            );
        }
        // A listing of what a root has installed refuses the empty value the
        // same way.
        let error = parse_error(&["--gentoo-installed="]);
        assert!(error.contains("empty value"), "{error}");
    }

    /// The export an argument list parses to, panicking if it is anything else.
    fn parse_export_args(args: &[&str]) -> (PathBuf, Option<PathBuf>, IdentityMap, Option<i64>) {
        match parse_args(args).expect("the export should parse") {
            Invocation::Export {
                source,
                dest,
                map,
                clamp_mtime,
            } => (source, dest, map, clamp_mtime),
            _ => panic!("expected an export for {args:?}"),
        }
    }

    #[test]
    fn export_rootfs_takes_its_settings_in_either_form() {
        for args in [
            [
                "--export-rootfs",
                "/roots/trixie",
                "--export-to",
                "/tmp/out.tar",
                "--identity-map",
                "single",
                "--clamp-mtime",
                "1700000000",
            ]
            .as_slice(),
            [
                "--export-rootfs=/roots/trixie",
                "--export-to=/tmp/out.tar",
                "--identity-map=single",
                "--clamp-mtime=1700000000",
            ]
            .as_slice(),
        ] {
            let (source, dest, map, clamp) = parse_export_args(args);
            assert_eq!(source, PathBuf::from("/roots/trixie"));
            assert_eq!(dest, Some(PathBuf::from("/tmp/out.tar")));
            assert_eq!(map, IdentityMap::Single);
            assert_eq!(clamp, Some(1_700_000_000));
        }
    }

    #[test]
    fn export_rootfs_defaults_to_standard_output_and_the_subordinate_map() {
        // Absent a destination the archive goes to standard output, so it pipes
        // into a compressor without a temporary file. The map default is the
        // one a bundled-delegate sandbox writes under, matching removal, since
        // that is the case that needs the escalation at all.
        let (source, dest, map, clamp) = parse_export_args(&["--export-rootfs", "/roots/a"]);
        assert_eq!(source, PathBuf::from("/roots/a"));
        assert_eq!(dest, None, "the default sink is standard output");
        assert_eq!(map, IdentityMap::Subordinate);
        assert_eq!(clamp, None, "an unclamped export records real times");
    }

    #[test]
    fn export_rootfs_refuses_every_launch_option_and_a_command() {
        // The export vocabulary is closed by exhaustion, so a flag added to a
        // launch later is refused here without anyone remembering to add it.
        for flag in [
            "--rootfs",
            "--restrict",
            "--share-net",
            "--provision-tar",
            "--profile",
            "--bind",
            "--remove-rootfs",
        ] {
            let error = parse_error(&["--export-rootfs", "/roots/a", flag]);
            assert!(
                error.contains(flag) && error.contains("--export-rootfs"),
                "the error should name both flags, got {error:?}",
            );
        }
        let error = parse_error(&["--export-rootfs", "/roots/a", "/bin/true"]);
        assert!(error.contains("/bin/true"), "{error}");
    }

    #[test]
    fn a_debian_source_date_epoch_is_a_timestamp_named_by_its_own_flag() {
        let options = run_options(&[
            "--rootfs",
            "/roots/trixie",
            "--provision-debian",
            "trixie",
            "--debian-source-date-epoch",
            "1700000000",
        ]);
        assert_eq!(options.debian_source_date_epoch, Some(1_700_000_000));
        let options = run_options(&[
            "--rootfs",
            "/roots/trixie",
            "--provision-debian",
            "trixie",
            "--debian-source-date-epoch=1700000000",
        ]);
        assert_eq!(options.debian_source_date_epoch, Some(1_700_000_000));

        // The parse is the one --clamp-mtime uses, and the error names the flag
        // it was given to rather than the other one.
        let error = parse_error(&[
            "--rootfs",
            "/roots/trixie",
            "--provision-debian",
            "trixie",
            "--debian-source-date-epoch",
            "yesterday",
        ]);
        assert!(
            error.contains("--debian-source-date-epoch") && !error.contains("--clamp-mtime"),
            "{error}",
        );
    }

    #[test]
    fn a_source_date_epoch_before_1970_is_a_usage_error() {
        // The bootstraps refuse a negative date when they are built, which made
        // a mistyped flag a bootstrap that could not be built, exit 125. A
        // ceiling for --clamp-mtime stays a plain instant.
        for (provisioner, flag) in [
            ("--provision-debian", "--debian-source-date-epoch"),
            ("--provision-alpine", "--alpine-source-date-epoch"),
        ] {
            let error = parse_error(&["--rootfs", "/roots/r", provisioner, "x", flag, "-1"]);
            assert!(error.contains(flag) && error.contains("1970"), "{error}");
            let joined = format!("{flag}=0");
            assert!(parse_args(&["--rootfs", "/roots/r", provisioner, "x", &joined]).is_ok());
        }
    }

    #[test]
    fn an_alpine_source_date_epoch_is_a_timestamp_named_by_its_own_flag() {
        let options = run_options(&[
            "--rootfs",
            "/roots/alpine",
            "--provision-alpine",
            "v3.23",
            "--alpine-source-date-epoch",
            "1700000000",
        ]);
        assert_eq!(options.alpine_source_date_epoch, Some(1_700_000_000));
        let error = parse_error(&[
            "--rootfs",
            "/roots/alpine",
            "--provision-alpine",
            "v3.23",
            "--alpine-source-date-epoch",
            "yesterday",
        ]);
        assert!(error.contains("--alpine-source-date-epoch"), "{error}");
    }

    #[test]
    fn export_rootfs_requires_a_source_and_a_well_formed_ceiling() {
        assert!(parse_args(&["--export-rootfs"]).is_err());
        assert!(parse_args(&["--export-rootfs", "/roots/a", "--export-to"]).is_err());
        for bad in ["yesterday", "1.5", ""] {
            assert!(
                parse_args(&["--export-rootfs", "/roots/a", "--clamp-mtime", bad]).is_err(),
                "{bad:?} must be refused as a timestamp",
            );
        }
        // The ceiling is a plain instant, so one before the epoch is a value
        // rather than an error.
        let (_, _, _, clamp) =
            parse_export_args(&["--export-rootfs", "/roots/a", "--clamp-mtime=-1"]);
        assert_eq!(clamp, Some(-1));
    }

    #[test]
    fn export_rootfs_still_answers_help_and_version() {
        assert!(matches!(
            parse_args(&["--export-rootfs", "/roots/a", "--help"]),
            Ok(Invocation::Help)
        ));
        assert!(matches!(
            parse_args(&["--export-rootfs", "/roots/a", "--version"]),
            Ok(Invocation::Version)
        ));
    }

    #[test]
    fn remove_rootfs_still_answers_help_and_version() {
        assert!(matches!(
            parse_args(&["--remove-rootfs", "/roots/a", "--help"]),
            Ok(Invocation::Help)
        ));
        assert!(matches!(
            parse_args(&["--remove-rootfs", "/roots/a", "--version"]),
            Ok(Invocation::Version)
        ));
    }

    #[test]
    fn rlimit_parses_a_shared_and_a_split_value() {
        let (resource, soft, hard) = parse_rlimit("processes=64").unwrap();
        assert_eq!(resource, Resource::Processes);
        assert_eq!(soft, Limit::of(64));
        assert_eq!(
            hard,
            Limit::of(64),
            "an omitted hard limit repeats the soft"
        );

        let (resource, soft, hard) = parse_rlimit("cpu-time=10:unlimited").unwrap();
        assert_eq!(resource, Resource::CpuTime);
        assert_eq!(soft, Limit::of(10));
        assert_eq!(hard, Limit::UNLIMITED);
    }

    #[test]
    fn rlimit_rejects_bad_input() {
        for bad in ["processes", "nonsense=1", "processes=x", "processes=1:x"] {
            assert!(parse_rlimit(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn rlimit_names_the_resources_it_accepts() {
        // The list comes from the library's own `Deserialize`, so it stays
        // correct as resources are added rather than being restated here.
        let error = parse_rlimit("nonsense=1").unwrap_err();
        assert!(error.contains("address-space"), "{error}");
        assert!(error.contains("stack"), "{error}");
    }

    #[test]
    fn identity_map_parses_the_unit_and_range_forms() {
        assert!(matches!(
            parse_identity_map("--identity-map", "single").unwrap(),
            IdentityMap::Single
        ));
        assert!(matches!(
            parse_identity_map("--identity-map", "subordinate").unwrap(),
            IdentityMap::Subordinate
        ));
        let map = parse_identity_map("--identity-map", "uid=0:1000:1,1:100000:65536 gid=0:1000:1")
            .unwrap();
        match map {
            IdentityMap::Ranges { uid, gid, .. } => {
                assert_eq!(uid.len(), 2);
                assert_eq!(
                    uid[1],
                    IdRange {
                        inside: 1,
                        outside: 100_000,
                        count: 65_536
                    }
                );
                assert_eq!(gid.len(), 1);
            }
            other => panic!("expected an explicit range map, got {other:?}"),
        }
    }

    #[test]
    fn identity_map_rejects_a_half_specified_range() {
        // Both extent lists are required: a map missing one cannot be written.
        assert!(parse_identity_map("--identity-map", "uid=0:1000:1").is_err());
        assert!(parse_identity_map("--identity-map", "nonsense").is_err());
        assert!(parse_identity_map("--identity-map", "uid=0:1000").is_err());
    }

    #[test]
    fn run_as_parses_ids_and_groups() {
        let identity = parse_run_as("250:250").unwrap();
        assert_eq!(identity, Identity::new(250, 250));
        let with_groups = parse_run_as("250:250:10,20").unwrap();
        assert_eq!(with_groups, Identity::new(250, 250).groups([10, 20]));
        for bad in ["", "250", "250:", "x:1", "250:250:x"] {
            assert!(parse_run_as(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn present_as_takes_ids_or_own() {
        let presented = |value: &str| {
            run_options(&["--rootfs", "/r", "--present-as", value, "--", "/bin/true"]).present_as
        };
        assert_eq!(
            presented("1000:100"),
            Some(PresentedIdentity::ids(1000, 100))
        );
        assert_eq!(presented("own"), Some(PresentedIdentity::Own));
        let error = parse_error(&["--rootfs", "/r", "--present-as", "root", "--", "/bin/true"]);
        assert!(
            error.contains("--present-as") && error.contains("UID:GID"),
            "{error}"
        );
    }

    #[test]
    fn present_as_cannot_be_used_with_restrict() {
        let error = parse_error(&["--restrict", "--present-as", "own", "--", "/bin/true"]);
        assert!(
            error.contains("--present-as cannot be used with --restrict"),
            "{error}"
        );
    }

    #[test]
    fn raw_mount_parses_its_fields() {
        let mount = parse_raw_mount("target=/sys fstype=sysfs flags=0xE").unwrap();
        assert_eq!(mount.get_target(), Path::new("/sys"));
        assert_eq!(mount.get_fstype(), Some("sysfs"));
        assert_eq!(mount.get_flags(), 0xE);
        assert_eq!(mount.get_source(), None);
        // A target is the one required field, and an unknown field is named.
        assert!(parse_raw_mount("fstype=sysfs").is_err());
        assert!(parse_raw_mount("target=/sys nonsense=1").is_err());
    }

    #[test]
    fn repository_requires_a_suite_and_orders_its_mirrors() {
        let repository = parse_repository(
            "suite=trixie mirror=file:///srv/pool mirror-fallback=file:///srv/snapshot \
             components=main,contrib trust-unsigned name=local",
        )
        .unwrap();
        let rendered = format!("{repository:?}");
        assert!(rendered.contains("file:///srv/pool"), "{rendered}");
        assert!(rendered.contains("trust: Unsigned"), "{rendered}");
        assert!(parse_repository("mirror=file:///srv/pool").is_err());
    }

    #[test]
    fn a_field_that_takes_no_value_refuses_one() {
        // `trust-unsigned=false` reads as the field being present, so a value
        // meaning the opposite turned archive signature verification off. A
        // field with no off state cannot honour one, so it is a usage error.
        for spec in [
            "suite=trixie mirror=file:///srv/pool trust-unsigned=false",
            "suite=trixie mirror=file:///srv/pool allow-stale-release=no",
        ] {
            let error = parse_repository(spec).expect_err("a value on a bare field is refused");
            assert!(error.contains("takes no value"), "{error}");
        }
        // Bare is the spelling, and it still means what it says.
        let repository = parse_repository("suite=trixie mirror=file:///srv/pool trust-unsigned")
            .expect("the bare field parses");
        assert!(format!("{repository:?}").contains("trust: Unsigned"));
    }

    #[test]
    fn priority_parses_the_archive_bands() {
        assert_eq!(parse_priority("required").unwrap(), Priority::Required);
        assert_eq!(parse_priority("optional").unwrap(), Priority::Optional);
        assert!(parse_priority("urgent").is_err());
    }

    #[test]
    fn an_empty_root_is_composed_by_the_mount_flags_and_stands_alone() {
        let options = run_options(&[
            "--empty-rootfs",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/bin",
            "/bin",
            "/bin/true",
        ]);
        assert!(options.empty_rootfs);
        // The link takes its place in the one mount sequence, after the bind.
        let [Mount::Bind(_), Mount::Symlink(link)] = &options.mounts[..] else {
            panic!("a bind then a link: {:?}", options.mounts);
        };
        assert_eq!(link.get_target(), Path::new("usr/bin"));
        assert_eq!(link.get_path(), Path::new("/bin"));

        for args in [
            ["--empty-rootfs", "--rootfs", "/r", "/bin/true"].as_slice(),
            [
                "--empty-rootfs",
                "--overlay-lower",
                "/l",
                "--overlay-upper",
                "/u",
                "/bin/true",
            ]
            .as_slice(),
        ] {
            let error = parse_error(args);
            assert!(error.contains("are alternatives"), "{args:?}: {error}");
        }
        for (args, flag) in [
            (
                [
                    "--restrict",
                    "--empty-rootfs",
                    "--landlock-ro",
                    "/usr",
                    "/bin/true",
                ]
                .as_slice(),
                "--empty-rootfs",
            ),
            (
                [
                    "--restrict",
                    "--symlink",
                    "a",
                    "/b",
                    "--landlock-ro",
                    "/usr",
                    "/bin/true",
                ]
                .as_slice(),
                "--symlink",
            ),
        ] {
            let error = parse_error(args);
            assert!(
                error.contains(flag) && error.contains("--restrict"),
                "{error}"
            );
        }
    }

    #[test]
    fn an_overlay_root_needs_a_lower_and_an_upper() {
        let args = |items: &[&str]| {
            items
                .iter()
                .map(|item| OsString::from(*item))
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert!(parse(args(&["--overlay-upper", "/tmp/up", "/bin/true"])).is_err());
        assert!(parse(args(&["--overlay-lower", "/tmp/low", "/bin/true"])).is_err());
        // A plain rootfs and an overlay root are alternatives, not a pair.
        assert!(
            parse(args(&[
                "--rootfs",
                "/tmp/root",
                "--overlay-lower",
                "/tmp/low",
                "--overlay-upper",
                "/tmp/up",
                "/bin/true",
            ]))
            .is_err()
        );
        assert!(
            parse(args(&[
                "--overlay-lower",
                "/tmp/low",
                "--overlay-upper",
                "/tmp/up",
                "/bin/true",
            ]))
            .is_ok()
        );
    }

    #[test]
    fn seconds_parse() {
        let parsed = parse_seconds("--timeout", OsStr::new("1.5")).unwrap();
        assert_eq!(parsed, Duration::from_millis(1500));
    }

    #[test]
    fn seconds_reject_bad_values() {
        // Includes values that are finite and positive but too large for a
        // Duration; these must be a usage error, not a panic.
        // A positive value below a nanosecond rounds to no time at all.
        for bad in ["", "abc", "0", "-1", "nan", "inf", "1e300", "1e-10"] {
            assert!(
                parse_seconds("--timeout", OsStr::new(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn cidr_rejects_an_out_of_range_prefix() {
        let (addr, len) = parse_cidr("10.0.2.0/24").unwrap();
        assert_eq!(addr, Ipv4Addr::new(10, 0, 2, 0));
        assert_eq!(len, 24);
        // A prefix past /32 is a usage error caught at parse time, not deferred
        // to the library's build-time rejection.
        for bad in ["10.0.2.0/33", "10.0.2.0/255"] {
            assert!(parse_cidr(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// The syscall number for a name on the host, for test expectations.
    fn sysno(name: &str) -> i64 {
        resolve_syscall_name("--test", name).expect("a known syscall name")
    }

    #[test]
    fn seccomp_names_resolve_and_accumulate() {
        let mut target = Vec::new();
        parse_seccomp_names("--seccomp-allow", "read, write ,exit_group", &mut target).unwrap();
        assert_eq!(
            target,
            vec![sysno("read"), sysno("write"), sysno("exit_group")]
        );
        parse_seccomp_names("--seccomp-allow", "ioctl", &mut target).unwrap();
        assert_eq!(target.last(), Some(&sysno("ioctl")));
    }

    #[test]
    fn seccomp_rule_parses_a_simple_condition() {
        let (syscall, conditions) = parse_seccomp_rule(
            "--seccomp-allow-rule",
            "ioctl arg=1 len=dword op=eq value=0x5413",
        )
        .unwrap();
        assert_eq!(syscall, sysno("ioctl"));
        assert_eq!(conditions, vec![SeccompArg::eq_dword(1, 0x5413)]);
    }

    #[test]
    fn seccomp_rule_parses_masked_eq_and_decimal() {
        let (syscall, conditions) = parse_seccomp_rule(
            "--seccomp-allow-rule",
            "clone arg=0 len=qword op=masked-eq value=0 mask=268435456",
        )
        .unwrap();
        assert_eq!(syscall, sysno("clone"));
        assert_eq!(
            conditions,
            vec![SeccompArg::masked_eq_qword(0, 0x1000_0000, 0)]
        );
    }

    #[test]
    fn seccomp_rule_parses_anded_conditions() {
        let (_, conditions) = parse_seccomp_rule(
            "--seccomp-deny-rule",
            "socket arg=0 len=dword op=eq value=2, arg=1 len=dword op=eq value=1",
        )
        .unwrap();
        assert_eq!(
            conditions,
            vec![SeccompArg::eq_dword(0, 2), SeccompArg::eq_dword(1, 1)]
        );
    }

    #[test]
    fn seccomp_rule_without_conditions_lists_the_syscall() {
        let (syscall, conditions) = parse_seccomp_rule("--seccomp-deny-rule", "ptrace").unwrap();
        assert_eq!(syscall, sysno("ptrace"));
        assert!(conditions.is_empty());
    }

    #[test]
    fn seccomp_rule_rejects_malformed_conditions() {
        let cases = [
            ("ioctl arg=1 op=eq value=1", "len"),     // missing width
            ("ioctl len=dword op=eq value=1", "arg"), // missing index
            ("ioctl arg=1 len=dword value=1", "op"),  // missing op
            ("ioctl arg=1 len=dword op=eq", "value"), // missing value
            ("ioctl arg=1 len=dword op=eq value=1 mask=3", "masked-eq"), // stray mask
            ("clone arg=0 len=qword op=masked-eq value=0", "mask"), // masked-eq needs mask
            ("ioctl arg=9 len=dword op=eq value=1", "0 through 5"), // bad index
            ("ioctl arg=1 len=word op=eq value=1", "dword"), // bad width
            ("ioctl arg=1 len=dword op=lol value=1", "op must be"), // bad op
            ("ioctl arg=1 len=dword op=eq value=xyz", "number"), // bad value
            ("ioctl arg=1 len=dword eq value=1", "key=value"), // bare token
            (
                "ioctl arg=1 len=dword op=eq value=1 extra=2",
                "unknown condition key",
            ),
            ("nope arg=1 len=dword op=eq value=1", "unknown syscall"),
        ];
        for (input, needle) in cases {
            let err = parse_seccomp_rule("--seccomp-allow-rule", input)
                .expect_err(&format!("{input:?} must be rejected"));
            assert!(
                err.contains(needle),
                "error {err:?} for {input:?} should mention {needle:?}"
            );
        }
    }

    #[test]
    fn u64_literals_accept_decimal_and_hex() {
        assert_eq!(parse_u64_literal("--f", "value", "42").unwrap(), 42);
        assert_eq!(parse_u64_literal("--f", "value", "0x2a").unwrap(), 42);
        assert_eq!(parse_u64_literal("--f", "value", "0X2A").unwrap(), 42);
        assert!(parse_u64_literal("--f", "value", "").is_err());
        assert!(parse_u64_literal("--f", "value", "0xzz").is_err());
    }

    #[test]
    fn assemble_seccomp_reconciles_the_flags() {
        // Nothing given: no policy.
        assert!(
            assemble_seccomp(false, vec![], vec![], vec![], vec![])
                .unwrap()
                .is_none()
        );
        // Curated alone.
        assert!(matches!(
            assemble_seccomp(true, vec![], vec![], vec![], vec![]).unwrap(),
            Some(SeccompPolicy::Curated)
        ));
        // An allow side (bare plus a rule) yields Rules.
        assert!(matches!(
            assemble_seccomp(
                false,
                vec![sysno("read")],
                vec![],
                vec![(sysno("ioctl"), vec![SeccompArg::eq_dword(1, 0x5413)])],
                vec![],
            )
            .unwrap(),
            Some(SeccompPolicy::Rules(_))
        ));
    }

    #[test]
    fn assemble_seccomp_rejects_contradictions() {
        // Curated cannot be combined with named rules.
        assert!(
            assemble_seccomp(true, vec![sysno("read")], vec![], vec![], vec![])
                .unwrap_err()
                .contains("curated")
        );
        // An allow side and a deny side cannot be combined.
        assert!(
            assemble_seccomp(
                false,
                vec![sysno("read")],
                vec![sysno("write")],
                vec![],
                vec![]
            )
            .unwrap_err()
            .contains("cannot be combined")
        );
    }

    #[test]
    fn seccomp_flags_flow_through_parse() {
        let args = [
            "--restrict",
            "--seccomp-deny-rule",
            "write arg=0 len=dword op=eq value=1",
            "--",
            "/bin/echo",
            "hi",
        ]
        .into_iter()
        .map(OsString::from);
        let parsed = parse(args).expect("a valid command line");
        match parsed {
            Invocation::Run(options) => {
                assert!(matches!(options.seccomp, Some(SeccompPolicy::Rules(_))));
            }
            _ => panic!("expected a run invocation"),
        }
    }

    #[test]
    fn seccomp_errnos_join_a_policy_or_make_one() {
        // By name in any case, or by number.
        assert_eq!(
            parse_seccomp_errno("--seccomp-errno", "clone3=enosys"),
            Ok((sysno("clone3"), 38)),
        );
        assert_eq!(
            parse_seccomp_errno("--seccomp-errno", "clone3=38"),
            Ok((sysno("clone3"), 38)),
        );
        for bad in ["clone3", "clone3=ENOPE", "nosuchcall=ENOSYS"] {
            assert!(
                parse_seccomp_errno("--seccomp-errno", bad).is_err(),
                "{bad}"
            );
        }
        // Only an errno a failed syscall can report. Zero answers a call with a
        // success it never performed, so `getpid=0` reports pid 0 and
        // `clone3=0` tells the parent it is the child; past 4095 the C library
        // reads the result as a value rather than a failure.
        for out_of_range in ["clone3=0", "getpid=4096", "getpid=65535", "getpid=-1"] {
            let error =
                parse_seccomp_errno("--seccomp-errno", out_of_range).expect_err(out_of_range);
            assert!(error.contains("1 to 4095"), "{out_of_range}: {error}");
        }
        assert_eq!(
            parse_seccomp_errno("--seccomp-errno", "getpid=4095"),
            Ok((sysno("getpid"), 4095)),
        );

        // An errno alone is a restriction's whole grant, so it is accepted.
        let alone = run_options(&[
            "--restrict",
            "--seccomp-errno",
            "clone3=ENOSYS",
            "/bin/true",
        ]);
        assert_eq!(alone.seccomp_errno, [(sysno("clone3"), 38)]);
        // Beside the curated posture it is refused, as soon as both are read.
        assert!(
            parse_error(&[
                "--restrict",
                "--seccomp",
                "curated",
                "--seccomp-errno",
                "clone3=ENOSYS",
                "/bin/true"
            ])
            .contains("--seccomp-errno")
        );
    }

    #[test]
    fn an_errno_parses_exactly_where_the_library_builds_it() {
        // A usage error at parse is the library's own refusal at build, met
        // earlier: both read the range through the library, at each of its
        // edges.
        for errno in [0, 1, 4095, 4096, u16::MAX] {
            let parsed = parse_seccomp_errno("--seccomp-errno", &format!("getpid={errno}"));
            let built = Restriction::builder()
                .command("/bin/true")
                .seccomp(SeccompPolicy::Rules(
                    SeccompRules::denying([]).errno_for(sysno("getpid"), errno),
                ))
                .build();
            assert_eq!(parsed.is_ok(), built.is_ok(), "errno {errno}");
        }
    }

    /// The rules a composed policy holds, rendered for comparison.
    fn rules_of(policy: Option<SeccompPolicy>) -> String {
        match policy {
            Some(SeccompPolicy::Rules(rules)) => format!("{rules:?}"),
            Some(_) => panic!("the policy is not a rule set"),
            None => panic!("no policy was composed"),
        }
    }

    #[test]
    fn a_seccomp_errno_joins_whichever_policy_stands() {
        let errno = || vec![(sysno("clone3"), 38)];
        let allow = || SeccompRules::allowing([sysno("read")]);
        let deny = || SeccompRules::denying([sysno("ptrace")]);

        // With no other policy, the errnos make a deny side of their own.
        assert_eq!(
            rules_of(compose_seccomp(None, errno(), None).unwrap()),
            format!(
                "{:?}",
                SeccompRules::denying([]).errno_for(sysno("clone3"), 38)
            ),
        );
        // Beside the flags' own side, they join it.
        assert_eq!(
            rules_of(compose_seccomp(Some(SeccompPolicy::Rules(allow())), errno(), None).unwrap()),
            format!("{:?}", allow().errno_for(sysno("clone3"), 38)),
        );
        // Beside a profile's allow-list, and no allow or deny flag, they join
        // the profile's list rather than replacing it with a deny side that
        // refuses only what they name. The list is the confinement.
        let profile = SeccompPolicy::Rules(allow());
        assert_eq!(
            rules_of(compose_seccomp(None, errno(), Some(&profile)).unwrap()),
            format!("{:?}", allow().errno_for(sysno("clone3"), 38)),
        );
        // A side the flags assemble replaces the profile's, as any flag beside
        // a profile overrides it, and the errnos join that side.
        assert_eq!(
            rules_of(
                compose_seccomp(Some(SeccompPolicy::Rules(deny())), errno(), Some(&profile))
                    .unwrap()
            ),
            format!("{:?}", deny().errno_for(sysno("clone3"), 38)),
        );
        // A profile's curated posture takes no errno.
        assert!(
            compose_seccomp(None, errno(), Some(&SeccompPolicy::Curated))
                .unwrap_err()
                .contains("profile's seccomp policy")
        );
        // Without errnos, the flags' policy stands as it is, and with no flag
        // at all the profile's is left in place.
        assert!(
            compose_seccomp(None, Vec::new(), Some(&profile))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_launch_beside_a_profile_keeps_its_seccomp_list_under_an_errno() {
        let dir = ferroday_cage_testkit::scratch::scratch_dir("fcage-profile-seccomp");
        let profile = dir.join("strict.toml");
        std::fs::write(
            &profile,
            "rootfs = \"/tmp\"\ncommand = \"/bin/true\"\n\n\
             [hardening.seccomp]\nallow = [\"read\", \"write\", \"execve\"]\n",
        )
        .expect("the profile is written");
        let options = run_options(&[
            "--profile",
            profile.to_str().expect("a UTF-8 scratch path"),
            "--seccomp-errno",
            "clone3=ENOSYS",
        ]);
        let launch = Launch::prepare(*options).unwrap_or_else(|_| panic!("the launch composes"));
        let joined = launch.builder.get_seccomp().cloned();
        assert_eq!(
            rules_of(joined),
            format!(
                "{:?}",
                SeccompRules::allowing([sysno("read"), sysno("write"), sysno("execve")])
                    .errno_for(sysno("clone3"), 38)
            ),
        );
    }

    #[test]
    fn landlock_scopes_parse_as_a_list() {
        let options = run_options(&[
            "--rootfs",
            "/srv/rootfs",
            "--landlock-scope",
            "signal,abstract-unix-socket",
            "/bin/true",
        ]);
        assert_eq!(
            options.landlock_scope,
            Some(vec![
                LandlockScope::Signal,
                LandlockScope::AbstractUnixSocket
            ]),
        );
        // An empty list is no scope, which a restriction needs to opt out.
        let options = run_options(&[
            "--restrict",
            "--seccomp",
            "curated",
            "--landlock-scope",
            "",
            "/bin/true",
        ]);
        assert_eq!(options.landlock_scope, Some(Vec::new()));
        assert!(parse_error(&["--landlock-scope", "signals", "/bin/true"]).contains("signals"));
    }

    /// Parses a command line, expecting a run invocation.
    fn parse_run(args: &[&str]) -> Result<Options, String> {
        match parse(args.iter().map(|arg| OsString::from(*arg)))? {
            Invocation::Run(options) => Ok(*options),
            _ => panic!("expected a run invocation"),
        }
    }

    #[test]
    fn profile_flags_set_the_trust_mode() {
        // --profile loads fully trusted.
        let options =
            parse_run(&["--profile", "/p.toml", "/bin/true"]).expect("a valid command line");
        assert_eq!(options.profile.as_deref(), Some(Path::new("/p.toml")));
        assert!(!options.profile_restricted);

        // --restricted-profile loads under the restricted policy.
        let options = parse_run(&["--restricted-profile", "/p.toml", "/bin/true"])
            .expect("a valid command line");
        assert_eq!(options.profile.as_deref(), Some(Path::new("/p.toml")));
        assert!(options.profile_restricted);

        // The two are mutually exclusive.
        assert!(
            parse_run(&["--profile", "/a", "--restricted-profile", "/b", "/bin/true"]).is_err()
        );
    }

    #[test]
    fn netstack_flags_flow_through_parse() {
        let options = parse_run(&[
            "--rootfs",
            "/r",
            "--netstack",
            "--netstack-cidr",
            "192.168.5.0/24",
            "--netstack-mtu",
            "1400",
            "--netstack-host-loopback",
            "--netstack-host-port",
            "5432",
            "--netstack-host-port",
            "6379",
            "--netstack-publish",
            "8080",
            "80",
            "--netstack-publish",
            "[::1]:8443",
            "443",
            "/bin/true",
        ])
        .expect("a valid command line");
        assert!(options.netstack);
        assert_eq!(
            options.netstack_cidr,
            Some((Ipv4Addr::new(192, 168, 5, 0), 24))
        );
        assert_eq!(options.netstack_mtu, Some(1400));
        assert!(options.netstack_host_loopback);
        assert_eq!(options.netstack_host_ports, [5432, 6379]);
        assert_eq!(
            options.netstack_publish,
            [
                ("127.0.0.1:8080".parse().unwrap(), 80),
                ("[::1]:8443".parse().unwrap(), 443),
            ],
        );
        netstack_from(&options).expect("the settings compose a stack");
    }

    #[test]
    fn a_published_host_side_is_an_address_or_a_loopback_port() {
        // A bare port stays on loopback, the address that reaches least; any
        // wider exposure is written out.
        assert_eq!(
            parse_publish_host("8080").expect("a bare port"),
            "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        );
        assert_eq!(
            parse_publish_host("0.0.0.0:8080").expect("an explicit wildcard"),
            "0.0.0.0:8080".parse::<SocketAddr>().unwrap(),
        );
        assert!(
            parse_publish_host("::1:8080").is_err(),
            "IPv6 needs brackets"
        );
        assert!(
            parse_publish_host("localhost:8080").is_err(),
            "no name lookup"
        );
        let err = parse_run(&[
            "--rootfs",
            "/r",
            "--netstack",
            "--netstack-publish",
            "8080",
            "/bin/true",
        ])
        .err()
        .expect("the flag takes a host and a guest port");
        assert!(err.contains("--netstack-publish"), "{err}");
        // Port 0 asks the kernel for a free port on the host side, and means
        // nothing on the guest's: refused here, it is a usage error rather than
        // a stack that cannot be built.
        let err = parse_run(&[
            "--rootfs",
            "/r",
            "--netstack",
            "--netstack-publish",
            "0",
            "0",
            "/bin/true",
        ])
        .err()
        .expect("a guest port of 0 is refused");
        assert!(
            err.contains("--netstack-publish") && err.contains("guest port"),
            "{err}"
        );
        assert!(
            parse_run(&[
                "--rootfs",
                "/r",
                "--netstack",
                "--netstack-publish",
                "0",
                "80",
                "/bin/true"
            ])
            .is_ok()
        );
    }

    #[test]
    fn every_netstack_setting_the_library_offers_has_a_flag_that_reaches_it() {
        // The stack the flags describe is assembled by `netstack_from`, so
        // driving that is what proves a flag reaches the builder rather than
        // only reaching `Options`.
        let options = parse_run(&[
            "--rootfs",
            "/r",
            "--netstack",
            "--netstack-cidr",
            "192.168.5.0/24",
            "--netstack-cidr6",
            "fd11:2233::/64",
            "--netstack-no-ipv6",
            "--netstack-interface",
            "eth9",
            "--netstack-mtu",
            "1400",
            "/bin/true",
        ])
        .expect("a valid command line");
        assert_eq!(
            options.netstack_cidr6,
            Some(("fd11:2233::".parse::<Ipv6Addr>().unwrap(), 64))
        );
        assert!(options.netstack_no_ipv6);
        assert!(!options.netstack_no_ipv4);
        assert_eq!(options.netstack_interface.as_deref(), Some("eth9"));
        netstack_from(&options).expect("the settings compose a stack");

        // Both protocols off is the one combination the flags can name and the
        // stack has no answer for, and it is the library that says so.
        let neither = parse_run(&[
            "--rootfs",
            "/r",
            "--netstack",
            "--netstack-no-ipv4",
            "--netstack-no-ipv6",
            "/bin/true",
        ])
        .expect("a valid command line");
        assert!(netstack_from(&neither).is_err());
    }

    #[test]
    fn netstack_cidr_and_mtu_reject_bad_values() {
        assert!(
            parse_cidr("10.0.2.0").is_err(),
            "a CIDR needs a prefix length"
        );
        assert!(parse_cidr("not-an-ip/24").is_err());
        assert!(parse_cidr("10.0.2.0/schwa").is_err());
        parse_cidr("10.0.2.0/24").expect("a well-formed CIDR parses");
        assert!(parse_mtu("70000").is_err(), "an MTU must fit a u16");
        parse_mtu("1500").expect("a valid MTU parses");

        assert!(
            parse_cidr6("fd00::").is_err(),
            "a CIDR needs a prefix length"
        );
        assert!(
            parse_cidr6("10.0.2.0/24").is_err(),
            "that is not an IPv6 address"
        );
        assert!(parse_cidr6("fd00::/schwa").is_err());
        assert!(
            parse_cidr6("fd00::/129").is_err(),
            "129 is past the ceiling"
        );
        parse_cidr6("fd00::/64").expect("a well-formed CIDR parses");
    }

    #[test]
    fn netstack_conflicts_with_share_net() {
        let err = parse_run(&["--rootfs", "/r", "--netstack", "--share-net", "/bin/true"])
            .err()
            .expect("sharing the host network contradicts the native stack");
        assert!(err.contains("--share-net"), "{err}");
    }

    #[test]
    fn netstack_modifiers_require_netstack() {
        let err = parse_run(&["--rootfs", "/r", "--netstack-mtu", "1400", "/bin/true"])
            .err()
            .expect("a sub-flag without --netstack is a usage error");
        assert!(err.contains("require --netstack"), "{err}");
    }

    #[test]
    fn terminal_conflicts_with_a_null_stdin() {
        // A terminal is all three of the command's standard streams, so a
        // stated disposition for one means two different things were asked for.
        // Named here rather than left to the launch, so the message names both
        // flags.
        let err = parse_run(&[
            "--rootfs",
            "/r",
            "--terminal",
            "--stdin",
            "null",
            "/bin/true",
        ])
        .err()
        .expect("a directed stream contradicts a terminal");
        assert!(err.contains("--terminal"), "{err}");
        assert!(err.contains("--stdin"), "{err}");
    }

    #[test]
    fn terminal_conflicts_with_a_null_stdin_under_restrict() {
        // The restriction fallback supports a terminal too, so the same
        // contradiction has to be caught on that path — which returns before
        // the launch checks below it.
        let err = parse_run(&[
            "--restrict",
            "--seccomp",
            "curated",
            "--terminal",
            "--stdin=null",
            "/bin/true",
        ])
        .err()
        .expect("a directed stream contradicts a terminal here too");
        assert!(err.contains("--terminal"), "{err}");
    }

    #[test]
    fn terminal_composes_with_a_restriction_and_with_the_native_stack() {
        // Both are advertised independently, so both compose: a restriction
        // allocates its own pseudoterminal, and a native-stack run takes the
        // pending path and hands the primary over before the command runs.
        parse_run(&[
            "--restrict",
            "--seccomp",
            "curated",
            "--terminal",
            "/bin/true",
        ])
        .expect("a restriction takes a terminal");
        parse_run(&["--rootfs", "/r", "--netstack", "--terminal", "/bin/true"])
            .expect("the native stack takes a terminal");
    }

    #[test]
    fn netstack_conflicts_with_restrict() {
        let err = parse_run(&[
            "--restrict",
            "--netstack",
            "--landlock-ro",
            "/lib",
            "/bin/true",
        ])
        .err()
        .expect("the native stack has no meaning under a restriction");
        assert!(err.contains("--netstack"), "{err}");
    }

    #[test]
    fn restrict_requires_a_grant() {
        // Without a Landlock or seccomp grant a restriction confines nothing;
        // it is a usage error, not a launch error.
        let err = parse_run(&["--restrict", "/bin/true"])
            .err()
            .expect("a restriction with no grant is rejected");
        assert!(err.contains("at least one grant"), "{err}");
        // A scope is not a grant: it enrolls no path and no port, so the
        // filesystem and the network stay open, and the help says so.
        let err = parse_run(&["--restrict", "--landlock-scope", "signal", "/bin/true"])
            .err()
            .expect("a restriction with only a scope is rejected");
        assert!(err.contains("--landlock-scope alone"), "{err}");
        let help = usage();
        assert!(
            help.contains("--restrict") && help.contains("requires a Landlock"),
            "the help names what a restriction requires",
        );
        // A single grant satisfies it, and so does an errno answer alone.
        parse_run(&["--restrict", "--landlock-ro", "/lib", "/bin/true"])
            .expect("a Landlock grant is enough");
        parse_run(&["--restrict", "--seccomp-errno", "ptrace=EPERM", "/bin/true"])
            .expect("a seccomp errno is enough");
    }

    #[test]
    fn kill_after_requires_timeout() {
        let err = parse_run(&["--rootfs", "/r", "--kill-after", "5", "/bin/true"])
            .err()
            .expect("--kill-after alone has nothing to hang on");
        assert!(err.contains("--kill-after requires --timeout"), "{err}");
        // With a timeout it is accepted.
        parse_run(&[
            "--rootfs",
            "/r",
            "--timeout",
            "10",
            "--kill-after",
            "5",
            "/bin/true",
        ])
        .expect("--kill-after with --timeout is valid");
    }

    #[test]
    fn only_a_nameserver_the_stack_forwards_to_is_composed() {
        let stack = NetStack::default();
        let forwarded = |contents: &str| names_a_forwarded_nameserver(contents, &stack);
        assert!(!forwarded("nameserver 127.0.0.53\noptions edns0\n"));
        assert!(forwarded("nameserver 127.0.0.53\nnameserver 9.9.9.9\n"));
        assert!(forwarded("nameserver 2606:4700:4700::1111\n"));
        assert!(!forwarded("# only a comment\n"));
        // A cloud host's own resolvers: AWS's link-local IPv4 one and its
        // instance-service IPv6 one, both of which the stack refuses.
        assert!(!forwarded("nameserver 169.254.169.253\n"));
        assert!(!forwarded("nameserver fd00:ec2::253\n"));
        // A resolver on the guest's own subnet is on-link to the guest, and the
        // stack forwards nothing there.
        assert!(!forwarded("nameserver 10.0.2.3\n"));
        // The keyword and the address run together is not a nameserver line.
        assert!(!forwarded("nameserver9.9.9.9\n"));
        // A protocol the run turns off reaches nothing.
        let ipv4_only = NetStack::builder()
            .ipv6(false)
            .build()
            .expect("a valid configuration");
        assert!(!names_a_forwarded_nameserver(
            "nameserver 2606:4700:4700::1111\n",
            &ipv4_only
        ));
    }
}
