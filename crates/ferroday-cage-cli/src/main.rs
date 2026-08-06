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
//! library accepts loads here, and every capability the builder offers has a
//! flag. Two library seams have no command-line form, because neither is
//! expressible as an argument: `Stdio::Fd`, which hands the command an open
//! descriptor, and `CageBuilder::id_mapper`, which supplies an identity-map
//! delegate as code. `--stdin` therefore offers the two dispositions a profile
//! can name, and `--identity-map` the delegates the library bundles. The output
//! pair has no flag at all: a shell already spells both of its dispositions,
//! and a profile carries `stdout` and `stderr` where they belong.

mod terminal;

use std::ffi::{OsStr, OsString};
use std::net::Ipv4Addr;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ferroday_cage::provision::debian::{Priority, Repository};
use ferroday_cage::{
    Bind, Cage, CageBuilder, Capability, Error, ExitStatus, FsAccess, IdRange, Identity,
    IdentityMap, Limit, Mount, NetAccess, NetStack, Network, Overlay, RawMount, Resource,
    RestrictedProfile, Restriction, Running, SeccompArg, SeccompArgLen, SeccompCompare,
    SeccompPolicy, SeccompRules, SetupStep, Stdio,
};
use serde::Deserialize as _;

const USAGE: &str = "\
Run a command inside an unprivileged Linux sandbox.

Usage: fcage [--rootfs DIR | --overlay-lower DIR | --profile FILE | --restricted-profile FILE | --restrict] [OPTIONS] [--] [COMMAND [ARGS...]]
       fcage --remove-rootfs DIR [--identity-map M]
       fcage --export-rootfs DIR [--export-to FILE] [--identity-map M] [--clamp-mtime EPOCH]

Provisioning the root filesystem:
  --rootfs DIR          Directory to present as the sandbox root filesystem
  --provision-tar FILE  Provision --rootfs from a tar archive (plain, gzip,
                        xz, or zstd) when the directory does not exist yet
  --provision-debian SUITE
                        Bootstrap --rootfs as a Debian SUITE (e.g. trixie)
                        from the archive; given without a command, provision
                        and exit
  --debian-arch ARCH    Target architecture for --provision-debian (default:
                        the host architecture)
  --debian-mirror URL   Archive mirror (default: http://deb.debian.org/debian)
  --debian-components L Comma-separated components (default: main; repeatable)
  --debian-include L    Extra packages to install (comma-separated, repeatable)
  --debian-exclude L    Packages to keep out of the resolution, with their
                        dependents (comma-separated, repeatable)
  --debian-extract-only Lay out files without configuring them (runs no
                        maintainer scripts; for a foreign architecture)
  --debian-cache DIR    Cache downloaded packages in DIR, reused across runs
  --debian-keyring FILE Verify the archive with FILE, not the embedded keyring
  --debian-mirror-fallback URL
                        A further URL for the same archive, tried when the
                        primary mirror does not serve a resource (repeatable,
                        in order)
  --debian-base-priority P
                        The priority floor the base set is drawn from:
                        required (default), important, standard, optional,
                        or extra
  --debian-trust-unsigned
                        Accept the archive without verifying its signature.
                        Refused for an http:// mirror, which offers no
                        authenticity of its own
  --debian-allow-stale-release
                        Accept a signed release whose validity has expired
  --debian-pre-configure-overlay DIR
                        Overlay DIR onto the root after the files are laid
                        out and before any maintainer script runs
  --debian-identity-map M
                        Identity map for the bootstrap's own cages, in the
                        form --identity-map takes; a range map records real
                        ownership instead of the single-map stubs
  --debian-repository SPEC
                        An additional archive source, merged into the same
                        resolution. SPEC is space-separated key=value fields:
                        'suite=S mirror=URL [mirror-fallback=URL]
                        [components=a,b] [keyring=PATH] [name=NAME]
                        [trust-unsigned] [allow-stale-release]'. Repeatable
  --remove-rootfs DIR   Delete the provisioned rootfs at DIR and exit,
                        including one a range-mapped sandbox wrote and a plain
                        'rm -rf' cannot remove. Give the --identity-map the
                        tree was provisioned under; the default is
                        'subordinate'. Removing a path that is not there
                        succeeds, so the call is repeatable. Takes no other
                        option: it removes a rootfs rather than running a
                        command in one
  --export-rootfs DIR   Write the provisioned rootfs at DIR to a tar archive
                        and exit, preserving the ownership the tree intends
                        and the extended attributes a host-side 'tar' cannot
                        read. Give the --identity-map the tree was provisioned
                        under; the default is 'subordinate'. Takes no other
                        option: it exports a rootfs rather than running a
                        command in one
  --export-to FILE      Where --export-rootfs writes. The default is standard
                        output, so the archive pipes into a compressor without
                        a temporary file; writing one to a terminal is refused
  --clamp-mtime EPOCH   Cap every modification time --export-rootfs records at
                        EPOCH, a Unix timestamp in seconds. With it the archive
                        is byte-reproducible given the tree

Profiles, overlays, and mounts:
  --profile FILE        Load a TOML sandbox profile; flags given alongside
                        override its settings, binds and variables extend it,
                        and any [hardening] table it carries takes effect. A
                        profile is trusted like a script: it can bind any host
                        path, issue raw mounts, share the host network, and
                        share the host PID namespace. Load only a profile you
                        trust, or use --restricted-profile
  --restricted-profile FILE
                        Load a TOML profile from an untrusted source: like
                        --profile, but the operations that map host resources
                        into the sandbox or share a host namespace (binds, raw
                        mounts, host networking, the host PID namespace) are
                        refused. The rootfs it names still grants access to that
                        host subtree, so pass a rootfs you control
  --overlay-lower DIR   Root the sandbox on an overlay whose base is DIR
                        (repeatable and ordered: the first is the base, each
                        later one is laid over it). Alternative to --rootfs
  --overlay-upper DIR   Where the overlay's writes land; DIR persists after
                        the sandbox exits, so discarding it reverts the run.
                        Required with --overlay-lower
  --overlay-work DIR    Override the overlay's work directory, which must sit
                        on the same filesystem as the upper
  --bind SRC DEST       Bind-mount host path SRC read-write at DEST
  --ro-bind SRC DEST    Bind-mount host path SRC read-only at DEST
  --raw-mount SPEC      A mount the typed options do not model, passed to the
                        kernel as given. SPEC is space-separated key=value
                        fields: 'target=/sys fstype=sysfs flags=0xE
                        [source=...] [data=...]'. Only the target is validated
                        and confined. Repeatable.
                        Mounts apply in the order these flags appear, so a
                        --raw-mount tmpfs followed by --bind flags into it
                        builds a directory the sandbox owns outright

Identity and limits:
  --identity-map M      How the user namespace maps identities: 'single'
                        (default: root inside is you outside, and no other id
                        exists), 'subordinate' (root plus your whole
                        subordinate allocation, through newuidmap/newgidmap),
                        or explicit extents,
                        'uid=IN:OUT:COUNT[,...] gid=IN:OUT:COUNT[,...]'
  --run-as UID:GID[:G,...]
                        Run the command as a non-root identity inside the
                        sandbox, with optional supplementary groups. Every id
                        must be contained in the identity map; groups need a
                        range gid map
  --rlimit RES=SOFT[:HARD]
                        Set a resource limit on the command, inherited by
                        every process it starts. A value may be 'unlimited',
                        and an omitted hard limit repeats the soft one.
                        Repeatable (e.g. --rlimit processes=64 --rlimit
                        address-space=536870912). RES is one of:
{rlimit-resources}

The command and its process:
  --path-lookup         Resolve a command with no slash against the sandbox's
                        PATH, the way a shell does
  --setenv NAME VALUE   Set an environment variable for the command
  --hostname NAME       Set the hostname inside the sandbox
  --chdir DIR           Working directory inside the sandbox (default /)
  --stdin MODE          Standard input: inherit (default) or null. With null
                        the command also runs in a session of its own, so the
                        terminal fcage was started from is not its controlling
                        terminal; an interrupt there stops fcage, which stops
                        the sandbox. Standard output and standard error still
                        reach that terminal unless redirected, which a shell
                        already spells and a profile carries as stdout/stderr
  --terminal            Give the sandbox a pseudoterminal of its own and relay
                        this terminal to it: interactive programs work, and the
                        sandbox reaches nothing of the terminal fcage was
                        started from. TERM passes through as ever, so set it
                        with --setenv TERM to override. From a script, where
                        fcage's own input is not a terminal, this degrades to a
                        plain byte relay around a sandbox that still has a real
                        terminal of its own, at 80x24
  --timeout SECS        Terminate the command after SECS seconds, kill it
                        --kill-after seconds later, and exit 124
  --kill-after SECS     Grace between terminate and kill (default 10)
  --stop-with-caller    Stop the sandbox when fcage itself exits (the default;
                        --no-stop-with-caller leaves it running)

Networking:
  --share-net           Share the host network (default: isolated loopback)
  --deny-net            Isolated network with loopback left down (no
                        connectivity at all, not even 127.0.0.1)
  --netstack            Attach the native userspace network stack: outbound
                        IPv4 and IPv6 for the isolated network, forwarded over
                        host sockets with no external helper. Composes the
                        sandbox's resolv.conf from the host's routable
                        nameservers unless --no-resolv-conf or
                        --no-managed-mounts is given; a host with only loopback
                        nameservers composes nothing, leaving the rootfs's own
                        resolv.conf in place
  --netstack-cidr V4/LEN
                        IPv4 network for --netstack (default 10.0.2.0/24; the
                        gateway is host 2, the guest host 15)
  --netstack-mtu N      Interface MTU for --netstack (default 1500)
  --netstack-host-loopback
                        Map connections to the gateway address onto the host's
                        127.0.0.1, port preserved, to reach a service bound
                        there (off by default; every other loopback destination
                        stays blocked, including a resolver on another loopback
                        address such as systemd-resolved's 127.0.0.53 stub)

Hardening:
  --restrict            Confine the command with Landlock and seccomp only:
                        no namespaces, no root filesystem swap, and paths are
                        host paths. The fallback for hosts without
                        unprivileged user namespaces; requires at least one
                        --landlock-* or --seccomp flag, and accepts only
                        those plus --setenv, --no-base-env, --chdir,
                        --stdin, --terminal, --timeout, --kill-after,
                        --rlimit, and --stop-with-caller
  --landlock-ro PATH    Grant the command read and execute beneath PATH under
                        a Landlock ruleset (repeatable; enrolling any grant
                        denies all filesystem access not granted)
  --landlock-rw PATH    Grant read, write, and execute beneath PATH
                        (repeatable)
  --landlock-bind PORT  Allow binding a TCP socket to PORT under a Landlock
                        ruleset (repeatable; enrolling any network grant denies
                        every bind and connect not granted; port 0 permits a
                        kernel-assigned ephemeral port; needs Landlock ABI 4)
  --landlock-connect PORT
                        Allow connecting a TCP socket to PORT (repeatable)
  --seccomp curated     Apply the curated seccomp deny-list of dangerous
                        syscalls to the command
  --seccomp-allow LIST  Allow only these syscalls, denying the rest with EPERM
                        (comma-separated names, repeatable; must name every
                        syscall the command needs)
  --seccomp-deny LIST   Deny these syscalls with EPERM, allowing the rest
                        (comma-separated names, repeatable)
  --seccomp-allow-rule RULE
                        Allow a syscall only when its arguments match; RULE is
                        a syscall name and comma-separated conditions, each of
                        the form 'arg=N len=dword|qword op=OP value=V', with
                        op one of eq, ne, ge, gt, le, lt, or masked-eq (which
                        also takes mask=M). Repeatable; repeating a syscall
                        accepts any of the rules. Example:
                        'ioctl arg=1 len=dword op=eq value=0x5413'
  --seccomp-deny-rule RULE
                        Deny a syscall only when its arguments match, in the
                        same form as --seccomp-allow-rule
  --drop-caps           Drop every capability from the command
  --keep-caps LIST      Drop every capability except LIST (comma-separated,
                        e.g. net-bind-service,sys-chroot)

Turning off what is on by default:
  --share-pid           Share the host PID namespace (default: isolated)
  --no-proc             Do not mount /proc
  --no-dev              Do not assemble the minimal /dev
  --no-tmp              Do not mount a tmpfs on /tmp
  --no-resolv-conf      Do not bind the host resolv.conf: neither the bind
                        --share-net makes nor the one --netstack composes
  --no-managed-mounts   Establish no mount of the library's own, so the sandbox
                        carries exactly the --bind and --raw-mount flags given.
                        Unlike the individual --no-* toggles this also excludes
                        any managed mount a later release adds
  --no-base-env         Give the command exactly the --setenv variables, with
                        no PATH or HOME supplied underneath them

Help and version:
  -h, --help            Print this help
  -V, --version         Print the version

Each toggle has a counterpart to override a profile in the other direction:
--isolate-net, --pid-ns, --proc, --dev, --tmp, --resolv-conf,
--managed-mounts, --base-env, --stop-with-caller, and --no-path-lookup.
A profile's [hardening] table composes with the hardening flags:
--landlock-ro, --landlock-rw, --landlock-bind, and --landlock-connect add
grants to it, while the seccomp flags, --drop-caps, and --keep-caps replace
its seccomp policy or capability posture. The seccomp flags are mutually
constrained: --seccomp curated stands alone, and an allow side
(--seccomp-allow, --seccomp-allow-rule) cannot be mixed with a deny side
(--seccomp-deny, --seccomp-deny-rule).

The command path is interpreted inside the sandbox (with --restrict, on the
host) and must be absolute; a command given on the command line replaces one
named by the profile. The command runs with inherited standard streams and a
clean environment: PATH and HOME, the host TERM when set, profile variables,
and the --setenv values. With --restrict the base is PATH alone, there being
no sandbox root for HOME to name. --no-base-env drops the base either way.

Exit status: the command's own exit code, or 128 plus the signal number
when it is terminated by a signal, or 124 when --timeout expires. fcage
itself exits 125 when the sandbox cannot be built or launched, 126 when
the command exists but cannot be executed, 127 when the command does not
exist, and 2 on usage errors.
";

/// A parsed command line.
enum Invocation {
    /// Launch a sandbox.
    Run(Box<Options>),
    /// Delete a provisioned rootfs, under the identity map it was written
    /// under.
    Remove {
        dest: PathBuf,
        map: IdentityMap,
    },
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
    provision_tar: Option<PathBuf>,
    provision_debian: Option<String>,
    debian_arch: Option<String>,
    debian_mirror: Option<String>,
    debian_components: Vec<String>,
    debian_include: Vec<String>,
    debian_exclude: Vec<String>,
    debian_extract_only: bool,
    debian_cache: Option<PathBuf>,
    debian_keyring: Option<PathBuf>,
    debian_mirror_fallback: Vec<String>,
    debian_base_priority: Option<Priority>,
    debian_trust_unsigned: bool,
    debian_allow_stale_release: bool,
    debian_pre_configure_overlay: Option<PathBuf>,
    debian_identity_map: Option<IdentityMap>,
    debian_repositories: Vec<Repository>,
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
    seccomp: Option<SeccompPolicy>,
    caps: Option<CapsChoice>,
    restrict: bool,
    netstack: bool,
    netstack_cidr: Option<(Ipv4Addr, u8)>,
    netstack_mtu: Option<u16>,
    netstack_host_loopback: bool,
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
    USAGE.replace(
        "{rlimit-resources}",
        &wrapped(
            &Resource::ALL
                .iter()
                .map(|r| r.spelling())
                .collect::<Vec<_>>(),
        ),
    )
}

/// The options that belong to the export mode rather than to a launch.
///
/// The suggester reads its candidates out of the help, and the help documents
/// every mode, so a launch would otherwise answer a stray `--export-to` by
/// suggesting the very flag it had just refused. Naming the mode that owns it is
/// the useful answer instead. The roster is short and a test pins it, failing if
/// an entry stops being an export's alone.
const EXPORT_ONLY_FLAGS: [&str; 2] = ["--export-to", "--clamp-mtime"];

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
    if let Some(owner) = export_only_owner(name) {
        return format!(
            "unrecognized option {given}\n{name} is an option of {owner}, which is a mode of \
             its own.",
        );
    }
    let usage = usage();
    let candidates: Vec<&str> = documented_flags(&usage)
        .into_iter()
        .filter(|flag| export_only_owner(flag).is_none())
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
fn export_only_owner(flag: &str) -> Option<&'static str> {
    EXPORT_ONLY_FLAGS
        .contains(&flag)
        .then_some("--export-rootfs")
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

/// Every long flag the help text names.
///
/// The roster is read out of the help rather than kept beside it, which is what
/// stops the two from drifting: a flag the help does not name is one the
/// suggester cannot offer, and that is a gap in the help either way. A second
/// hand-maintained table would instead fall quietly behind the parser.
///
/// Flags named in prose count, not only those introducing an entry, so the
/// toggles the closing paragraphs list — `--proc`, `--tmp`, and the rest of the
/// counterparts — can be suggested too. The punctuation the prose wraps them in
/// is trimmed off.
///
/// Two things that look like flags are not. A bare `--` is the end-of-options
/// separator, and the help names a family as `--landlock-*` or `--no-*`, which
/// trims to a trailing hyphen. No flag ends in one, so that is what tells them
/// apart, and neither is a name to suggest.
fn documented_flags(usage: &str) -> Vec<&str> {
    let mut flags: Vec<&str> = usage
        .split_whitespace()
        .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-'))
        .filter(|token| token.starts_with("--") && token.len() > 2 && !token.ends_with('-'))
        .collect();
    flags.sort_unstable();
    flags.dedup();
    flags
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

fn main() -> ExitCode {
    match parse(std::env::args_os().skip(1)) {
        Ok(Invocation::Help) => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Invocation::Version) => {
            println!("fcage {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Invocation::Run(options)) => run(*options),
        Ok(Invocation::Remove { dest, map }) => remove_rootfs(&dest, map),
        Ok(Invocation::Export {
            source,
            dest,
            map,
            clamp_mtime,
        }) => export_rootfs(&source, dest.as_deref(), map, clamp_mtime),
        Err(message) => {
            eprintln!("fcage: {message}");
            eprintln!("Try 'fcage --help' for usage.");
            ExitCode::from(2)
        }
    }
}

/// Parses the command line, excluding the program name.
fn parse(args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
    let args: Vec<OsString> = args.collect();
    // A removal is a mode of its own rather than a launch, so it is recognized
    // before the launch vocabulary is parsed and accepts only its own flags.
    // Splitting it this way is what keeps the two in step: a flag added to a
    // launch is refused alongside --remove-rootfs by the same `else` that
    // refuses every other one, rather than being silently accepted and then
    // ignored by a removal that never reads it.
    //
    // The scan stops at `--`, since past it every argument belongs to the
    // command: a tool with an `--export-rootfs` flag of its own must still be
    // runnable inside a sandbox. Nothing before `--` can belong to the command,
    // so the flags this finds are fcage's.
    let configuring = &args[..args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len())];
    if configuring.iter().any(|arg| names_removal(arg)) {
        return parse_removal(args);
    }
    if configuring.iter().any(|arg| names_export(arg)) {
        return parse_export(args);
    }
    // Kept for the no-effect check at the end, which asks what was written
    // rather than what it parsed to.
    let raw = args.clone();
    let mut args = args.into_iter();

    let mut options = Options {
        profile: None,
        profile_restricted: false,
        rootfs: None,
        provision_tar: None,
        provision_debian: None,
        debian_arch: None,
        debian_mirror: None,
        debian_components: Vec::new(),
        debian_include: Vec::new(),
        debian_exclude: Vec::new(),
        debian_extract_only: false,
        debian_cache: None,
        debian_keyring: None,
        debian_mirror_fallback: Vec::new(),
        debian_base_priority: None,
        debian_trust_unsigned: false,
        debian_allow_stale_release: false,
        debian_pre_configure_overlay: None,
        debian_identity_map: None,
        debian_repositories: Vec::new(),
        command_line: Vec::new(),
        path_lookup: None,
        mounts: Vec::new(),
        overlay_lowers: Vec::new(),
        overlay_upper: None,
        overlay_work: None,
        identity_map: None,
        run_as: None,
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
        // On by default here, unlike in the library: `fcage` waits for the
        // command and exits with it, so a sandbox that outlived the process is
        // never what a shell or a supervisor meant. Without the tie a SIGTERM
        // to `fcage` — `timeout(1)` is the everyday source — kills the waiter
        // and orphans the sandbox.
        stop_with_caller: Some(true),
        landlock: Vec::new(),
        landlock_net: Vec::new(),
        seccomp: None,
        caps: None,
        restrict: false,
        netstack: false,
        netstack_cidr: None,
        netstack_mtu: None,
        netstack_host_loopback: false,
    };

    let value_for = |name: &str, args: &mut dyn Iterator<Item = OsString>| {
        args.next().ok_or(format!("{name} requires a value"))
    };

    // Seccomp is assembled after the argument loop: the curated posture and the
    // allow/deny lists and rules are mutually constrained, so they are gathered
    // first and reconciled once, into `options.seccomp`.
    let mut seccomp_curated = false;
    let mut seccomp_allow: Vec<i64> = Vec::new();
    let mut seccomp_deny: Vec<i64> = Vec::new();
    let mut seccomp_allow_rules: Vec<(i64, Vec<SeccompArg>)> = Vec::new();
    let mut seccomp_deny_rules: Vec<(i64, Vec<SeccompArg>)> = Vec::new();

    while let Some(arg) = args.next() {
        if arg == "-h" || arg == "--help" {
            return Ok(Invocation::Help);
        } else if arg == "-V" || arg == "--version" {
            return Ok(Invocation::Version);
        } else if arg == "--rootfs" {
            options.rootfs = Some(PathBuf::from(value_for("--rootfs", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--rootfs=") {
            options.rootfs = Some(PathBuf::from(value));
        } else if arg == "--provision-tar" {
            options.provision_tar = Some(PathBuf::from(value_for("--provision-tar", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--provision-tar=") {
            options.provision_tar = Some(PathBuf::from(value));
        } else if arg == "--provision-debian" {
            options.provision_debian = Some(string_value("--provision-debian", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--provision-debian=") {
            options.provision_debian = Some(into_string("--provision-debian", value)?);
        } else if arg == "--debian-arch" {
            options.debian_arch = Some(string_value("--debian-arch", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--debian-arch=") {
            options.debian_arch = Some(into_string("--debian-arch", value)?);
        } else if arg == "--debian-mirror" {
            options.debian_mirror = Some(string_value("--debian-mirror", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--debian-mirror=") {
            options.debian_mirror = Some(into_string("--debian-mirror", value)?);
        } else if arg == "--debian-components" {
            extend_comma(
                &mut options.debian_components,
                &string_value("--debian-components", &mut args)?,
            );
        } else if let Some(value) = flag_value(&arg, b"--debian-components=") {
            extend_comma(
                &mut options.debian_components,
                &into_string("--debian-components", value)?,
            );
        } else if arg == "--debian-include" {
            extend_comma(
                &mut options.debian_include,
                &string_value("--debian-include", &mut args)?,
            );
        } else if let Some(value) = flag_value(&arg, b"--debian-include=") {
            extend_comma(
                &mut options.debian_include,
                &into_string("--debian-include", value)?,
            );
        } else if arg == "--debian-cache" {
            options.debian_cache = Some(PathBuf::from(value_for("--debian-cache", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--debian-cache=") {
            options.debian_cache = Some(PathBuf::from(value));
        } else if arg == "--debian-keyring" {
            options.debian_keyring = Some(PathBuf::from(value_for("--debian-keyring", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--debian-keyring=") {
            options.debian_keyring = Some(PathBuf::from(value));
        } else if arg == "--debian-extract-only" {
            options.debian_extract_only = true;
        } else if arg == "--profile" {
            let path = PathBuf::from(value_for("--profile", &mut args)?);
            set_profile(&mut options, path, false)?;
        } else if let Some(value) = flag_value(&arg, b"--profile=") {
            set_profile(&mut options, PathBuf::from(value), false)?;
        } else if arg == "--restricted-profile" {
            let path = PathBuf::from(value_for("--restricted-profile", &mut args)?);
            set_profile(&mut options, path, true)?;
        } else if let Some(value) = flag_value(&arg, b"--restricted-profile=") {
            set_profile(&mut options, PathBuf::from(value), true)?;
        } else if arg == "--bind" || arg == "--ro-bind" {
            let name = if arg == "--bind" {
                "--bind"
            } else {
                "--ro-bind"
            };
            let source = value_for(name, &mut args)?;
            let target = args
                .next()
                .ok_or(format!("{name} requires a source and a target"))?;
            options.mounts.push(Mount::Bind(
                Bind::new(PathBuf::from(source), PathBuf::from(target))
                    .read_only(name == "--ro-bind"),
            ));
        } else if arg == "--setenv" {
            let name = value_for("--setenv", &mut args)?;
            // Validate the name here so a bad one is the usage error it is
            // (exit 2), rather than deferring to the library's build-time
            // rejection (exit 125). The rule matches the library's.
            if name.is_empty() || name.as_bytes().contains(&b'=') {
                return Err(format!(
                    "--setenv: {name:?} is not a valid environment variable name \
                     (it is empty or contains '=')"
                ));
            }
            let value = args
                .next()
                .ok_or("--setenv requires a name and a value".to_string())?;
            options.setenv.push((name, value));
        } else if arg == "--hostname" {
            options.hostname = Some(value_for("--hostname", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--hostname=") {
            options.hostname = Some(value);
        } else if arg == "--chdir" {
            options.chdir = Some(PathBuf::from(value_for("--chdir", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--chdir=") {
            options.chdir = Some(PathBuf::from(value));
        } else if arg == "--stdin" {
            options.stdin = Some(parse_stdin(&value_for("--stdin", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--stdin=") {
            options.stdin = Some(parse_stdin(&value)?);
        } else if arg == "--terminal" {
            options.terminal = true;
        } else if arg == "--timeout" {
            options.timeout = Some(parse_seconds(
                "--timeout",
                &value_for("--timeout", &mut args)?,
            )?);
        } else if let Some(value) = flag_value(&arg, b"--timeout=") {
            options.timeout = Some(parse_seconds("--timeout", &value)?);
        } else if arg == "--kill-after" {
            options.kill_after =
                parse_seconds("--kill-after", &value_for("--kill-after", &mut args)?)?;
            options.kill_after_given = true;
        } else if let Some(value) = flag_value(&arg, b"--kill-after=") {
            options.kill_after = parse_seconds("--kill-after", &value)?;
            options.kill_after_given = true;
        } else if arg == "--share-net" {
            options.network = Some(Network::Host);
        } else if arg == "--isolate-net" {
            options.network = Some(Network::Isolated);
        } else if arg == "--deny-net" {
            options.network = Some(Network::None);
        } else if arg == "--netstack" {
            options.netstack = true;
        } else if arg == "--netstack-cidr" {
            options.netstack_cidr = Some(parse_cidr(&string_value("--netstack-cidr", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--netstack-cidr=") {
            options.netstack_cidr = Some(parse_cidr(&into_string("--netstack-cidr", value)?)?);
        } else if arg == "--netstack-mtu" {
            options.netstack_mtu = Some(parse_mtu(&string_value("--netstack-mtu", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--netstack-mtu=") {
            options.netstack_mtu = Some(parse_mtu(&into_string("--netstack-mtu", value)?)?);
        } else if arg == "--netstack-host-loopback" {
            options.netstack_host_loopback = true;
        } else if arg == "--path-lookup" {
            options.path_lookup = Some(true);
        } else if arg == "--no-path-lookup" {
            options.path_lookup = Some(false);
        } else if arg == "--raw-mount" {
            options
                .mounts
                .push(Mount::Raw(parse_raw_mount(&string_value(
                    "--raw-mount",
                    &mut args,
                )?)?));
        } else if let Some(value) = flag_value(&arg, b"--raw-mount=") {
            options.mounts.push(Mount::Raw(parse_raw_mount(&into_string(
                "--raw-mount",
                value,
            )?)?));
        } else if arg == "--overlay-lower" {
            options
                .overlay_lowers
                .push(PathBuf::from(value_for("--overlay-lower", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--overlay-lower=") {
            options.overlay_lowers.push(PathBuf::from(value));
        } else if arg == "--overlay-upper" {
            options.overlay_upper = Some(PathBuf::from(value_for("--overlay-upper", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--overlay-upper=") {
            options.overlay_upper = Some(PathBuf::from(value));
        } else if arg == "--overlay-work" {
            options.overlay_work = Some(PathBuf::from(value_for("--overlay-work", &mut args)?));
        } else if let Some(value) = flag_value(&arg, b"--overlay-work=") {
            options.overlay_work = Some(PathBuf::from(value));
        } else if arg == "--identity-map" {
            options.identity_map = Some(parse_identity_map(
                "--identity-map",
                &string_value("--identity-map", &mut args)?,
            )?);
        } else if let Some(value) = flag_value(&arg, b"--identity-map=") {
            options.identity_map = Some(parse_identity_map(
                "--identity-map",
                &into_string("--identity-map", value)?,
            )?);
        } else if arg == "--run-as" {
            options.run_as = Some(parse_run_as(&string_value("--run-as", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--run-as=") {
            options.run_as = Some(parse_run_as(&into_string("--run-as", value)?)?);
        } else if arg == "--rlimit" {
            options
                .rlimits
                .push(parse_rlimit(&string_value("--rlimit", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--rlimit=") {
            options
                .rlimits
                .push(parse_rlimit(&into_string("--rlimit", value)?)?);
        } else if arg == "--debian-exclude" {
            extend_comma(
                &mut options.debian_exclude,
                &string_value("--debian-exclude", &mut args)?,
            );
        } else if let Some(value) = flag_value(&arg, b"--debian-exclude=") {
            extend_comma(
                &mut options.debian_exclude,
                &into_string("--debian-exclude", value)?,
            );
        } else if arg == "--debian-mirror-fallback" {
            options
                .debian_mirror_fallback
                .push(string_value("--debian-mirror-fallback", &mut args)?);
        } else if let Some(value) = flag_value(&arg, b"--debian-mirror-fallback=") {
            options
                .debian_mirror_fallback
                .push(into_string("--debian-mirror-fallback", value)?);
        } else if arg == "--debian-base-priority" {
            options.debian_base_priority = Some(parse_priority(&string_value(
                "--debian-base-priority",
                &mut args,
            )?)?);
        } else if let Some(value) = flag_value(&arg, b"--debian-base-priority=") {
            options.debian_base_priority = Some(parse_priority(&into_string(
                "--debian-base-priority",
                value,
            )?)?);
        } else if arg == "--debian-trust-unsigned" {
            options.debian_trust_unsigned = true;
        } else if arg == "--debian-allow-stale-release" {
            options.debian_allow_stale_release = true;
        } else if arg == "--debian-pre-configure-overlay" {
            options.debian_pre_configure_overlay = Some(PathBuf::from(value_for(
                "--debian-pre-configure-overlay",
                &mut args,
            )?));
        } else if let Some(value) = flag_value(&arg, b"--debian-pre-configure-overlay=") {
            options.debian_pre_configure_overlay = Some(PathBuf::from(value));
        } else if arg == "--debian-identity-map" {
            options.debian_identity_map = Some(parse_identity_map(
                "--debian-identity-map",
                &string_value("--debian-identity-map", &mut args)?,
            )?);
        } else if let Some(value) = flag_value(&arg, b"--debian-identity-map=") {
            options.debian_identity_map = Some(parse_identity_map(
                "--debian-identity-map",
                &into_string("--debian-identity-map", value)?,
            )?);
        } else if arg == "--debian-repository" {
            options
                .debian_repositories
                .push(parse_repository(&string_value(
                    "--debian-repository",
                    &mut args,
                )?)?);
        } else if let Some(value) = flag_value(&arg, b"--debian-repository=") {
            options
                .debian_repositories
                .push(parse_repository(&into_string(
                    "--debian-repository",
                    value,
                )?)?);
        } else if arg == "--restrict" {
            options.restrict = true;
        } else if arg == "--landlock-ro" {
            let path = value_for("--landlock-ro", &mut args)?;
            options.landlock.push((PathBuf::from(path), false));
        } else if let Some(value) = flag_value(&arg, b"--landlock-ro=") {
            options.landlock.push((PathBuf::from(value), false));
        } else if arg == "--landlock-rw" {
            let path = value_for("--landlock-rw", &mut args)?;
            options.landlock.push((PathBuf::from(path), true));
        } else if let Some(value) = flag_value(&arg, b"--landlock-rw=") {
            options.landlock.push((PathBuf::from(value), true));
        } else if arg == "--landlock-bind" {
            let value = string_value("--landlock-bind", &mut args)?;
            options
                .landlock_net
                .push((parse_port("--landlock-bind", &value)?, NetAccess::BIND));
        } else if let Some(value) = flag_value(&arg, b"--landlock-bind=") {
            let value = into_string("--landlock-bind", value)?;
            options
                .landlock_net
                .push((parse_port("--landlock-bind", &value)?, NetAccess::BIND));
        } else if arg == "--landlock-connect" {
            let value = string_value("--landlock-connect", &mut args)?;
            options.landlock_net.push((
                parse_port("--landlock-connect", &value)?,
                NetAccess::CONNECT,
            ));
        } else if let Some(value) = flag_value(&arg, b"--landlock-connect=") {
            let value = into_string("--landlock-connect", value)?;
            options.landlock_net.push((
                parse_port("--landlock-connect", &value)?,
                NetAccess::CONNECT,
            ));
        } else if arg == "--seccomp" {
            parse_seccomp(&string_value("--seccomp", &mut args)?, &mut seccomp_curated)?;
        } else if let Some(value) = flag_value(&arg, b"--seccomp=") {
            parse_seccomp(&into_string("--seccomp", value)?, &mut seccomp_curated)?;
        } else if arg == "--seccomp-allow" {
            let value = string_value("--seccomp-allow", &mut args)?;
            parse_seccomp_names("--seccomp-allow", &value, &mut seccomp_allow)?;
        } else if let Some(value) = flag_value(&arg, b"--seccomp-allow=") {
            let value = into_string("--seccomp-allow", value)?;
            parse_seccomp_names("--seccomp-allow", &value, &mut seccomp_allow)?;
        } else if arg == "--seccomp-deny" {
            let value = string_value("--seccomp-deny", &mut args)?;
            parse_seccomp_names("--seccomp-deny", &value, &mut seccomp_deny)?;
        } else if let Some(value) = flag_value(&arg, b"--seccomp-deny=") {
            let value = into_string("--seccomp-deny", value)?;
            parse_seccomp_names("--seccomp-deny", &value, &mut seccomp_deny)?;
        } else if arg == "--seccomp-allow-rule" {
            let value = string_value("--seccomp-allow-rule", &mut args)?;
            seccomp_allow_rules.push(parse_seccomp_rule("--seccomp-allow-rule", &value)?);
        } else if let Some(value) = flag_value(&arg, b"--seccomp-allow-rule=") {
            let value = into_string("--seccomp-allow-rule", value)?;
            seccomp_allow_rules.push(parse_seccomp_rule("--seccomp-allow-rule", &value)?);
        } else if arg == "--seccomp-deny-rule" {
            let value = string_value("--seccomp-deny-rule", &mut args)?;
            seccomp_deny_rules.push(parse_seccomp_rule("--seccomp-deny-rule", &value)?);
        } else if let Some(value) = flag_value(&arg, b"--seccomp-deny-rule=") {
            let value = into_string("--seccomp-deny-rule", value)?;
            seccomp_deny_rules.push(parse_seccomp_rule("--seccomp-deny-rule", &value)?);
        } else if arg == "--drop-caps" {
            options.caps = Some(CapsChoice::DropAll);
        } else if arg == "--keep-caps" {
            options.caps = Some(CapsChoice::Keep(parse_caps(&string_value(
                "--keep-caps",
                &mut args,
            )?)?));
        } else if let Some(value) = flag_value(&arg, b"--keep-caps=") {
            options.caps = Some(CapsChoice::Keep(parse_caps(&into_string(
                "--keep-caps",
                value,
            )?)?));
        } else if arg == "--share-pid" {
            options.pid_namespace = Some(false);
        } else if arg == "--pid-ns" {
            options.pid_namespace = Some(true);
        } else if arg == "--no-proc" {
            options.mount_proc = Some(false);
        } else if arg == "--proc" {
            options.mount_proc = Some(true);
        } else if arg == "--no-dev" {
            options.mount_dev = Some(false);
        } else if arg == "--dev" {
            options.mount_dev = Some(true);
        } else if arg == "--no-tmp" {
            options.mount_tmp = Some(false);
        } else if arg == "--tmp" {
            options.mount_tmp = Some(true);
        } else if arg == "--no-managed-mounts" {
            options.managed_mounts = Some(false);
        } else if arg == "--managed-mounts" {
            options.managed_mounts = Some(true);
        } else if arg == "--no-base-env" {
            options.base_env = Some(false);
        } else if arg == "--base-env" {
            options.base_env = Some(true);
        } else if arg == "--no-resolv-conf" {
            options.resolv_conf = Some(false);
        } else if arg == "--resolv-conf" {
            options.resolv_conf = Some(true);
        } else if arg == "--stop-with-caller" {
            options.stop_with_caller = Some(true);
        } else if arg == "--no-stop-with-caller" {
            options.stop_with_caller = Some(false);
        } else if arg == "--" {
            options.command_line.extend(args);
            break;
        } else if arg.as_bytes().starts_with(b"-") && arg != "-" {
            return Err(unrecognized_option(&arg));
        } else {
            // The first positional argument is the command; everything after
            // it belongs to the command, dashes included.
            options.command_line.push(arg);
            options.command_line.extend(args);
            break;
        }
    }

    options.seccomp = assemble_seccomp(
        seccomp_curated,
        seccomp_allow,
        seccomp_deny,
        seccomp_allow_rules,
        seccomp_deny_rules,
    )?;

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
            (
                options.profile.is_some(),
                "--profile or --restricted-profile",
            ),
            (options.provision_tar.is_some(), "--provision-tar"),
            (options.provision_debian.is_some(), "--provision-debian"),
            (has_debian_modifiers(&options), "the --debian-* options"),
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
                !options.overlay_lowers.is_empty()
                    || options.overlay_upper.is_some()
                    || options.overlay_work.is_some(),
                "the --overlay-* options",
            ),
            (options.identity_map.is_some(), "--identity-map"),
            (options.run_as.is_some(), "--run-as"),
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
        {
            return Err(
                "--restrict requires at least one grant: a --landlock-* rule or a --seccomp filter"
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

    // An overlay root and a plain rootfs are alternatives; the last builder
    // call would silently win, so name the contradiction here instead.
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
    if options.rootfs.is_none() && options.profile.is_none() && !overlay_given {
        return Err(
            "--rootfs, --overlay-lower, --profile, --restricted-profile, or --restrict is required"
                .to_string(),
        );
    }
    if options.provision_tar.is_some() && options.provision_debian.is_some() {
        return Err("--provision-tar and --provision-debian are mutually exclusive".to_string());
    }
    if options.provision_tar.is_some() && options.rootfs.is_none() {
        return Err("--provision-tar requires --rootfs to name the destination".to_string());
    }
    if options.provision_debian.is_some() && options.rootfs.is_none() {
        return Err("--provision-debian requires --rootfs to name the destination".to_string());
    }
    if options.provision_debian.is_none() && has_debian_modifiers(&options) {
        return Err("the --debian-* options require --provision-debian".to_string());
    }
    // A provisioning run without a command provisions and exits; otherwise a
    // command (or a profile that names one) is required.
    let provisioning = options.provision_tar.is_some() || options.provision_debian.is_some();
    if options.command_line.is_empty() && options.profile.is_none() && !provisioning {
        return Err("no command given".to_string());
    }
    // Nothing is launched, so a flag that configures a launch has nothing to
    // configure. Every other no-effect combination is refused above, and
    // silently dropping this one leaves a caller believing a sandbox was shaped
    // the way the command line said.
    if options.command_line.is_empty()
        && options.profile.is_none()
        && let Some(flag) = first_launch_flag(&raw)
    {
        return Err(format!(
            "{flag} configures a launch, and a provisioning run without a command does not \
             launch one",
        ));
    }
    Ok(Invocation::Run(Box::new(options)))
}

/// The first argument of a provision-and-exit invocation that configures the
/// launch rather than the provisioning, if any.
///
/// A provision-and-exit run names no command, so nothing in the vector is a
/// positional and every `--` argument is one of fcage's own. The provisioning
/// vocabulary is short enough to name; everything else shapes a sandbox that is
/// never built.
fn first_launch_flag(args: &[OsString]) -> Option<String> {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .find(|arg| arg.starts_with("--") && !provisions(flag_name(arg)))
}

/// Whether `flag` configures the provisioning rather than the launch.
fn provisions(flag: &str) -> bool {
    matches!(flag, "--rootfs" | "--provision-tar" | "--provision-debian")
        || flag.starts_with("--debian-")
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

/// Whether `arg` names the removal flag, in either the separated or the
/// `=`-joined form.
fn names_removal(arg: &OsStr) -> bool {
    arg == "--remove-rootfs" || arg.as_bytes().starts_with(b"--remove-rootfs=")
}

/// Parses a `--remove-rootfs` command line, excluding the program name.
///
/// A removal takes the destination and the identity map the tree was written
/// under. Every other flag configures a launch that does not happen here, so
/// naming one is a usage error rather than a setting with no effect.
fn parse_removal(args: Vec<OsString>) -> Result<Invocation, String> {
    if let Some(answer) = help_or_version(&args) {
        return Ok(answer);
    }
    let mut dest: Option<PathBuf> = None;
    // The same default the library's own removal carries: a tree written by a
    // bundled-delegate sandbox is the case that needs the escalation at all.
    let mut map = IdentityMap::Subordinate;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if arg == "--remove-rootfs" {
            let value = args
                .next()
                .ok_or_else(|| "--remove-rootfs requires a value".to_string())?;
            dest = Some(PathBuf::from(value));
        } else if let Some(value) = flag_value(&arg, b"--remove-rootfs=") {
            dest = Some(PathBuf::from(value));
        } else if arg == "--identity-map" {
            map = parse_identity_map(
                "--identity-map",
                &string_value("--identity-map", &mut args)?,
            )?;
        } else if let Some(value) = flag_value(&arg, b"--identity-map=") {
            map = parse_identity_map("--identity-map", &into_string("--identity-map", value)?)?;
        } else {
            return Err(mode_conflict(
                &arg,
                "--remove-rootfs",
                &["--remove-rootfs", "--identity-map"],
            ));
        }
    }

    // The caller established that the flag is present, so this is a guard
    // rather than a live path: the only value-taking flag here would reject
    // `--remove-rootfs` as a map spelling before reaching it. It stays a usage
    // error rather than an `expect` because what upholds it is the shape of the
    // argument vector, not an invariant of this module.
    let dest = dest.ok_or_else(|| "--remove-rootfs requires a value".to_string())?;
    Ok(Invocation::Remove { dest, map })
}

/// Whether `arg` names the export flag, in either the separated or the
/// `=`-joined form.
fn names_export(arg: &OsStr) -> bool {
    arg == "--export-rootfs" || arg.as_bytes().starts_with(b"--export-rootfs=")
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
            let value = args
                .next()
                .ok_or_else(|| "--export-rootfs requires a value".to_string())?;
            source = Some(PathBuf::from(value));
        } else if let Some(value) = flag_value(&arg, b"--export-rootfs=") {
            source = Some(PathBuf::from(value));
        } else if arg == "--export-to" {
            let value = args
                .next()
                .ok_or_else(|| "--export-to requires a value".to_string())?;
            dest = Some(PathBuf::from(value));
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
            clamp_mtime = Some(parse_epoch(&string_value("--clamp-mtime", &mut args)?)?);
        } else if let Some(value) = flag_value(&arg, b"--clamp-mtime=") {
            clamp_mtime = Some(parse_epoch(&into_string("--clamp-mtime", value)?)?);
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

/// Parses the `--clamp-mtime` ceiling: a Unix timestamp in seconds.
///
/// Signed, because the ceiling is a plain timestamp rather than a duration and
/// a tree may legitimately be pinned to an instant before the epoch.
fn parse_epoch(value: &str) -> Result<i64, String> {
    value
        .parse::<i64>()
        .map_err(|_| format!("--clamp-mtime: {value:?} is not a Unix timestamp in whole seconds"))
}

/// Whether any `--debian-*` modifier flag was given.
fn has_debian_modifiers(options: &Options) -> bool {
    options.debian_arch.is_some()
        || options.debian_mirror.is_some()
        || !options.debian_components.is_empty()
        || !options.debian_include.is_empty()
        || !options.debian_exclude.is_empty()
        || options.debian_extract_only
        || options.debian_cache.is_some()
        || options.debian_keyring.is_some()
        || !options.debian_mirror_fallback.is_empty()
        || options.debian_base_priority.is_some()
        || options.debian_trust_unsigned
        || options.debian_allow_stale_release
        || options.debian_pre_configure_overlay.is_some()
        || options.debian_identity_map.is_some()
        || !options.debian_repositories.is_empty()
}

/// Whether any `--netstack-*` modifier flag was given.
fn has_netstack_modifiers(options: &Options) -> bool {
    options.netstack_cidr.is_some()
        || options.netstack_mtu.is_some()
        || options.netstack_host_loopback
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
fn parse_priority(value: &str) -> Result<Priority, String> {
    match value {
        "required" => Ok(Priority::Required),
        "important" => Ok(Priority::Important),
        "standard" => Ok(Priority::Standard),
        "optional" => Ok(Priority::Optional),
        "extra" => Ok(Priority::Extra),
        other => Err(format!(
            "--debian-base-priority: unknown priority {other:?}; expected required, important, \
             standard, optional, or extra"
        )),
    }
}

/// Parses a `--debian-repository` specification:
/// `suite=S mirror=URL [mirror-fallback=URL] [components=a,b] [keyring=PATH]
/// [name=NAME] [trust-unsigned] [allow-stale-release]`.
fn parse_repository(spec: &str) -> Result<Repository, String> {
    let mut suite = None;
    let mut mirrors: Vec<String> = Vec::new();
    let mut components: Vec<String> = Vec::new();
    let mut keyring = None;
    let mut name = None;
    let mut trust_unsigned = false;
    let mut allow_stale = false;
    for (key, value) in spec_pairs("--debian-repository", spec)? {
        match key {
            "suite" => suite = Some(value.to_string()),
            "mirror" => mirrors.insert(0, value.to_string()),
            "mirror-fallback" => mirrors.push(value.to_string()),
            "components" => extend_comma(&mut components, value),
            "keyring" => keyring = Some(PathBuf::from(value)),
            "name" => name = Some(value.to_string()),
            "trust-unsigned" => trust_unsigned = true,
            "allow-stale-release" => allow_stale = true,
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
    let mut builder = Repository::builder(suite)
        .trust_unsigned(trust_unsigned)
        .allow_stale_release(allow_stale);
    let mut mirrors = mirrors.into_iter();
    if let Some(primary) = mirrors.next() {
        builder = builder.mirror(primary);
    }
    for fallback in mirrors {
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
        .map_err(|error| format!("--debian-repository: {error}"))
}

/// Consumes the next argument as a required UTF-8 string value.
fn string_value(name: &str, args: &mut dyn Iterator<Item = OsString>) -> Result<String, String> {
    let value = args.next().ok_or(format!("{name} requires a value"))?;
    into_string(name, value)
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
/// the `syscalls` crate, the same table the library uses.
fn resolve_syscall_name(flag: &str, name: &str) -> Result<i64, String> {
    name.parse::<syscalls::Sysno>()
        .map(|sysno| i64::from(sysno.id()))
        .map_err(|_| format!("{flag}: unknown syscall {name:?}"))
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

/// Parses a TCP port for a `--landlock-bind` or `--landlock-connect` grant.
///
/// The value is a decimal port in `0..=65535`; port 0 with `--landlock-bind`
/// permits binding to a kernel-assigned ephemeral port.
fn parse_port(flag: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("{flag} requires a TCP port in 0..=65535, not {value:?}"))
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
    Duration::try_from_secs_f64(seconds).map_err(|_| format!("{name} is too large"))
}

/// What the CLI needs to know about a loaded profile beyond the builder itself.
struct ProfileMeta {
    /// The profile sets a `TERM` variable, so the host `TERM` is not applied as
    /// a fallback beneath it.
    sets_term: bool,
    /// The profile requests host networking, which `--netstack` cannot attach
    /// a stack to.
    network_host: bool,
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
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read profile {}: {err}", path.display()))?;
    let mut table: toml::Table = text
        .parse()
        .map_err(|err| format!("cannot parse profile {}: {err}", path.display()))?;
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
    };
    let builder = if restricted {
        let profile: RestrictedProfile = table
            .try_into()
            .map_err(|err| format!("cannot load profile {}: {err}", path.display()))?;
        profile.into_builder()
    } else {
        table
            .try_into()
            .map_err(|err| format!("cannot load profile {}: {err}", path.display()))?
    };
    Ok((builder, meta))
}

/// Deletes the provisioned rootfs at `dest`, under the identity map it was
/// written under.
///
/// A tree a range-mapped sandbox wrote carries subordinate ownership that a
/// plain `rm -rf` cannot delete; the library re-enters the same map to remove
/// it. A failure exits 125, the code every other setup failure uses: nothing
/// ran, so there is no command status to report.
fn remove_rootfs(dest: &Path, map: IdentityMap) -> ExitCode {
    match ferroday_cage::provision::Remove::new(dest).map(map).run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("fcage: {error}");
            ExitCode::from(125)
        }
    }
}

/// Writes a provisioned rootfs to a tar archive, to a file or to standard
/// output.
///
/// The terminal refusal is here rather than in the parser, so that parsing a
/// command line stays a function of the command line: whether standard output
/// is a terminal is a property of how `fcage` was invoked, not of what was
/// typed, and a parser that consulted it would answer differently under a test
/// harness than at a prompt. It is still the usage error it looks like, exit
/// code and all.
fn export_rootfs(
    source: &Path,
    dest: Option<&Path>,
    map: IdentityMap,
    clamp_mtime: Option<i64>,
) -> ExitCode {
    use std::io::IsTerminal as _;

    if dest.is_none() && std::io::stdout().is_terminal() {
        eprintln!("fcage: refusing to write an archive to the terminal");
        eprintln!("Try '--export-to FILE', or pipe the output into a compressor.");
        return ExitCode::from(2);
    }

    let mut export = ferroday_cage::provision::Export::new(source).map(map);
    if let Some(epoch) = clamp_mtime {
        export = export.clamp_mtime(epoch);
    }

    // The library buffers the writer itself, so neither arm wraps it again.
    let written = match dest {
        Some(path) => match std::fs::File::create(path) {
            Ok(file) => {
                let written = export.write_to(file);
                if written.is_err() {
                    // The archive is partial, and `File::create` truncated any
                    // previous one to make it. Leaving it behind offers a
                    // script an empty or half-written file where the exit
                    // status said there was none.
                    let _ = std::fs::remove_file(path);
                }
                written
            }
            Err(error) => {
                eprintln!("fcage: cannot write {}: {error}", path.display());
                return ExitCode::from(125);
            }
        },
        None => export.write_to(std::io::stdout().lock()),
    };

    match written {
        Ok(()) => ExitCode::SUCCESS,
        // A reader that stopped early — `fcage --export-rootfs X | head -c 512`
        // — is not a failure of the export. The conventional ending is a quiet
        // one, so it is reported as the signal a writer to a closed pipe would
        // ordinarily die of rather than as noise on stderr.
        Err(ferroday_cage::provision::ProvisionError::Io { source, .. })
            if dest.is_none() && source.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            ExitCode::from(141)
        }
        Err(error) => {
            eprintln!("fcage: {error}");
            ExitCode::from(125)
        }
    }
}

/// Builds and runs the sandbox, mapping the outcome onto the exit status.
fn run(options: Options) -> ExitCode {
    if options.restrict {
        return run_restricted(options);
    }
    if let Some(tarball) = &options.provision_tar {
        // The parser guarantees a rootfs accompanies --provision-tar. An
        // already-provisioned rootfs is reused as it stands.
        let rootfs = options.rootfs.as_deref().expect("checked at parse time");
        let mut provisioner = ferroday_cage::provision::Tarball::new(tarball);
        if let Err(error) = ferroday_cage::provision::ensure(rootfs, &mut provisioner) {
            eprintln!("fcage: {error}");
            return ExitCode::from(125);
        }
    }
    if let Some(suite) = &options.provision_debian {
        let rootfs = options.rootfs.as_deref().expect("checked at parse time");
        if let Err(code) = provision_debian(suite, &options, rootfs) {
            return code;
        }
    }

    // A provisioning run with no command and no profile provisions and exits.
    if options.command_line.is_empty() && options.profile.is_none() {
        return ExitCode::SUCCESS;
    }

    let mut profile_sets_term = false;
    let mut profile_network_host = false;
    let mut builder = match &options.profile {
        Some(path) => match load_profile(
            path,
            !options.command_line.is_empty(),
            options.profile_restricted,
        ) {
            Ok((builder, meta)) => {
                profile_sets_term = meta.sets_term;
                profile_network_host = meta.network_host;
                builder
            }
            Err(message) => {
                eprintln!("fcage: {message}");
                return ExitCode::from(125);
            }
        },
        None => Cage::builder(),
    };

    // The parse-time guard rejects --netstack with --share-net, but a profile
    // can request host networking without any CLI network flag, leaving that
    // check blind. Reconcile against the loaded profile: attaching a stack to a
    // host-network sandbox cannot work, and the usage error belongs here.
    if options.netstack && options.network.is_none() && profile_network_host {
        eprintln!("fcage: --netstack cannot be used with a profile that sets network = \"host\"");
        eprintln!("Try 'fcage --help' for usage.");
        return ExitCode::from(2);
    }

    if let Some(rootfs) = options.rootfs {
        builder = builder.rootfs(rootfs);
    }
    // An overlay root, when the run named one. Parse-time validation has
    // already established that a lower and an upper are both present and that
    // no --rootfs competes with them.
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
    // The host TERM passes through so interactive commands work at a prompt,
    // but only as a fallback: a profile or --setenv TERM overrides it. Since
    // `envs` appends (last-wins), adding the host TERM unconditionally would
    // override the profile, so it is added only when neither the profile nor
    // --setenv sets TERM.
    let mut env = options.setenv;
    let setenv_sets_term = env.iter().any(|(key, _)| key.to_str() == Some("TERM"));
    if !profile_sets_term
        && !setenv_sets_term
        && let Some(term) = std::env::var_os("TERM")
    {
        env.push((OsString::from("TERM"), term));
    }
    builder = builder.envs(env);
    // One pass, so a `--raw-mount` written between two `--bind` flags is
    // applied between them.
    for mount in options.mounts {
        builder = match mount {
            Mount::Bind(bind) => {
                if bind.is_read_only() {
                    builder.bind_ro(bind.get_source(), bind.get_target())
                } else {
                    builder.bind(bind.get_source(), bind.get_target())
                }
            }
            Mount::Raw(raw) => builder.raw_mount(raw),
            // `Mount` is non-exhaustive. A kind this build cannot apply must
            // not be dropped in silence: a sandbox missing a mount it was
            // asked for is not the sandbox that was asked for.
            other => {
                eprintln!("fcage: unsupported mount kind: {other:?}");
                return ExitCode::from(125);
            }
        };
    }
    for (resource, soft, hard) in options.rlimits {
        builder = builder.rlimit(resource, soft, hard);
    }
    if let Some(map) = options.identity_map {
        builder = builder.identity_map(map);
    }
    if let Some(identity) = options.run_as {
        builder = builder.run_as(identity);
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
    if let Some(base) = options.base_env {
        builder = builder.base_env(base);
    }
    if let Some(tie) = options.stop_with_caller {
        builder = builder.stop_with_caller(tie);
    }
    for (path, writable) in options.landlock {
        builder = builder.landlock_fs(landlock_access(writable), path);
    }
    for (port, access) in options.landlock_net {
        builder = builder.landlock_net(access, port);
    }
    if let Some(policy) = options.seccomp {
        builder = builder.seccomp(policy);
    }
    match options.caps {
        Some(CapsChoice::DropAll) => builder = builder.drop_all_capabilities(),
        Some(CapsChoice::Keep(caps)) => builder = builder.keep_capabilities(caps),
        None => {}
    }

    if options.netstack {
        // The native stack composes the sandbox's DNS from the host's routable
        // nameservers, unless the run opts out. --no-managed-mounts opts out
        // as surely as --no-resolv-conf does: its promise is that the sandbox
        // carries exactly the binds the command line names, and this would be
        // one it does not.
        //
        // The builder is asked rather than the flags, so that a profile
        // setting either toggle governs this composition exactly as the
        // matching flag does. Both have already been applied above.
        if builder.get_resolv_conf() {
            builder = compose_netstack_resolv_conf(builder);
        }
        return run_with_netstack(
            builder,
            options.netstack_cidr,
            options.netstack_mtu,
            options.netstack_host_loopback,
            options.terminal,
            options.timeout,
            options.kill_after,
        );
    }

    if options.terminal {
        return run_on_a_terminal(builder, options.timeout, options.kill_after);
    }

    let outcome = builder
        .build()
        .and_then(|cage| cage.spawn())
        .and_then(|running| wait_with_deadline(running, options.timeout, options.kill_after));
    conclude(outcome)
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
    let signals = match terminal::Signals::install() {
        Ok(signals) => signals,
        Err(error) => return conclude_relay(Err(error)),
    };
    let launched = builder
        .build()
        .and_then(|cage| cage.spawn_terminal(&terminal::terminal_for_caller()));
    let (running, pty) = match launched {
        Ok(launched) => launched,
        Err(error) => {
            eprintln!("fcage: {error}");
            return ExitCode::from(error_exit_code(&error));
        }
    };
    conclude_relay(terminal::relay(running, pty, signals, timeout, kill_after))
}

/// Maps a relay's outcome onto the process exit status.
///
/// The library's own failures go through [`conclude`], so a launch that fails
/// the same way with and without a terminal exits the same way. The relay's own
/// plumbing failing is a `fcage` failure, which is 125.
fn conclude_relay(outcome: Result<Option<ExitStatus>, terminal::RelayError>) -> ExitCode {
    match outcome {
        Ok(outcome) => conclude(Ok(outcome)),
        Err(terminal::RelayError::Cage(error)) => conclude(Err(error)),
        Err(terminal::RelayError::Io(error)) => {
            eprintln!("fcage: the terminal relay failed: {error}");
            ExitCode::from(125)
        }
    }
}

/// Builds and runs a sandbox with the native network stack attached at the
/// pending seam: build, hold the command, attach the stack, then release it
/// so the network is up before the command's first instruction.
fn run_with_netstack(
    builder: CageBuilder,
    cidr: Option<(Ipv4Addr, u8)>,
    mtu: Option<u16>,
    host_loopback: bool,
    terminal: bool,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> ExitCode {
    // Blocked before the stack's own thread exists, so that thread inherits the
    // mask and no process-directed signal can be delivered behind the relay's
    // back. Nothing is allocated for a run without a terminal.
    let signals = if terminal {
        match terminal::Signals::install() {
            Ok(signals) => Some(signals),
            Err(error) => return conclude_relay(Err(error)),
        }
    } else {
        None
    };
    let cage = match builder.build() {
        Ok(cage) => cage,
        Err(error) => {
            eprintln!("fcage: {error}");
            return ExitCode::from(error_exit_code(&error));
        }
    };

    let mut stack = NetStack::builder().host_loopback(host_loopback);
    if let Some((network, prefix_len)) = cidr {
        stack = stack.ipv4_cidr(network, prefix_len);
    }
    if let Some(mtu) = mtu {
        stack = stack.mtu(mtu);
    }
    let stack = match stack.build() {
        Ok(stack) => stack,
        Err(error) => {
            eprintln!("fcage: {error}");
            return ExitCode::from(125);
        }
    };

    // Hold the command at the gate, attach the stack to the sandbox's
    // namespace, then release the command. A failed attach drops the
    // pending launch, which tears the sandbox down.
    //
    // With a terminal, the primary comes back here rather than out of
    // `proceed`: the pseudoterminal is allocated before the fork and the gate
    // sits after its controlling terminal is established, so the stack is
    // attached with the primary already in hand.
    let held = if terminal {
        cage.spawn_pending_terminal(&terminal::terminal_for_caller())
            .map(|(pending, pty)| (pending, Some(pty)))
    } else {
        cage.spawn_pending().map(|pending| (pending, None))
    };
    let (pending, pty) = match held {
        Ok(held) => held,
        Err(error) => {
            eprintln!("fcage: {error}");
            return ExitCode::from(error_exit_code(&error));
        }
    };
    let handle = match stack.attach(&pending) {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("fcage: {error}");
            return ExitCode::from(125);
        }
    };
    let running = match pending.proceed() {
        Ok(running) => running,
        Err(error) => {
            eprintln!("fcage: {error}");
            return ExitCode::from(error_exit_code(&error));
        }
    };

    // The relay when a terminal was allocated, the plain wait otherwise. Both
    // return the same outcome; only the driving differs.
    let outcome = match (pty, signals) {
        (Some(pty), Some(signals)) => terminal::relay(running, pty, signals, timeout, kill_after),
        _ => wait_with_deadline(running, timeout, kill_after).map_err(Into::into),
    };
    // The stack is torn down after the command; a failure here loses no
    // data, so it is a warning, not the run's outcome. Printed after the relay
    // has restored the caller's terminal, so it is not stair-stepped.
    if let Err(error) = handle.stop() {
        eprintln!("fcage: the network stack did not stop cleanly: {error}");
    }
    conclude_relay(outcome)
}

/// Composes the sandbox's `resolv.conf` for a native-stack run: binds the
/// host's `resolv.conf` read-only when it names a routable nameserver, and
/// otherwise composes nothing and says so.
///
/// A loopback nameserver — systemd-resolved's `127.0.0.53` stub is the
/// common one — is unreachable through the stack, which refuses loopback
/// destinations, so binding it would only produce silent DNS failures.
///
/// Composing nothing leaves whatever `resolv.conf` the rootfs ships, which
/// may name a routable resolver and resolve perfectly well. The warning
/// therefore reports what was not composed; it does not predict that the
/// sandbox has no DNS, which is not this function's to know.
fn compose_netstack_resolv_conf(builder: CageBuilder) -> CageBuilder {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        // No host resolv.conf to compose from; leave the sandbox's as-is.
        return builder;
    };
    if resolv_conf_has_routable_nameserver(&contents) {
        return builder.bind_ro("/etc/resolv.conf", "/etc/resolv.conf");
    }
    eprintln!(
        "fcage: the host's nameservers are all on loopback, which the network stack \
         refuses, so no resolv.conf was composed; the sandbox resolves through whatever \
         its rootfs ships (point it at a routable nameserver, or give it the gateway \
         address and pass --netstack-host-loopback, which reaches a host resolver only \
         when that resolver listens on 127.0.0.1 — not systemd-resolved's 127.0.0.53 \
         stub)"
    );
    builder
}

/// Whether a `resolv.conf` names at least one nameserver that is not a
/// loopback address, and so reachable through the network stack.
fn resolv_conf_has_routable_nameserver(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        let Some(address) = line.strip_prefix("nameserver") else {
            return false;
        };
        match address.trim().parse::<std::net::IpAddr>() {
            Ok(address) => !address.is_loopback(),
            Err(_) => false,
        }
    })
}

/// Builds and runs a restriction — the --restrict mode — mapping the outcome
/// onto the exit status exactly as the sandbox path does.
fn run_restricted(options: Options) -> ExitCode {
    let mut builder = Restriction::builder();
    let mut command_line = options.command_line.into_iter();
    if let Some(command) = command_line.next() {
        builder = builder.command(PathBuf::from(command)).args(command_line);
    }
    // The host TERM passes through so interactive commands work at a
    // prompt; it is set first, so a --setenv TERM overrides it.
    let mut env = options.setenv;
    if let Some(term) = std::env::var_os("TERM") {
        env.insert(0, (OsString::from("TERM"), term));
    }
    builder = builder.envs(env);
    if let Some(base) = options.base_env {
        builder = builder.base_env(base);
    }
    if let Some(chdir) = options.chdir {
        builder = builder.current_dir(chdir);
    }
    if let Some(stdin) = options.stdin {
        builder = builder.stdin(stdin);
    }
    for (resource, soft, hard) in options.rlimits {
        builder = builder.rlimit(resource, soft, hard);
    }
    if let Some(tie) = options.stop_with_caller {
        builder = builder.stop_with_caller(tie);
    }
    for (path, writable) in options.landlock {
        builder = builder.landlock_fs(landlock_access(writable), path);
    }
    for (port, access) in options.landlock_net {
        builder = builder.landlock_net(access, port);
    }
    if let Some(policy) = options.seccomp {
        builder = builder.seccomp(policy);
    }

    if options.terminal {
        // A host-allocated pseudoterminal needs no devpts instance, so the
        // fallback gets the same interactive story a cage does.
        let signals = match terminal::Signals::install() {
            Ok(signals) => signals,
            Err(error) => return conclude_relay(Err(error)),
        };
        let launched = builder
            .build()
            .and_then(|restriction| restriction.spawn_terminal(&terminal::terminal_for_caller()));
        let (running, pty) = match launched {
            Ok(launched) => launched,
            Err(error) => {
                eprintln!("fcage: {error}");
                return ExitCode::from(error_exit_code(&error));
            }
        };
        return conclude_relay(terminal::relay(
            running,
            pty,
            signals,
            options.timeout,
            options.kill_after,
        ));
    }

    let outcome = builder
        .build()
        .and_then(|restriction| restriction.spawn())
        .and_then(|running| wait_with_deadline(running, options.timeout, options.kill_after));
    conclude(outcome)
}

/// The Landlock access set a --landlock-ro or --landlock-rw grant confers.
fn landlock_access(writable: bool) -> FsAccess {
    if writable {
        FsAccess::READ | FsAccess::WRITE | FsAccess::EXECUTE
    } else {
        FsAccess::READ | FsAccess::EXECUTE
    }
}

/// Waits a launch out under the optional deadline: terminate at the
/// deadline, kill after the grace period. `Ok(None)` means the deadline
/// fired.
fn wait_with_deadline(
    mut running: Running<'_>,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> Result<Option<ExitStatus>, Error> {
    let Some(timeout) = timeout else {
        return running.wait().map(Some);
    };
    if let Some(status) = running.wait_timeout(timeout)? {
        return Ok(Some(status));
    }
    running.terminate()?;
    if running.wait_timeout(kill_after)?.is_none() {
        running.kill()?;
        running.wait()?;
    }
    Ok(None)
}

/// Maps a launch outcome onto the process exit status.
fn conclude(outcome: Result<Option<ExitStatus>, Error>) -> ExitCode {
    match outcome {
        // The timeout(1) convention: 124 announces an expired timeout,
        // whatever became of the command afterwards.
        Ok(None) => ExitCode::from(124),
        Ok(Some(status)) => {
            if let Some(code) = status.code() {
                // Wait statuses carry exit codes in the 0..=255 range.
                ExitCode::from(code as u8)
            } else if let Some(signal) = status.signal() {
                // The shell convention for termination by a signal.
                ExitCode::from(128_u8.wrapping_add(signal as u8))
            } else {
                // A wait status is always an exit code or a signal; a fallback
                // rather than a panic keeps this tail total.
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("fcage: {error}");
            ExitCode::from(error_exit_code(&error))
        }
    }
}

/// Bootstraps a Debian rootfs from the archive, printing progress to stderr.
///
/// Returns `Err` with the process exit code on failure.
fn provision_debian(suite: &str, options: &Options, rootfs: &Path) -> Result<(), ExitCode> {
    use ferroday_cage::provision::debian::Debian;

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
    if let Some(map) = &options.debian_identity_map {
        builder = builder.identity_map(map.clone());
    }
    for repository in &options.debian_repositories {
        builder = builder.repository(repository.clone());
    }

    let mut debian = builder.build().map_err(|error| {
        eprintln!("fcage: {error}");
        ExitCode::from(125)
    })?;
    let mut progress = print_debian_event;
    ferroday_cage::provision::ensure(rootfs, &mut debian.observe(&mut progress)).map_err(
        |error| {
            eprintln!("fcage: {error}");
            ExitCode::from(125)
        },
    )?;
    Ok(())
}

/// Prints a Debian bootstrap progress event to stderr.
fn print_debian_event(event: ferroday_cage::provision::debian::DebianEvent<'_>) {
    use ferroday_cage::provision::debian::DebianEvent;
    use std::io::Write;
    match event {
        DebianEvent::Fetching { url, .. } => eprintln!("fcage: fetching {url}"),
        DebianEvent::Resolving => eprintln!("fcage: resolving the package set"),
        DebianEvent::Downloading {
            package,
            index,
            total,
            ..
        } => eprintln!("fcage: downloading {package} ({index}/{total})"),
        DebianEvent::Extracting { package, .. } => eprintln!("fcage: extracting {package}"),
        // dpkg's own output flows straight to stderr.
        DebianEvent::CommandOutput { bytes, .. } => {
            let _ = std::io::stderr().write_all(bytes);
        }
        _ => {}
    }
}

/// The launcher conventions: 127 when the command does not exist, 126 when
/// it exists but cannot be executed, 125 for any other library failure.
fn error_exit_code(error: &Error) -> u8 {
    match error {
        Error::Setup {
            step: SetupStep::Exec,
            errno,
            ..
        } => match std::io::Error::from_raw_os_error(*errno).kind() {
            std::io::ErrorKind::NotFound => 127,
            _ => 126,
        },
        _ => 125,
    }
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

    /// Every long flag the parser compares an argument against, read out of
    /// this file's own source.
    ///
    /// There is no roster to read instead — the parser is a chain of
    /// comparisons — and a list written out here would be the second table the
    /// suggester exists to avoid. The scan stops at the test module, so a flag
    /// spelled in a test is not mistaken for one the parser accepts.
    fn parser_flags() -> Vec<&'static str> {
        const SOURCE: &str = include_str!("main.rs");
        let parser = SOURCE
            .split_once("\n#[cfg(test)]")
            .map_or(SOURCE, |(before, _)| before);

        let mut flags = Vec::new();
        // `arg == "--flag"`, and the inline-value form `--flag=VALUE`.
        for (opening, closing) in [("== \"", '"'), ("starts_with(b\"", '=')] {
            for (offset, _) in parser.match_indices(opening) {
                let rest = &parser[offset + opening.len()..];
                let Some(end) = rest.find(closing) else {
                    continue;
                };
                let flag = &rest[..end];
                if flag.starts_with("--") && flag.len() > 2 {
                    flags.push(flag);
                }
            }
        }
        flags.sort_unstable();
        flags.dedup();
        flags
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
    fn the_export_only_roster_holds_only_export_options() {
        // The roster is written out rather than derived, so this is what keeps
        // it honest: every entry must be one a launch refuses and an export
        // accepts, or the suggester attributes a flag to the wrong mode.
        for flag in EXPORT_ONLY_FLAGS {
            let launch = parse_error(&["--rootfs", "/srv/alpine", flag, "/bin/sh"]);
            assert!(
                launch.contains("unrecognized option"),
                "a launch accepts {flag}, which the roster calls an export's: {launch:?}",
            );
            let export = parse_args(&["--export-rootfs", "/roots/a", flag, "1700000000"]);
            assert!(
                export.is_ok(),
                "an export refuses {flag}, which the roster calls its own: {:?}",
                export.err(),
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
        let options = parse_run(&["--rootfs", "/srv/alpine", "/bin/true"]).expect("it parses");
        assert_eq!(options.stop_with_caller, Some(true));
        let options = parse_run(&[
            "--rootfs",
            "/srv/alpine",
            "--no-stop-with-caller",
            "/bin/true",
        ])
        .expect("it parses");
        assert_eq!(options.stop_with_caller, Some(false));
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
    }

    #[test]
    fn every_flag_the_parser_accepts_is_in_the_help() {
        // The suggester offers what the help documents, so a flag the help
        // does not name is one it can never offer. That is a gap in the help
        // whether or not anything suggests it, which is why the check is here
        // rather than left to the reader of a second table.
        let usage = usage();
        let documented = documented_flags(&usage);
        for flag in parser_flags() {
            assert!(
                documented.contains(&flag),
                "the parser accepts {flag}, which --help never names",
            );
        }
    }

    #[test]
    fn every_flag_the_help_names_is_one_the_parser_accepts() {
        // The other direction, and what keeps the derived candidate list
        // honest: a suggestion the parser would then refuse is worse than no
        // suggestion, and it is what a stray token scanned out of the prose
        // would produce.
        //
        // A flag is offered to each mode's vocabulary in turn, since some
        // belong to one mode only -- `--clamp-mtime` is an export's -- and
        // trying all three is what covers them without a table recording which
        // flag belongs where.
        let usage = usage();
        for flag in documented_flags(&usage) {
            let vocabularies: [Vec<&str>; 3] = [
                vec![flag],
                vec!["--remove-rootfs", "/roots/a", flag],
                vec!["--export-rootfs", "/roots/a", flag],
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
                "--help names {flag}, which no mode's parser accepts",
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
                Invocation::Remove { dest, map } => {
                    assert_eq!(dest, PathBuf::from("/var/lib/roots/trixie"));
                    assert_eq!(
                        map,
                        IdentityMap::Subordinate,
                        "the default is the map a bundled-delegate sandbox writes under"
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
    fn priority_parses_the_archive_bands() {
        assert_eq!(parse_priority("required").unwrap(), Priority::Required);
        assert_eq!(parse_priority("optional").unwrap(), Priority::Optional);
        assert!(parse_priority("urgent").is_err());
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
        for bad in ["", "abc", "0", "-1", "nan", "inf", "1e300"] {
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
        // A single grant satisfies it.
        parse_run(&["--restrict", "--landlock-ro", "/lib", "/bin/true"])
            .expect("a Landlock grant is enough");
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
    fn a_loopback_only_resolv_conf_is_not_routable() {
        assert!(!resolv_conf_has_routable_nameserver(
            "nameserver 127.0.0.53\noptions edns0\n"
        ));
        assert!(resolv_conf_has_routable_nameserver(
            "nameserver 127.0.0.53\nnameserver 9.9.9.9\n"
        ));
        assert!(resolv_conf_has_routable_nameserver(
            "nameserver 2606:4700:4700::1111\n"
        ));
        assert!(!resolv_conf_has_routable_nameserver("# only a comment\n"));
    }
}
