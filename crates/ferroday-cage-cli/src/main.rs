//! The ferroday-cage command-line interface.
//!
//! `fcage` runs a command inside an unprivileged Linux sandbox built by the
//! ferroday-cage library: fresh namespaces, the given root filesystem
//! presented at `/` with the default mount profile assembled over it, and
//! the calling user mapped to root inside. Every flag maps onto a call on
//! the library's builder, and `--profile` loads a TOML sandbox
//! specification through the library's `serde` feature; the binary contains
//! no sandboxing logic of its own. `--restrict` selects the library's
//! restriction fallback instead: Landlock and seccomp confinement of a
//! plain process, for hosts without unprivileged user namespaces.
//!
//! The binary is built with every library feature enabled, so any profile the
//! library accepts loads here, and every capability the builder offers has a
//! flag. Two library seams have no command-line form, because neither is
//! expressible as an argument: `Stdin::Fd`, which hands the command an open
//! descriptor, and `CageBuilder::id_mapper`, which supplies an identity-map
//! delegate as code. `--stdin` therefore offers the two dispositions a profile
//! can name, and `--identity-map` the delegates the library bundles.

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
    SeccompPolicy, SeccompRules, SetupStep, Stdin,
};
use serde::Deserialize as _;

const USAGE: &str = "\
Run a command inside an unprivileged Linux sandbox.

Usage: fcage [--rootfs DIR | --profile FILE | --restricted-profile FILE | --restrict] [OPTIONS] [--] [COMMAND [ARGS...]]

Options:
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
  --path-lookup         Resolve a command with no slash against the sandbox's
                        PATH, the way a shell does
  --setenv NAME VALUE   Set an environment variable for the command
  --hostname NAME       Set the hostname inside the sandbox
  --chdir DIR           Working directory inside the sandbox (default /)
  --stdin MODE          Standard input: inherit (default) or null
  --timeout SECS        Terminate the command after SECS seconds, kill it
                        --kill-after seconds later, and exit 124
  --kill-after SECS     Grace between terminate and kill (default 10)
  --stop-with-caller    Stop the sandbox when fcage itself exits
  --share-net           Share the host network (default: isolated loopback)
  --deny-net            Isolated network with loopback left down (no
                        connectivity at all, not even 127.0.0.1)
  --netstack            Attach the native userspace network stack: outbound
                        IPv4 and IPv6 for the isolated network, forwarded over
                        host sockets with no external helper. Composes the
                        sandbox's resolv.conf from the host's usable
                        nameservers unless --no-resolv-conf is given
  --netstack-cidr V4/LEN
                        IPv4 network for --netstack (default 10.0.2.0/24; the
                        gateway is host 2, the guest host 15)
  --netstack-mtu N      Interface MTU for --netstack (default 1500)
  --netstack-host-loopback
                        Map connections to the gateway address onto the host's
                        loopback, to reach a host-local service (off by
                        default; other loopback destinations stay blocked)
  --restrict            Confine the command with Landlock and seccomp only:
                        no namespaces, no root filesystem swap, and paths are
                        host paths. The fallback for hosts without
                        unprivileged user namespaces; requires at least one
                        --landlock-* or --seccomp flag, and accepts only
                        those plus --setenv, --no-base-env, --chdir,
                        --stdin, --timeout, --kill-after, --rlimit, and
                        --stop-with-caller
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
  --share-pid           Share the host PID namespace (default: isolated)
  --no-proc             Do not mount /proc
  --no-dev              Do not assemble the minimal /dev
  --no-tmp              Do not mount a tmpfs on /tmp
  --no-resolv-conf      Do not bind the host resolv.conf with --share-net
  --no-managed-mounts   Establish no mount of the library's own, so the sandbox
                        carries exactly the --bind and --raw-mount flags given.
                        Unlike the individual --no-* toggles this also excludes
                        any managed mount a later release adds
  --no-base-env         Give the command exactly the --setenv variables, with
                        no PATH or HOME supplied underneath them
  -h, --help            Print this help
  -V, --version         Print the version

Each toggle has a counterpart to override a profile in the other direction:
--isolate-net, --pid-ns, --proc, --dev, --tmp, --resolv-conf,
--managed-mounts, --base-env, --no-stop-with-caller, and --no-path-lookup.
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
    stdin: Option<Stdin>,
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
        Err(message) => {
            eprintln!("fcage: {message}");
            eprintln!("Try 'fcage --help' for usage.");
            ExitCode::from(2)
        }
    }
}

/// Parses the command line, excluding the program name.
fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Invocation, String> {
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
        stop_with_caller: None,
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
            if options.profile.replace(path).is_some() {
                return Err("only one --profile or --restricted-profile may be given".to_string());
            }
        } else if let Some(value) = flag_value(&arg, b"--profile=") {
            if options.profile.replace(PathBuf::from(value)).is_some() {
                return Err("only one --profile or --restricted-profile may be given".to_string());
            }
        } else if arg == "--restricted-profile" {
            let path = PathBuf::from(value_for("--restricted-profile", &mut args)?);
            if options.profile.replace(path).is_some() {
                return Err("only one --profile or --restricted-profile may be given".to_string());
            }
            options.profile_restricted = true;
        } else if let Some(value) = flag_value(&arg, b"--restricted-profile=") {
            if options.profile.replace(PathBuf::from(value)).is_some() {
                return Err("only one --profile or --restricted-profile may be given".to_string());
            }
            options.profile_restricted = true;
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
            return Err(format!("unrecognized option {}", arg.to_string_lossy()));
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
    Ok(Invocation::Run(Box::new(options)))
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
fn parse_stdin(value: &OsStr) -> Result<Stdin, String> {
    if value == "inherit" {
        Ok(Stdin::Inherit)
    } else if value == "null" {
        Ok(Stdin::Null)
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
        // The native stack composes the sandbox's DNS from the host's
        // usable nameservers, unless the run opts out.
        if options.resolv_conf != Some(false) {
            builder = compose_netstack_resolv_conf(builder);
        }
        return run_with_netstack(
            builder,
            options.netstack_cidr,
            options.netstack_mtu,
            options.netstack_host_loopback,
            options.timeout,
            options.kill_after,
        );
    }

    let outcome = builder
        .build()
        .and_then(|cage| cage.spawn())
        .and_then(|running| wait_with_deadline(running, options.timeout, options.kill_after));
    conclude(outcome)
}

/// Builds and runs a sandbox with the native network stack attached at the
/// pending seam: build, hold the command, attach the stack, then release it
/// so the network is up before the command's first instruction.
fn run_with_netstack(
    builder: CageBuilder,
    cidr: Option<(Ipv4Addr, u8)>,
    mtu: Option<u16>,
    host_loopback: bool,
    timeout: Option<Duration>,
    kill_after: Duration,
) -> ExitCode {
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
    let pending = match cage.spawn_pending() {
        Ok(pending) => pending,
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

    let outcome = wait_with_deadline(running, timeout, kill_after);
    // The stack is torn down after the command; a failure here loses no
    // data, so it is a warning, not the run's outcome.
    if let Err(error) = handle.stop() {
        eprintln!("fcage: the network stack did not stop cleanly: {error}");
    }
    conclude(outcome)
}

/// Composes the sandbox's `resolv.conf` for a native-stack run: binds the
/// host's `resolv.conf` read-only when it names a routable nameserver, and
/// otherwise warns that DNS will not resolve.
///
/// A loopback nameserver — systemd-resolved's `127.0.0.53` stub is the
/// common one — is unreachable through the stack, which refuses loopback
/// destinations, so binding it would only produce silent DNS failures.
fn compose_netstack_resolv_conf(builder: CageBuilder) -> CageBuilder {
    let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
        // No host resolv.conf to compose from; leave the sandbox's as-is.
        return builder;
    };
    if resolv_conf_has_routable_nameserver(&contents) {
        return builder.bind_ro("/etc/resolv.conf", "/etc/resolv.conf");
    }
    eprintln!(
        "fcage: the host's nameservers are all on loopback and unreachable through the \
         network stack; the sandbox has no working DNS (point it at a routable resolver, \
         or use --netstack-host-loopback to reach a host-local one via the gateway)"
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
        assert!(rendered.contains("unsigned"), "{rendered}");
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
