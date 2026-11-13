# Profiles

With the library's `serde` feature, the sandbox specification — the builder
itself — serializes and deserializes. A profile is a sandbox described in a
file: a versionable, reviewable artifact that any consumer can load, in any
serde format. The `fcage` binary loads TOML profiles with `--profile`; a
program does the same in three lines:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let text = std::fs::read_to_string("build.toml")?;
let builder: ferroday_cage::CageBuilder = toml::from_str(&text)?;
let status = builder.build()?.run()?;
# Ok(())
# }
```

The library itself carries no TOML dependency; it implements the serde
traits and leaves the format to the consumer.

## The format

Keys are kebab-case, and each sets what a builder method sets. Most share the
method's name. `workdir` is set by `current_dir`, and `[[mount]]` entries by
`bind`, `bind_ro`, `raw_mount` and `symlink`. In `[hardening]`, `drop-caps` and
`keep-caps` are set by `drop_all_capabilities` and `keep_capabilities`.
Unknown keys are rejected — a typo in a profile is an error, not a silently
ignored setting. Every key is optional; an omitted key keeps the library
default.

```toml
rootfs = "/srv/rootfs/alpine"
command = "/usr/bin/make"
args = ["-j4", "all"]

network = "host"            # "isolated" (default) | "host" | "none"
hostname = "builder"
workdir = "/build"
stdin = "null"              # "inherit" (default) | "null"
stdout = "inherit"          # "inherit" (default) | "null"; "null" discards
stderr = "null"             # the same, per stream

pid-namespace = true        # default true
mount-proc = true           # default true; see below before turning it off
mount-dev = true            # default true
mount-tmp = true            # default true
resolv-conf = true          # default true; binds the host resolv.conf with
                            # network = "host", and governs the one fcage
                            # composes for --netstack
managed-mounts = true       # default true; false establishes none of the four
                            # above, nor any managed mount a later release adds
base-env = true             # default true; false gives the command exactly the
                            # [env] table, with no PATH or HOME underneath
stop-with-caller = false    # default false
path-lookup = false         # default false; true resolves a command with no
                            # slash against the sandbox's PATH

identity-map = "subordinate"  # "single" (default) | "subordinate" | ranges

[run-as]                    # a non-root identity for the command
uid = 250
gid = 250
groups = [250]              # default empty

[env]
CARGO_HOME = "/cache/cargo"
RUST_LOG = "debug"

[[mount]]
kind = "bind"
source = "/home/user/project"
target = "/build"

[[mount]]
kind = "bind"
source = "/home/user/cache"
target = "/cache"
read-only = true            # default false

[[mount]]
kind = "raw"
target = "/sys"
fstype = "sysfs"
flags = 14                  # raw MS_* bits: MS_NOSUID | MS_NODEV | MS_NOEXEC
```

An `[overlay]` table roots the sandbox on an overlay instead of a plain
`rootfs`; the two are alternatives, and a profile naming both is refused at
build time rather than silently taking one:

```toml
command = "/usr/bin/make"

[overlay]
lower = ["/srv/base", "/srv/patches"]  # ordered, base first; at least one
upper = "/srv/scratch/run-1"           # required; created if absent
work = "/srv/scratch/run-1-work"       # optional; defaults beside the upper
```

The first `lower` is the base the overlay mounts over and the rest stack on it,
base first — the reverse of the kernel's own option order, so the array reads
the way the layers were built. `upper` is where the sandbox's writes land, and
discarding it reverts them. The upper and the work directory lie outside every
lower, and no lower lies inside another. `build` refuses an overlap before it
creates anything on the host. Note that a `RestrictedProfile` refuses an overlay
root outright, for the reason [below](#untrusted-profiles).

`empty-rootfs = true` roots the sandbox on an [empty
root](how-the-sandbox-is-built.md#an-empty-root) instead, which the `[[mount]]`
entries compose. It is the third alternative, refused beside either of the
others:

```toml
empty-rootfs = true
command = "/bin/sh"

[[mount]]
kind = "bind"
source = "/usr"
target = "/usr"
read-only = true

[[mount]]
kind = "symlink"
target = "usr/bin"   # what the link points at, as `ln -s` writes it
path = "/bin"        # the link itself, inside the sandbox
```

`host-rootfs = true` roots the sandbox on the [host's own
root](how-the-sandbox-is-built.md#the-hosts-own-root), read-only, and is the
fourth alternative. `reveal` takes back paths it hides by default:

```toml
host-rootfs = true
reveal = ["/var/tmp"]          # shown read-only, as the rest of the host
command = "/usr/bin/make"
workdir = "/home/user/project"

[[mount]]
kind = "bind"
source = "/home/user/project"
target = "/home/user/project"

[[mount]]
kind = "read-only"
target = "/home/user/project/.git/hooks"
```

`[env]` is a table of environment variables, added on top of the
deterministic base (`PATH`, and `HOME` for a command running as root inside) —
or the whole environment, where `base-env = false`.

`managed-mounts = false` and `base-env = false` are opt-outs rather than
toggles: each reduces the library's contribution to nothing, including
anything it may contribute in a later release. Setting `managed-mounts =
false` alongside an explicit `mount-dev = true` is a contradiction and is
refused at build time.

A profile that suppresses the managed `/proc` — with `managed-mounts = false`
or `mount-proc = false` — normally has to mount a procfs of its own, as a
`[[mount]]` entry. The nested user namespace the command enters establishes its
identity map through one, by path, so a container that reads one and has none is
refused at build time. See [The nested user
namespace](how-the-sandbox-is-built.md#the-nested-user-namespace) and [Identity
maps](identity-maps.md), which sets out the one configuration that reads none.

`[[mount]]` entries apply in the order they appear, after the managed mount
profile. The `kind` selects which fields the entry carries:

- `kind = "bind"` presents a host path inside the sandbox: `source`, `target`,
  and an optional `read-only`.
- `kind = "raw"` is the escape hatch for mounts the typed specification does
  not model: the target is validated and confined to the rootfs like every
  mount target, and the `source`, `fstype`, `flags` — the kernel's raw `MS_*`
  bits — and `data` string go to the kernel verbatim.
- `kind = "symlink"` makes a symbolic link at `path`, pointing at `target`. The
  link is not a mount, but it takes its place in the same order.
- `kind = "hide"` leaves `target` empty: a directory holds nothing and a file
  reads empty, and neither can be written. A `target` with nothing at it hides
  nothing.
- `kind = "read-only"` makes `target` read-only where it stands, mounts beneath
  it included. The `target` must exist.

Every kind shares one array so that their relative order is expressible. It
matters whenever a mount covers a path an earlier one established: declaring a
`raw` tmpfs on a directory and then the binds that populate it builds a
directory whose contents the sandbox owns outright, and the reverse order
leaves the binds hidden beneath the tmpfs.

`identity-map` and `[run-as]` select the sandbox's [identity
map](identity-maps.md) and the identity the command runs as; explicit
ranges are spelled as an `[identity-map.ranges]` table, shown in that
chapter. Every identity form loads in every build, and `build` refuses one no
delegate can establish: `subordinate` on a build without the `subid` feature
needs a configured delegate that reports an allocation. The identity-map
delegate itself is code, not configuration, and has no profile key. Under the
single-identity map, `present-as` shows the caller to the command as another
identity, `own` or `UID:GID`, as that chapter describes.

## Inspecting a loaded profile

A consumer that loads configuration it did not write usually wants to look at
it before running it — to log what a group binds, to refuse one that shares the
host network, to show a user what a `RestrictedProfile` from an untrusted
source actually asks for. Every setting has a `get_` accessor on the builder,
so that is a read rather than a guess:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use ferroday_cage::{CageBuilder, Network};

let builder: CageBuilder = toml::from_str(&std::fs::read_to_string("build.toml")?)?;

if builder.get_network() == Network::Host {
    eprintln!("warning: this profile shares the host network");
}
for bind in builder.get_binds() {
    println!(
        "{} -> {}{}",
        bind.get_source().display(),
        bind.get_target().display(),
        if bind.is_read_only() { " (read-only)" } else { "" },
    );
}
// Or `get_mounts` for every mount in the order it will be applied, which is
// what a reviewer needs when one mount covers another. `mounts` takes the
// sequence back, so a reviewed one carries over to another builder whole.
for mount in builder.get_mounts() {
    println!("mounts at {}", mount.get_target().display());
}
# Ok(())
# }
```

The prefix is there because the setters own the bare names, the same
arrangement `std::process::Command` uses for `get_program` and `get_args`.

For a whole-configuration view rather than a field at a time, the builder
serializes as well as deserializes, so it round-trips back to the format it
came from:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let builder = ferroday_cage::Cage::builder();
// Render the requested configuration — profile plus the consumer's own
// calls — for a log or a confirmation prompt.
println!("{}", toml::to_string(&builder)?);
# Ok(())
# }
```

One thing never appears there, because it is code rather than configuration:
an `id_mapper` delegate, which is set on the builder in a consumer's own code,
and which a profile naming the key is rejected for rather than silently
ignored. `Debug` is derived on the builder too, which prints the delegate as
well.

## Intent and effect

A profile records what its author asked for, not everything that will happen.
A key left out stays out through a render-and-reload cycle, so `mount-dev`
absent means "not stated" rather than "stated as `true`" — which is what lets
`managed-mounts = false` coexist with an unstated `mount-dev` instead of
contradicting it.

For what a configuration actually resolves to, build it and ask the cage:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let builder = ferroday_cage::Cage::builder().rootfs("/srv/rootfs").command("/bin/sh");
let cage = builder.build()?;
// Every mount the sandbox will establish, managed profile included, and the
// command's whole environment with the library's base composed in.
println!("{}", toml::to_string(&cage.resolved_inputs())?);
# Ok(())
# }
```

The two answer different questions, and a consumer recording provenance wants
the second — see [Recording what a build ran
under](embedding.md#recording-what-a-build-ran-under).

## Resource limits in a profile

An `[rlimit]` table sets the kernel's per-process limits on the command, keyed
by resource name. One value sets the soft and hard limits alike; a
`{ soft, hard }` table sets them apart. Either position takes an amount in the
resource's own unit or `"unlimited"`.

```toml
[rlimit]
processes = 64                                # 64 processes, soft and hard
address-space = 536870912                     # 512 MiB of mapped address space
open-files = "unlimited"
cpu-time = { soft = 10, hard = "unlimited" }  # SIGXCPU at ten seconds
```

The resource names are the ones the [hardening
chapter](hardening.md#resource-limits) lists, and the same ones `fcage
--rlimit` takes. A soft limit above its hard limit is rejected when the builder
is built rather than when the profile is parsed, alongside every other
configuration error.

A limit is safe in an untrusted profile and `RestrictedProfile` permits it: it
is set on the command process, and an unprivileged `setrlimit` can only lower a
hard limit or move a soft one within the hard limit the caller already had.

A `[cgroup]` table places each launch in a cgroup of its own and holds the whole
process tree to its limits, as the [hardening
chapter](hardening.md#limits-on-the-whole-tree) describes:

```toml
[cgroup]
parent = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/sandboxes.scope"
memory-max = 536870912                        # 512 MiB for the whole tree
pids-max = 64
cpu-max = { quota = 50000, period = 100000 }  # half a processor
```

`RestrictedProfile` refuses a `parent`. It names a host directory each launch
creates a cgroup in, and whose controllers it enables for every cgroup beneath
it. A trusted caller sets the parent after loading, with
`CageBuilder::cgroup_parent`.

A limit with no parent is refused at build, unless the table sets `required =
false`. The launch then runs without the limits where no parent is named, and
the resolved inputs report them as not applied. The [hardening
chapter](hardening.md#limits-on-the-whole-tree) shows the pairing with an
`[rlimit]` table as the floor.

## Hardening in a profile

With the `hardening` feature, a profile carries the sandbox's Landlock,
seccomp, and capability posture in a `[hardening]` table, so the security
configuration is versioned and reviewed alongside the rest of the sandbox.

```toml
[hardening]
drop-caps = true                    # drop every capability...
# keep-caps = ["net-bind-service"]  # ...or keep only these, dropping the rest

landlock-scope = ["signal"]         # no signals to processes outside the sandbox

seccomp = "curated"                 # the curated deny-list of dangerous syscalls

[[hardening.landlock-fs]]
access = "rx"                       # the r, w, and x letters, like a file mode
path = "/usr"

[[hardening.landlock-fs]]
access = "rwx"
path = "/work"

[[hardening.landlock-net]]
access = "bc"                       # the b (bind) and c (connect) letters
port = 8080
```

`drop-caps` and `keep-caps` set the capability posture and are mutually
exclusive. Capabilities are named in kebab-case (`net-bind-service`). An empty
`keep-caps` is rejected, since `drop-caps = true` is how a profile drops every
capability.

An `[[hardening.landlock-fs]]` entry grants an `access` set beneath a `path`, in
the `r`, `w`, and `x` letters. An `[[hardening.landlock-net]]` entry grants an
`access` set on a TCP `port`, in the `b` (bind) and `c` (connect) letters.
Enrolling any grant denies every path, bind, and connect not granted. Paths are
sandbox paths, resolved after the pivot, and network rights require Landlock ABI
4. `landlock-scope` lists the scopes, `signal` and `abstract-unix-socket`, that
confine those reaches to the sandbox's own processes. Scopes require Landlock
ABI 6.

`seccomp` is either the string `"curated"` or a table naming syscalls to
filter — a deny-list, or an allow-list that must name every syscall the command
needs. A deny-list table with `curated = true` extends the curated roster:

```toml
[hardening.seccomp]
deny = ["mount", "ptrace", "bpf"]     # these fail with EPERM, the rest allowed

# ...or an allow-list:
[hardening.seccomp]
allow = ["read", "write", "execve"]   # only these allowed, the rest fail EPERM

# ...or the curated roster and more:
[hardening.seccomp]
curated = true
deny = ["sethostname"]
```

A syscall may be narrowed by its arguments through an `allow-rule` or
`deny-rule` array-of-tables, so the listed action applies only when the
arguments match. Each entry names a syscall and a list of `arg` conditions,
every one of which must hold; each condition sets an argument `index` (0 through
5), a width `len` (`dword` for the low 32 bits, `qword` for all 64), an `op`,
and a `value`. The `masked-eq` operator also takes a `mask` and tests
`(arg & mask) == (value & mask)`:

```toml
[hardening.seccomp]
allow = ["read", "write", "exit_group"]

[[hardening.seccomp.allow-rule]]
syscall = "ioctl"
[[hardening.seccomp.allow-rule.arg]]
index = 1
len = "dword"
op = "eq"
value = 21523                         # TIOCGWINSZ; ioctl allowed only for this request
```

The width has no safe default — comparing the wrong one lets a value hide in the
bits that are not checked — so a condition must state it. An `allow` and a `deny`
side are mutually exclusive within one table.

An `errno` table answers a syscall with an errno of its own, named as the C
headers name it, ahead of either side. A table with `errno` alone is a deny-list
of what it names:

```toml
[hardening.seccomp]
errno = { clone3 = "ENOSYS" }         # the C library falls back to clone
```

Syscalls are named as the kernel names them (`exit_group`), resolved for the
host architecture. The precompiled-program escape hatch
(`SeccompPolicy::Program`) has no place in a declarative profile and cannot be
written to one.

A profile that configures hardening requires a library built with the
`hardening` feature; a build without it refuses such a profile rather than
loading it with the restrictions silently dropped.

## Untrusted profiles

Deserializing a profile straight into a `CageBuilder` trusts it as
code-equivalent configuration: it can bind any host path, issue raw mounts,
share the host network, and share the host PID namespace. A profile from a
source the consumer does not control — a repository, a download, a
multi-tenant store — is loaded through `RestrictedProfile` instead, in the same
serde format:

```rust,no_run
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let text = std::fs::read_to_string("untrusted.toml")?;
let restricted: ferroday_cage::RestrictedProfile = toml::from_str(&text)?;
let builder = restricted.into_builder();      // extend with the consumer's own trusted calls
# let _ = builder;
# Ok(())
# }
```

The restricted policy refuses the operations that map host resources into the
sandbox, write to the host outside it, or share a host namespace:

- a bind mount or a raw mount
- a symbolic link, a `[[mount]]` entry with `kind = "symlink"`
- host networking
- an overlay root
- the host's own root, `host-rootfs`, and a path it hides taken back, `reveal`
- sharing the host PID namespace

A hidden path and a path made read-only only take away, so the policy admits
both. The host's own root maps the host's whole tree in, and a path the
profile takes back from its hides would be shown by a consumer's own
`host_rootfs` after loading.

An overlay root is refused because, unlike the root filesystem, its upper layer
is created rather than required to exist. The profile would choose a host path
for the library to create directories at. A trusted consumer configures one with
`overlay` after loading.

A symbolic link is refused because the setup makes it before any confinement
applies. In a plain root filesystem it stays on the host after the sandbox
exits. A link at `/etc/ld.so.preload` there, pointing at a path the command can
write, reaches every later sandbox on that tree. A restricted profile binds
nothing, so an empty root gains nothing from a link either.

The policy also refuses the parts of `[hardening]` that the consumer's own calls
add to rather than replace. A profile's part would otherwise widen whatever the
consumer configures after loading:

- `landlock-fs` and `landlock-net`, the Landlock grants. Grants are an
  allow-list the builder only appends to, so the profile's grants would be
  added to the consumer's.
- `keep-caps`, a kept capability set. It survives the switch to a non-root
  `run_as` identity the consumer adds, which otherwise clears every capability.

The rest of `[hardening]` only removes, and a restricted profile can carry it. A
seccomp policy refuses syscalls, `drop-caps` drops every capability, and a
Landlock scope denies a reach outside the sandbox. A consumer's own call for
any of them replaces the profile's.

Deserializing a `RestrictedProfile` reports a refusal through the format's own
error, as text. A consumer that matches on the refusal deserializes a
`CageBuilder` and converts it with `RestrictedProfile::try_from` instead. The
conversion applies the same policy and returns
`ConfigError::ProfileOperationForbidden`, naming the operation.

The policy bounds what the profile may map in, not the host authority the
command wields, which remains the calling user's. The rootfs the profile names
is presented read-write, so it still grants access to that host subtree. A
consumer that does not trust the profile to choose its own rootfs overrides it
after loading, with `into_builder().rootfs(path)` naming a directory the
consumer controls.

A range `identity-map` and a `run-as` identity pass the filter too. The bundled
delegates hold the outside ids a map names to the caller's own authority: its
capabilities and its namespace's map, or its subordinate allocation. A custom
delegate supplied with `id_mapper`, such as a privileged broker, must check them
itself. Otherwise a profile can map host ids the caller does not hold into the
sandbox, host root among them. [Identity maps](identity-maps.md#delegates)
states the delegate's duty.

## Profiles at the command line

`fcage --profile FILE` loads a profile; flags given alongside compose with
it:

- Scalar flags override the profile's value. Every toggle has both
  directions for this purpose — `--share-net`/`--isolate-net`,
  `--share-pid`/`--pid-ns`, `--proc`/`--no-proc`, and so on.
- `--bind`, `--ro-bind`, `--raw-mount`, `--symlink`, `--hide`, `--read-only`,
  `--reveal`, and `--setenv` extend the profile's lists.
- A command on the command line replaces the profile's `command` and
  `args` as a unit.
- `stop-with-caller` is the one key `fcage` defaults differently from the
  library: `fcage` waits for the command and exits with it, so a sandbox that
  outlived the process is never what a shell or a supervisor meant, and the tie
  is on unless something says otherwise. A profile stating the key is that
  something, so `stop-with-caller = false` holds — the flag still overrides
  either way.
- Hardening flags compose with a profile's `[hardening]` table. `--landlock-ro`,
  `--landlock-rw`, `--landlock-unix`, `--landlock-bind`, and `--landlock-connect`
  add grants to it. `--landlock-scope`, `--landlock-resolve-unix` and
  `--no-landlock-resolve-unix`, `--drop-caps`, `--keep-caps`, and the seccomp
  flags that set a posture replace its scopes, unix-socket restriction,
  capability posture, or seccomp policy.
  `--seccomp-errno` joins the policy that stands instead, the flags' or else the
  profile's. The seccomp flags mirror the profile's seccomp table, so a rule reads
  the same on a flag as in the table.
  `--seccomp-allow` and `--seccomp-deny` take comma-separated syscall names.
  `--seccomp-allow-rule` and `--seccomp-deny-rule` take a syscall name with
  `arg`/`len`/`op`/`value`/`mask` conditions, and `--seccomp-errno` takes
  `SYSCALL=ERRNO`.

```sh
# The profile's sandbox, its command replaced for one run:
fcage --profile build.toml -- /bin/sh -c 'ls /build'

# The profile with the network cut off:
fcage --profile build.toml --isolate-net
```

`--profile` trusts the file like a script: it can bind any host path, issue
raw mounts, share the host network, and share the host PID namespace. Load only
a profile you trust. `--restricted-profile FILE` loads under the restricted
policy instead, refusing what [Untrusted profiles](#untrusted-profiles) lists
for a profile from an untrusted source. The root filesystem it names still
grants access to that host subtree, so pass one you control.

A profile is plain data: loading one performs no filesystem access and
grants nothing by itself. Validation happens at `build`, launch behavior is
identical to the equivalent builder calls, and the profile's paths are
interpreted exactly as if they had been passed to the builder.

The same composition is available to any consumer, because a profile is a
`CageBuilder`: scalar setters replace, `bind` and `env` extend, and
`clear_args` before `command` replaces a profile's command as a unit.
[Building an orchestrator](building-an-orchestrator.md) works this into a
group-based launcher.
