# The restriction fallback

Some hosts cannot run the sandbox at all: unprivileged user namespaces are
disabled, and with them every namespace facility the cage is built from. For
those hosts the library offers a degraded mode, the *restriction*: it spawns
the command directly on the host and confines it with the same Landlock
filesystem rules, Landlock network rules, and seccomp filters the hardening
layer provides, always under the no-new-privileges flag.

A restriction is a weaker boundary than a cage, and the difference is worth
stating plainly. The command runs as the calling user, on the host
filesystem (as far as the Landlock grants allow), with the host network and
the host PID space visible. What a restriction delivers is filesystem-access
and syscall confinement plus the library's process model — the clean
deterministic environment, output streaming, and the running handle — on
hosts where nothing stronger is possible.

The restriction is part of the `hardening` feature and requires only
Landlock or seccomp from the kernel, not user namespaces.

## Configuring a restriction

[`Restriction`] mirrors the cage's builder shape. Because there is no
private rootfs, every path is a host path — including the grants that make
the command runnable at all: with any Landlock grant configured, reading and
executing a file needs a grant, so the command's own binary, its interpreter,
and its libraries need read and execute grants alongside the data paths it
works on. As in a sandbox, Landlock leaves a file's metadata ungoverned, as
[Hardening](hardening.md#what-this-boundary-does-not-cover) sets out.

A grant's path resolves as the host resolves it, through symbolic links. A grant
on a merged-`/usr` host's `/lib` therefore covers `/usr/lib`. A sandbox refuses a
link on a grant's path instead, because its root may not be trusted.

```rust,no_run
# use ferroday_cage::{FsAccess, Restriction};
# fn main() -> ferroday_cage::Result<()> {
let status = Restriction::builder()
    .command("/usr/bin/sort")
    .args(["/work/input"])
    .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/usr")
    .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
    .landlock_fs(FsAccess::READ, "/etc")
    .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/work")
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

[`landlock_fs`], [`landlock_net`], and [`seccomp`] behave exactly as they do on
the cage builder, and at least one control must be configured: a restriction
that restricts nothing is rejected at build time rather than launching a plain
process that appears sandboxed.

[`landlock_net`] grants TCP bind and connect on a named port. Configuring any
grant — filesystem or network — enrolls the command in Landlock, so a
restriction whose only grant is a network one denies every TCP bind and connect
it did not name, and the filesystem stays open. It governs TCP alone: UDP, raw
sockets, and other socket families, `AF_UNIX` among them, are untouched.

Network rights need Landlock ABI 4, where filesystem rights need only ABI 1. A
sandbox narrows a network grant away on an older kernel, with its network
namespace still behind it. A restriction has no such namespace, so a restriction
with any network grant is refused at build on that kernel, whatever filesystem
grants it also makes. The refusal is
[`ConfigError::RestrictionLandlockUnenforceable`].

The command starts in `/` (or the [`current_dir`]) with a deterministic base
environment plus the caller's variables. The base is `PATH` alone. It carries
no `HOME`, as a sandbox's does not for an identity other than root, because the
command runs as the real calling user, for whom `/root` would be wrong; set
`HOME` explicitly if the command needs one. Standard streams, the [`stdin`] disposition, output
streaming through an observer, a pseudoterminal of its own (see [A terminal of
the sandbox's own](terminal.md)), and the [`Running`] handle — wait, deadline,
terminate, kill, [`stop_with_caller`] — all work as they do for a cage.

The command starts with no capabilities. A restriction always drops to the
empty capability set, and the always-set no-new-privileges flag prevents a
set-user-ID or file-capabilities binary from acquiring any across the exec.
This matters when the caller is privileged — a root process on a host with
unprivileged user namespaces disabled is a plausible way to reach the
restriction fallback — which would otherwise pass its full capability set to
the command; when the caller is already unprivileged the drop is a no-op.

Because a restriction runs a host process with no namespace or root-swap
isolation, some host-reaching surfaces remain:

- **Signals.** The command shares the host's PID space as the calling user, so
  it can signal every process that user owns.
- **Abstract sockets.** It shares the host's network namespace, so it can reach
  the session bus and the X server through their abstract sockets. A Landlock
  network grant governs TCP alone, and seccomp cannot read a socket's address.
- **Pathname sockets.** It can connect to any unix socket at a path it can name:
  the session bus's under `/run/user`, an SSH agent's, a container runtime's. A
  Landlock filesystem grant governs files, not a `connect`. From Landlock ABI 9,
  [`landlock_resolve_unix`] confines it to the sockets the command created and
  those beneath a path granted `FsAccess::RESOLVE_UNIX`, and a restriction that
  asks for it is refused on an older kernel.
- **Other processes' memory and environment.** Without a Landlock domain, it can
  `ptrace` the calling user's other processes and read their
  `/proc/<pid>/environ`.

On a kernel with Landlock ABI 6 (Linux 6.12) or later, a restriction closes all
three. Its default [`landlock_scope`] confines signals and abstract-socket
connections to the processes the command started. The scopes also give every
restriction a Landlock domain, and any domain refuses ptrace access to the
processes outside it. Name fewer scopes only for a command that needs that
reach.

On an older kernel the default scopes are dropped, and signals and abstract
sockets stay open. A Landlock grant still creates a domain there, and the
curated seccomp policy still denies `ptrace` and `process_vm_readv`. Scopes a
restriction names itself are refused there instead, with
[`ConfigError::LandlockScopeUnenforceable`], since nothing else bounds those
reaches. A default sandbox closes all three through its PID and network
namespaces.

The caller's terminal is not among them, because it is not a namespace question:
a controlling terminal is reached through the session, so a cage and a
restriction answer it identically, by the rule described in
[The dispositions and the caller's
terminal](streaming.md#the-dispositions-and-the-callers-terminal). A command that
inherits the caller's standard input shares the caller's terminal deliberately;
one that does not runs in a session of its own and cannot reach it at all.
Independently of the session, the curated seccomp policy denies `ioctl` for the
`TIOCSTI` and `TIOCLINUX` requests, the two that write to a terminal's input
queue.

Every launch of a sandbox or a restriction gives the command a fresh session
keyring in place of the one it inherited. The command therefore does not possess
the keys the caller's login session holds. Where the kernel refuses the launch
that keyring, the launch refuses the command every key syscall instead. A
restriction leaves more of the user's keys in reach than a sandbox does, though.
The user keyring, the user session keyring, and the persistent keyring belong to
the user rather than to the session. A restricted command runs as that user, so
it can link them into its own keyring and read every key they hold. That
includes a Kerberos ticket cache kept in the persistent keyring. The curated
seccomp policy denies `keyctl`, which closes this. See [The session
keyring](how-the-sandbox-is-built.md#the-session-keyring).

## Falling back from a cage

A cage launch on a host without user namespaces fails with
[`Error::UsernsUnavailable`], naming the blocking configuration when the
probe identifies it. A program that wants to degrade catches that error and
runs its restriction:

```rust,no_run
# use ferroday_cage::{Cage, Error, FsAccess, Restriction};
# fn main() -> ferroday_cage::Result<()> {
# let cage = Cage::builder().rootfs("/srv/rootfs").command("/usr/bin/job").build()?;
let status = match cage.run() {
    Err(Error::UsernsUnavailable { .. }) => {
        // The degraded path: host paths, weaker guarantees.
        Restriction::builder()
            .command("/usr/bin/job")
            .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/usr")
            .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/var/lib/job")
            .seccomp(ferroday_cage::SeccompPolicy::Rules(
                ferroday_cage::SeccompRules::curated(),
            ))
            .build()?
            .run()?
    }
    outcome => outcome?,
};
# let _ = status;
# Ok(())
# }
```

The fallback is a second, deliberate configuration, not a translation of the
cage's. A cage describes a private mounted view; a restriction describes the
host. The paths differ, the trust model differs, and the decision to accept
the weaker boundary belongs to the caller, which is why the library never
degrades automatically.

## Process model

A restriction launch takes the same shape as a cage without a PID namespace:
a supervisor process watches the command from outside, and the same caveats
apply. Descendants of the command can outlive it. A kill reaches only the
command process itself, unless the restriction has a [cgroup](#cgroups) of its
own, through which it ends every process of the tree. When output is captured,
a surviving descendant that holds the streams keeps an unbounded wait blocked —
prefer a deadline wait for commands that may leave children behind. The
Landlock ruleset, the seccomp filter, and no-new-privileges are all inherited
by every process the command starts, so the confinement itself does extend to
descendants.

## Cgroups

[`cgroup_parent`] places each launch in a cgroup of its own beneath a
delegated cgroup v2 directory, [`cgroup_limit`] holds the command's whole
process tree to a limit on its memory, its processes, or its processor time,
and [`cgroup_required`] says whether a limit with no parent is refused or runs
without its limits. They behave as they do for a cage, as [Limits on the whole
tree](hardening.md#limits-on-the-whole-tree) describes: the launch stage joins
the cgroup before the command starts, [`ResourceUsage`] reports what the whole
tree used, and [`Running::kill`] ends every process of the tree through the
cgroup's `cgroup.kill`, descendants that left the command's process tree
included.

An [`rlimit`] bounds each process alone, so a command can stay under it and
still use as much as it likes by starting more processes. A cgroup's limits
bound the tree together, which is the bound a restriction otherwise lacks.

## Host support

Landlock enforcement follows the running kernel's ABI, best-effort downward,
exactly as in the hardening layer. A kernel with no Landlock LSM refuses a
restriction with any Landlock grant at build, with
[`ConfigError::RestrictionLandlockUnenforceable`]. A kernel below ABI 4 refuses
one with a network grant the same way. A seccomp-only restriction runs on
either, without the default scopes a kernel below ABI 6 cannot enforce. One
that names its scopes is refused there instead, with
[`ConfigError::LandlockScopeUnenforceable`]. [`host::landlock_abi`] reports the
kernel's Landlock ABI, [`host::landlock_enforces_scope`] and its siblings whether
the kernel enforces a scope or a right, and [`host::seccomp_available`] whether
this process can install a seccomp filter.

## On the command line

`--restrict` selects the restriction instead of the sandbox. The hardening
grant flags apply with host paths, and the flags that configure namespace
facilities are rejected:

```console
$ fcage --restrict \
    --landlock-ro /usr --landlock-ro /lib --landlock-ro /etc \
    --landlock-rw /work \
    --seccomp curated \
    -- /usr/bin/sort /work/input
```

`--landlock-scope` replaces the default scopes, and an empty list turns them
off. Scopes named this way are refused on a kernel that cannot enforce them.
`--landlock-resolve-unix` and `--landlock-unix PATH` restrict pathname sockets
as they do for a sandbox. The flags that shape the command's process, its
environment, standard streams, terminal, timeout, resource limits, and cgroup,
behave as they do for a sandbox, and `fcage --help` lists every flag
`--restrict` takes. Resource limits matter more here than in a cage: without
namespaces, the [`rlimit`]s and a cgroup's limits are the only things bounding
what the command consumes.

[`Restriction`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Restriction.html
[`landlock_fs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.landlock_fs
[`landlock_net`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.landlock_net
[`ConfigError::RestrictionLandlockUnenforceable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.ConfigError.html
[`ConfigError::LandlockScopeUnenforceable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.ConfigError.html
[`landlock_scope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.landlock_scope
[`landlock_resolve_unix`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.landlock_resolve_unix
[`seccomp`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.seccomp
[`current_dir`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.current_dir
[`stdin`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.stdin
[`stop_with_caller`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.stop_with_caller
[`rlimit`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.rlimit
[`cgroup_parent`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.cgroup_parent
[`cgroup_limit`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.cgroup_limit
[`cgroup_required`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.cgroup_required
[`ResourceUsage`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.ResourceUsage.html
[`Running::kill`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html#method.kill
[`Running`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html
[`Error::UsernsUnavailable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Error.html
[`host::landlock_abi`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_abi.html
[`host::landlock_enforces_scope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_enforces_scope.html
[`host::seccomp_available`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.seccomp_available.html
