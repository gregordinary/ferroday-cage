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
the command runnable at all: with any Landlock grant configured, everything
ungranted is denied, so the command's own binary, its interpreter, and its
libraries need read and execute grants alongside the data paths it works on.

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
sockets, and other socket families, `AF_UNIX` among them, are untouched, which
is why the abstract-socket surfaces below survive it.

Network rights need Landlock ABI 4, where filesystem rights need only ABI 1. On
an older Landlock kernel a filesystem grant narrows away best-effort, but a
restriction whose *only* grant is a network one would then enforce nothing at
all, so it is refused at build with
[`ConfigError::RestrictionLandlockUnenforceable`].

The command starts in `/` (or the [`current_dir`]) with a deterministic base
environment plus the caller's variables. The base is `PATH` alone — unlike
the cage's, it carries no `HOME`, because the command runs as the real
calling user, for whom `/root` would be wrong; set `HOME` explicitly if the
command needs one. Standard streams, the [`stdin`] disposition, output
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
isolation, some host-reaching surfaces remain, governed only by the Landlock
and seccomp the caller configured: abstract-socket services such as D-Bus and
the X server (a Landlock network grant governs TCP alone), same-user `/proc`
under a seccomp-only restriction, and same-user `ptrace` under a Landlock-only
restriction (the curated seccomp policy blocks it). A cage closes these three
through its namespaces and swapped root.

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
            .seccomp(ferroday_cage::SeccompPolicy::Curated)
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
apply. Descendants of the command can outlive it, a kill reaches only the
command process itself, and when output is captured, a surviving descendant
that holds the streams keeps an unbounded wait blocked — prefer a deadline
wait for commands that may leave children behind. The Landlock ruleset, the
seccomp filter, and no-new-privileges are all inherited by every process the
command starts, so the confinement itself does extend to descendants.

## Host support

Landlock enforcement follows the running kernel's ABI, best-effort downward,
exactly as in the hardening layer; a kernel with no Landlock LSM fails a
Landlock-bearing restriction as a setup error. A seccomp-only restriction
runs there. [`host::landlock_abi`] and [`host::seccomp_available`] report
what the kernel offers.

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

Alongside the grant flags, `--setenv`, `--no-base-env`, `--chdir`, `--stdin`,
`--rlimit`, `--timeout`, `--kill-after`, and `--stop-with-caller` behave as they
do for a sandbox. [`rlimit`] matters more here than in a cage: without
namespaces, a resource limit is the only thing bounding what the command
consumes.

[`Restriction`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Restriction.html
[`landlock_fs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.landlock_fs
[`landlock_net`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.landlock_net
[`ConfigError::RestrictionLandlockUnenforceable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.ConfigError.html
[`seccomp`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.seccomp
[`current_dir`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.current_dir
[`stdin`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.stdin
[`stop_with_caller`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.stop_with_caller
[`rlimit`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.RestrictionBuilder.html#method.rlimit
[`Running`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.Running.html
[`Error::UsernsUnavailable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Error.html
[`host::landlock_abi`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_abi.html
[`host::seccomp_available`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.seccomp_available.html
