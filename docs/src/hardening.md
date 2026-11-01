# Hardening

The default sandbox is a rootless convenience for code you trust: a controlled
filesystem view, a clean environment, and isolated namespaces. Confining
untrusted code is this layer's work. It adds three opt-in restrictions to the
command — Landlock filesystem rules, seccomp syscall filters, and capability
drops — plus a fully denied network. The default profile alone is not a
boundary against hostile code.

The layer is behind the `hardening` feature, compiled in only when a consumer
enables it. Every restriction is configured on the builder, applies
only to the command and the processes it starts, and is enforced after the root
pivot and immediately before the command executes.

More precisely, it is enforced after the command enters [its nested user
namespace](how-the-sandbox-is-built.md#the-nested-user-namespace), and that
ordering is a requirement rather than a detail of the implementation. Entering a
user namespace has the kernel re-derive the whole credential: the securebits
return to their defaults, the capability bounding set is refilled, and the
inheritable and ambient sets are cleared. Anything on this page applied before
the entry would be undone without a word. What the entry itself establishes —
the locks on the sandbox's mount flags — needs none of this layer, and holds in
every build.

## Landlock filesystem rules

[`landlock_fs`] grants a set of accesses beneath a path. Configuring any grant
enrolls the sandbox in Landlock: from then on the command reaches a path only
where a grant allows it, and every other path is denied.

```rust,no_run
# use ferroday_cage::{Cage, FsAccess};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/build")
    .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/usr")
    .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
    .landlock_fs(FsAccess::READ | FsAccess::WRITE, "/work")
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

[`FsAccess`] composes three primitives with `|`: `READ` (read files and list
directories), `WRITE` (write files and create, remove, and rename entries), and
`EXECUTE` (execute files). Paths are sandbox paths, resolved after the pivot, so
a grant describes the mounted view — the rootfs, the bind mounts, and the
`/proc`, `/dev`, and `/tmp` mounts alike. A read-write grant on the tmpfs `/tmp`
governs exactly the files the sandbox mounts there. A grant may also name a
single file or device node, such as `/etc/hostname` or `/dev/null`. There it
allows only the rights that act on a file, since there are no entries to list,
create, or remove.

A grant's path names its target itself. No component may be a symbolic link,
the last one included. A link in a root that is not fully trusted can point
anywhere in the sandbox, and a grant resolved through it would cover wherever it
points. A grant that crosses a link fails the launch with `ELOOP`, naming the
grant. On a merged-`/usr` root, where `/lib` is a link to `usr/lib`, grant
`/usr` instead.

The rules are enforced on any kernel that offers Landlock, best-effort down to
the kernel's supported ABI. A rule naming an access right a kernel does not
define is narrowed to what that kernel enforces, never widened. A kernel with no
Landlock support at all fails the launch with a setup error, rather than run the
command without its rules. [`host::landlock_abi`] reports the running kernel's
supported ABI version, or `None` when Landlock is absent.

## Landlock network rules

[`landlock_net`] grants a set of accesses on a TCP port. The kernel keys network
rights by port rather than by path, so these are the network counterpart of the
filesystem rules: configuring any grant — filesystem or network — enrolls the
sandbox in Landlock, and a network grant then governs both binding and
connecting.

```rust,no_run
# use ferroday_cage::{Cage, FsAccess, NetAccess};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/proxy")
    .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/usr")
    .landlock_fs(FsAccess::READ | FsAccess::EXECUTE, "/lib")
    .landlock_net(NetAccess::BIND, 8080)
    .landlock_net(NetAccess::CONNECT, 443)
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

[`NetAccess`] composes two primitives with `|`: `BIND` (bind a TCP socket to the
port) and `CONNECT` (connect a TCP socket to the port). The example lets the
command listen on 8080 and reach HTTPS services on 443, and denies every other
bind and connect — enrolling a network grant denies all network access not
granted, exactly as a filesystem grant denies all paths not granted. A `BIND`
grant on port `0` permits binding to a kernel-assigned ephemeral port.

Network rights arrive in Landlock ABI 4. On an older kernel that still offers
Landlock they are narrowed away best-effort, the same downgrade an unsupported
filesystem right receives; a network-only request on such a kernel becomes a
no-op rather than an error, and no ruleset is built at all. Check
[`host::landlock_abi`] for a version of 4 or more when a command must not run
unless its network restriction can be enforced.

The one place that downgrade is refused rather than taken is where the grant is
the sandbox's only network boundary: a host-network cage, and the restriction
fallback. Both fail the build on a kernel that cannot enforce the grant. An
isolated cage keeps its network namespace either way, which is why the same
kernel is tolerated there.

## Landlock scopes

A sandbox's PID and network namespaces hide the calling user's other processes.
With them go two reaches that no grant governs: signals, and connections to
abstract `AF_UNIX` sockets. [`pid_namespace(false)`] gives the first back, and
[`Network::Host`] the second. [`landlock_scope`] takes either away again,
confining it to the processes the sandbox started:

```rust,no_run
# use ferroday_cage::{Cage, LandlockScope};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/build")
    .pid_namespace(false)
    .landlock_scope([LandlockScope::Signal])
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

[`LandlockScope`] has two values. `Signal` denies a signal to any process outside
the sandbox's Landlock domain. `AbstractUnixSocket` denies a connection to an
abstract socket such a process created. Both reaches stay open between the
command and the processes it starts. A scope is not a grant, so it enrolls no
path or port and leaves the filesystem and the network as the grants left them.

Scopes need Landlock ABI 6 (Linux 6.12). Where a namespace also bounds its
reach, a scope is additive, and an older kernel that offers Landlock narrows it
away best-effort. Where nothing else bounds the reach, the scope is the
boundary. That is `Signal` under [`pid_namespace(false)`], and
`AbstractUnixSocket` under [`Network::Host`]. There a kernel below ABI 6, or one
without Landlock, refuses the build with
[`ConfigError::LandlockScopeUnenforceable`].

The [restriction fallback](restriction-fallback.md), which has neither
namespace, applies both scopes by default. A kernel that cannot enforce them
drops the default scopes, and refuses scopes a restriction names itself.

## Seccomp syscall filters

[`seccomp`] applies a syscall filter to the command. Three policies are
available through [`SeccompPolicy`]:

- `Curated` — a built-in deny-list of dangerous and rarely-legitimate syscalls,
  answering each with `EPERM` and allowing the rest. It covers mounting,
  creating or entering a namespace, kernel modules, the keyring, tracing,
  time-setting, and similar. Some entries name an argument rather than a whole
  syscall. `ioctl` is denied for the `TIOCSTI` and `TIOCLINUX` requests, which
  write to a terminal's input queue. `clone` and `unshare` are denied when their
  flags create a namespace, so processes and threads still start. `clone3` is
  answered `ENOSYS`, for the reason [Argument
  conditions](#argument-conditions) gives. A command that builds a sandbox of its
  own, such as a browser, needs a policy of its own. The roster grows as new
  syscalls warrant denial; it is a convenience posture, not a boundary claim.
- `Rules` — a caller-authored [`SeccompRules`] allow-list or deny-list. An
  allow-list names the syscalls the command may make and denies the rest, so it
  must include every syscall the command needs. A deny-list names the syscalls
  to refuse and allows the rest. Syscalls are named by their kernel number for
  the host architecture, which [`SeccompRules::syscall`] reads from a name such
  as `clone3`.
- `Program` — a pre-compiled BPF program ([`SockFilter`] instructions),
  installed verbatim, for a policy produced by an external compiler.

```rust,no_run
# use ferroday_cage::{Cage, SeccompPolicy};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/convert")
    .seccomp(SeccompPolicy::Curated)
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

### Argument conditions

A listed syscall may carry conditions on its arguments through
[`SeccompRules::rule`], so the listed action applies only to invocations whose
arguments match — an allow-list that permits `ioctl` only for a specific
request, a deny-list that refuses `socket` only for `AF_INET`. Each condition is
a [`SeccompArg`]: an argument index (0 through 5), a width, a comparison, and a
value. Repeating a syscall accepts any of several condition sets; a syscall
listed both plainly and with conditions matches unconditionally.

```rust,no_run
# use ferroday_cage::{Cage, SeccompArg, SeccompPolicy, SeccompRules};
# const TIOCGWINSZ: u64 = 0x5413;
# fn main() -> ferroday_cage::Result<()> {
// Allow read, write, and ioctl, but ioctl only for the TIOCGWINSZ request.
let rules = SeccompRules::allowing([libc::SYS_read, libc::SYS_write])
    .rule(libc::SYS_ioctl, [SeccompArg::eq_dword(1, TIOCGWINSZ)]);
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/convert")
    .seccomp(SeccompPolicy::Rules(rules))
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

The width is a deliberate choice. The kernel presents every argument as a
64-bit value, and the `_dword` constructors compare only its low 32 bits while
the `_qword` constructors compare all 64. Match the width to the argument's
kernel type: `dword` for an `int` or a 32-bit flag set, `qword` for a pointer or
a 64-bit value. Comparing the wrong width lets a value hide in the bits that are
not checked. A `dword` value or mask wider than 32 bits is refused at build,
since its high bits could take no part in the comparison. The `masked_eq_*`
constructors test individual flag bits — for example, that `CLONE_NEWUSER` is
clear in a `clone` flags argument.

A filter sees a syscall's registers and nothing they point at. `clone3` takes its
flags in a structure in memory, so a condition on `clone`'s flags does not reach
it. Denying `clone3` with `EPERM` breaks thread creation in glibc 2.34 and later.
[`SeccompRules::errno_for`] answers it with `ENOSYS` instead, and the C library
then falls back to `clone`, where the condition applies:

```rust,no_run
# use ferroday_cage::{Cage, SeccompArg, SeccompPolicy, SeccompRules};
# const CLONE_NEWUSER: u64 = 0x1000_0000;
# fn main() -> ferroday_cage::Result<()> {
// No new user namespace through clone or unshare, and clone3's callers sent
// to clone.
let new_user_namespace = [SeccompArg::masked_eq_qword(0, CLONE_NEWUSER, CLONE_NEWUSER)];
let rules = SeccompRules::denying([])
    .rule(libc::SYS_clone, new_user_namespace)
    .rule(libc::SYS_unshare, new_user_namespace)
    .errno_for(libc::SYS_clone3, libc::ENOSYS as u16);
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/build")
    .seccomp(SeccompPolicy::Rules(rules))
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

A syscall answered this way cannot also be listed, since one of the two answers
would never apply. The build refuses that policy. It also refuses an errno
outside 1 through 4095, whether given here or as a `SeccompAction::Errno`. Zero
reports a success the syscall never performed, and the C library reads a larger
number as the value the syscall returned.

The filter binds the command and its descendants. Seccomp filtering is available
on the `x86_64`, `aarch64`, and `riscv64` architectures; a policy on any other
is a build error. [`host::seccomp_available`] reports whether the kernel offers
seccomp at all.

A root filesystem for a foreign architecture, run through `qemu-user`, is
filtered correctly: the task making each syscall is the emulator, a host binary
making host syscalls. What differs is the set it makes. An allowlist written
against a native run can be too narrow for the same workload emulated. The
curated policy compiles and runs the foreign-architecture example's probe
unchanged, as [A foreign-architecture test
run](cross-architecture.md#where-the-architecture-is-decided-and-where-it-is-not)
describes.

## Capability drops

In a user namespace the command is mapped to root and holds every capability
*within that namespace*. None of them confers authority over the host, but they
do grant power inside the sandbox. [`drop_all_capabilities`] sheds them all;
[`keep_capabilities`] retains only a named few:

```rust,no_run
# use ferroday_cage::{Cage, Capability};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/sbin/service")
    .keep_capabilities([Capability::NetBindService])
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

The drop narrows the bounding, ambient, permitted, effective, and inheritable
sets, so a dropped capability cannot be regained across the command's `execve`.

A capability posture composes with a non-root [run-as
identity](identity-maps.md#running-as-a-non-root-identity). Without a keep
request the identity switch itself clears the command's capabilities, which
is usually the point; with one, the launch locks the securebits that carry
the kept set across the switch, so the command runs as its non-root identity
holding exactly the kept capabilities. Keeping `CAP_SETUID`, `CAP_SETGID`,
or `CAP_SETPCAP` alongside a non-root identity is rejected at build time —
it would let the command return to the mapped uid 0.

## Denied network

Beyond the default isolated network — a namespace whose loopback is brought up,
so the sandbox can talk to itself — [`Network::None`] leaves loopback down. The
command has no connectivity at all, not even to `127.0.0.1`.

```rust,no_run
# use ferroday_cage::{Cage, Network};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/analyze")
    .network(Network::None)
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

## Resource limits

The restrictions above bound what the command can *reach*. They say nothing
about what it can *consume*, and the two are independent: a command confined to
a private root, denied the network, filtered by seccomp, and stripped of every
capability can still fork without end, allocate without end, and fill the
filesystem it was given.

[`rlimit`] sets the kernel's own per-process limits on the command, and every
process it starts inherits them:

```rust,no_run
# use ferroday_cage::{Cage, Limit, Resource, SeccompPolicy};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/analyze")
    .seccomp(SeccompPolicy::Curated)
    .drop_all_capabilities()
    // 64 processes, 512 MiB of address space, 64 MiB of file, 10 CPU seconds.
    .rlimit(Resource::Processes, 64, 64)
    .rlimit(Resource::AddressSpace, 512 << 20, 512 << 20)
    .rlimit(Resource::FileSize, 64 << 20, 64 << 20)
    .rlimit(Resource::CpuTime, 10, Limit::UNLIMITED)
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

Each call names a [`Resource`] and its soft and hard values in that resource's
own unit; `Limit::UNLIMITED` is the kernel's `RLIM_INFINITY`, and a soft limit
above its hard limit is rejected at build time. Repeating a resource replaces
the earlier setting. The limits are applied to the command process before the
hardening layer, so a seccomp filter cannot deny the call that sets them.

The resources, with the kernel limit each sets and the unit it counts in. The
name in the first column is what a profile's `[rlimit]` table and the
`--rlimit` flag both spell:

| Name | Kernel limit | Unit |
| --- | --- | --- |
| `address-space` | `RLIMIT_AS` | bytes of mapped address space |
| `core-dump` | `RLIMIT_CORE` | bytes |
| `cpu-time` | `RLIMIT_CPU` | seconds of CPU time |
| `data` | `RLIMIT_DATA` | bytes of heap and anonymous mappings |
| `file-size` | `RLIMIT_FSIZE` | bytes, the largest file created |
| `locked-memory` | `RLIMIT_MEMLOCK` | bytes lockable into RAM |
| `open-files` | `RLIMIT_NOFILE` | one past the highest descriptor |
| `pending-signals` | `RLIMIT_SIGPENDING` | queued signals |
| `processes` | `RLIMIT_NPROC` | processes and threads |
| `stack` | `RLIMIT_STACK` | bytes of main-thread stack |

Two carry kernel semantics worth knowing before relying on them:

- **`Processes`** is `RLIMIT_NPROC`, which from Linux 5.14 the kernel counts per
  user id within each user namespace. The count is then the sandbox's own
  processes, and the caller's processes outside it do not count. From 5.6 to
  5.13 the kernel counts per host user id across the whole system. A command
  running as the calling user's host id then shares the cap with the caller's
  other processes. A [range identity map](identity-maps.md) with a non-root
  run-as identity gives it a host id of its own. `pending-signals` counts queued
  signals the same way.
- **`AddressSpace`** counts mapped address space, not resident memory. A
  runtime that maps far more than it touches — many do — hits the limit well
  before its real memory use approaches the value.

On the command line, `--rlimit RESOURCE=SOFT[:HARD]` sets one, repeatably:
`--rlimit processes=64 --rlimit cpu-time=10:unlimited`. `fcage --help` lists
the accepted names, and so does the message rejecting one it does not know.

A [profile](profiles.md) carries the same limits in an `[rlimit]` table, keyed
by the resource names above. One value sets the soft and hard limits alike; a
`{ soft, hard }` table sets them apart. Either position takes an amount or
`"unlimited"`.

```toml
[rlimit]
processes = 64
address-space = 536870912
file-size = 67108864
cpu-time = { soft = 10, hard = "unlimited" }
```

## What this boundary does not cover

Two things a reader configuring the strongest posture on this page might
reasonably assume are covered, and are not:

- **Resource governance beyond the per-process axis.** The limits above are
  `setrlimit` values, which is all an unprivileged process can set on itself.
  CPU shares, memory ceilings that count resident rather than mapped pages,
  I/O throttling, and PID caps that are genuinely per-sandbox all live in
  cgroup controllers, and disk consumption lives in filesystem quotas. Both are
  the host's to configure, and neither is something this library sets up. A
  consumer that needs them places the calling process in a cgroup of its own
  before launching, and the sandbox inherits it.
- **The rootfs itself.** The command is root inside the sandbox and the rootfs
  is mounted read-write, so it can modify anything in the provisioned tree that
  the calling user could modify on the host. A Landlock grant narrows this; so
  does [`overlay_rootfs`](provisioning.md#keeping-a-provisioned-root-pristine),
  which leaves the base untouched and sends every write to a disposable upper.
  The root is mounted `nosuid`, so what the command writes into the tree cannot
  be executed back with elevated ids — but the tree's contents are still the
  command's to change.

Neither gap is silent: what the layer does enforce, it enforces completely,
and what it does not, it does not claim.

## In a profile

With the `serde` feature, every restriction on this page is expressible in a
[profile](profiles.md): a `[hardening]` table carries the capability posture,
the seccomp policy, and the Landlock filesystem and network grants, so a
sandbox's security configuration is a reviewable, versionable artifact rather
than a sequence of builder calls.

```toml
[hardening]
keep-caps = ["net-bind-service"]
seccomp = "curated"

[[hardening.landlock-fs]]
access = "rx"
path = "/usr"

[[hardening.landlock-net]]
access = "c"
port = 443
```

The [profiles chapter](profiles.md#hardening-in-a-profile) documents the table
in full. A library built without the `hardening` feature refuses a profile that
configures it, rather than dropping the restrictions silently.

## Order and interaction

The restrictions are applied to the command in a fixed order, wrapped around
the identity switch: the securebits are locked (when a non-root identity keeps
capabilities), no-new-privileges is set, and Landlock is enforced; then the
identity switch is performed; then capabilities are dropped and the seccomp
filter is installed last, so the active filter governs only the command's
`execve` and what follows. No-new-privileges is set a second time by the switch
itself when a run-as identity is configured, so that a build without this
feature — and a sandbox that asks for a non-root identity and no hardening at
all — still gets it. The ordering is deliberate. Landlock and its
grant-path opens run while the process still holds its in-namespace root
credentials, before the switch and the capability drop take them away, so the
grants are established successfully; and the seccomp filter, installed after the
switch, never governs the switch's own syscalls. Each restriction is inherited
across `execve`, and none touches the sandbox init or the supervisor.

On the command line, `--landlock-ro` and `--landlock-rw` add filesystem grants,
`--landlock-bind` and `--landlock-connect` add network grants by port, and
`--landlock-scope` names the scopes. `--seccomp curated` applies the curated
profile, and `--seccomp-allow` and `--seccomp-deny` filter syscalls by name.
`--seccomp-allow-rule` and `--seccomp-deny-rule` add argument conditions in the
profile's `arg`/`len`/`op`/`value` terms, for example `--seccomp-allow-rule
'ioctl arg=1 len=dword op=eq value=0x5413'`. `--seccomp-errno clone3=ENOSYS`
answers one syscall with an errno of its own. `--drop-caps` and `--keep-caps`
control capabilities, and `--deny-net` selects the denied network.

The Landlock and seccomp primitives also stand on their own: on hosts
without unprivileged user namespaces, [the restriction
fallback](restriction-fallback.md) applies them to a plain spawned command,
with no sandbox around it.

[`landlock_fs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.landlock_fs
[`landlock_net`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.landlock_net
[`FsAccess`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.FsAccess.html
[`NetAccess`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetAccess.html
[`seccomp`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.seccomp
[`SeccompPolicy`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.SeccompPolicy.html
[`SeccompRules`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html
[`SeccompRules::rule`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.rule
[`SeccompRules::syscall`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.syscall
[`SeccompArg`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompArg.html
[`SockFilter`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SockFilter.html
[`drop_all_capabilities`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.drop_all_capabilities
[`keep_capabilities`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.keep_capabilities
[`Capability`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Capability.html
[`Network::None`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`Network::Host`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`pid_namespace(false)`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.pid_namespace
[`landlock_scope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.landlock_scope
[`LandlockScope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.LandlockScope.html
[`SeccompRules::errno_for`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.errno_for
[`ConfigError::LandlockScopeUnenforceable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.ConfigError.html
[`host::landlock_abi`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_abi.html
[`host::seccomp_available`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.seccomp_available.html
