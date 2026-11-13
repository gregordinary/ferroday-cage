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
enrolls the sandbox in Landlock: from then on the command reads, writes, and
executes files, and lists, creates, removes, and renames entries, only where a
grant allows it. Landlock does not govern a file's metadata, as [What this
boundary does not cover](#what-this-boundary-does-not-cover) sets out.

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

[`FsAccess`] composes four primitives with `|`: `READ` (read files and list
directories), `WRITE` (write files and create, remove, and rename entries),
`EXECUTE` (execute files), and `RESOLVE_UNIX` (connect to the unix sockets
beneath it, as [Landlock and unix sockets](#landlock-and-unix-sockets)
describes). Paths are sandbox paths, resolved after the pivot, so a grant
describes the mounted view — the rootfs, the bind mounts, and the `/proc`,
`/dev`, and `/tmp` mounts alike. A read-write grant on the tmpfs `/tmp`
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
[`host::landlock_enforces_net`] when a command must not run unless its network
restriction can be enforced.

The downgrade is refused rather than taken wherever the grant is the only bound
on the command's network reach. A host-network cage and the restriction
fallback fail the build on a kernel that cannot enforce the grant. An isolated
cage keeps its network namespace either way, which is why the build tolerates
the same kernel there. Attaching the [native network
stack](userspace-networking.md) changes that: the stack gives the namespace
outbound TCP, so
[`NetStack::attach`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.NetStack.html#method.attach)
refuses a sandbox whose grant the kernel cannot enforce, and `fcage --netstack`
with it.

## Landlock scopes

A sandbox's PID and network namespaces hide the calling user's other processes.
With them go two reaches that no grant governs: signals, and connections to
abstract `AF_UNIX` sockets. Under a PID namespace the sandbox also runs in a
process group or a session of its own, so a signal it sends to its own group
reaches its own processes alone. [`pid_namespace(false)`] gives the first reach
back. The command then shares the host's PID space, where it can signal every
process of the calling user's, the caller among them. [`Network::Host`] gives
the second back. [`landlock_scope`] takes either
away again, confining it to the processes the sandbox started:

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
[`ConfigError::LandlockScopeUnenforceable`]. [`host::landlock_enforces_scope`]
reports whether the running kernel enforces a scope.

## Landlock and unix sockets

A read-only mount refuses writing files, not connecting to a socket, and a
hidden path covers only the places it names. A pathname socket anywhere else in
the command's view accepts its connection: one inside a bound working tree, or
an agent's socket at a path nothing hid. [`landlock_resolve_unix`] refuses
those connections, except to a socket the command or a process it started
created, and beneath a path granted [`FsAccess::RESOLVE_UNIX`]:

```rust,no_run
# use ferroday_cage::{Cage, FsAccess};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .bind("/run/egress", "/run/egress")
    .landlock_resolve_unix(true)
    .landlock_fs(FsAccess::RESOLVE_UNIX, "/run/egress")
    .command("/usr/bin/agent")
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

This is Landlock's `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` right. It governs
`connect`, and `sendmsg` with an explicit address, to a pathname socket, and a
refusal answers `EACCES`. A grant of the right alone enrolls no other filesystem
right, so it opens a socket directory without closing the rest of the
filesystem. In a profile the grant's access letter is `u`, and the setting is
`resolve-unix` in the `[hardening]` table.

The restriction is off by default, so a sandbox's existing grants behave as
they did. The [host's own root](how-the-sandbox-is-built.md#the-hosts-own-root)
turns it on, since that root leaves the host's sockets in view wherever no hide
covers them.

The right needs Landlock ABI 9. Asked for on an older kernel, or on one without
Landlock, the build is refused with
[`ConfigError::LandlockResolveUnixUnenforceable`], since nothing else bounds the
sockets the mounts leave in view. [`host::landlock_enforces_fs`] reports whether
the running kernel enforces a right, `FsAccess::RESOLVE_UNIX` among them, so a
caller can ask for the restriction only where it applies. The host root's default is dropped on such a
kernel instead, and the [resolved inputs](embedding.md#recording-what-a-build-ran-under)
report whether it applies. On the command line, `--landlock-resolve-unix` turns
it on, `--no-landlock-resolve-unix` off, and `--landlock-unix PATH` grants the
right beneath a path.

The [restriction fallback](restriction-fallback.md), which has neither
namespace, applies both scopes by default. A kernel that cannot enforce them
drops the default scopes, and refuses scopes a restriction names itself.

## Seccomp syscall filters

[`seccomp`] applies a syscall filter to the command. A [`SeccompPolicy`] is one
of two:

- `Rules` — a [`SeccompRules`] allow-list or deny-list. An allow-list names the
  syscalls the command may make and denies the rest, so it must include every
  syscall the command needs. A deny-list names the syscalls to refuse and
  allows the rest. Syscalls are named by their kernel number for the host
  architecture, which [`SeccompRules::syscall`] reads from a name such as
  `clone3`.
- `Program` — a pre-compiled BPF program ([`SockFilter`] instructions),
  installed verbatim, for a policy produced by an external compiler.

[`SeccompRules::curated`] is the built-in deny-list of dangerous and
rarely-legitimate syscalls, answering each with `EPERM` and allowing the rest.
It covers mounting, creating or entering a namespace, kernel modules, the
keyring, tracing, time-setting, and similar. Some entries name an argument
rather than a whole syscall. `ioctl` is denied for the `TIOCSTI` and
`TIOCLINUX` requests, which write to a terminal's input queue. `clone` and
`unshare` are denied when their flags create a namespace, so processes and
threads still start. `clone3` is answered `ENOSYS`, for the reason [Argument
conditions](#argument-conditions) gives. A command that builds a sandbox of its
own, such as a browser, needs a policy of its own. The roster grows as new
syscalls warrant denial. It is a convenience posture, not a boundary claim.

The curated roster is a deny-list like any other, so a caller's rules extend
it. An errno the caller gives for a syscall the roster lists answers that
syscall in place of the roster's entry.

```rust,no_run
# use ferroday_cage::{Cage, SeccompPolicy, SeccompRules};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/convert")
    .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
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

The filter binds the command and its descendants. A `Rules` policy compiles
for a 64-bit host: `x86_64`, `aarch64`, or `riscv64`. The `hardening` feature
builds for x86 and 32-bit arm as well, where the build refuses a `Rules` policy
with `ConfigError::SeccompUnsupportedArch` and the Landlock rules and capability
drops apply as anywhere. A `Rules` policy is compiled for the host's own
syscall ABI, and kills a process that makes a syscall under any other audit
architecture, as a natively run 32-bit userland does at its first syscall. [Host
requirements](host-requirements.md#architecture) describes that case. A
`Program` is installed as given, and a syscall made under another architecture
gets whatever the program answers. A program written by hand therefore checks
the architecture first, as every program the library compiles does.
[`host::seccomp_available`] reports whether this process can install a filter
at all.

A sandbox with a network namespace of its own already carries a filter of the
launch's own. It refuses vsock, io_uring, and socket creation through x86's
`socketcall`, as [The network
filter](how-the-sandbox-is-built.md#the-network-filter) describes. A policy here
is installed after it. Where both refuse a syscall with an errno, the command
sees the policy's. Under the curated policy, `io_uring_setup` therefore fails
with `EPERM` rather than the network filter's `ENOSYS`.

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
It drops every capability the running kernel defines, including any added to
the kernel after this library was built.

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
command has no connectivity at all, not even to `127.0.0.1`. Both postures carry
[the network filter](how-the-sandbox-is-built.md#the-network-filter), which
closes the routes out that a namespace does not cover.

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
# use ferroday_cage::{Cage, Limit, Resource, SeccompPolicy, SeccompRules};
# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/analyze")
    .seccomp(SeccompPolicy::Rules(SeccompRules::curated()))
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

### Limits on the whole tree

An `rlimit` bounds each process alone, so it cannot bound what the sandbox's
processes use together. A cgroup can. Its memory ceiling counts resident pages
across the whole tree. Its process cap counts every process in it, and its
processor limits apply to all of them together.
[`cgroup_parent`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.cgroup_parent)
places each launch in a cgroup of its own, beneath a directory the caller
delegates, and
[`cgroup_limit`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.cgroup_limit)
sets its limits:

```rust,no_run
# use ferroday_cage::{Cage, CgroupLimit};
# fn main() -> ferroday_cage::Result<()> {
let output = Cage::builder()
    .rootfs("/srv/rootfs/alpine")
    .command("/usr/bin/analyze")
    .cgroup_parent("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/sandboxes.scope")
    .cgroup_limit(CgroupLimit::MemoryMax(512 << 20))
    .cgroup_limit(CgroupLimit::MemorySwapMax(0))
    .cgroup_limit(CgroupLimit::PidsMax(64))
    .cgroup_limit(CgroupLimit::cpu_max(50_000, 100_000))
    .build()?
    .output()?;
if let Some(usage) = output.usage {
    println!("peak memory of the whole tree: {:?}", usage.cgroup_peak_memory_bytes);
    println!("OOM kills: {:?}", usage.cgroup_oom_kills);
}
# Ok(())
# }
```

The library creates no hierarchy and needs no privilege. The parent is a cgroup
v2 directory the caller can create cgroups in. The scope `systemd-run --user
--scope -p Delegate=yes` runs a command in is one. Each launch creates
`fcage-<unique>` beneath it, enables the controllers its limits need, and
writes them. Beneath that it creates `fcage-<unique>/sandbox`, a leaf that
enables no controller of its own. The launch stage moves itself into the leaf
before it creates any namespace. Everything the sandbox runs is then charged
to `fcage-<unique>` and held to its limits, and the sandbox's cgroup namespace
is rooted at the leaf.

The kernel creates a cgroup's files owned by the process that created it, the
caller, and the sandbox's processes run as the caller's own user on the host.
The leaf is what keeps the limits out of their reach. A sandboxed command that
mounts the cgroup filesystem in a namespace of its own sees the leaf as the
hierarchy's root, with no limit in it, and nothing above it: neither the
limits nor the parent's `cgroup.procs`, through which it could move itself out
of the tree. That holds whatever the host mounts its cgroup filesystem with. A
bind of the host's cgroup filesystem into the sandbox, writable, puts both back
in reach.

The cgroup does three things besides the limits:

- **Whole-tree usage.** `ResourceUsage` gains the tree's processor time from
  `cpu.stat`, its peak memory from `memory.peak`, its peak process count from
  `pids.peak`, and its OOM kills from `memory.events`. These count every
  process the cgroup held, an orphan collected outside the sandbox included,
  and the launching process's own pages are not among them. They are read for
  a killed sandbox too, whose init a kill ends before it reports.
- **A kill that reaches every process.** `Running::kill` and `KillHandle::kill`
  also write `cgroup.kill`, where the kernel has it (Linux 5.14). Without a PID
  namespace, that is what ends the descendants that left the command's process
  tree, before the outcome is known or after it.
- **Removal.** The handle removes the cgroup once the outcome is known and no
  process is left in it. A sandbox without a PID namespace can leave processes
  running past the outcome, and the handle then keeps the cgroup. A kill ends
  them, and the last of the handle and its kill handles to drop removes the
  cgroup once they have exited, waiting up to five seconds for them. Without a
  kill, a cgroup still holding them when the last handle drops stays beneath
  the parent. The caller removes it once they have ended, by themselves or
  through a write of `1` to its `cgroup.kill`: an `rmdir` of the leaf, and then
  one of the cgroup.

A cgroup with processes of its own cannot enable controllers for its children.
A caller that runs inside the parent therefore moves itself into a leaf beside
the sandboxes' cgroups first. The library moves no process of the caller's.
[`host::own_cgroup`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.own_cgroup.html)
names the cgroup a process runs in, and a shell reads it from
`/proc/self/cgroup`:

```sh
systemd-run --user --scope -p Delegate=yes sh -c '
    parent=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
    mkdir "$parent/caller"
    echo 0 > "$parent/caller/cgroup.procs"
    exec fcage --cgroup-parent "$parent" --cgroup memory-max=536870912 \
        --cgroup pids-max=64 --rootfs /srv/rootfs/alpine -- /usr/bin/analyze'
```

A process moves with its threads, except a thread already exiting, which stays
in the parent until its exit completes. The parent refuses controllers for its
children until then, as it does while it holds a process. A caller whose
threads can be ending as it moves waits for the parent's `cgroup.threads` to
list none before it launches.

A launch does not run without the limits it was given. It fails with
`Error::CgroupRefused`, and a `CgroupRefusal` saying why, where the parent
cannot hold the sandbox's cgroup:

- it is missing, or outside a cgroup v2 hierarchy;
- its cgroup filesystem is mounted read-only;
- it is not delegated to the caller;
- it lacks a controller a limit needs, or holds processes of its own;
- the kernel lacks a limit's file;
- the caller runs where the launch cannot move from into the parent's subtree.
  The kernel lets a process move one only where it may write the
  `cgroup.procs` of the nearest cgroup the two share.

A value the kernel would refuse is refused at build, and so is a limit with no
parent to apply it beneath, unless the limits are not required.
[`host::cgroup_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.cgroup_blocker.html)
gives the same answer before a launch, by the launch's own steps: it creates a
cgroup and its leaf beneath the parent, moves a short-lived child into the
leaf, and removes both.
Inside a container, the runtime mounts the cgroup filesystem read-only by
default, which leaves a sandbox there no parent. [Running inside a
container](running-in-a-container.md) gives the detail.

The limits, in the units of the files they are written to. The name in the
first column is what a profile's `[cgroup]` table and `fcage --cgroup` both
spell:

| Name | File | Unit |
| --- | --- | --- |
| `memory-max` | `memory.max` | bytes the tree uses at most |
| `memory-swap-max` | `memory.swap.max` | bytes of swap the tree uses at most |
| `pids-max` | `pids.max` | processes and threads at once |
| `cpu-max` | `cpu.max` | microseconds of processor time per period |
| `cpu-weight` | `cpu.weight` | a share against siblings, from 1 to 10000 |

```toml
[cgroup]
parent = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/sandboxes.scope"
memory-max = 536870912
pids-max = 64
cpu-max = { quota = 50000, period = 100000 }
```

A configuration meant for hosts with and without a delegated cgroup marks its
limits not required, with
[`cgroup_required(false)`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.cgroup_required),
`required = false` in the table, or `fcage --no-cgroup-required`. Where a
parent is named, the limits apply as above. Where none is, the launch runs
without them rather than being refused. Nothing drops silently: the [resolved
inputs](embedding.md#recording-what-a-build-ran-under) report the limits as
`ResolvedCgroup::NotApplied`, and `fcage` says so on standard error. `[rlimit]`
limits then serve as the floor that holds everywhere:

```toml
[rlimit]
data = 4294967296
processes = 1024

[cgroup]
required = false
memory-max = 4294967296
pids-max = 1024
```

A named parent that cannot hold the sandbox's cgroup is refused whether or not
the limits are required.

## What this boundary does not cover

Three things a reader configuring the strongest posture on this page might
reasonably assume are covered, and are not:

- **I/O and disk consumption.** The limits above cover memory, processes and
  processor time. I/O throttling lives in the cgroup's `io` controller, which
  the library does not set, and disk consumption lives in filesystem quotas.
  Both are the host's to configure. A consumer that needs them sets them on the
  cgroup parent, or on the filesystem the root lives on.
- **The rootfs itself.** The command is root inside the sandbox and the rootfs
  is mounted read-write, so it can modify anything in the provisioned tree that
  the calling user could modify on the host. A Landlock grant narrows this; so
  does [`overlay_rootfs`](provisioning.md#keeping-a-provisioned-root-pristine),
  which leaves the base untouched and sends every write to a disposable upper.
  The root is mounted `nosuid`, so what the command writes into the tree cannot
  be executed back with elevated ids — but the tree's contents are still the
  command's to change.
- **A file's metadata, under Landlock.** Landlock governs a file's contents and
  a directory's entries. It does not govern `chmod`, `chown`, extended
  attributes, timestamps, `stat`, or `chdir`, which reach any path the command
  can name. A read-only grant over a writable bind of a home directory still
  lets the command make the files beneath it world-writable. Two rights arrive
  late: truncation is governed from Landlock ABI 3 (Linux 6.2), and device
  `ioctl` from ABI 5 (Linux 6.10). Below those a grant leaves them unrestricted.
  A tree whose metadata the command must not change is bound read-only, or not
  at all.

None of the three is silent: the layer states what it does not enforce, here
and beside each control.

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

A sandbox with a network namespace of its own installs the network filter first.
It does so right after the command enters its nested user namespace, before
anything on this page.

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
roster, which the deny flags extend, and `--seccomp-allow` and `--seccomp-deny`
filter syscalls by name.
`--seccomp-allow-rule` and `--seccomp-deny-rule` add argument conditions in the
terms of a profile's `arg` entries, `len`, `op`, `value` and `mask`, except that
the flag names the argument `arg=` where the profile's entry names it `index`:
`--seccomp-allow-rule 'ioctl arg=1 len=dword op=eq value=0x5413'`. `--seccomp-errno clone3=ENOSYS`
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
[`SeccompRules::curated`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.curated
[`SeccompRules::syscall`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.syscall
[`SeccompArg`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompArg.html
[`SockFilter`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SockFilter.html
[`drop_all_capabilities`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.drop_all_capabilities
[`keep_capabilities`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.keep_capabilities
[`Capability`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Capability.html
[`Network::None`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`Network::Host`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.Network.html
[`pid_namespace(false)`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.pid_namespace
[`rlimit`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.rlimit
[`Resource`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/limits/enum.Resource.html
[`landlock_scope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.landlock_scope
[`LandlockScope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.LandlockScope.html
[`SeccompRules::errno_for`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.SeccompRules.html#method.errno_for
[`ConfigError::LandlockScopeUnenforceable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.ConfigError.html
[`landlock_resolve_unix`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.landlock_resolve_unix
[`FsAccess::RESOLVE_UNIX`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.FsAccess.html#associatedconstant.RESOLVE_UNIX
[`ConfigError::LandlockResolveUnixUnenforceable`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/enum.ConfigError.html#variant.LandlockResolveUnixUnenforceable
[`host::landlock_abi`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_abi.html
[`host::landlock_enforces_fs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_enforces_fs.html
[`host::landlock_enforces_net`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_enforces_net.html
[`host::landlock_enforces_scope`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.landlock_enforces_scope.html
[`host::seccomp_available`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.seccomp_available.html
