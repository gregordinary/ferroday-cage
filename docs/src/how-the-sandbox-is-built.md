# How the sandbox is built

A launch is a fork followed by a fixed setup sequence, ending in `execve`.
Everything the setup needs is prepared and validated in the caller
beforehand — the command line marshaled, the rootfs path resolved and
checked — so the post-fork windows perform no allocation and no fallible
preparation of their own. All syscalls are issued directly against the
kernel through rustix, and the default build drives the whole sequence
itself; the one opt-in exception — the `subid` feature's range-map
delegation to the shadow suite's helpers — runs in the caller, outside the
sandbox.

The setup runs across a short chain of forked stages — the launch stage,
the sandbox init, and the command process — because a process that unshares
a PID namespace does not enter it: only its next child process becomes the
namespace's PID 1. [The process model](process-model.md) describes the
resulting process tree and its lifetimes; this chapter follows the setup
sequence itself.

## The setup sequence

1. **Reset the signal state.** Every signal disposition returns to its
   default and the signal mask empties, immediately after the first fork.
   The caller's ignored dispositions would otherwise survive into the
   command, and an inherited signal handler must never run inside these
   tightly constrained processes.
2. **Unshare.** One `unshare` call creates user, mount, PID, UTS, IPC, and
   cgroup namespaces, plus a network namespace unless the host network is
   shared. The user namespace is owned by the process with full
   capabilities over it, and every other namespace is owned by that user
   namespace — the ownership is what lets an unprivileged process perform
   the mount, hostname, and network steps below.
3. **Sweep the descriptors.** The launch closes every descriptor it
   inherited except the launch channels and the standard streams. The
   sandbox processes are forked from the swept table, so the command starts
   with only its streams and the supervisor pins no caller resource for the
   sandbox's lifetime.
4. **Identity map.** The launch stage establishes the map of its freshly
   created user namespace, per the configured
   [identity map](identity-maps.md). The default single-identity map is
   written in process: `deny` to `/proc/self/setgroups`, then a one-line
   gid map, then a one-line uid map, assigning the calling user's effective
   ids to root — denying `setgroups` first is what the kernel requires
   before an unprivileged process may write its own gid map. A range map
   cannot be self-written, so the stage instead signals ready on an
   internal gate and blocks while the caller's delegate writes the map
   against its pid, leaving `setgroups` at `allow`; the gate closes before
   anything else is forked. Either way the map is complete before the next
   step, so every process the caller can observe lives in a fully mapped
   namespace.
5. **Publish the supervisor.** The launch stage forks the sandbox init,
   opens a pidfd for it, and passes it back to the caller — the anchor for
   `kill`, immune to pid reuse. The remaining steps run in the init, inside
   all the new namespaces.
6. **Hostname.** When a hostname is configured, `sethostname` sets it in the
   new UTS namespace; otherwise the sandbox keeps the host's hostname, and
   either way a change inside the sandbox never reaches the host.
7. **Loopback.** In an isolated network namespace the only interface is
   loopback, which starts down; the init brings it up with the
   interface-flags ioctls on a throwaway datagram socket. To give the
   isolated namespace outbound connectivity, a caller attaches a userspace
   network stack at the seam described in
   [Userspace networking](userspace-networking.md).
8. **Privatize propagation.** Mount propagation for the inherited tree is
   made recursively private, so nothing done here propagates back to the
   host, and because `pivot_root` refuses to operate under shared mounts.
9. **Bind the rootfs.** The rootfs is bind-mounted onto itself, recursively.
   `pivot_root` requires the new root to be a mount point; the self-bind
   makes it one without imposing any staging directory. The canonical path
   validated at build time is resolved here, inside the new namespace — the
   kernel requires bind sources and targets to be mounts attached in the
   caller's own mount namespace, so a descriptor opened before the unshare
   cannot anchor this step.
10. **The mount profile.** The init executes the frozen mount operations in
    order: the fresh `/proc`, the minimal `/dev`, the `/tmp` tmpfs, the
    caller's own mounts, and the `resolv.conf` bind, as configured. Bind
    sources are host paths and resolve normally — the host
    tree is still mounted. Targets resolve against the new root with
    `openat2` and `RESOLVE_IN_ROOT`, so a symlink inside the rootfs — even
    an absolute one — resolves within the rootfs and can never address the
    host; the mount syscalls then reach the resolved target through its
    `/proc/self/fd` path. Missing mount targets are created; a directory
    stays afterwards, a file does not (see [What a launch leaves in the
    root](#what-a-launch-leaves-in-the-root)). A read-only bind is made read-only
    after binding with `mount_setattr` and `AT_RECURSIVE`, so the bind and
    every mount beneath it become read-only in one step; on a kernel before
    5.12, which lacks `mount_setattr`, only the top mount is made read-only
    (carrying along the flags the user namespace holds locked) and any
    submounts of the source keep their own flags. The restriction becomes a
    boundary at step 12, where the command enters a nested user namespace and
    the kernel locks it — see [A read-only bind is a
    boundary](#a-read-only-bind-is-a-boundary).
11. **Pivot.** The init enters the new mount and calls
    `pivot_root(".", ".")`, stacking the old root on the same mount point,
    then lazily detaches the old root and changes directory to the new `/`.
    When the step completes, the host filesystem is no longer reachable
    from the sandbox's view.
12. **Fork and exec.** After changing to the configured working directory,
    the init forks the command process — PID 2 — which wires its standard
    streams per the configuration, applies the configured [resource
    limits](hardening.md#resource-limits), enters a nested user namespace
    (below), applies any hardening, and calls `execve`, resolved inside the new
    root. The hardening layer applies in two halves around the switch to the
    configured [run-as
    identity](identity-maps.md#running-as-a-non-root-identity), when one is
    set: securebits, no-new-privileges, and Landlock before it, the
    capability drop and the seccomp filter after. The command receives the
    composed environment: the deterministic base (`PATH` and `HOME`) plus
    the caller's variables, nothing from the host. The init remains as the
    namespace's supervisor.

## The nested user namespace

The command does not execute in the user namespace the sandbox was built in.
Between the resource limits and the hardening layer it enters a second one, of
its own, with a fresh mount namespace alongside it.

The reason is that the kernel locks a mount's flags exactly when it copies a
mount tree *into* a new user namespace. A sandbox built the other way round —
create the namespace, then build the mounts inside it — carries no locks at all,
and root of the namespace that owns a mount may lift any restriction on it. The
nested entry makes the kernel perform the copy, and every mount the command
inherits comes across locked.

The nested namespace's map is the sandbox's own map reflected onto its inside
ids: for each extent `inside outside count` of the sandbox's map, a line
`inside inside count`. The command therefore sees exactly the ids it saw
before, under the same names. It is established the same way the sandbox's own
is — written in process under the single-identity map, and written by a
delegate under a [range map](identity-maps.md), the delegate here being the
sandbox init rather than the caller, since only a process inside the sandbox's
namespace is root of it. It is reached through a procfs, by path, which is why a
sandbox that mounts none is refused at build time — except where the delegate is
outside the sandbox and reads the host's own, which [Identity
maps](identity-maps.md) sets out.

The entry sits where it does because the kernel re-derives the whole credential
for a new user namespace: securebits return to their defaults, the capability
bounding set is refilled, and the inheritable and ambient sets are cleared. Any
hardening applied before it would be silently undone. The [launch
gate](userspace-networking.md) stays above it, so a caller attaches its network
stack against the namespaces it already knows, and the resource limits stay
above it because they are unaffected either way.

### What the command gives up

Past the entry the command is root of a namespace that owns nothing but its own
mount namespace. It therefore holds no capability over the namespaces the
sandbox created, which the sandbox's user namespace still owns:

- It cannot clear a locked flag on any mount it inherited, cannot change atime
  behaviour on one — the kernel locks atime on every copied mount, whatever it
  was — and cannot unmount one to reveal what is beneath. It can still mount
  whatever it likes in its own namespace; those mounts are its own, unlocked,
  and private to it.
- It cannot bind a TCP port below 1024 (`CAP_NET_BIND_SERVICE`), open a raw
  socket, or send ICMP — so `ping` does not work inside a sandbox. Ordinary
  sockets are unaffected: connecting out, listening above 1024, and everything
  the [userspace network stack](userspace-networking.md) carries all behave as
  before.
- It cannot change the sandbox's hostname, and cannot reconfigure the network
  interfaces the setup brought up.

### The host requirement

Every launch now holds two user namespaces rather than one, and a namespace is
charged against `user.max_user_namespaces` at every level up to the initial
namespace. [`host::userns_blocker`](host-requirements.md) reports a ceiling of
`1` as a blocker for that reason. The check is necessary and not sufficient — a
host whose ceiling is four with three namespaces already live fails the same way
— so the launch itself reports the exhausted budget as
`Error::NestedUsernsBudgetExhausted`, naming the sysctl.

## The mount profile

The default profile assembles three mounts over the rootfs, each of which
can be disabled:

- **`/proc`** is a fresh procfs instance, mounted from inside the new PID
  namespace, so it presents the sandbox's processes and nothing else.
  With `pid_namespace(false)` it is instead the host's procfs, bind-mounted
  with its submounts: without a new PID namespace a fresh instance would
  present the same processes anyway, and the kernel refuses to mount one in
  a user namespace when the host `/proc` carries overmounts, as common host
  configurations do. Either way, `/proc/net` and `/proc/sys/net` resolve
  through the reading process's own network namespace, so they reflect the
  sandbox's network, not the host's.
- **`/dev`** is a tmpfs holding the host's `null`, `zero`, `full`, `random`,
  `urandom`, and `tty` devices — bind-mounted read-write, since `mknod` for
  character devices is denied in an unprivileged user namespace — together
  with the `stdin`, `stdout`, `stderr`, `fd`, and `ptmx` symlinks, a fresh
  `devpts` instance on `/dev/pts`, and a tmpfs on `/dev/shm`. The `/dev`
  tmpfs is `nosuid` but, by design, not `nodev`: it has to carry those device
  nodes, which `nodev` would render inoperable. This is deliberate and safe
  in the sandbox's user namespace — the bound nodes are the host's own, not
  fresh nodes the sandbox could use to reach an arbitrary device, and access
  to them is governed by the namespace. `tty` is the exception to "the host's
  own": it is the character device `5:0`, whose open returns the *opening
  process's* controlling terminal rather than the inode the bind carries, so
  what the sandbox reaches through it follows from the sandbox's session. See
  [The dispositions and the caller's
  terminal](streaming.md#the-dispositions-and-the-callers-terminal), and
  [A terminal of the sandbox's own](terminal.md) for the posture where it
  resolves to a terminal the caller does not share.
- **`/tmp`** is a fresh tmpfs.

The caller's own mounts apply after the managed profile, in configuration
order, with one exception: the `resolv.conf` bind is applied last of all.
Binds and raw mounts (see [Profiles](profiles.md) for the escape hatch) share
one sequence rather than being applied kind by kind, so a mount that
covers a path an earlier one established can be ordered deliberately: a raw
tmpfs followed by the binds that populate it yields a directory the sandbox
owns outright, which is how the managed `/dev` is itself assembled.

Last, the host's `resolv.conf` — resolved to its real file — is bound
read-only onto `/etc/resolv.conf` when the host network is shared. Unless the
caller mounted that target themselves: a mount of their own there replaces this
one rather than sitting under it, so applying it last does not take back the
rule that among the caller's mounts the order is theirs. Every kind of mount
counts, a raw mount as much as a bind.

### A read-only bind is a boundary

A read-only bind establishes both what the sandbox *sees* and what the command
*can do*. The command cannot remount it read-write, and a write to it answers
`EROFS`.

The kernel locks a mount's flags when it copies a mount tree into a new user
namespace, and [the nested user namespace](#the-nested-user-namespace) the
command enters before it execs is that copy. The lock is unconditional: it needs
no hardening, no capability drop, and no non-root identity, and it holds against
a command that is root of its own namespace with `CAP_SYS_ADMIN` and an
unfiltered `mount` syscall.

The same lock covers every restriction the sandbox's mounts carry — `nosuid` on
the root, `nodev` and `noexec` where the profile sets them — and it holds for
unmounting too: the command cannot detach an inherited mount to reveal what is
beneath it. What the command remains free to do is mount things of its own; those
mounts are its own, unlocked, and private to its mount namespace.

### The root is `nosuid`

The root mount carries `nosuid`, so a set-user-ID or set-group-ID binary in the
rootfs confers nothing on the command that executes it, and a file capability
recorded on one is ignored. This matters because a provisioned rootfs applies
the tree's permission bits verbatim: a Debian or Alpine root ships set-user-ID
binaries owned by in-namespace uid 0, which a non-root [run-as
identity](identity-maps.md#running-as-a-non-root-identity) would otherwise be
able to execute its way back through. The flag is locked by the nested entry
like every other, so the command cannot clear it.

The scope is the root and whatever the root bind carried with it. A caller's own
`bind` and `bind_ro` mounts keep inheriting their source's flags: a caller who
binds a host tree in order to run what is in it is entitled to a different
answer than the rootfs gets.

## What a launch leaves in the root

A mount needs its target to exist, so the sandbox creates any that is
missing. What it creates divides in two.

A missing *directory* is a mount point, and it stays. It is created at the
mode of the directory it stands for — `1777` for `/tmp` and `/dev/shm`,
`0755` otherwise — so the tree is left holding the directory it would have
shipped, rather than one the mount's own mode happened to hide.

A missing *file* target is content the root never had — an empty
`/etc/resolv.conf`, an empty file where a binary is bound — present only for
its mount to cover. It is created at `0644` exactly, independent of the
launching process's umask, and does not survive the sandbox: the paths are
recorded at build time, and dropping the handle removes each one, whether the
sandbox ran to completion or the launch never proceeded. Only an empty regular
file is removed, so anything that gained content or changed type in the
meantime belongs to whoever put it there. The rule covers the managed
`resolv.conf` bind and the caller's own file binds alike.

A target the root already ships is never touched, whatever kind of entry it
is. A symbolic link is one such entry, and it is left as it is rather than
created through: the mount resolves it as the root intends. A root that ships
a link to a path it does not have — the shape `/etc/resolv.conf` takes on a
host running a resolver daemon — therefore has no target to bind onto, and the
launch reports a failed mount naming that bind rather than creating a file
somewhere the root did not ask for.

Two targets are outside the rule, because neither is a file in the root: one
created inside an earlier mount — under the `/tmp` tmpfs, or under a bind of
the caller's own — belongs to that mount rather than to the root, and for an
overlay root the created file lands in the upper, where the merged view's
writes go, and is removed from there.

## Failure reporting

Every stage shares a close-on-exec report pipe created before the first
fork. If any step fails, the failing stage writes a single 12-byte record —
the step, the `errno`, and the index of the item it concerned, all
little-endian — and exits; the write is atomic at that size, and the caller
surfaces it as a typed error naming the failed step and its subject: for a
mount step the mount it was assembling, for a resource limit the limit, and
for the exec step the command path. When `execve` succeeds, close-on-exec
closes the last write end: the caller reads end-of-file and knows the
command is running.

### Reading an `ENOENT` from the exec step

```console
sandbox setup failed while executing the command (/usr/bin/build): \
    No such file or directory (os error 2)
```

`execve` answers `ENOENT` in two distinct situations, and the kernel does
not distinguish them:

- **The command is not there.** The usual case, and the error names the path
  so a typo is visible in the message reporting it.
- **The command's ELF interpreter is not there.** A dynamically linked
  binary names its loader — `/lib/ld-musl-x86_64.so.1`, `/lib64/ld-linux-x86-64.so.2`
  — and the kernel reports a missing loader as `ENOENT` against the binary,
  not against the loader. So a command that plainly exists inside the rootfs
  can still fail this way: the rootfs is missing the loader, or the binary
  was built against a different libc than the rootfs provides, or a merged-usr
  symlink the loader path resolves through is absent.

The second reading is the one to reach for when the named path is present.
`ls -l` the path inside the sandbox to confirm it is there, then check the
interpreter the binary asks for — `readelf -l` on the host names it in the
`INTERP` segment — and confirm that path resolves inside the rootfs.

`spawn` blocks until the report pipe settles, so a returned handle always
means a running command, and a setup failure is always a typed error at the
point of launch. The command's exit status travels separately, over a
status pipe written by the supervisor, with full fidelity — an exit code
and a fatal signal are never conflated.

## The scope of the isolation

The sandbox presents the rootfs as `/` with the mount profile assembled
over it, and maps the calling user to root inside. The rootfs itself is
writable by the command wherever the calling user could write it, and mount
point directories created during setup persist there — see [What a launch
leaves in the root](#what-a-launch-leaves-in-the-root). The mount, PID, UTS, IPC,
cgroup, and — by default — network spaces are isolated.

The default profile is a rootless convenience for code you trust: a
controlled filesystem view, isolated namespaces, and a clean environment.
Hostile code calls for [the hardening layer](hardening.md); the default
profile alone is not a boundary against it.

### What the sandbox does not hide

Isolation is about what the command can *reach*, not about what it can learn.
The command reads its own mount table — `/proc/self/mountinfo`, and the
`/proc/mounts` symlink to it — and every line carries the host path the mount
came from:

```text
263 191 252:1 /home/alice/build/alpine-rootfs / rw,nosuid,noatime - ext4 ...
408 263 252:1 /tmp/build-inputs         /ro    ro,noatime         - ext4 ...
```

So a sandboxed command can read the calling user's name, the layout of the
build that started it, and the host path behind each bind. This is what every
bind-mount-based sandbox exposes — Docker and bubblewrap alike — and it follows
from binding host paths at all; closing it would take a mount over `mountinfo`
in a `/proc` of the sandbox's own, which is a larger mechanism than the
disclosure warrants.

It is called out because the rest of the crate leans the other way. A
[`Terminal`](terminal.md) refuses to read the host's window size, `base_env`
exists so that no host variable reaches the command unasked, and `TERM` is the
caller's to state. None of that extends to the mount table: a command that wants
to know where it is running can find out. Where that matters — a build whose
output must not embed a path, code whose behaviour should not vary with one —
bind the inputs at stable in-sandbox paths and treat the mount table as one more
thing the command may read.
