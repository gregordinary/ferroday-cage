# How the sandbox is built

A launch is a fork followed by a fixed setup sequence, ending in `execve`.
Everything the setup needs is prepared and validated in the caller
beforehand — the command line marshaled, the rootfs path resolved and
checked — so the post-fork windows perform no allocation and no fallible
preparation of their own. The stages issue their syscalls directly against the
kernel, through rustix and the `syscalls` crate. The one call that passes
through the C library is the `close` the standard library makes for a dropped
descriptor, a single async-signal-safe syscall. The default build drives the
whole sequence itself; the one opt-in exception — the `subid` feature's
range-map delegation to the shadow suite's helpers — runs in the caller,
outside the sandbox.

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
4. **Replace the session keyring.** The launch joins a fresh, anonymous session
   keyring in place of the one it inherited from the caller. A keyring is a
   credential rather than a descriptor, so the sweep does not reach it. No
   namespace partitions it either. See [The session
   keyring](#the-session-keyring).
5. **Identity map.** The launch stage establishes the map of its freshly
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
6. **Publish the supervisor.** The launch stage forks the sandbox init,
   opens a pidfd for it, and passes it back to the caller — the anchor for
   `kill`, immune to pid reuse. The remaining steps run in the init, inside
   all the new namespaces.
7. **Hostname.** When a hostname is configured, `sethostname` sets it in the
   new UTS namespace; otherwise the sandbox keeps the host's hostname, and
   either way a change inside the sandbox never reaches the host.
8. **Loopback.** In an isolated network namespace the only interface is
   loopback, which starts down; the init brings it up with the
   interface-flags ioctls on a throwaway datagram socket. To give the
   isolated namespace outbound connectivity, a caller attaches a userspace
   network stack at the seam described in
   [Userspace networking](userspace-networking.md).
9. **Privatize propagation.** Mount propagation for the inherited tree is
   made recursively private, so nothing done here propagates back to the
   host, and because `pivot_root` refuses to operate under shared mounts.
10. **Mount the root.** `pivot_root` requires the new root to be a mount
    point. A plain root filesystem is bind-mounted onto itself, recursively,
    which makes it one without a staging directory. An overlay root is mounted
    over its base. The canonical path validated at build time is resolved here,
    inside the new namespace. The kernel requires bind sources and targets to be
    attached in the caller's own mount namespace, so a descriptor opened before
    the unshare cannot anchor this step. An [empty root](#an-empty-root) has no
    path: it is a tmpfs created for the launch.
11. **The mount profile.** The init executes the frozen mount operations in
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
    boundary at step 13, where the command enters a nested user namespace and
    the kernel locks it — see [A read-only bind is a
    boundary](#a-read-only-bind-is-a-boundary). An empty root is made read-only
    once the profile is in place.
12. **Pivot.** The init enters the new mount and calls
    `pivot_root(".", ".")`, stacking the old root on the same mount point,
    then lazily detaches the old root and changes directory to the new `/`.
    When the step completes, the host filesystem is no longer reachable
    from the sandbox's view.
13. **Fork and exec.** After changing to the configured working directory,
    the init forks the command process — PID 2. The command wires its standard
    streams per the configuration, applies the configured [resource
    limits](hardening.md#resource-limits), and enters a nested user namespace
    (below). It then installs the [network filter](#the-network-filter) where
    the sandbox has its own network namespace, applies any hardening, and calls
    `execve`, resolved inside the new root. The hardening layer applies in two halves around the switch to the
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

Every launch holds two user namespaces and two mount namespaces, and a namespace
is charged against its `user.max_*_namespaces` count at every level up to the
initial namespace. [`host::userns_blocker`](host-requirements.md) reports a
`user.max_user_namespaces` of `1` as a blocker for that reason. The check is
necessary and not sufficient. A host whose ceiling is four with three namespaces
already live fails the same way. The launch itself therefore reports a refused
namespace as `Error::NamespaceLimitReached`, naming the limits.

## The network filter

Under `Network::Isolated` and `Network::None`, the sandbox has a network
namespace of its own. The namespace governs every address family that routes
through it, and three routes out do not pass through a network namespace at all.
The command closes them with a seccomp filter, installed right after it enters
its nested user namespace:

| Route | Why the namespace misses it | Answer |
| --- | --- | --- |
| `socket` with `AF_VSOCK` | vsock reaches the hypervisor's host from a virtual machine guest, and the host's own services where the host runs vsock loopback, whatever the namespace | `EAFNOSUPPORT` |
| `io_uring_setup` | A ring creates and connects sockets itself, out of any syscall filter's sight | `ENOSYS` |
| `socketcall` creating a socket, on x86 | The call passes the address family by pointer, which a filter cannot read, and 64-bit code reaches it through `int 0x80` | `EAFNOSUPPORT` |

Each answer is the one a kernel without the facility gives. A program that
probes for vsock or io_uring therefore reads it as absent. The filter compares
only the low 32 bits of a socket's family, because the kernel reads it as an
`int`. A family with high bits set is still `AF_VSOCK`, and is refused. The
filter checks every entry point the host's kernel presents: the 64-bit ABI, x32,
and the 32-bit compat layer. A syscall under any other architecture kills the
process, and no kernel the build runs on makes one.

The `socketcall` refusal has a cost. A 32-bit x86 program built against glibc
creates every socket through `socketcall`, so in such a sandbox it creates none,
a Unix-domain socket included. A program built against musl tries the direct
`socket` call first, and a 64-bit program always makes it, so neither is
affected. A 32-bit glibc userland that needs sockets runs under `Network::Host`,
which carries no filter.

The refusal answers `EAFNOSUPPORT`, as `socket` does for a family the kernel
does not offer, so a program that opens a socket only for an optional facility
carries on without it. The shadow suite's account tools open the kernel's audit
socket that way. A 32-bit Debian bootstrap therefore still creates the system
accounts its packages' scripts ask for.

The launch sets no-new-privileges only where the hardening layer asks for it, so
the filter is installed without it. Creating the nested user namespace grants
the capability the kernel requires in its place. A [seccomp
policy](hardening.md#seccomp-syscall-filters) is installed after the filter.
Where both refuse a syscall with an errno, the command sees the policy's. A host
that cannot install the filter fails the launch at
`SetupStep::InstallNetworkFilter`. [Host requirements](host-requirements.md)
covers the hosts that cannot.

## The session keyring

A forked process inherits its parent's session keyring, and no namespace a
launch creates changes that. A process *possesses* every key reachable from its
session keyring, and possession is what the default key permissions grant reading
to. A command holding the caller's session keyring can therefore read every key
the caller's login session holds. That includes a Kerberos ticket cache, an
fscrypt or eCryptfs key, and any secret a desktop cached there.

The launch stage joins a fresh, anonymous session keyring before it forks
anything. Every process of the sandbox starts with that keyring, and none
possesses the caller's. The restriction fallback does the same.

Possession is what the fresh keyring takes away, and it is not the only way to a
key. A key's permissions can grant reading to its owner as well as to its
possessor, and the sandbox's processes are that owner. Such a key stays readable
from the sandbox by its serial number. The default permissions grant the owner
only *view*, so a key keeps that exposure only where its permissions were
widened.

The user keyring, the user session keyring, and the persistent keyring belong to
the user rather than to the session. A sandbox's user namespace gives its
processes keyrings of their own in their place. A
[restriction](restriction-fallback.md) has no user namespace, so its command can
link the caller's into its own keyring and read every key they hold. The curated
seccomp policy denies `keyctl`, which closes both reaches.

The kernel still lists in `/proc/keys` every key whose permissions let its owner
view it, and the sandbox's processes are that owner. A key's description
therefore stays visible, as the mount table does. See [What the sandbox does not
hide](#what-the-sandbox-does-not-hide).

The fresh keyring counts against the calling user's key quota for as long as
the sandbox runs. The quota is `kernel.keys.maxkeys` keys and
`kernel.keys.maxbytes` bytes, 200 and 20000 by default. Every other key the user
holds counts against it too. A launch that finds the quota spent reports
`Error::KeyQuotaExhausted`, which names both sysctls.

A process that cannot call `keyctl` at all has no keyring to replace. Neither
has anything it forks, because a seccomp filter is inherited, and so is a kernel
built without key support. Container runtimes' default seccomp profiles deny the
call in exactly this way, and a launch under one proceeds. Before it proceeds,
the launch confirms that reading the inherited keyring is refused the same way.
A policy that refuses only the join therefore fails the launch, rather than
leaving the caller's keyring in place.

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
Binds, raw mounts (see [Profiles](profiles.md) for the escape hatch), and
symbolic links share one sequence rather than being applied kind by kind. A
mount that covers a path an earlier one established can then be ordered
deliberately. A raw tmpfs followed by the binds that populate it yields a
directory the sandbox owns outright. The managed `/dev` is assembled that way.

A link is made where the sequence reaches it, in whatever holds its path then.
On a plain root filesystem it stays on the host after the sandbox exits. A path
already holding a link with the same target is left as it is, so the next
launch over that root succeeds. Anything else at the path fails the launch.

Last, the host's `resolv.conf` — resolved to its real file — is bound
read-only onto `/etc/resolv.conf` when the host network is shared. Unless the
caller mounted that target themselves: a mount of their own there replaces this
one rather than sitting under it, so applying it last does not take back the
rule that among the caller's mounts the order is theirs. Every kind of mount
counts, a raw mount as much as a bind, and so does a link of the caller's at
the target. A bind or a link of the caller's at a directory above the target,
such as `/etc`, counts too. That directory is the caller's own, or where the
link sends it, and the target would otherwise be created there. A tmpfs there
is the sandbox's own, and the bind lands in it.

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

### An empty root

[`empty_rootfs`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.empty_rootfs)
roots the sandbox on a tmpfs of its own rather than a host directory. It suits a
sandbox composed entirely from binds: the host's `/usr` read-only, a working
tree read-write, and the links a merged `/usr` layout expects. The launch writes
nothing on the host, and what it creates in the root goes with the sandbox.

The tmpfs is created detached and attached on top of the inherited root.
Mounted over a host directory instead, it would hide any bind source beneath
that directory. A lookup by absolute path does not cross a mount stacked on its
starting root, so every source still resolves on the host until the pivot.

Once the profile is in place, the root mount itself is made read-only, and only
it. The mounts the profile made keep their own flags. A writable bind and the
managed `/tmp` stay writable, and the command can write nowhere else. A place to
write elsewhere is a mount of its own: a bind, or a tmpfs added as a raw mount.

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
launching process's umask. The sandbox reports each file it creates, and the
handle removes it once the sandbox is gone. That holds whether the sandbox ran
to completion, failed at launch, or never proceeded. Only that same file, still
empty and still a regular file, is removed. Anything that took its name or
gained content belongs to whoever put it there. The rule covers the managed
`resolv.conf` bind and the caller's own file binds alike.

Removal waits for the sandbox, because unlinking a file a bind covers unmounts
the bind in every mount namespace. A handle dropped while the sandbox runs
therefore leaves the file in the root. With a PID namespace the sandbox is gone
when its init exits. Without one it is gone when the command exits, and a
descendant still running then loses the bind.

Two sandboxes on one root can bind onto one such target. The first creates it,
and the second finds it. Each holds a shared lock on the file, and the handle
removes a file only under an exclusive lock, so neither unmounts the other's
bind. The file then stays in the root, since the sandbox that found it did not
create it. Without a PID namespace the second sandbox holds its lock only until
its command executes, so the protection ends there.

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

For an overlay root, whether a target is already there is what the merged view
shows. A whiteout or an opaque directory in a higher layer hides what a lower
layer holds. A target created over a whiteout in the upper replaces it, and the
whiteout is restored once the target is removed.

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

`/proc/keys` is a disclosure of the same kind. It lists the description of every
key the calling user owns, wherever the key's permissions let its owner view it.
The command possesses none of those keys. It reads the contents only of one whose
permissions grant its owner reading. See [The session
keyring](#the-session-keyring).

The init is a third. It is a fork of the calling process that runs no program
of its own, so `/proc/1/cmdline` and `/proc/1/comm` show the caller's command
line and name. A secret an application takes as an argument is therefore
readable inside the sandbox. On a host whose `/proc` has no `hidepid`, every
local user reads it too. Pass a secret through a file or a descriptor instead.

It is called out because the rest of the crate leans the other way. A
[`Terminal`](terminal.md) refuses to read the host's window size, `base_env`
exists so that no host variable reaches the command unasked, and `TERM` is the
caller's to state. None of that extends to the mount table: a command that wants
to know where it is running can find out. Where that matters — a build whose
output must not embed a path, code whose behaviour should not vary with one —
bind the inputs at stable in-sandbox paths and treat the mount table as one more
thing the command may read.
