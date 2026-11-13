# Host requirements

ferroday-cage requires Linux 5.6 or later with unprivileged user namespaces
enabled. The sandbox is built entirely from unprivileged facilities — there
is no setuid helper and no daemon — so the kernel must permit an ordinary
user to create user namespaces. The 5.6 floor comes from `openat2`, which
the sandbox uses to confine mount-target resolution to the rootfs and the
tarball provisioner uses to confine extraction to its destination.

The default network posture also needs seccomp filtering. A sandbox with a
network namespace of its own installs a filter, which closes the routes out that
the namespace does not cover. [The network
filter](how-the-sandbox-is-built.md#the-network-filter) describes it.

A kernel built without `CONFIG_SECCOMP_FILTER` fails such a launch at
`SetupStep::InstallNetworkFilter`. So does a container runtime whose seccomp
profile refuses the `seccomp` syscall.
[`host::seccomp_available`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.seccomp_available.html)
reports whether this process can install a filter. It installs one in a
short-lived child, so it answers for both cases. A Debian or Alpine bootstrap
runs its packages' scripts in such sandboxes, and asks the same before it
downloads anything. `Network::Host` installs no filter and needs none.

Two opt-in capabilities have host requirements of their own. A [uid/gid range
map](identity-maps.md) requested by an unprivileged caller needs the shadow
suite's `newuidmap` and `newgidmap` helpers and a subordinate-id allocation,
and [`host::range_map_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.range_map_blocker.html)
reports what a host is missing. An [overlay-rooted cage](#overlay-rooted-cages)
needs a kernel that permits an unprivileged overlay mount and an upper layer on a
filesystem that records `user.*` extended attributes, and
[`host::overlay_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.overlay_blocker.html)
reports what a host is missing. Neither is used unless requested; a plain,
single-identity cage needs nothing beyond this page.

Most desktop and server distributions permit this by default, but several
common configurations disable it:

| Configuration | Effect |
| --- | --- |
| `kernel.unprivileged_userns_clone = 0` | Denies creation outright. An out-of-tree sysctl found on Debian-derived kernels. |
| `user.max_user_namespaces = 0` | Denies creation outright by setting the namespace limit to zero. |
| `user.max_user_namespaces = 1` | Admits the sandbox's own user namespace and refuses the nested one its command enters. Every launch holds two; see [The nested user namespace](how-the-sandbox-is-built.md#the-nested-user-namespace). |
| `kernel.apparmor_restrict_unprivileged_userns = 1` | Restricts creation to programs granted the capability by an AppArmor profile. The default on Ubuntu 23.10 and later. |
| Container seccomp profiles | Container runtimes commonly deny `unshare` with `EPERM` in their default seccomp profiles, so sandboxes nested inside such containers fail unless the profile permits it. |

## How a blocked host surfaces

A launch on a host that denies user namespaces fails with
`Error::UsernsUnavailable`. The library probes the configurations above and
names the one responsible, together with the remedy, rather than surfacing a
raw `EPERM`.

The probe is also available directly as `host::userns_blocker`, which returns
the first blocking configuration it identifies. Test suites use it to skip
sandbox tests explicitly on hosts that cannot run them. The probe is
best-effort: a clear result does not guarantee creation succeeds, since a
seccomp filter or LSM policy can deny it invisibly.

The namespace budget is the clearest case of that. A ceiling of `1` is
reportable, because it cannot admit the two namespaces a launch holds; a
ceiling of four with three namespaces already live cannot be, because only the
launch can know how many are in use. That one surfaces at launch as
`Error::NamespaceLimitReached`, which names the limits.

The kernel key quota is a second budget of the same kind. Every running sandbox
holds a session keyring of its own (see [The session
keyring](how-the-sandbox-is-built.md#the-session-keyring)), charged against the
calling user's `kernel.keys.maxkeys`, 200 by default. A launch that finds the
quota spent reports `Error::KeyQuotaExhausted`.

A host that cannot be unblocked is not entirely without options: with the
`hardening` feature, [the restriction fallback](restriction-fallback.md)
confines a command with Landlock and seccomp alone, which need no user
namespace.

## A fresh procfs

A sandbox with a PID namespace of its own, the default, mounts a procfs for
that namespace. The kernel lets a process inside a user namespace mount one
only where its mount namespace already holds a procfs that is fully visible.
That means a procfs mounted at its own root, with no mount on any of its entries
except the permanently empty directories the kernel keeps for mounting on, such
as `/proc/sys/fs/binfmt_misc`. A host's own `/proc` qualifies. The procfs of a
container started with its runtime's defaults does not: the runtime masks
entries such as `/proc/kcore` and `/proc/sys` by mounting over them. Inside such
a container every launch with a PID namespace of its own fails, whatever the
sandbox does.

The launch reports this as `Error::ProcfsRefused`, which names the mounts lying
on the procfs and the remedies, rather than a bare `EPERM`:

1. **Unmask the runtime's procfs.** Docker's `--security-opt
   systempaths=unconfined` does, and so does Kubernetes' `procMount: Unmasked`,
   which needs `hostUsers: false`.
2. **Share the caller's PID namespace**, with
   [`CageBuilder::pid_namespace(false)`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.pid_namespace)
   or `fcage --share-pid`. The managed profile then binds the existing `/proc`,
   masks included, and needs no fresh one. The command can then see the
   processes of the caller's PID namespace, and signal those that run as the
   same user. The `hardening` feature's `LandlockScope::Signal` refuses the
   signals, and any Landlock domain refuses `ptrace` of a process outside it.

A third arrangement is accepted and not recommended: binding the existing
`/proc` under a PID namespace of the sandbox's own. That procfs presents the
caller's PID namespace, so the command's view of itself is incoherent: its own
pid and the pids under `/proc` belong to different namespaces.

[`host::procfs_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.procfs_blocker.html)
answers the same question before a launch. It forks a short-lived child that
mounts a procfs in namespaces of its own, as a launch does. A mount table cannot
answer it alone, since the rule also weighs the existing procfs's read-only and
access-time flags. It then reads the mount table to name the mounts in the way.

## Where the rootfs lives

The rootfs must sit under a directory the calling user controls — not a
world-writable one such as a shared `/tmp`, and not one whose path passes
through a directory another local user can write to.

Inside the sandbox, containment is kernel-enforced: mount targets and
extraction both resolve with `RESOLVE_IN_ROOT`, so nothing the sandbox or an
archive contains can reach past the root. What those guarantees rest on is
the host path naming that root. The launch resolves it twice — once to mount it,
and again inside the new mount namespace to anchor the mount targets and the
pivot — because a descriptor opened before `unshare` cannot anchor a mount in
the namespace that follows. A local user able to replace a component of that
path between the two resolutions could point the second one elsewhere.

The same requirement applies to
[`provision::ensure`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/fn.ensure.html),
which places its lock file and staging directory beside the destination, and to
an [overlay-rooted cage](#overlay-rooted-cages)'s upper layer, whose sibling work
directory and preflight probe live beside it.

## Overlay-rooted cages

[`CageBuilder::overlay_rootfs`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.overlay_rootfs)
roots a cage on an overlay of a read-only lower and a writable upper, so the
sandbox runs against a base whose changes it can discard. The overlay is mounted
unprivileged, from inside the cage's user namespace, which two host properties
gate:

- **An unprivileged overlay mount.** Mounting `overlay` inside a user namespace
  requires Linux 5.11 or later. Below it the mount is refused.
- **`user.*` extended attributes on the upper's filesystem.** An unprivileged
  overlay records its metadata — whiteouts and opaque markers — in `user.*`
  xattrs, so the filesystem holding the upper layer must support them. An on-disk
  filesystem such as ext4, xfs, or btrfs does throughout; tmpfs gained support
  only in Linux 6.6, so an upper on a tmpfs needs that kernel while an on-disk
  upper does not.

The build refuses an overlay-rooted cage a host cannot establish, naming the
missing property rather than failing at launch. The probe is also available
directly as
[`host::overlay_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.overlay_blocker.html),
which tests a given filesystem and returns the first blocker it identifies; test
suites use it to skip overlay tests on hosts that cannot run them. It is
best-effort — it forks a short-lived child that attempts a throwaway mount — and
a clear result does not guarantee a later mount succeeds.

The base rootfs (the lower) should not itself sit on an overlay: a nested overlay
is restricted on older kernels. This matters only when the base is cached on a
filesystem that is already an overlay, as inside some container runtimes; a base
on an ordinary filesystem is unaffected.

### A transient on a parallel first touch

A heavily parallel build on an overlay root can fail with `ENOENT` on a file the
upper layer holds, and pass on immediate retry. The file is momentarily
unfindable rather than absent. The fault does not reproduce on demand, and its
cause is unconfirmed.

Its observed shape is narrow. Each failure is an upper-side path in a directory
both layers carry, one overlayfs assembles from both. Lower-side paths, opened
far more often by the same processes, do not fail. Each failure comes from a
parallel build in a fresh mount: one cage per command over a shared upper, so
the build's lookups are the first its superblock sees.

The `overlay-race` example in the repository probes for it. It mounts, releases
a storm of parallel first-touch lookups, unmounts, and repeats. Each storm probes
an upper-only file, a file in an upper-only subdirectory, and a lower-only file,
so a fault that misses all three evenly reads as a different one. `--warm` adds
one serial lookup in the same mount before the storm, which tests the fresh
mount as the cause.

Where a pipeline runs several commands over one overlay upper, running them in
one cage rather than one cage each avoids the condition at no cost.

## Architecture

ferroday-cage builds for x86_64, x86, aarch64, 32-bit arm, and riscv64 Linux.
The launch issues its own system calls after the fork without libc, and those
are the architectures it states them for. The build fails on any other. The
binaries inside the rootfs must be ones the host CPU executes — its own
architecture, or one it runs natively, such as i386 on an amd64 host — or a
matching `qemu-user` binfmt handler must be registered for them.

An i386 userland runs on an amd64 host as it would on its own, with two
exceptions:

- **Sockets under the network filter.** Under a network posture with a
  namespace of its own, a 32-bit program built against glibc creates no socket.
  That C library creates every socket through `socketcall`, which [the network
  filter](how-the-sandbox-is-built.md#the-network-filter) refuses with
  `EAFNOSUPPORT`, the answer for an address family the kernel does not offer. A
  program that opens a socket only for an optional facility carries on without
  it. A 32-bit Debian bootstrap creates its system accounts for that reason.
- **A seccomp policy of the hardening layer.** A `Rules` policy is compiled for
  the host's 64-bit syscall ABI and kills a process that makes a syscall under
  any other audit architecture. A 32-bit program makes every syscall through
  the 32-bit compat layer, so under any such policy `SIGSYS` kills it at its
  first one. A 32-bit userland runs without a policy, or under a precompiled
  `SeccompPolicy::Program` that handles the 32-bit architecture itself.

A userland emulated through `qemu-user` meets neither: the emulator is a host
binary, and it makes the host's own syscalls on the guest's behalf.

A full Debian bootstrap for an architecture the host does not run natively runs
that architecture's dpkg and maintainer scripts, so the `qemu-user` handler must
be registered with the fix-binary (`F`) flag — the form that preloads the
interpreter so nothing is copied into the rootfs. The bootstrap checks whether
the host runs the target natively, requires a suitable handler only when it does
not, and reports an actionable error when one is missing; extract-only mode lays
out the files without running any foreign binary and needs no handler.
