# Running inside a container

A sandbox can run inside a container, such as a build step in a CI job. A
harness deployed as a pod can confine the tools it runs the same way. A
container runtime's defaults refuse what a sandbox is built from, in four
places. This chapter says what each refuses and why, then gives the remedies
for Docker and for Kubernetes.

## The seccomp profile

A runtime's default seccomp profile allows creating namespaces and mounting only
to a container that holds `CAP_SYS_ADMIN`, which a default container does not.
Moby's default profile, the one Docker applies, refuses `pivot_root` and
`keyctl` to every container. A launch then fails at its first namespace, and
reports `Error::UsernsUnavailable`, since the kernel answered with `EPERM`.

These are the syscalls a launch makes that such a profile refuses, with what the
launch makes each one for:

```toml
{{#include ../../tools/seccomp-additions.toml}}
```

`tools/seccomp-profile.py` adds them to whatever default profile the runtime
uses, and leaves the rest of that profile as it is:

```sh
python3 tools/seccomp-profile.py default.json > fcage-seccomp.json
```

For Docker, `default.json` is moby's `default.json`, from the
[moby/profiles](https://github.com/moby/profiles) repository. Docker, Podman and
CRI-O read profiles in moby's format, which grants some syscalls only to a
container holding a capability. The containerd runtime reads the OCI runtime
specification's format, which has no such conditions, so give it a profile
written in that format. The generator reads and writes either, since both keep their rules in
one `syscalls` list.

A default profile answers `clone3` with `ENOSYS` rather than `EPERM`, which is
harmless. The library forks with `clone`, without namespace flags, and a C
library that creates a thread with `clone3` falls back to `clone` on `ENOSYS`.

## The AppArmor profile

Docker's `docker-default` profile denies `mount`, and so does containerd's
`cri-containerd.apparmor.d`, which is built from the same template. Under either
profile, the sandbox's first mount is refused. Run the container unconfined, or
under an AppArmor profile of your own that allows `mount`.

## The masked procfs

A runtime masks entries of the container's procfs, such as `/proc/kcore` and
`/proc/sys`, by mounting over them. The kernel then refuses the fresh procfs a
sandbox with a PID namespace of its own mounts. The launch reports
`Error::ProcfsRefused`, which names the mounts in the way and the two remedies:
unmasking the procfs, or sharing the container's PID namespace. [A fresh
procfs](host-requirements.md#a-fresh-procfs) states the kernel's rule, and
[`host::procfs_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.procfs_blocker.html)
answers the same question before a launch.

A launcher that runs both inside and outside containers can ask first, and share
the PID namespace only where the procfs leaves no choice. That is a weaker
sandbox, as [Sharing the PID namespace](#sharing-the-pid-namespace) says, so the
choice belongs to the launcher:

```rust,no_run
use ferroday_cage::{Cage, host};

# fn main() -> Result<(), ferroday_cage::Error> {
let masked = host::procfs_blocker().is_some();
let status = Cage::builder()
    .rootfs("/srv/rootfs")
    .pid_namespace(!masked)
    .command("/bin/true")
    .build()?
    .run()?;
assert!(status.success());
# Ok(())
# }
```

## The host's sysctls

A container cannot change a host sysctl, so two of them are the node's to set.
`user.max_user_namespaces` has to admit two user namespaces for every running
sandbox, as [Host requirements](host-requirements.md) says. On Ubuntu 23.10 and
later, `kernel.apparmor_restrict_unprivileged_userns` refuses user namespaces to
a process no AppArmor profile grants them to. That includes a container run
unconfined. Set it to `0` on the node, or run the container under a profile
that grants `userns`.

## Docker

The generated seccomp profile, no AppArmor confinement, and an unmasked procfs:

```sh
docker run \
    --security-opt seccomp=fcage-seccomp.json \
    --security-opt apparmor=unconfined \
    --security-opt systempaths=unconfined \
    IMAGE fcage --rootfs /srv/rootfs -- /bin/true
```

`systempaths=unconfined` unmasks the container's whole procfs and lifts the
read-only binds the runtime puts on `/proc/sys` and `/sys/firmware`. The
container's own processes can then read and write what those masks covered, as
far as the container's capabilities allow. Where that is too much, leave the
procfs masked and share the PID namespace instead, with `fcage --share-pid` or
`CageBuilder::pid_namespace(false)`.

## Kubernetes

A `Localhost` seccomp profile is a file on every node, under the kubelet's
seccomp directory, `/var/lib/kubelet/seccomp` by default. `procMount: Unmasked`
is accepted only for a pod in a user namespace of its own, with `hostUsers:
false`. That needs a cluster that supports user namespaces:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: harness
spec:
  hostUsers: false
  containers:
    - name: harness
      image: IMAGE
      securityContext:
        procMount: Unmasked
        seccompProfile:
          type: Localhost
          localhostProfile: fcage-seccomp.json
        appArmorProfile:
          type: Unconfined
```

On a cluster without user namespaces, leave out `hostUsers` and `procMount`, and
share the PID namespace in the sandbox instead.

## Sharing the PID namespace

With `pid_namespace(false)`, the managed profile binds the container's `/proc`,
masks included, and the sandbox needs no fresh procfs. The command then runs in
the container's PID namespace. It can see the container's processes, the
harness that launched it among them. It can signal those that run as the same
user outside the sandbox.

Two Landlock controls close that. A Landlock domain refuses `ptrace` of any
process outside it, so a sandbox with any Landlock rule cannot trace the
harness. `LandlockScope::Signal`, or `fcage --landlock-scope signal`, refuses
signals to processes outside the domain. Both need the `hardening` feature. See
[Hardening](hardening.md).

## What the CI job checks

The repository's CI runs `fcage` inside Docker, from a stock image, and asserts
what this chapter says:

- Under the generated profile and no AppArmor confinement, a default launch fails
  with `Error::ProcfsRefused`, naming the remedies.
- Sharing the PID namespace launches, as root and as another user.
- An unmasked procfs launches.
- Docker's own seccomp profile refuses the sandbox's namespaces.
- Docker's own AppArmor profile refuses the sandbox's mounts.
