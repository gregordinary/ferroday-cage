# Quick start

A sandbox needs a root filesystem. Any directory laid out like a Linux root
works. The Alpine minirootfs is a convenient, small one:

```sh
mkdir alpine-root
curl -fsSL https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-minirootfs-3.24.1-x86_64.tar.gz \
    | tar -xz -C alpine-root
```

## Using the library

Add the dependency. The crate has no default features, so the bare line gives
the sandbox alone — which is all this chapter needs:

```sh
cargo add ferroday-cage
```

Later chapters cover capabilities that are opt-in: provisioning a root
filesystem, hardening, profiles, the network stack. Each names its feature, and
[Cargo features](features.md) lists them in one place. A typical consumer wants
a few:

```sh
cargo add ferroday-cage --features serde,tarball,hardening
```

Configure a sandbox with the builder, validate it with `build`, and launch it
with `run`:

```rust,no_run
use ferroday_cage::Cage;

fn main() -> ferroday_cage::Result<()> {
    let status = Cage::builder()
        .rootfs("alpine-root")
        .command("/bin/sh")
        .args(["-c", "echo hello from the cage"])
        .build()?
        .run()?;
    assert!(status.success());
    Ok(())
}
```

`build` performs all validation: a missing root filesystem or a malformed
command is a typed configuration error before anything is launched. `run` blocks
until the command terminates and returns its `ExitStatus` whether or not the
exit code was zero. A failing command is data, not an error. `Err` is reserved
for the library itself failing, and a failure during sandbox setup names the
exact step and OS error.

The command runs with inherited standard streams and `/` as its working
directory. Its environment is clean: `PATH` and `HOME`, plus whatever the
builder's `env` calls add. The command path is interpreted inside the sandbox
and must be absolute. It is not searched for on `PATH` unless `path_lookup` is
enabled. That resolves a command with no slash against the sandbox's `PATH`,
like a shell.

By default the sandbox mounts a fresh `/proc`, a minimal `/dev`, and a tmpfs
`/tmp` over the root filesystem. It runs the command as PID 2 in its own PID
namespace under a minimal init, and isolates the network to a loopback
interface. [How the sandbox is built](how-the-sandbox-is-built.md) has the full
profile and the builder methods that adjust it:

```rust,no_run
use ferroday_cage::{Cage, Network};

fn main() -> ferroday_cage::Result<()> {
    let status = Cage::builder()
        .rootfs("alpine-root")
        .bind("/home/user/project", "/build")
        .bind_ro("/home/user/cache", "/cache")
        .network(Network::Host)
        .hostname("builder")
        .current_dir("/build")
        .env("CACHE_DIR", "/cache")
        .command("/bin/sh")
        .args(["-c", "echo building in $PWD on $(hostname)"])
        .build()?
        .run()?;
    assert!(status.success());
    Ok(())
}
```

`bind_ro` is a boundary and not merely a view: the command cannot remount it
read-write, cannot unmount it, and a write to it answers `EROFS`. Nothing else
has to be configured for that to hold — see [A read-only bind is a
boundary](how-the-sandbox-is-built.md#a-read-only-bind-is-a-boundary) for the
mechanism.

A read-write bind hands the command everything beneath it, and a project holds
files the host runs later. A repository's `.git` directory is the sharpest case.
Git on the host runs the hooks a repository holds, and most `git` commands start
the program its `core.fsmonitor` setting names. A command that can write `.git`
can therefore run code on the host the next time anyone uses the repository.
Binding `.git` read-only over the project keeps that directory out of reach:

```rust,no_run
use ferroday_cage::Cage;

# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .rootfs("alpine-root")
    .bind("/home/user/project", "/build")
    .bind_ro("/home/user/project/.git", "/build/.git")
    .current_dir("/build")
    .command("/usr/bin/make")
    .build()?;
# let _ = cage;
# Ok(())
# }
```

Mounts apply in the order they are configured, so the read-only bind covers that
one path of the writable one. It does not make the rest of the tree safe to run.
A build can still edit a `Makefile` or a script, or create a subdirectory
holding a repository of its own, with hooks. Review what a run changed before
running anything from the tree on the host. `fcage` spells the same pair as
`--bind` followed by `--ro-bind`.

A sandbox can also run the host's own programs over the host's own files,
read-only, with the working tree the one place it writes. The host's `/home`,
`/root`, `/run`, `/var/run` and `/var/tmp` are hidden, so the project is bound
back in.
[`read_only`](https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.read_only)
protects a path inside it where it stands:

```rust,no_run
use ferroday_cage::Cage;

# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .host_rootfs()
    .bind("/home/user/project", "/home/user/project")
    .read_only("/home/user/project/.git")
    .hide("/home/user/project/.env")
    .current_dir("/home/user/project")
    .command("/usr/bin/make")
    .build()?;
# let _ = cage;
# Ok(())
# }
```

[The host's own root](how-the-sandbox-is-built.md#the-hosts-own-root) sets out
what stays in view. `fcage` spells it `--host-rootfs`, with `--hide` and
`--read-only`.

## Using the command line

The `fcage` binary offers the same sandbox at a shell prompt:

```sh
cargo install ferroday-cage-cli
```


```sh
$ fcage --rootfs alpine-root -- /bin/sh -c 'echo hello && /bin/busybox uname -m'
hello
x86_64

$ fcage --rootfs alpine-root /bin/busybox id
uid=0(root) gid=0(root) groups=65534(nobody),65534(nobody),0(root)

$ fcage --rootfs alpine-root --ro-bind ~/project /project --chdir /project \
    --share-net -- /bin/sh -c 'ls && cat /etc/resolv.conf'
```

The command is root inside. One `65534(nobody)` stands for each supplementary
group the calling user holds, so the count above depends on who ran it.

Under the default [single-identity map](identity-maps.md), the only ids that
exist are root inside and the calling user outside. Every other id the process
carries presents as the overflow id. The list is inherited rather than cleared.
`setgroups` is denied under that map, so the sandbox bounds what the groups name
rather than dropping them.

`fcage` exits with the command's own exit code. A signal that terminates the
command gives 128 plus the signal number, and an expired `--timeout` gives 124.
The first two come from `ExitStatus::shell_code`, so a consumer that re-exports
a sandboxed command's outcome reports the same codes without restating the
convention. `Error::shell_code` is its counterpart for a launch that failed. It
gives 127 for a command that does not exist, 126 for one that cannot be
executed, and 125 otherwise.

A sandbox can also be described in a TOML file and loaded with `--profile`,
which [Profiles](profiles.md) covers. `fcage --help` prints the full
interface.

## Going further

- Compose the root from the host's own files, with no root directory at all:
  [An empty root](how-the-sandbox-is-built.md#an-empty-root).
- Run over the host's own tree, read-only, with credentials and sockets hidden:
  [The host's own root](how-the-sandbox-is-built.md#the-hosts-own-root).
- Stream the command's output to your own code: [Streaming
  output](streaming.md).
- Wait with deadlines, stop gracefully, kill outright, and tie the
  sandbox's lifetime to your process: [The process
  model](process-model.md).
- Launch sandboxes from a thread pool or an async runtime, and cancel them
  from one: [Embedding in a runtime](embedding.md).
- Pick the cargo features your consumer needs: [Cargo features](features.md).
