# Quick start

A sandbox needs a root filesystem. Any directory laid out like a Linux root
works; the Alpine minirootfs is a convenient, small one:

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

Later chapters cover capabilities that are opt-in: provisioning a rootfs,
hardening, profiles, the network stack. Each names its feature, and [Cargo
features](features.md) lists them in one place. A typical consumer wants a few:

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

`build` performs all validation: a missing rootfs or a malformed command is a
typed configuration error before anything is launched. `run` blocks until the
command terminates and returns its `ExitStatus` whether or not the exit code
was zero — a failing command is data, not an error. `Err` is reserved for the
library itself failing, and a failure during sandbox setup names the exact
step and OS error.

The command runs with inherited standard streams, `/` as its working
directory, and a clean environment: `PATH` and `HOME`, plus whatever the
builder's `env` calls add. The command path is interpreted inside the
sandbox and must be absolute; it is not searched for on `PATH` unless
`path_lookup` is enabled, which resolves a command with no slash against the
sandbox's `PATH` like a shell. By default
the sandbox mounts a fresh `/proc`, a minimal `/dev`, and a tmpfs `/tmp`
over the rootfs, runs the command as PID 2 in its own PID namespace under a
minimal init, and isolates the network to a loopback interface — see [How
the sandbox is built](how-the-sandbox-is-built.md) for the full profile and
the builder methods that adjust it:

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
uid=0(root) gid=0(root) groups=0(root)

$ fcage --rootfs alpine-root --ro-bind ~/project /project --chdir /project \
    --share-net -- /bin/sh -c 'ls && cat /etc/resolv.conf'
```

`fcage` exits with the command's own exit code, or 128 plus the signal number
when the command is terminated by a signal, or 124 when a `--timeout`
expires. A sandbox can also be described in a TOML file and loaded with
`--profile` — see [Profiles](profiles.md). See `fcage --help` for the full
interface.

## Going further

- Stream the command's output to your own code: [Streaming
  output](streaming.md).
- Wait with deadlines, stop gracefully, kill outright, and tie the
  sandbox's lifetime to your process: [The process
  model](process-model.md).
- Launch sandboxes from a thread pool or an async runtime, and cancel them
  from one: [Embedding in a runtime](embedding.md).
- Pick the cargo features your consumer needs: [Cargo features](features.md).
