# ferroday-cage

A pure-Rust library for running a command inside an unprivileged Linux sandbox. The
command gets its own root filesystem view, its own namespaces, and a clean environment,
all established by talking to the kernel directly.

Configure a sandbox with a typed builder, launch a command, and consume its streamed
output and a typed result. The command runs under a minimal init in its own PID
namespace. A running sandbox is driven through a handle that can wait, set a deadline,
terminate, or kill. A companion command-line tool, `fcage`, offers the same sandbox at a
shell prompt.

The library issues the sandbox's syscalls itself, so a default build depends on nothing
but the kernel and pure-Rust crates. Nothing in its public API requires a caller to write
`unsafe`, and [CONTRIBUTING.md](CONTRIBUTING.md) names the three modules that use it.

The sandbox uses the same kernel primitives as bubblewrap: user and mount namespaces,
`pivot_root`, and seccomp. It presents them as a library with a typed builder and an
in-process handle, rather than as a command to shell out to. `fcage` covers the
command-line case.

A root filesystem is a directory you supply or provision. Every sandbox is rootless,
built with the caller's own credentials and with no daemon involved. It is not a container
runtime, so there are no images, no registry, and no OCI runtime specification.

The library can also produce that root filesystem. It extracts one from a tar archive, or
bootstraps one from a distribution's own archive: Debian, Alpine and postmarketOS, or a
signed Gentoo stage3. It verifies the signatures, resolves the package closure in process,
and runs no distribution tooling on the host. Each is an opt-in feature, and the table
below has the detail.

## Features

A bare dependency gives the sandbox itself: namespaces, mounts, the root swap,
identity maps, the process model, output streaming, and resource limits. Each
capability below is opt-in, and every dependency it brings is pure Rust with C
backends off, so any combination keeps the build self-contained.

`subid` is the one feature that reaches outside at runtime. It adds no dependency, and it
executes the shadow suite's `newuidmap` and `newgidmap`. A build without it invokes no
external binary.

| Feature | What it adds |
| --- | --- |
| `hardening` | Landlock filesystem and network rules, seccomp syscall filters, and capability drops applied to the command — plus a restriction fallback for hosts that disable user namespaces, confining a plain process with the same primitives |
| `tarball` | Provision a root filesystem atomically from a tar archive (uncompressed, gzip, xz, or zstd, detected by content) with kernel-enforced containment, and export one back with its ownership and extended attributes intact |
| `debian` | Bootstrap a Debian suite and architecture straight from the archive — a `debootstrap` replacement that verifies the release signature, resolves the dependency closure itself, and configures the root in a sandbox |
| `alpine` | Bootstrap an Alpine root from an apk repository — verifying each index signature, resolving the dependency closure itself, and running the install scripts in a sandbox. Serves postmarketOS's repositories too |
| `gentoo` | Provision a Gentoo root from a signed stage3 and install prebuilt packages into it from the archive's binary-package host — the archive's own enumeration verified against a vendored keyring, the tarball held to a SHA-512 a signed document records, and each package held to the cleartext-signed `Manifest` inside it |
| `netstack` | A native userspace TCP/IP stack giving the isolated network outbound IPv4 and IPv6, terminated in-process and forwarded over ordinary host sockets |
| `serde` | The sandbox specification round-trips through profile files, including a restricted mode for profiles from an untrusted source |
| `subid` | uid/gid range maps through the shadow suite's `newuidmap`/`newgidmap`, so a userland needing more than one identity works inside |

```sh
cargo add ferroday-cage --features hardening,tarball
```

## Usage

```rust,no_run
use ferroday_cage::Cage;

fn main() -> ferroday_cage::Result<()> {
    let status = Cage::builder()
        .rootfs("/srv/rootfs/alpine")
        .command("/bin/sh")
        .args(["-c", "echo hello from the cage"])
        .build()?
        .run()?;
    assert!(status.success());
    Ok(())
}
```

Or at a shell prompt, through `fcage`:

```sh
cargo install ferroday-cage-cli
fcage --rootfs /srv/rootfs/alpine -- /bin/sh -c 'echo hello from the cage'
```

Requires Rust 1.91 or later, and Linux 5.6 or later with unprivileged user namespaces
enabled. A host that denies them is reported by name, with the blocking configuration
and its remedy. Two capabilities need more: an unprivileged overlay mount needs 5.11, and
an overlay upper on tmpfs needs 6.6. The
[guide](https://gregordinary.github.io/ferroday-cage/) covers all of this, and its [host
requirements](https://gregordinary.github.io/ferroday-cage/host-requirements.html) chapter
states each floor.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and propose changes,
and [SECURITY.md](SECURITY.md) for how to report a containment bypass or another
security issue. Released changes are recorded in [CHANGELOG.md](CHANGELOG.md).

## Workspace

- `crates/ferroday-cage`: the library.
- `crates/ferroday-cage-cli`: the `fcage` binary, a thin consumer of the library's
  public API.
- `docs/`: the guide, an [mdBook](https://rust-lang.github.io/mdBook/).

## Status

The library's public surface is guarded by a committed API snapshot,
`cargo-semver-checks`, and auto-trait assertions. The API settles over
the 0.x series: while the major version is 0,
a breaking change bumps the minor version. The [stability
chapter](https://gregordinary.github.io/ferroday-cage/stability.html) states
what each interface promises.

## License

<!-- prose-lint: off -- license text, quoted verbatim. -->

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](https://github.com/gregordinary/ferroday-cage/blob/main/LICENSE-APACHE)
  or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license
  ([LICENSE-MIT](https://github.com/gregordinary/ferroday-cage/blob/main/LICENSE-MIT)
  or <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

<!-- prose-lint: on -->
