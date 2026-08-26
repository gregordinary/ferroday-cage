# fcage

Run a command inside an unprivileged Linux sandbox from a shell prompt: its own root
filesystem view, its own namespaces, and a clean environment, established by talking to
the kernel directly. No daemon, no image, no root.

```sh
cargo install ferroday-cage-cli
fcage --rootfs /srv/rootfs/alpine -- /bin/sh -c 'echo hello from the cage'
```

`fcage` is a thin consumer of the [`ferroday-cage`](https://crates.io/crates/ferroday-cage)
library, built with every feature enabled. Any profile the library accepts loads here, and
every capability of the launch builder and the network stack has a flag — which makes it
the quickest way to try a configuration before committing to a feature set in a consumer's
`Cargo.toml`. The provisioners' bootstrap surface has flags too, plans and pins included;
layered builds, which produce an increment rather than a published rootfs, stay in the
library.

## Producing the root filesystem

A root filesystem is a directory you supply, or one `fcage` provisions. Given a
provisioning flag without a command, it provisions and exits.

```sh
# From a tar archive: plain, gzip, xz, or zstd, detected by content.
fcage --rootfs ./root --provision-tar rootfs.tar.xz

# Bootstrap a Debian suite from the archive, verifying the release signature.
fcage --rootfs ./trixie --provision-debian trixie --debian-include build-essential

# Bootstrap an Alpine release from an apk repository. postmarketOS too, through
# --alpine-keys postmarketos and --alpine-repository.
fcage --rootfs ./alpine --provision-alpine v3.23 --alpine-include alpine-base

# Provision a Gentoo root from a signed stage3, held to a digest a signed
# document records.
fcage --rootfs ./gentoo --provision-gentoo amd64 --gentoo-variant amd64-openrc
```

Each provisioner carries its own option set — mirrors and their fallbacks, an
architecture, a package cache reused across runs, an alternative keyring, extra
repositories merged into one resolution. `fcage --gentoo-variants amd64` prints what an
architecture publishes, and `fcage --gentoo-keyring-horizon` prints what the vendored
Gentoo keyring can still vouch for and until when, reaching no network to do it.

Two further modes stand on their own:

```sh
fcage --remove-rootfs ./root                      # including trees not owned by you
fcage --export-rootfs ./root --export-to root.tar # ownership and xattrs preserved
```

## Confining the command

The default profile is a rootless convenience for code you trust. Untrusted code calls for
the hardening flags, which add Landlock filesystem and network rules, seccomp syscall
filters, and capability drops:

```sh
fcage --rootfs ./root \
    --landlock-ro /usr --landlock-rw /work --landlock-connect 443 \
    --seccomp curated --drop-caps \
    -- /work/build.sh
```

`--restrict` is the fallback for a host that disables user namespaces entirely: it confines
a plain host process with the same Landlock and seccomp primitives, without a sandbox root.

The isolated network is loopback-only by default. `--netstack` attaches a native userspace
TCP/IP stack for outbound IPv4 and IPv6 with no helper binary; `--share-net` gives the
command the host's network instead.

Other flags cover mounts and overlays, uid/gid range maps, resource limits, a pseudoterminal
of the sandbox's own (`--terminal`), timeouts, and the environment. `fcage --help` lists
them all, grouped.

## Profiles

With a profile file, the sandbox specification is configuration rather than a command line:

```sh
fcage --profile ./build.toml -- /usr/bin/make
```

`--restricted-profile` is the path for a profile from a source you do not control. It
refuses the keys that would let one bind an arbitrary host path or reach the host network.
Flags given alongside a profile override it, and each default-on toggle has a counterpart
in both directions.

## Exit codes

| Code | Meaning |
| --- | --- |
| the command's own | the command ran and exited |
| 128 + signal | the command was terminated by a signal |
| 124 | `--timeout` expired |
| 125 | the sandbox could not be built or launched |
| 126 | the command exists but could not be executed |
| 127 | the command does not exist |
| 2 | usage error |

## Requirements

Rust 1.91 or later to build, and Linux 5.6 or later with unprivileged user namespaces
enabled. A host that denies them is reported by name, with the blocking configuration and
its remedy. `--restrict` is the exception: it needs only Landlock or seccomp.

## Documentation

The [guide](https://gregordinary.github.io/ferroday-cage/) covers the sandbox, the
provisioners, hardening, profiles, and the identity model in full. `fcage` versions
independently of the library: its compatibility contract is its flags, exit codes, and
output format, so a library release does not move it.

## License

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
