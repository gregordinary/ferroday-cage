# fcage

Run a command inside an unprivileged Linux sandbox from a shell prompt. The command gets
its own root filesystem view, its own namespaces, and a clean environment, established by
talking to the kernel directly. No daemon, no image, no root.

```sh
cargo install ferroday-cage-cli
fcage --rootfs /srv/rootfs/alpine -- /bin/sh -c 'echo hello from the cage'
```

`fcage` is a thin consumer of the [`ferroday-cage`](https://crates.io/crates/ferroday-cage)
library, built with every feature enabled. Any profile the library accepts loads here, and
every capability of the launch builder and the network stack has a flag. That makes it the
quickest way to try a configuration before committing to a feature set in a consumer's
`Cargo.toml`. The provisioners' bootstrap surface has flags too, plans and pins included.
Layered builds stay in the library, because they produce an increment rather than a
published root filesystem.

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

Each provisioner carries its own option set:

- Mirrors, and the fallbacks to try after them.
- An architecture.
- A package cache reused across runs.
- An alternative keyring.
- Extra repositories, merged into one resolution.

`fcage --gentoo-variants amd64` prints what an architecture publishes.
`fcage --gentoo-keyring-horizon` prints what the vendored Gentoo keyring can still vouch
for and until when, reaching no network to do it.

Two further modes stand on their own:

```sh
fcage --remove-rootfs ./root                      # including trees not owned by you
fcage --remove-overlay-upper ./run-42             # an overlay upper, with its work directory
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

`--restrict` is the fallback for a host that disables user namespaces entirely. It confines
a plain host process with the same Landlock and seccomp primitives, without a sandbox root.

A standard stream that is a file, as in `fcage ... < notes.txt` or `fcage ... >> build.log`,
is never handed to the command. The command gets a pipe instead, and `fcage` copies between
the pipe and the file. Without that, the command could reopen the file through
`/proc/self/fd` with more access than the stream carried, and rewrite it.

A relayed stream behaves as a pipe does: the command cannot seek it or read the file's size.
Input the command leaves unread stays in the file for the next reader, so
`while read -r line; do fcage ...; done < list` reads the whole list. A pipe, a socket, or a
character device such as a terminal is handed over as it is. Any other kind of stream, a
directory among them, is refused before anything starts.

The isolated network is loopback-only by default. `--netstack` attaches a native userspace
TCP/IP stack for IPv4 and IPv6 with no helper binary, outbound and to any port
`--netstack-publish` opens on the host. `--forward-loopback PORT TARGET` gives the command
one way out instead. The command connects to `PORT` on its loopback, and `fcage` carries each
connection to a unix socket or an address on the host. `--share-net` gives the command the
host's network.

A sandbox can also run over the host's own tree. `--host-rootfs` roots it on the host's
filesystem, read-only, with `/home`, `/root`, `/run`, `/var/run` and `/var/tmp` hidden. A
working tree bound back in is where the command writes, `--hide` empties a path, and
`--read-only` protects one inside the working tree:

```sh
fcage --host-rootfs --bind ~/project ~/project --read-only ~/project/.git \
    --hide ~/project/.env --chdir ~/project -- make
```

A sandbox composed from host binds needs no root directory. `--empty-rootfs` roots it on an
empty filesystem of its own, which the mount flags populate and which becomes read-only once
they are in place:

```sh
fcage --empty-rootfs --ro-bind /usr /usr \
    --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --bind ./work /work -- /bin/sh
```

Other flags cover mounts and overlays, uid/gid range maps, resource limits, a pseudoterminal
of the sandbox's own (`--terminal`), timeouts, and the environment. `fcage --help` lists
them all, grouped.

## Profiles

With a profile file, the sandbox specification is configuration rather than a command line:

```sh
fcage --profile ./build.toml -- /usr/bin/make
```

`--restricted-profile` is the path for a profile from a source you do not control. It
refuses the keys that map host resources in, write to the host, or share a host namespace,
and the hardening keys the flags add to rather than replace. The guide's [untrusted
profiles](https://gregordinary.github.io/ferroday-cage/profiles.html#untrusted-profiles)
section links the list. Flags given alongside a profile override it, and each default-on
toggle has a counterpart in both directions.

## Exit codes

| Code | Meaning |
| --- | --- |
| the command's own | the command ran and exited |
| 128 + signal | the command was terminated by a signal |
| 124 | `--timeout` expired |
| 125 | the sandbox could not be built or launched, a standard stream was refused, or a relayed stream could not be read or delivered |
| 126 | the command exists but could not be executed |
| 127 | the command does not exist |
| 141 | a reader of `fcage`'s own output or diagnostics went away before `fcage` was done |
| 2 | usage error |

## Requirements

Rust 1.91 or later to build, and Linux 5.6 or later with unprivileged user namespaces
enabled. A host that denies them is reported by name, with the blocking configuration and
its remedy. The default network posture also installs a seccomp filter, which a kernel
without `CONFIG_SECCOMP_FILTER` or a container runtime's seccomp profile can refuse.
`--share-net` needs none. `--restrict` is the exception: it needs only Landlock or
seccomp.

## Documentation

The [guide](https://gregordinary.github.io/ferroday-cage/) covers the sandbox, the
provisioners, hardening, profiles, and the identity model in full. `fcage` versions
independently of the library: its compatibility contract is its flags, exit codes, and
output format, so a library release does not move it.

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
