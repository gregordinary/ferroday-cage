# Cargo features

The crate has **no default features**. A bare dependency gives the sandbox
itself: namespaces, mounts, the root swap, identity maps, the process model,
output streaming, and resource limits. It is self-contained, pure Rust
throughout and resting on the kernel alone.

Everything beyond that is opt-in, so a consumer that wants a sandbox and
nothing else pays for a sandbox and nothing else.

```sh
# The sandbox alone.
cargo add ferroday-cage

# A typical consumer: profiles, a tarball-provisioned rootfs, and hardening.
cargo add ferroday-cage --features serde,tarball,hardening
```

## The features

| Feature | What it adds | What it pulls in |
| --- | --- | --- |
| [`serde`](profiles.md) | The profile format: `CageBuilder` serializes and deserializes as the sandbox specification, and `RestrictedProfile` loads one from an untrusted source | `serde` |
| [`tarball`](provisioning.md#the-tarball-provisioner) | The `Tarball` provisioner (gzip, xz, and zstd, detected by content) and `export_tar`, its ownership-preserving counterpart | `flate2`, `lzma-rust2`, `ruzstd` |
| [`debian`](debian.md) | The Debian provisioner: bootstrap a suite and architecture from the archive, with signature verification and dependency resolution. Implies `tarball` | `irongall`, `sha2`, and `tarball`'s |
| [`alpine`](alpine.md) | The Alpine provisioner: resolve and install a package set from an apk repository, with signature verification. Serves postmarketOS's repositories too. Implies `tarball` | `irongall`, `sha2`, and `tarball`'s |
| [`gentoo`](gentoo.md) | The Gentoo provisioner: resolve a stage3 variant to the build the archive currently publishes and extract it, then install prebuilt packages into it from the archive's binary-package host, all verified against a vendored keyring. Implies `tarball` | `irongall`, `sha2`, `md-5`, and `tarball`'s |
| [`hardening`](hardening.md) | Landlock filesystem and network rules, seccomp syscall filters, capability drops, and the [restriction fallback](restriction-fallback.md) for hosts without user namespaces | `seccompiler` |
| [`netstack`](userspace-networking.md) | A native userspace TCP/IP stack giving the isolated network IPv4 and IPv6, outbound and through published ports, terminated in-process | `smoltcp` |
| [`subid`](identity-maps.md) | The subordinate-id delegate: uid/gid range maps established through the shadow suite's `newuidmap`/`newgidmap` | nothing (see below) |

Every dependency above is pure Rust, with any C backend it offers left off, so
no combination needs a C compiler. Two reach the `libc` crate's bindings to the
C library the target already has. `seccompiler`, under `hardening`, does on
every target. `cpufeatures` does on aarch64, where it asks the C library which
processor extensions the hashes can use. The SHA-2 crate brings it under
`tarball` and every userland. Both run in the calling process, and neither
is reached from the sandbox stages after the fork.

`subid` is the one feature that changes that property in a different way: it
adds no dependency, but it is the only feature under which the library executes
an external binary. A build without it invokes none. The
[`DirectMapper`](identity-maps.md) delegate, which needs no helper, is in the
featureless build and is tried first regardless.

## Choosing a set

- **Running a command in a prepared root.** No features. Provision the root
  however you like — the library only needs a directory.
- **Running untrusted code.** `hardening`, for the Landlock, seccomp, and
  capability controls, and the restriction fallback if the target hosts might
  disable user namespaces.
- **Loading sandbox configuration from files.** `serde`.
- **Producing the root filesystem too.** `tarball` for an archive, `debian` for
  a bootstrapped Debian userland, `alpine` for an Alpine or postmarketOS one,
  `gentoo` for one bootstrapped from a signed stage3. Each adds little to what
  `tarball` compiles: `irongall`, which has no dependencies of its own, and for
  `gentoo` `md-5`.
- **Giving the sandbox network access.** `netstack` for the bundled stack.
  Without it, the [seam](userspace-networking.md) an external stack attaches to
  is still there — it is part of the featureless build.
- **Running a userland that needs more than one identity.** `subid`, plus the
  shadow helpers and a subordinate allocation on the host.

## In the command-line tool

`fcage` is built with every feature enabled, so any profile the library accepts
loads there. It is the quickest way to try a configuration before committing to
a feature set in a consumer's `Cargo.toml`.

What it spells, surface by surface:

| Surface | In `fcage` |
| --- | --- |
| The launch builder, and the restriction fallback behind `--restrict` | Every setting, but the two no argument can carry: a command's standard input as an open descriptor, and an identity-map delegate supplied as code. The output pair has no flag either, a shell already spelling both of its dispositions. |
| The native network stack | Every setting, as `--netstack-*`. |
| The provisioners' bootstrap surface | Every setting, plan and pin documents included, so a reproducible install is expressible at a prompt. A custom transport is code and has none. |
| Layered provisioning | Nothing. A provisioner given a base layer produces an increment in a disposable overlay upper rather than a published rootfs, and `fcage` publishes rootfs directories. |
| Exporting a rootfs | The identity map and the modification-time clamp, as `--identity-map` and `--clamp-mtime`, writing where `--export-to` names. The two settings that take code have none: an identity-map delegate, and the entry filter that says what the archive holds. |
| Read-only archive inspection | Gentoo's, which prints stage3 variants, binhost packages, an installed set, and the vendored keyring's horizon. Debian and Alpine have no equivalent mode. |

The record behind the table is `tools/parity.toml`. It names every setting of
every public builder against the flag that reaches it, or the reason no flag
does, and a check in CI holds it to both surfaces. The check finds the builders
in the API rather than reading a list, so a new one cannot go unrecorded.
Read-only archive inspection is the one row built from something other than a
builder.

## Documentation

docs.rs builds with all features, so the published API documentation shows the
whole surface. Items only some builds provide are gated in the source, which
means a local `cargo doc` reflects exactly the features you enabled — including
a no-feature build, where the feature-gated sections and their links are absent
rather than dangling.
