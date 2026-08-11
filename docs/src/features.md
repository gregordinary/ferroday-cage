# Cargo features

The crate has **no default features**. A bare dependency gives the sandbox
itself — namespaces, mounts, the root swap, identity maps, the process model,
output streaming, and resource limits — and it is self-contained: pure Rust
throughout, resting on the kernel alone.

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
| [`debian`](debian.md) | The Debian provisioner: bootstrap a suite and architecture from the archive, with signature verification and dependency resolution. Implies `tarball` | `pgp`, `sha2`, and `tarball`'s |
| [`alpine`](alpine.md) | The Alpine provisioner: resolve and install a package set from an apk repository, with signature verification. Serves postmarketOS's repositories too. Implies `tarball` | `rsa`, `sha1`, `sha2`, and `tarball`'s |
| [`gentoo`](gentoo.md) | The Gentoo provisioner: resolve a stage3 variant to the build the archive currently publishes and extract it, verified against a vendored keyring. Implies `tarball` | `pgp`, `sha2`, and `tarball`'s |
| [`hardening`](hardening.md) | Landlock filesystem and network rules, seccomp syscall filters, capability drops, and the [restriction fallback](restriction-fallback.md) for hosts without user namespaces | `seccompiler` |
| [`netstack`](userspace-networking.md) | A native userspace TCP/IP stack giving the isolated network outbound IPv4 and IPv6, terminated in-process | `smoltcp` |
| [`subid`](identity-maps.md) | The subordinate-id delegate: uid/gid range maps established through the shadow suite's `newuidmap`/`newgidmap` | nothing (see below) |

Every dependency above is pure Rust with C backends and libc off, so enabling
any combination keeps the build self-contained.

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
  `gentoo` for one bootstrapped from a signed stage3. An `alpine`-only build is
  the lightest of the three userlands: it needs no OpenPGP implementation, which
  `debian` and `gentoo` each pull in.
- **Giving the sandbox network access.** `netstack` for the bundled stack.
  Without it, the [seam](userspace-networking.md) an external stack attaches to
  is still there — it is part of the featureless build.
- **Running a userland that needs more than one identity.** `subid`, plus the
  shadow helpers and a subordinate allocation on the host.

## In the command-line tool

`fcage` is built with every feature enabled, so any profile the library accepts
loads there and every builder capability has a flag. It is the quickest way to
try a configuration before committing to a feature set in a consumer's
`Cargo.toml`.

## Documentation

docs.rs builds with all features, so the published API documentation shows the
whole surface. Items only some builds provide are gated in the source, which
means a local `cargo doc` reflects exactly the features you enabled — including
a no-feature build, where the feature-gated sections and their links are absent
rather than dangling.
