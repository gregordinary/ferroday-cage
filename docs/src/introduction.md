# Introduction

ferroday-cage is a pure-Rust library for running a command inside an
unprivileged Linux sandbox. It creates a set of Linux namespaces, presents a
root filesystem the caller provides, and executes the command in a clean,
reproducible environment — established directly against the kernel by an
ordinary unprivileged user. A default build is self-contained: pure Rust
throughout, resting on the kernel alone.

The library is the product. A program links it, configures a sandbox with a
typed builder, launches a command, and consumes a typed result. A companion
command-line tool, `fcage`, is a thin consumer of the same public API and
offers the same sandbox at a shell prompt: it is built with every feature
enabled, so any profile the library accepts loads there and every capability of
the launch builder has a flag. Two seams stay in the library alone, being the
ones no argument could carry — handing the command an open descriptor as its
standard input, and supplying an identity-map delegate as code. The
[feature guide](features.md#in-the-command-line-tool) states what the tool
covers of the other builders.

A bare dependency gives the sandbox itself. Provisioning, hardening, profiles,
and the network stack are opt-in, each named by the chapter that covers it and
listed together in [Cargo features](features.md).

## Isolation model

The sandbox is built from unprivileged user namespaces: the calling user is
mapped to root inside the sandbox, and the isolation is established directly
against the kernel. The command sees the provided root filesystem at `/`
with a standard mount profile — a fresh `/proc`, a minimal `/dev`, a tmpfs
`/tmp`, and the caller's bind mounts — assembled over it, and runs as PID 2
under a minimal reaping init in isolated PID, mount, UTS, IPC, cgroup, and
(by default) network namespaces, with a clean, reproducible environment,
scrubbed signal state, and a descriptor table holding only its standard
streams. It runs one user namespace deeper than the rest of the sandbox: the
command enters a nested one before it execs, which is what locks the flags of
every mount the setup established, so a read-only bind is a boundary and the
root is `nosuid`. The surface grows additively from there. [How the sandbox is
built](how-the-sandbox-is-built.md) describes the mechanism and [The
process model](process-model.md) the process tree, lifetimes, and signal
behavior.

Output is collected whole or streamed live to a caller-supplied observer, a
running sandbox is driven through a handle — wait, deadline, terminate, kill —
and, with the `serde` feature, the sandbox specification round-trips through
profile files. See [Streaming output](streaming.md) and
[Profiles](profiles.md); [Embedding in a runtime](embedding.md) covers driving
launches from a thread pool or an async runtime, and [Building an
orchestrator](building-an-orchestrator.md) works a profile-driven consumer end
to end.

The isolated network is loopback-only by default. A caller gives it network
access by attaching a userspace network stack at a seam, while the sandbox keeps
its private namespace and the host network policy stays outside it. The library
ships its own native stack, self-contained and unprivileged. It carries outbound
IPv4 and IPv6, and inbound connections to the ports a caller publishes. The seam
also accepts an external stack such as `pasta` or `slirp4netns`. See
[Userspace networking](userspace-networking.md).

The root filesystem is the caller's to supply, and the library can also produce
one — provisioning from a tarball, or bootstrapping [a Debian](debian.md), [an
Alpine or postmarketOS](alpine.md), or [a Gentoo](gentoo.md) userland from the
distribution's own archive. See [Provisioning a rootfs](provisioning.md); [An
ebuild development sandbox](ebuild-sandbox.md) provisions a Gentoo stage3 and
builds a package in it, and [Building a Debian
package](building-a-debian-package.md) bootstraps a Debian suite and builds a
`.deb` from source. A bootstrapped root need not be for the host's own
architecture: [A foreign-architecture test run](cross-architecture.md) builds
and runs arm64 binaries on an x86_64 host through the `qemu-user` binfmt
handler.

The default profile is a rootless convenience for code you trust: a controlled
filesystem view, isolated namespaces, and a clean environment. Untrusted code
calls for the hardening layer, which adds Landlock filesystem rules, seccomp
syscall filters, and capability drops on request — the default profile alone is
not a hardening boundary against hostile code. See [Hardening](hardening.md),
and for hosts that cannot create user namespaces at all, [the restriction
fallback](restriction-fallback.md).

## Requirements

- Rust 1.91 or later. See [Stability and versioning](stability.md#minimum-supported-rust-version)
  for how that floor moves.
- Linux 5.6 or later, with unprivileged user namespaces enabled. See [Host
  requirements](host-requirements.md). The [restriction
  fallback](restriction-fallback.md) is the exception: it needs only
  Landlock or seccomp.

## Status

ferroday-cage is under active development. The API settles over the 0.x
series; [Stability and versioning](stability.md) states what each interface
promises, and this guide grows as the library does.
