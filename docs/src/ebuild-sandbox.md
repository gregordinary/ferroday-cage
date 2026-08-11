# An ebuild development sandbox

A package build wants a clean root filesystem, the package tree to build from,
and the network to fetch sources — and it wants none of that to touch the host.
Those are exactly a cage's parts: a provisioned root, a read-only bind for the
tree, a read-write bind for the caches, and a shared network. Put them together
and a small tool falls out: an ebuild development sandbox that provisions a
Gentoo stage3, binds a portage tree into it, and runs `emerge`. The library
ships one as a worked example.

Where [Building an orchestrator](building-an-orchestrator.md) composes a
prepared rootfs with profile data, this example is the one that *provisions* its
root: it is the worked consumer of the [provisioning](provisioning.md) module,
fetching a stage3 through the [Gentoo provisioner](gentoo.md) before it launches
anything.

```sh
ebuild-sandbox --variant amd64-openrc --rootfs ./gentoo \
    --repo /var/db/repos/gentoo --distfiles ./distfiles \
    app-misc/hello
```

`--variant` names one of the stage3s Gentoo publishes and the layer does the
rest: it follows the signed pointer to the build that variant currently points
at, holds the tarball to the SHA-512 a signed digest document records for it, and
extracts it. `--stage3 FILE` provisions from a tarball already on the host
instead, which is what an air-gapped machine or a locally built stage3 needs; the
two are alternatives.

## The build posture

The example builds one `CageBuilder` and layers the build's needs onto it, each
an ordinary builder call:

- **The root is provisioned, once.** `provision::ensure` extracts the stage3
  into the `--rootfs` directory and publishes it atomically. The first run pays
  for the download and the extraction; every later run finds the root already
  published and skips both, so the flag can stay in an invocation permanently.
  `--stage3-cache` keeps the downloaded tarball across runs, which is what a
  caller building more than one root from a build wants.
- **The tree is read-only.** `--repo` binds a host portage tree read-only at
  `/var/db/repos/gentoo`. The build reads ebuilds and eclasses through the bind
  but cannot write back to the host's tree.
- **The caches are read-write.** `--distfiles` and `--binpkgs` bind host
  directories read-write at `/var/cache/distfiles` and `/var/cache/binpkgs`, so
  fetched source tarballs and built binary packages persist across runs instead
  of being discarded with the sandbox.
- **The network is shared for fetches.** The default is the host network, which
  `emerge` needs to fetch sources; `--offline` denies it for a build that works
  only from the distfiles cache.

With package atoms the sandbox runs `emerge --oneshot` over them; with a command
after `--` it runs that command instead — a shell, for interactive ebuild work
in the same posture.

## Why no hardening

The example applies no [hardening](hardening.md) layer, and disables portage's
own internal sandboxing through a default `FEATURES` value. A package merge
legitimately writes across the tree, changes file ownership, and runs helper
processes; the boundary it needs is the cage's namespaces and private root, not
a syscall filter layered over the top. Portage's `sandbox`, `usersandbox`, and
`*-sandbox` features exist to build that boundary when there is none — inside
the cage there already is one, and nesting the two fights the cage's own
namespaces. A `--env FEATURES=...` overrides the default when a build genuinely
needs a portage feature back.

## Portage and the identity map

Portage, left to its defaults, assumes more than one identity: it chowns its
own state directories to the `portage` group when it starts, and its
`userpriv` and `userfetch` features drop to the unprivileged `portage` user to
build and fetch. Under the library's default single-identity map none of those
ids exist, and every one of those operations fails — the first before a build
even begins.

The example therefore requests the [subordinate identity
map](identity-maps.md): root plus the calling user's whole subordinate-id
allocation, established through the shadow suite's helpers. Inside the
sandbox the `portage` uid and gid are real, so portage needs no configuration
at all — its chowns succeed, and the example's default `FEATURES` enables
`userpriv` so builds drop to `portage:portage` exactly as they would on a
host. The map requires the `subid` feature, the `newuidmap` and `newgidmap`
helpers, and a subordinate allocation for the calling user;
[`host::range_map_blocker`](https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.range_map_blocker.html)
names whichever piece a host is missing, and the example repeats it when the
sandbox cannot be built.

Real ids have one consequence outside the sandbox: directories portage chowns
to its own user — its state and cache trees — are owned by subordinate ids on
the host, so a later `rm -rf` of the rootfs by the plain calling user fails
inside them. `provision::remove` handles exactly this case: it starts with a
plain removal and, when ownership refuses, re-enters the same map and deletes
the tree from inside, where the ids are the caller's own.

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Remove;

# fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
Remove::new("./gentoo-root").map(IdentityMap::Subordinate).run()?;
# Ok(())
# }
```

At a shell prompt, `fcage` removes the same tree. The example provisions under
the subordinate map, which is what the flag assumes:

```sh
fcage --remove-rootfs ./gentoo-root
```

## Running the example

The example lives at `crates/ferroday-cage/examples/ebuild-sandbox.rs`. It
provisions the root through the Gentoo provisioner — falling back to the tarball
one for a `--stage3` file of your own — and establishes the range map through
the subid delegate, so it builds with the `gentoo` and `subid` features:

```sh
cargo run --example ebuild-sandbox --features gentoo,subid -- --help
```

A complete invocation needs a portage tree of your own; the stage3 the example
fetches itself. The tree comes from the `gentoo-latest.tar.xz` snapshot under a
Gentoo mirror's `snapshots/`, which extracts to a `gentoo/` directory to point
`--repo` at.

```sh
# Provision the root and build a package into it:
cargo run --example ebuild-sandbox --features gentoo,subid -- \
    --variant amd64-openrc --rootfs ./gentoo-root \
    --stage3-cache ./stage3-cache \
    --repo ./gentoo --distfiles ./distfiles \
    app-misc/hello

# A shell in the same posture, for interactive work:
cargo run --example ebuild-sandbox --features gentoo,subid -- \
    --rootfs ./gentoo-root --repo ./gentoo -- /bin/bash
```

The command's exit code becomes the sandbox's, so a build composes into scripts
like any other launcher.

## A note on clean builds

The cage mounts the root read-write, so a build writes into the provisioned root
and the next build starts from where the last one left off — convenient for
iterating on one ebuild, but not a fresh root each time.

For a pristine root per build, root the cage on an
[overlay](provisioning.md#keeping-a-provisioned-rootfs-pristine) of the stage3
instead of on the stage3 itself: the provisioned root becomes a read-only lower
layer, every write lands in a disposable upper, and discarding the upper is the
whole of the cleanup. One provisioned stage3 then serves any number of clean
builds, with no second extraction and no copy.

```rust,no_run
# use ferroday_cage::Cage;
# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .overlay_rootfs("./gentoo-root", "./builds/hello")
    .command("/usr/bin/emerge")
    .args(["--oneshot", "app-misc/hello"])
    .build()?;
# let _ = cage;
# Ok(())
# }
```

Keeping the upper instead of discarding it gives an incremental build root
layered over the shared stage3 — the same base, one upper per line of work.
Discard an upper with `provision::remove` rather than `rm -rf`: the kernel
creates a mode-`0` directory in the overlay's work area that a plain recursive
delete cannot descend into.

The library models one prepared root per launch and leaves the choice of reuse
or renewal to the consumer; the overlay is how the choice is expressed without
duplicating the root.
