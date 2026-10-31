# Building a Debian package

Building a Debian package from source wants a root filesystem with the build
toolchain, the package's build dependencies, and the source tree — and it wants
none of that on the host. Those are a cage's parts again: a provisioned root, a
read-only bind for the source, a read-write bind for the results. Put them
together and the Debian counterpart of the [ebuild
sandbox](ebuild-sandbox.md) falls out: a tool that bootstraps a Debian suite
with build tooling and runs `dpkg-buildpackage` inside a cage. The library ships
one as a worked example.

Where the ebuild sandbox provisions a Gentoo stage3 from a tarball, this example
bootstraps a Debian suite from the archive through the [Debian
provisioner](debian.md); it is that provisioner's worked consumer, the way the
ebuild sandbox is the [tarball provisioner](provisioning.md)'s.

```sh
deb-build --rootfs ./trixie-build --cache ./deb-cache \
    --source ./hello-2.10 --output ./out
```

## The build posture

The example builds one `CageBuilder` and layers the build's needs onto it, each
an ordinary builder call:

- **The root is provisioned once, with the build environment baked in.** The
  bootstrap installs the generic Debian build toolchain and the source tree's
  own build dependencies, then `provision::ensure` publishes it. The first run
  pays for the bootstrap; every later run finds the root already published and
  skips it, so the `--rootfs` flag can stay in an invocation permanently.
- **The source is read-only.** `--source` binds the unpacked source tree
  read-only at `/src`. The build copies it to a writable directory in the root
  and builds the copy, so the host's tree keeps its original state —
  `dpkg-buildpackage` writes build products throughout a tree it builds.
- **The output is read-write.** `--output` binds a host directory read-write at
  `/out`. Only the finished packages are copied there; the source copy and the
  intermediate build tree stay inside the cage and vanish with it.
- **The network is isolated.** Because the build dependencies are baked into the
  root, the build resolves nothing at build time and runs with a loopback-only
  network — which a policy-conforming Debian build does not need anyway.
  `--network` shares the host network for a build that reaches for it; note that
  provisioning always fetches from the archive over the host network, since that
  is where the userland comes from.

With no trailing command the sandbox runs `dpkg-buildpackage -us -uc -b` over
the copied source and collects the built packages; with a command after `--` it
runs that instead — a shell, for interactive packaging work in the same posture.

## Build dependencies are discovered, then baked

A source package declares its build dependencies in `debian/control`. The
example reads them from the tree through
[`debian::build_depend_names`], which parses the
`Build-Depends`, `Build-Depends-Arch`, and `Build-Depends-Indep` fields and
returns the package names, and folds them into the bootstrap's install set
alongside the toolchain. `--build-dep` adds packages beyond the declared set.

The names are the ones that apply to the architecture the root is built for,
the host's here. An alternative restricted to other architectures, such as
`libhurd-dev [hurd-any]`, is skipped in favor of the next one, as the archive's
own build daemons skip it.

Discovering build dependencies this way, and baking them into the root, keeps to
the provisioner's model: it speaks to the archive directly and resolves the
whole install set — toolchain, declared build dependencies, and their closure —
with its own resolver. The build that follows runs offline, entirely from the
build environment installed in the root.

The alternative, running `apt-get build-dep` inside the cage, would need a
`deb-src` line in the root's `sources.list` and an `apt-get update` before it
could resolve anything, and would move dependency resolution to build time over
the network. The bootstrap writes only a binary package line, so that path is
deliberately not the one the example takes.

Because the dependencies are baked into the root, changing them means
provisioning a fresh `--rootfs`: an existing root is reused as it stands, with
whatever build environment the first run installed. `dpkg-buildpackage` reports
an unmet build dependency by name, so the loop when one is missing is to add a
`--build-dep` and provision a new root.

## Why no hardening

The example applies no [hardening](hardening.md) layer. A package build compiles
code, writes across a tree, and runs helper processes; the boundary it needs is
the cage's namespaces and private root, not a syscall filter layered over the
top.

## The identity map

The cage maps the calling user to root and nothing else, and a Debian source
build is content with that. A package's file ownership is stored in the package
itself — in the archive's data member — and applied by `dpkg` when the package
is installed, not by changing ownership on the build tree. So a build performs
no ownership change to a user the map does not contain, and it completes under
the single root identity. Modern packages go further: `hello`, like a growing
share of the archive, declares `Rules-Requires-Root: no`, so
`dpkg-buildpackage` builds it with no privilege emulation at all, packaging
every file as `root:root` directly.

This is the contrast with the ebuild sandbox. A Gentoo `emerge` fails under the
same map because portage chowns its own state directories to a dedicated
`portage` uid, which a single-identity map cannot represent; the ebuild sandbox
works around it by running portage wholly as root. A Debian build needs no such
accommodation. Where a package does still require root during its packaging step
— the historical default — `dpkg-buildpackage` fakes it in userspace with
`fakeroot`, one of the baked-in tools, so even then no real ownership change
reaches the kernel.

## Provisioning progress

The bootstrap is the heavy part of a first run: it fetches and verifies the
release, resolves the toolchain and build dependencies, downloads the packages,
and configures them. The example wires an [`observe`] sink to the provisioner and prints each event,
so the bootstrap reports what it is doing rather than sitting silent. The sink
attaches to the `Debian` provisioner, not to its builder, and yields a value
that is itself a `Provisioner`:

```rust,ignore
let mut sink = print_event;
provision::ensure(rootfs, &mut debian.observe(&mut sink))?;
```

That is the Debian-specific channel, carrying the events only a bootstrap has —
fetches, resolution, per-package downloads, and dpkg's own output. The same
events also reach a [`Provision::observe`](provisioning.md#progress-and-cancellation)
observer, wrapped as `ProvisionEvent::Debian`, for a consumer that wants one
adapter across every provisioner. Either observer can stop the run.

The sink is a `DebianObserver`, and a closure is one — which is why the example
passes a function. A caller that also wants to *stop* a bootstrap implements the
trait instead and answers its `cancelled`. The bootstrap consults it at each
mirror it asks for a release or an index, at each package, and before each dpkg
wave. A stopped bootstrap fails with `ProvisionError::Cancelled` and leaves no
root behind.

The sink is also the way to cancel a `Debian::observe(...).resolve()` or
`.available()`. Both run outside a provisioning run, with no `Provision`
observer to ask, and stop at a mirror boundary with `DebianError::Cancelled`.

```rust,ignore
impl DebianObserver for Progress {
    fn progress(&mut self, event: DebianEvent<'_>) {
        eprintln!("{event:?}");
    }

    fn cancelled(&mut self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}
```

## Running the example

The example lives at `crates/ferroday-cage/examples/deb-build.rs`. It bootstraps
through the Debian provisioner, so it builds with the `debian` feature:

```sh
cargo run --example deb-build --features debian -- --help
```

A complete invocation needs an unpacked Debian source tree. One comes from the
archive with `dpkg-source`, or with `apt-get source` on a Debian or derivative
host:

```sh
# Fetch and unpack a source package to build:
apt-get source hello        # leaves ./hello-2.10/ (version may differ)

# Provision the build root and build the package into ./out:
cargo run --example deb-build --features debian -- \
    --rootfs ./trixie-build --cache ./deb-cache \
    --source ./hello-2.10 --output ./out

# A shell in the same posture, for interactive packaging work:
cargo run --example deb-build --features debian -- \
    --rootfs ./trixie-build --source ./hello-2.10 --output ./out -- /bin/bash
```

The first run reports the bootstrap's progress and prints each built package;
the built `.deb` lands in `./out`. The command's exit code becomes the
sandbox's, so a build composes into scripts like any other tool.

[`debian::build_depend_names`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/fn.build_depend_names.html
[`observe`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.observe
