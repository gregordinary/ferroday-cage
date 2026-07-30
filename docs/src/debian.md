# A Debian userland

The `debian` feature provisions a Debian root filesystem: it bootstraps a
suite and architecture from the archive and installs packages into it, so a
sandbox can build or run Debian software from a userland the library assembles
for it. It speaks to the archive directly — a pure-Rust replacement for
`debootstrap` and `mmdebstrap` — and configures packages by running dpkg
inside a cage of its own.

```rust,no_run
use ferroday_cage::provision::{self, debian::Debian};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut debian = Debian::builder("trixie")
    .include(["build-essential", "git"])
    .cache_dir("/var/cache/fcage/debs")
    .build()?;
provision::ensure("/var/lib/machines/trixie", &mut debian)?;
# Ok(())
# }
```

`Debian` implements [`Provisioner`](provisioning.md), so `provision::ensure`
publishes the result atomically: the destination directory either does not
exist or holds a complete, configured rootfs.

[Building a Debian package](building-a-debian-package.md) works this into a
consumer: it bootstraps a suite with build tooling and builds a `.deb` from
source inside a cage, with the host untouched.

## How it works

A bootstrap runs in stages:

1. **The signed release.** It fetches `InRelease`, verifies the OpenPGP
   signature against the archive keyring, confirms the release identifies as
   the requested suite and has not expired, and reads the release, which
   carries the digest of every package index.
2. **The package set.** It fetches each component's `Packages` index, verifies
   it against the release digest, and resolves the install set: the base system
   (every essential and required package, plus `apt`) together with the
   packages named by `include`, closed over their dependencies.
3. **Download and extract.** It downloads each package, verifies its digest,
   and extracts its files into a staging tree with the same kernel-enforced
   containment the tarball provisioner uses. The merged-usr symlink layout is
   created first, so packages that ship `/usr`-native paths resolve correctly.
4. **Configuration.** It configures the packages by running dpkg inside a cage
   rooted at the staging tree, in waves modeled on a second-stage bootstrap.
   Because configuration runs in the sandbox, it needs no privilege on the
   host. It writes the rootfs's `sources.list` and installs the archive keyring
   as its `signed-by` trust anchor, so the finished rootfs is apt-usable: an
   in-cage `apt-get update` verifies the release against that keyring without
   the `debian-archive-keyring` package, which the base install set does not
   pull in. Under the single-identity map it also configures apt to run its
   download methods as root, since the `_apt` user apt would otherwise drop to
   is not represented in that map; a range map keeps apt's default sandbox.
   When every package reaches the installed state, the rootfs is published.

A bootstrapped rootfs carries no `/etc/resolv.conf`, because the provisioner
writes none: a resolver configuration belongs to wherever the tree is deployed,
not to the archive it was built from. An in-cage `apt-get update` still resolves
names, because host networking binds the host's `resolv.conf` in — creating the
file to mount onto, and removing it once the sandbox is gone, so the tree keeps
carrying none:

```rust,no_run
# use ferroday_cage::{Cage, Network};
# fn main() -> ferroday_cage::Result<()> {
Cage::builder()
    .rootfs("/var/lib/myapp/debian")
    .network(Network::Host)
    .command("/usr/bin/apt-get")
    .args(["update"])
    .build()?
    .run()?;
# Ok(())
# }
```

[What a launch leaves in the
tree](provisioning.md#what-a-launch-leaves-in-the-tree) covers the general rule
for a tree that goes on to be exported.

## The package cache

`cache_dir` sets a directory downloaded packages are kept in, so a later
bootstrap that resolves the same version reuses the file instead of fetching it
again. Entries are content-addressed by digest, and every reuse verifies the
file against that digest, so a truncated or altered entry is downloaded again
rather than trusted. Without a cache directory, packages are downloaded to a
temporary directory and discarded with the bootstrap.

One cache directory serves any number of concurrent bootstraps, in one process
or several, whether or not their package sets overlap. Each entry is staged
under a name unique to the writer and published with a rename, so two
bootstraps downloading the same package at once both succeed and both end up
naming the one file. A builder that provisions several rootfs trees in parallel
can therefore point them all at a single cache.

## Selecting packages

The install set is the base system, plus the packages `include` names, closed
over their dependencies, minus the packages `exclude` removes.

The base system is chosen by priority, not by an enumerated list. `base_priority`
sets the least essential `Priority` band it seeds from: the base is every
essential package plus every package at least as essential as the floor. The
default, `Priority::Required`, is `debootstrap`'s minbase — essential and
required packages only. A less essential floor seeds more:

```rust,no_run
use ferroday_cage::provision::debian::{Debian, Priority};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let debian = Debian::builder("trixie")
    .base_priority(Priority::Important)
    .build()?;
# let _ = debian;
# Ok(())
# }
```

`Priority::Important` additionally seeds that band — `cron`, `logrotate`, and
the like — so a package the archive marks at that priority is present without
being named in `include`, matching the corresponding bootstrap variant.
Choosing the base by priority rather than by listing packages keeps the set in
step with the archive: a package the archive promotes into the band appears
without the selection being revised. Floors below `Priority::Standard` seed the
bulk of the archive and are not meaningful for a base system.

`exclude` removes a package from the resolved closure. An excluded package is
dropped from the base seed and skipped as a dependency alternative, so a group
such as `network-manager | isc-dhcp-client` resolves to the surviving
alternative rather than pulling the excluded one — apt's `pkgname-` deselection,
a way to keep out a package a broader selection would otherwise draw in:

```rust,no_run
use ferroday_cage::provision::debian::Debian;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let debian = Debian::builder("trixie")
    .include(["network-manager"])
    .exclude(["isc-dhcp-client", "dhcpcd-base"])
    .build()?;
# let _ = debian;
# Ok(())
# }
```

Exclusion is a resolver decision, so the resolved plan and the finished rootfs
agree — unlike a post-install purge, which would install a package only to
remove it. A hard dependency that only an excluded package can satisfy fails the
bootstrap rather than producing a broken closure, as does excluding a package
that is also an `include`.

## Repositories

A bootstrap resolves against one or more repositories. The
[`mirror`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.mirror)
and its companion setters configure the primary — a single-mirror bootstrap
needs nothing more — and [`repository`] merges in additional sources. A
[`Repository`] carries an ordered list of mirror URLs, and the two things a
caller reaches for both fall out of that one type.

**Distinct sources in one resolution.** A local trusted pool of a build's own
`.deb`s and one or more signed feature repositories are separate repositories,
each with its own trust anchor, contributing packages to a single dependency
closure:

```rust,no_run
use ferroday_cage::provision::{self, debian::{Debian, Repository}};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let local = Repository::builder("trixie")
    .mirror("file:///srv/my-debs")
    .trust_unsigned(true)
    .name("local")
    .build()?;

let mut debian = Debian::builder("trixie")
    .include(["my-package"])
    .repository(local)
    .build()?;
provision::ensure("/var/lib/machines/trixie", &mut debian)?;
# Ok(())
# }
```

Resolution is highest-version-wins across every repository, so a package a
feature repository ships at a higher version supersedes the mirror's, and a
package only the local pool ships is pulled from it while its dependencies close
against the mirror; an exact-version tie resolves to the earlier repository, the
primary first. The local pool is a `dists/`-structured repository — the layout
apt reads, the same one the provisioner fetches from a mirror — trusted without
a signature, which is apt's `[trusted=yes]` and the shape a build produces when
it regenerates a pool of its own `.deb`s each run. Each additional repository
writes its own `/etc/apt/sources.list.d/<name>.list` into the finished rootfs,
signed by its own `/usr/share/keyrings/<name>.gpg` when it carries a keyring.
Those file names have to be distinct, so a set in which two additional
repositories would write the same pair is refused at build time; a repository
with no [`name`] takes a generated one from its position, which a caller-supplied
name must not collide with either.

**Interchangeable URLs for one source.** A live mirror with a
`snapshot.debian.org` backstop is one source reached two ways.
[`mirror_fallback`] adds a backstop URL to the primary — and
[`Repository::builder`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Repository.html#method.builder)
[`mirror_fallback`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.RepositoryBuilder.html#method.mirror_fallback)
to any repository — tried in order when the live mirror reports a resource
missing, for a version that has rotated off the live pool:

```rust,no_run
use ferroday_cage::provision::debian::Debian;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let _debian = Debian::builder("trixie")
    .mirror("http://deb.debian.org/debian")
    .mirror_fallback("http://snapshot.debian.org/archive/debian/20250101T000000Z")
    .allow_stale_release(true)
    .build()?;
# Ok(())
# }
```

The freshness posture is repository-wide, so a repository with a snapshot
backstop sets [`allow_stale_release`], the snapshot's release being expired by
design; the signature is still verified. The backstop is a fetch-time concern
only — the finished rootfs's `sources.list` names the live mirror, not the
snapshot.

Multiplying repositories does not dilute trust. Every authenticity check — the
signature against the repository's keyring, the release bound to its suite, the
refusal of `trust_unsigned` over `http://` — simply runs once per repository.
The `deb-multirepo` example provisions a root from the archive mirror plus a
local trusted pool, auditing the repository builder end to end.

## Publishing a local pool

[`Pool`] produces the local trusted pool the previous section consumes: it
writes or updates a `dists/`-structured repository from a set of `.deb`s, so a
pipeline that builds packages can feed each one into the resolution of the next.

```rust,no_run
use ferroday_cage::provision::debian::Pool;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
Pool::at("/srv/my-debs")
    .suite("trixie")
    .publish(["build/my-package_1.0_amd64.deb"])?;
# Ok(())
# }
```

The component defaults to `main` and the architecture to the host's; both have
setters. `publish` takes anything that iterates paths, and may be called
repeatedly on the same `Pool` — each call merges into what the pool already
indexes.

The call reads each `.deb`'s control stanza, copies it into the pool under
`pool/`, and regenerates the component's `Packages` index (with its `.gz`) and
the suite's `Release`. It is idempotent and incremental: the pool directory is
updated in place, and the index keeps the highest version of each package name —
the same rule resolution applies — so republishing over a superset of a prior
run is well-defined.

Publishing an empty set writes a valid, empty repository: the `Release` still
declares the architecture and component, so the pool can be created before the
first `.deb` exists and referenced from the start, resolving against an empty
package set rather than a missing repository. The pool is trusted, not signed —
a `file://` repository under the caller's control, apt's `[trusted=yes]` — so no
OpenPGP signature is written and none is expected.

### The pool's own layout

A pool reports the paths it owns, so nothing outside it needs to know how an
archive is laid out. [`Pool::mirror_url`] is the `file://` URL that declares the
pool as a [`Repository`]; [`Pool::release_path`] and [`Pool::dists_dir`] are the
suite's `Release` and the directory it sits in. A relative pool root is made
absolute for the URL, and none of the three requires the pool to exist, so a
pipeline can wire itself together before its first publish.

```rust,no_run
use ferroday_cage::provision::debian::{Pool, Repository};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let pool = Pool::at("build/pool").suite("trixie");
pool.publish(["build/my-package_1.0_amd64.deb"])?;

let repository = Repository::builder("trixie")
    .mirror(pool.mirror_url()?)
    .trust_unsigned(true)
    .name("build-pool")
    .build()?;
# let _ = repository;
# Ok(())
# }
```

### Signing a pool

A pool that leaves the machine that built it is signed by its owner:
`release_path` names the document to sign and `dists_dir` the directory the
signature belongs in. The signature must be an inline cleartext-signed
`InRelease` — the form the provisioner reads for a repository with a
[`keyring`] — since a detached `Release.gpg` is not fetched. A signed pool needs
no `Valid-Until`; a release that carries none is simply unbounded, as Debian
stable's is.

Publishing removes any signature the pool already carries, both spellings, so a
signature made over a superseded `Release` can never outlive it. That matters
more than it looks: the by-hash index copies are immutable and never removed, so
a stale-but-valid signature would not fail a reader — it would quietly resolve
the older package set. Leaving the pool unsigned between a publish and its
signature fails closed instead, and it means a pool is signed after every
publish rather than once.

### What publishing costs

Publishing never holds a package in memory. A `.deb`'s control stanza is read by
seeking to the control member of its `ar` container, its digest is taken in
chunks, and its payload is copied without being buffered, so publishing a 90 MB
kernel package costs what publishing a shell script costs.

Where the build tree and the pool sit on one filesystem that can share extents —
btrfs, XFS formatted with reflink, bcachefs — the payload is cloned rather than
copied. The clone is a metadata operation: no time proportional to the package,
and no additional disk. Everywhere else, including ext4 and any pool on a
different filesystem from the build tree, the bytes are streamed through
instead. The two produce the same pool.

The copy is a clone and never a hard link, and the difference is what a reader
sees. A hard link would alias the caller's file, so rebuilding a package in place
would rewrite the pool's copy along with it, and a reader partway through
resolving that package would fail its digest check against a `Release` that
described the older bytes. A clone shares storage and nothing else, so a
published file is fixed once published.

The index describes the pool's own copy, not the file the caller offered. Both
the control stanza and the digest are read back from the published bytes, so a
recorded `SHA256` always names content the pool holds. Republishing a `.deb` the
pool already has compares digests and writes nothing, leaving a warm pool
untouched.

### Publishing in parallel

A pipeline that builds components in parallel can publish each one the moment it
finishes, and resolve against the pool while other components are still
publishing into it. Neither needs coordination of its own.

Publishes exclude each other with a lock on `.lock` in the pool root, held for
the whole call. The index is rebuilt by merging into what the pool already
holds, so without that lock two publishes would each start from the same prior
index and the later would drop the earlier's packages.

Readers take no lock, and cannot: a reader reaches the pool through the fetch
transport as an ordinary repository and does not know a pool is what it is
reading. Instead a publish becomes visible all at once. Every file is written
atomically; the indexes are additionally written under `by-hash/SHA256/<digest>`,
where they are immutable and are never rewritten or removed; and the `Release`
that names those digests is written last. A bootstrap that has read a `Release`
therefore keeps resolving the indexes that `Release` described, however many
publishes land while it works.

One case falls outside this. Republishing a package at a version the pool
already holds, with *different* bytes, writes to the path the older bytes
occupy, because the archive layout stores both there. A reader partway through
resolving the older bytes fails its digest check. In a build pipeline that means
two components produced the same package version. Republishing *identical* bytes
is the ordinary incremental case and rewrites nothing.

## The resolved plan

[`resolve`] reports what a bootstrap would install without installing it. It
runs the read half of the pipeline — the signed release and the package index,
then dependency resolution — and returns the exact package set, each with its
version, architecture, and archive-verified SHA-256, downloading nothing:

```rust,no_run
use ferroday_cage::provision::debian::Debian;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut debian = Debian::builder("trixie").include(["build-essential"]).build()?;
let plan = debian.resolve()?;
for package in &plan.packages {
    println!("{} {} {}", package.name, package.version, package.sha256);
}
# Ok(())
# }
```

The plan is the same closure a full bootstrap installs — both resolve through
one code path — so it is a faithful preview and a stable key for a
content-addressed build cache. Every digest chains back to the release
signature, so the key is anchored to the archive rather than to a mirror's word.
Because it runs nothing, `resolve` needs neither a `qemu-user` binfmt handler
nor an establishable identity map, and so serves an architecture the host cannot
execute.

A full bootstrap reports the same plan inline: it emits `DebianEvent::Resolved`
once the closure is resolved and before the first download, carrying the plan it
is about to install. A [progress sink](streaming.md) can read it there, keying a
build cache on what the running bootstrap actually resolved without a separate
`resolve` pass.

## Layered build roots

A pipeline that builds many packages against one shared base — a build root of
`base + toolchain + this component's build-dependencies`, rebuilt per component —
need not re-provision the shared part each time. Provision the base once, then
stage each component's increment over it as a disposable overlay layer:
[`base_layer`] marks the pristine base, and [`stage_layer`] resolves and installs
only the packages the base does not already carry into an overlay upper, leaving
the base untouched.

```rust,no_run
use ferroday_cage::Cage;
use ferroday_cage::provision::{self, debian::Debian};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Provision the shared base once: system plus build toolchain.
let base = "/var/cache/build/base-trixie";
provision::ensure(
    base,
    &mut Debian::builder("trixie").include(["build-essential"]).build()?,
)?;

// Per component, stage only its build-dependencies over the base.
let layer = Debian::builder("trixie")
    .base_layer(base)
    .include(["libssl-dev", "pkg-config"])
    .build()?
    .stage_layer("/var/cache/build/component-upper")?;

// Build against the merged base-plus-increment view.
let status = Cage::builder()
    .overlay_rootfs(base, layer.path())
    .command("/usr/bin/dpkg-buildpackage")
    .build()?
    .run()?;
# let _ = status;

// Dropping the layer discards the increment; the base stays pristine.
drop(layer);
# Ok(())
# }
```

The increment resolves against the base's *already-installed set*, read from the
base's own dpkg status database: every package the base configured, and the
virtual packages they provide, is treated as satisfied, so the resolution closes
over only the delta. Because most components share build-dependencies already
present in `base + toolchain`, that delta is small — which is the point.
[`resolve_layer`] previews it without staging, the layered counterpart of
[`resolve`], so a build-root cache can be keyed on the increment inline.

`stage_layer` installs the delta into the overlay upper and returns a
[`BuildLayer`]. Root a cage on [`overlay_rootfs`] with the base as the read-only
lower and the layer's `path()` as the writable upper, and the build sees the
merged view; every write lands in the upper, and the base is never mutated.
Dropping the `BuildLayer` removes the upper — and the overlay work directory
beside it — reverting the increment and leaving the base ready for the next
component.

The base must be a full, configured bootstrap, not an
[`extract_only`](#extract-only-and-foreign-architectures) tree: the overlay's
lower supplies the dpkg database the increment's configuration reads. A base and
its layers must share a suite, an architecture, and an [identity
map](identity-maps.md) — a base configured under one map carries ownership a
layer under another would not agree with. The increment's configuration runs the
target's binaries, so a foreign architecture needs the same `qemu-user` binfmt
handler a full bootstrap does. Staging roots a cage on an unprivileged overlay,
which the host must support; see [overlay-rooted
cages](host-requirements.md#overlay-rooted-cages), reported by
[`host::overlay_blocker`]. `stage_layer` refuses a host that cannot establish one
before downloading anything.

## The pre-configure overlay

[`pre_configure_overlay`] lays a directory of configuration into the rootfs
after the packages are unpacked and before their maintainer scripts run, so a
script observes the injected values — a debconf pre-seed, a locale selection, a
hardware-probe guard:

```rust,no_run
use ferroday_cage::provision::{self, debian::Debian};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut debian = Debian::builder("trixie")
    .pre_configure_overlay("./rootfs-config")
    .build()?;
provision::ensure("/var/lib/machines/trixie", &mut debian)?;
# Ok(())
# }
```

The source is a rootfs-shaped tree: `./rootfs-config/etc/locale.gen` becomes
`/etc/locale.gen`. File modes and symlinks are preserved, and a file replaces
the package's own copy of the same path, which is how a shipped conffile is
overridden. The tree is laid with the same kernel-enforced containment as
package extraction, so nothing in it can be written outside the rootfs. The
overlay applies only to a full bootstrap; because the base system is configured
first, it governs the configuration of the non-essential packages.

## Trust

Authenticity comes from the archive's OpenPGP signature, not the transport, so
packages are fetched over plain HTTP by default. The `InRelease` signature is
verified against an embedded copy of the Debian archive keyring; every index
and every package is then checked against a SHA-256 digest that chains back to
that signature. A different keyring is supplied with
[`keyring`], and
[`trust_unsigned`] accepts an unsigned `Release`
for a local mirror under the caller's control — the equivalent of apt's
`trusted=yes`.

The signature alone does not say which suite was delivered — a single archive
key signs every suite — so the release is also bound to the request: its
`Suite` or `Codename` must equal the requested suite, which stops a mirror
from answering a request for one suite with a genuine, validly-signed release
for another. Key validity is enforced beyond the cryptographic check: a
revoked archive key is dropped from the keyring, and a signature made after
its signing key expired is rejected, so a retired key cannot vouch for a
release.

The release must also be fresh. A `Valid-Until` the release carries must be
parseable and in the future, and the archive signature must not itself have
expired; this refuses a stale but validly-signed release, which a mirror or an
on-path attacker could otherwise replay to deliver superseded, potentially
vulnerable packages. A release that omits `Valid-Until` — as the Debian stable
suite does, so its release does not expire between point releases — carries no
freshness bound and is accepted, as apt accepts it.
[`allow_stale_release`] relaxes the freshness
check entirely — the signature is still verified — for the legitimate case of
pinning a historical archive state, such as a `snapshot.debian.org` suite. A
`trust_unsigned` mirror is never freshness-checked.

The transport is a trait. The built-in fetcher speaks plain HTTP and
`file://`, addressing a mirror by DNS name, IPv4 literal, or bracketed IPv6
literal (`http://[::1]:8080/debian`); a consumer that needs HTTPS, a proxy, or a
private mirror protocol supplies their own through
[`fetcher`]. A transport is `Send`, because the provisioner owns it and is
itself `Send` — see [thread bounds](stability.md#thread-bounds). Fetches run on
the thread that called into the provisioner, so a transport is never used from
two threads at once.

## Ownership

The bootstrap's [identity map](identity-maps.md) decides the ownership the
finished rootfs carries, and the right map follows from what the rootfs is
for.

The default is the single-identity map: the sandbox maps the calling user to
root and nothing else, so every file in the bootstrapped rootfs is owned by
root. Debian expects some files to belong to other system users and groups;
those ownerships cannot be represented under this map, and the bootstrap
reconciles the difference — recording the intended overrides in dpkg's
database and neutralizing the ownership changes that would otherwise fail —
so configuration completes and the rootfs is internally consistent. The
result is a working userland whose files are uniformly root-owned: exactly
right for a build or run environment consumed back inside single-identity
cages, which cannot observe the flattening, and whose caller-owned output
needs no extra host support to copy or delete.

A rootfs that is itself the product — deployed, exported, or run under a
range map — wants real ownership, and
[`identity_map`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.identity_map)
selects it:

```rust,no_run
# #[cfg(all(feature = "debian", feature = "subid"))]
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::{self, debian::Debian};

let mut debian = Debian::builder("trixie")
    .identity_map(IdentityMap::Subordinate)
    .build()?;
provision::ensure("/srv/images/trixie", &mut debian)?;
# Ok(())
# }
# #[cfg(not(all(feature = "debian", feature = "subid")))]
# fn main() {}
```

Under the subordinate map the system ids genuinely exist, every `chown` a
maintainer script or compiled tool performs happens for real, and no stub or
override is involved: the tree is a correct Debian system as `dpkg` and
`base-passwd` define one. The map requires the `subid` feature and a host
that can establish it, and a bootstrap that cannot fails before any download
rather than falling back to the flattened form. Because the ownership is
real, it reaches the host: a directory the system chowns to a non-root id
refuses the plain caller's removal, and
[`provision::remove`](provisioning.md#removing-a-rootfs) deletes the
produced rootfs either way, re-entering the map where ownership requires it.

## Extract-only and foreign architectures

The bootstrap targets the host architecture by default; another is selected
with [`architecture`]. A full bootstrap for a
foreign architecture runs that architecture's dpkg and maintainer scripts, and
so requires a registered `qemu-user` binfmt handler (see
[Host requirements](host-requirements.md)); the bootstrap checks for one and
reports an actionable error when it is absent.

Where the foreign binaries cannot run, `extract_only` lays out the packages'
files without configuring them. An extract-only rootfs has run no maintainer
scripts and has no configured dpkg database; it is the raw file tree, suitable
for completing the configuration elsewhere.

## The command line

`fcage --provision-debian SUITE` bootstraps the `--rootfs` directory before
launching. Given without a command, it provisions and exits; the
already-provisioned case is fast, so the flag can stay in an invocation
permanently.

```console
$ fcage --rootfs ./trixie --provision-debian trixie \
        --debian-include git,build-essential --debian-cache ./deb-cache
$ fcage --rootfs ./trixie /usr/bin/dpkg --list
```

The `--debian-arch`, `--debian-mirror`, `--debian-components`,
`--debian-include`, `--debian-extract-only`, `--debian-cache`, and
`--debian-keyring` options map onto the builder. `--debian-include` and
`--debian-components` take comma-separated lists and may be repeated.

[`keyring`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.keyring
[`trust_unsigned`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.trust_unsigned
[`allow_stale_release`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.allow_stale_release
[`fetcher`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.fetcher
[`architecture`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.architecture
[`resolve`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.resolve
[`pre_configure_overlay`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.pre_configure_overlay
[`Repository`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Repository.html
[`repository`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.repository
[`mirror_fallback`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.mirror_fallback
[`name`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.RepositoryBuilder.html#method.name
[`Pool`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html
[`Pool::mirror_url`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.mirror_url
[`Pool::release_path`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.release_path
[`Pool::dists_dir`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.dists_dir
[`base_layer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.base_layer
[`stage_layer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.stage_layer
[`resolve_layer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.resolve_layer
[`BuildLayer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.BuildLayer.html
[`overlay_rootfs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.overlay_rootfs
[`host::overlay_blocker`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.overlay_blocker.html
