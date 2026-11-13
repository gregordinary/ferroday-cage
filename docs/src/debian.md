# A Debian userland

The `debian` feature provisions a Debian root filesystem. It bootstraps a suite
and architecture from the archive and installs packages into it. A sandbox can
then build or run Debian software from a userland the library assembles for
it.
It speaks to the archive directly, a pure-Rust replacement for `debootstrap` and
`mmdebstrap`, and configures packages by running dpkg inside a sandbox of its
own.

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
exist or holds a complete, configured tree.

[Building a Debian package](building-a-debian-package.md) works this into a
consumer. It bootstraps a suite with build tooling and builds a `.deb` from
source inside a sandbox, with the host untouched.

## How it works

A bootstrap runs in stages:

1. **The signed release.** It fetches `InRelease` and verifies the OpenPGP
   signature against the archive keyring. It confirms the release identifies as
   the requested suite and has not expired, then reads the release, which
   carries the digest of every package index.
2. **The package set.** It fetches each component's `Packages` index and
   verifies it against the release digest. It then resolves the install set:
   the base system (every essential and required package the primary
   repository marks, plus `apt`) together with the packages named by
   `include`, closed over their dependencies.
3. **Download and extract.** It downloads each package, verifies its digest,
   and extracts its files into a staging tree with the same kernel-enforced
   containment the tarball provisioner uses. The merged-usr symlink layout is
   created first, so packages that ship `/usr`-native paths resolve correctly.
   The staging tree's own directory is mode `0755`, the mode `base-files`
   gives `/`. Every `.deb` describes the root it is unpacked into as well as
   its contents. Taking the root's mode from one of them would make it a
   property of whichever package happened to be extracted last.
4. **Configuration.** It configures the packages by running dpkg inside a
   sandbox rooted at the staging tree, in waves modeled on a second-stage
   bootstrap. Because configuration runs in the sandbox, it needs no privilege
   on the host.

   It writes the tree's `sources.list` with a `signed-by` keyring, so the
   finished tree is apt-usable. A release verified against the embedded archive
   keyring names `/usr/share/keyrings/debian-archive-keyring.gpg`. That file
   belongs to the `debian-archive-keyring` package `apt` depends on, whose
   upgrades deliver the keys the archive rotates to, and nothing is written over
   it. A keyring supplied with [`keyring`] is written to
   `/usr/share/keyrings/fcage-archive-keyring.gpg`, a path no package ships, and
   keeping it current is the caller's. A tree without the keyring package gets
   the embedded keyring at that path instead.

   Each line carries the posture its repository was verified under. One that
   [allows a stale release](#repositories) gets `check-valid-until=no`, so the
   tree's `apt-get update` reads the expired release it was built from. A
   repository on a `file://` mirror gets no line and no keyring. Its URL names a
   directory on the host, which a sandbox rooted at the tree does not see, and an
   unreachable source fails every update.

   Under the single-identity map it also configures apt to run its download
   methods as root. The `_apt` user apt would otherwise drop to is not
   represented in that map. A range map keeps apt's default sandbox.

   It removes what the waves recorded of their own run and empties any machine
   id a package generated. [What a bootstrap does not
   keep](#what-a-bootstrap-does-not-keep) lists both. When every package
   reaches the installed state, the tree is published.

A bootstrapped tree carries no `/etc/resolv.conf`, because the provisioner
writes none. A resolver configuration belongs to wherever the tree is deployed,
not to the archive it was built from. An in-sandbox `apt-get update` still
resolves names, because host networking binds the host's `resolv.conf` in. That
bind creates the file to mount onto and removes it once the sandbox is gone, so
the tree keeps carrying none:

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

`cache_dir` sets a directory downloaded packages are kept in. A later bootstrap
that resolves the same version then reuses the file instead of fetching it
again. Entries are content-addressed by digest, and every reuse verifies the
file against that digest. A truncated or altered entry is therefore downloaded
again rather than trusted, from every mirror the package's repository lists. A
cache directory is the caller's: it is created if absent and never removed,
which is what makes it a cache.

Without one, packages are downloaded into a directory beside the tree being
built and discarded when the run ends. That holds whether the run succeeded or
failed, so a bootstrap that fails partway leaves nothing beside the tree it did
not publish.

With one, the packages a run installs are first copied from the cache into that
same run-owned directory. Extraction verifies the copy, and every dpkg wave
reads the copy. A cache is shared and outlives the run, so a package replaced
there after it was verified never reaches dpkg.

A package is never held in memory. The bytes are written to a staging file as
they arrive, then read back and digested as a cache entry is. The file is
renamed into the cache only once the digest matches the one the archive
recorded. Installing reads it back the same way, streaming the `data.tar`
through the decompressor into the extractor. So a 90 MB kernel package costs
what a shell script costs, and nothing unverified is ever visible at a cache
path.

One cache directory serves any number of concurrent bootstraps, in one process
or several, whether or not their package sets overlap. Each entry is staged
under a name unique to the writer and published with a rename. Two bootstraps
downloading the same package at once therefore both succeed, and both end up
naming the one file. A builder that provisions several trees in parallel can
point them all at a single cache.

## Selecting packages

The install set is the base system, plus the packages `include` names, closed
over their dependencies, minus the packages `exclude` removes.

The base system is chosen by priority, not by an enumerated list.
`base_priority` sets the least essential `Priority` band it seeds from. The base
is then every essential package, plus every package at least as essential as the
floor. Both are read from the primary repository alone, as `debootstrap` seeds
from one archive. The default, `Priority::Required`, is `debootstrap`'s
minbase: essential and required packages only. A less essential floor seeds
more:

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

`Priority::Important` additionally seeds that band, meaning `cron`, `logrotate`,
and the like. A package the archive marks at that priority is then present
without being named in `include`, matching the corresponding bootstrap variant.
Choosing the base by priority rather than by listing packages keeps the set in
step with the archive. A package the archive promotes into the band appears
without the selection being revised. Floors below `Priority::Standard` seed the
bulk of the archive and are not meaningful for a base system.

`exclude` removes a package from the resolved closure. An excluded package is
dropped from the base seed and skipped as a dependency alternative. A group such
as `network-manager | isc-dhcp-client` therefore resolves to the surviving
alternative rather than pulling the excluded one. It is apt's `pkgname-`
deselection, a way to keep out a package a broader selection would otherwise
draw in:

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

Exclusion is a resolver decision, so the resolved plan and the finished tree
agree. A post-install purge would instead install a package only to remove it. A
hard dependency that only an excluded package can satisfy fails the bootstrap
rather than producing a broken closure. So does excluding a package that is also
an `include`.

### What a resolution refuses

A dependency nothing can satisfy fails the resolution. Four cases reach it:

- A name no configured archive carries.
- A name carried only at a version the declared constraint rules out.
- One an exclusion removed that a hard dependency needed.
- One a [pin](#holding-a-resolution-to-a-plans-versions) holds at a version the
  declared constraint rules out.

Installing anyway would succeed, since dpkg configures with `--force-depends`,
and leave a root whose packages cannot work. The resolution refuses instead.

Every refusal is reported before the run fails, and the failure names all of
them. A resolution reports each one as a `DebianEvent::Unsatisfiable` carrying
what could not be supplied, who asked for it, and what the wall was. An install
list with four mistakes in it is therefore corrected in one pass rather than in
four bootstraps. Where the pin is among the refusals, the failure is
`DebianError::Pin`, naming every package the pin could not hold.

The resolution keeps walking past a refusal to find the next. A group nothing
satisfies contributes nothing to the selection, so the rest of the closure is
unaffected by it. Two packages needing one absent name produce two refusals
rather than one. That is the fact rather than noise, since both have to
change.

## Repositories

A bootstrap resolves against one or more repositories. The
[`mirror`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.mirror)
and its companion setters configure the primary — a single-mirror bootstrap
needs nothing more — and [`repository`] merges in additional sources. A
[`Repository`] carries an ordered list of mirror URLs, and the two things a
caller reaches for both fall out of that one type.

Every mirror URL is fetched through the configured transport, and the built-in
one speaks `http://` and `file://` only. An `https://` mirror therefore needs a
transport of the caller's own, supplied through [`fetcher`] and covered under
[Trust](#trust). It is the archive signature, not the transport, that
authenticates a package.

**Distinct sources in one resolution.** A local trusted pool of a build's own
`.deb`s and one or more signed feature repositories are separate repositories.
Each has its own trust anchor, and each contributes packages to a single
dependency closure:

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

Each name resolves to one version across every repository, chosen as apt
chooses one by default. Between repositories of one
[rank](#releases-ranked-below-the-rest) the higher version wins. A package a feature repository ships at a higher version therefore
supersedes the mirror's. A package only the local pool ships is pulled from it,
while its dependencies close against the mirror. An exact-version tie resolves
to the earlier repository, the primary first.

The local pool is a `dists/`-structured repository, the layout apt reads and the
same one the provisioner fetches from a mirror. It is trusted without a
signature, which is apt's `[trusted=yes]`. That is the shape a build produces
when it regenerates a pool of its own `.deb`s each run.

Each additional repository writes its own
`/etc/apt/sources.list.d/<name>.list` into the finished tree, signed by its own
`/usr/share/keyrings/<name>.gpg` when it carries a keyring. Those file names
have to be distinct, so a set in which two additional repositories would write
the same pair is refused at build time. A repository with no [`name`] takes a
generated one from its position, which a caller-supplied name must not collide
with either.

A local pool on a `file://` mirror writes neither file, since the tree cannot
see the host path. To give a sandbox's `apt` the pool, bind the pool into the
sandbox read-only. Then write a `deb [trusted=yes] file:///<path>` line naming
the path it is bound at.

**Interchangeable URLs for one source.** A live mirror with a
`snapshot.debian.org` backstop is one source reached two ways.
[`mirror_fallback`] adds a backstop URL to the primary, and
[`Repository::builder`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Repository.html#method.builder)
[`mirror_fallback`](https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.RepositoryBuilder.html#method.mirror_fallback)
does the same for any repository. Backstops are tried in order when the live
mirror reports a resource missing. That is what happens to a version that has
rotated off the live pool:

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
design. The signature is still verified. The backstop is a fetch-time concern
only: the finished tree's `sources.list` names the live mirror, not the
snapshot.

Every authenticity check runs once per repository: the signature against that
repository's keyring, the release bound to its suite, and the transport
`trust_unsigned` requires. Package names are not divided between repositories,
though. Any configured repository can supersede any package name by offering a
higher version at the same rank. That includes `debian-archive-keyring`, whose
keyring the finished tree's primary source names whichever repository supplied
it. Adding a repository therefore trusts its signer with the whole tree, as
adding a source to apt does.

The `deb-multirepo` example provisions a root from the archive mirror plus a
local trusted pool, auditing the repository builder end to end.

### Releases ranked below the rest

A release can rank itself below the others, and apt gives such a release a
lower priority. `experimental` sets `NotAutomatic`, which apt ranks at 1. A
backports suite also sets `ButAutomaticUpgrades`, which apt ranks at 100, and
every other release ranks at 500. A version from a higher-ranked release is
taken over one from a lower-ranked release, whatever the two versions are. A
lower-ranked release therefore supplies only the names no other repository
offers.

Adding `experimental` to reach one package thus changes nothing else in the
root. To take a package from it, name the release with the package in
`include`, the way apt's `apt install name/release` does:

```rust,no_run
use ferroday_cage::provision::debian::{Debian, Repository};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let backports = Repository::builder("trixie-backports")
    .mirror("http://deb.debian.org/debian")
    .keyring("/usr/share/keyrings/debian-archive-keyring.gpg")
    .name("backports")
    .build()?;
let debian = Debian::builder("trixie")
    .repository(backports)
    .include(["linux-image-amd64/trixie-backports"])
    .build()?;
# let _ = debian;
# Ok(())
# }
```

An entry written `name/release` takes the highest version of the name the
repository configured with that suite offers. A versioned dependency of it that
the other candidates cannot satisfy is taken from the same release, and so on
down. That is how apt resolves the same request, so the release supplies what
the entry needs and nothing else. A release no repository is configured with is
refused at build time, and a name the release does not carry fails the
resolution.

A layered build ranks the base's installed packages as apt ranks an installed
version, at 100. A base package is replaced only where a dependency needs a
newer version, and only by one apt would upgrade to. A default release's newer
version replaces it. A backports version replaces it only where no default
release offers the installed version, meaning backports supplied it. An
`experimental` version never does, and nothing is downgraded.

## Publishing a local pool

[`Pool`] produces the local trusted pool the previous section consumes. It
writes or updates a `dists/`-structured repository from a set of `.deb`s. A
pipeline that builds packages can then feed each one into the resolution of the
next.

```rust,no_run
use ferroday_cage::provision::debian::Pool;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
Pool::at("/srv/my-debs")
    .suite("trixie")
    .publish(["build/my-package_1.0_amd64.deb"])?;
# Ok(())
# }
```

The component defaults to `main` and the architecture to the host's. Both have
setters, and both select what the call writes rather than what the suite offers.
The next section covers a suite that holds more than one of either. `publish`
takes anything that iterates paths, and it can be called repeatedly on the same
`Pool`, each call merging into what the pool already indexes.

The call reads each `.deb`'s control stanza, copies it into the pool under
`pool/`, and regenerates the component's `Packages` index (with its `.gz`) and
the suite's `Release`. It is idempotent and incremental. The pool directory is
updated in place, and the index keeps the highest version of each package name,
which is the same rule resolution applies. Republishing over a superset of a
prior run is therefore well-defined.

A `.deb` below the version the index keeps for its name is neither indexed nor
copied. The pool path drops the epoch, as the archive's does, so `1:1.0-1` and
`1.0-1` share one file name. Copying the lower version would replace the file
the index describes.

A pool path is not one index's alone. Each suite that publishes a package into
one component stores it at the same path, and so does each architecture's index
for an `Architecture: all` package. A publish that would replace such a file
with other bytes, at the same version or at a higher one differing only by its
epoch, fails with `DebianError::Deb` where another index names the bytes the
file holds now. That index would otherwise go on naming bytes the pool no longer
holds. A refused publish changes nothing. Publishing the same `.deb` into each
index, or a new version, succeeds.

Publishing an empty set writes a valid, empty repository. The `Release` still
declares the architecture and component, so the pool can be created before the
first `.deb` exists and referenced from the start. It then resolves against an
empty package set rather than a missing repository. The pool is trusted, not
signed: a `file://` repository under the caller's control, apt's
`[trusted=yes]`. No OpenPGP signature is written and none is expected.

### A suite accumulates

A suite holds as many components and architectures as are published into it, and
its `Release` describes all of them. Each publish rescans `dists/<suite>` for
the indexes it holds and rewrites the release from what it finds. Publishing a
second architecture therefore leaves the first reachable, and a component
published beside another does not retire it.

```rust,no_run
use ferroday_cage::provision::debian::Pool;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
Pool::at("build/pool")
    .suite("trixie")
    .architecture("amd64")
    .publish(["build/tool_1.0_amd64.deb"])?;

Pool::at("build/pool")
    .suite("trixie")
    .architecture("arm64")
    .publish(["build/tool_1.0_arm64.deb"])?;
# Ok(())
# }
```

The release the second call writes offers both, and names the indexes of both:

```text
Architectures: amd64 arm64
Components: main
```

This matters more than it looks. A reader consults the release before it knows
which digests to ask for, and verifies every index it fetches against a digest
the release records. A section the release does not name therefore cannot be
resolved however intact it is on disk. The `by-hash` copies are no way around
that, for the same reason. A release describing only the publish that wrote it
would make each publish retire the last.

The scan costs the digest of every index in the suite rather than only the one
just written. Indexes are small beside the packages they describe, and the scan
runs under the publish lock along with the rest of the call. A pipeline
publishing components in parallel therefore serializes on it exactly as it
already does.

A component can be laid out as a subtree, which is how `main/debian-installer`
sits in the archive. It records in `Components` under its full path, since that
is the name a reader has to ask for to reach it.

The suite is a path too, since Debian's security archive published
`buster/updates` for years, so both accept an interior slash. What they refuse
is a value that would resolve somewhere other than where it says. That means a
leading `/`, a `..` segment, or an empty or `.` segment. An architecture is
always a single directory name and takes no slash at all.

All three also refuse whitespace and control characters, which a release field
has no way to name. `Architectures` and `Components` are whitespace-delimited
lists. A component with a space in it would therefore read back as two
components, neither of them the one published. Each refusal is a configuration
error naming the field and the value.

The same rule holds on the reading side. A [`Repository`]'s suite and components
and a bootstrap's architecture become path segments of every URL the archive is
fetched through. They are also words of the `deb` line written into the finished
tree. Each is therefore checked when the repository or the builder is built. A
`..` segment would climb out of the mirror root, which for a `file://` mirror is
a local read. A control character would split the request line the value is
interpolated into.

Every other character a URL path cannot carry as written is refused too, such
as `%`, `?`, `#`, or one outside ASCII. A server would decode a component spelled
`%2e%2e` as `..`.

### What a published `.deb` must declare

`publish` derives the path a package is stored at, and the `Filename` the index
records, from the package's own control stanza. Two things follow.

`Package` and `Version` are held to the alphabet Debian policy gives them. A
name is lowercase letters, digits, `+`, `-`, and `.`, at least two characters
and starting with a letter or a digit. A version is alphanumerics and `.`, `+`,
`-`, `:`, `~`. Neither alphabet contains a separator, so the derived path stays
where the pool put it. Without the check, a package naming itself `../../..`
would create directories and write a file outside the pool root, as the
publishing user.

The control file must be one paragraph and must not itself carry `Filename`,
`Size`, or `SHA256`. A pool entry is the control file verbatim with those three
appended, and a deb822 reader resolves a field by its first occurrence. A
package carrying one would therefore shadow the archive's value. That is a
digest it chose rather than one taken from the bytes on disk, or a `Filename`
naming another package's file.

A second paragraph does the same by another route. The appended fields land on
the last paragraph, which is then the one that reads back as the entry. It reads
back under whatever name and version it declares. A pool is consumed as
`[trusted=yes]` and ranks alongside the primary archive, where the higher version
wins. An entry a package wrote for itself would therefore supersede the primary
archive's.

Both are `DebianError::Deb`, naming the file and what is wrong with it. No
conforming `.deb` is affected. `dpkg-deb` builds a one-paragraph control file,
and the three appended names are archive fields that a control file has no
reason to carry.

### The pool's own layout

A pool reports the paths it owns, so nothing outside it needs to know how an
archive is laid out. [`Pool::mirror_url`] is the `file://` URL that declares the
pool as a [`Repository`]. [`Pool::release_path`] and [`Pool::dists_dir`] are the
suite's `Release` and the directory it sits in. A relative pool root is made
absolute for the URL, and none of the three requires the pool to exist. A
pipeline can therefore wire itself together before its first publish.

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

### Dating a release

The `Release` carries `Date`, the required field naming when the pool was
published. A client reads it to tell how old a snapshot is, and to check its own
clock against the archive's. One that finds no `Date` reports the release as
malformed rather than as merely undated.

The release carries no `Valid-Until`, the separate and optional field, so it
never expires. A pool stays usable for as long as its packages are wanted,
however long after the build that wrote it that is. Dating a release does not
bound its freshness, since expiry is enforced on `Valid-Until` alone.

By default the field names the time of the publish. That is what makes the
release the one part of a pool that varies between two publishes of the same
packages. The indexes are a function of the package set, and the release is a
function of the indexes and the date. [`Pool::date`] pins it, making a publish
byte-reproducible.

```rust,no_run
use ferroday_cage::provision::debian::Pool;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
Pool::at("build/pool")
    .suite("trixie")
    // The same timestamp a reproducible build pins everything else to.
    .date(1_700_000_000)
    .publish(["build/my-package_1.0_amd64.deb"])?;
# Ok(())
# }
```

The pinned value is a plain Unix timestamp rather than something read from the
environment. A pipeline that already pins a build date therefore pins the pool's
with the same number it gives [`Export::clamp_mtime`].

### Naming a pool

A release can carry `Origin`, `Label`, and `Description`, which name who
produced the archive, what it is, and what it holds. None has a default and each
is emitted only when set, so a pool that names none of them is a valid archive.
Inventing an origin would put a name in an archive its owner did not choose.

```rust,no_run
use ferroday_cage::provision::debian::Pool;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
Pool::at("build/pool")
    .suite("trixie")
    .origin("Example")
    .label("Example build pool")
    .description("Packages built by the example pipeline")
    .publish(["build/my-package_1.0_amd64.deb"])?;
# Ok(())
# }
```

They are informational, and nothing resolves against them. What they buy is how
a client presents the archive. `apt policy` renders a repository under its
origin and label, and `Pin: release o=Example` is the pinning form apt's own
documentation leads with. Without them, a pool is still pinned by suite or
codename.

The three are free text and take spaces and punctuation. What they cannot carry
is a control character. A release field ends at a newline, so a value holding
one would continue into the release as further fields. An empty value is refused
as well, the way to have no `Origin` being not to set one.

### Signing a pool

A pool that leaves the machine that built it is signed by its owner.
`release_path` names the document to sign, and `dists_dir` the directory the
signature belongs in. The signature must be an inline cleartext-signed
`InRelease`, which is the form the provisioner reads for a repository with a
[`keyring`]. A detached `Release.gpg` is not fetched. A signed pool needs no
`Valid-Until`, and a release that carries none is simply unbounded, as Debian
stable's is.

Publishing removes any signature the pool already carries, both spellings, so a
signature made over a superseded `Release` can never outlive it. That matters
more than it looks. The by-hash index copies are immutable and never removed, so
a stale-but-valid signature would not fail a reader. It would quietly resolve
the older package set. Leaving the pool unsigned between a publish and its
signature fails closed instead. It also means a pool is signed after every
publish rather than once.

### What publishing costs

Publishing never holds a package in memory. A `.deb`'s control stanza is read by
seeking to the control member of its `ar` container. Its digest is taken in
chunks, and its payload is copied without being buffered. Publishing a 90 MB
kernel package therefore costs what publishing a shell script costs.

The payload is cloned rather than copied where the build tree and the pool sit
on one filesystem that can share extents. That means btrfs, XFS formatted with
reflink, or bcachefs. The clone is a metadata operation, costing no time
proportional to the package and no additional disk. Everywhere else, including ext4 and any pool on
a different filesystem from the build tree, the bytes are streamed through
instead. The two produce the same pool.

The copy is a clone and never a hard link, and the difference is what a reader
sees. A hard link would alias the caller's file, so rebuilding a package in
place would rewrite the pool's copy along with it. A reader partway through
resolving that package would then fail its digest check against a `Release` that
described the older bytes. A clone shares storage and nothing else, so a
published file is fixed once published.

The index describes the pool's own copy, not the file the caller offered. Both
the control stanza and the digest are read back from the published bytes, so a
recorded `SHA256` always names content the pool holds. Republishing a `.deb` the
pool already has compares digests and writes nothing, leaving a warm pool
untouched.

A publish reads what the pool already holds without following a symbolic link,
and opens only a regular file. A link or a named pipe where a package or an
index copy belongs is replaced by the file the publish writes. One where the
merged index belongs fails the publish, which cannot go on without that index.

### Publishing in parallel

A pipeline that builds components in parallel can publish each one the moment it
finishes. It can resolve against the pool while other components are still
publishing into it. Neither needs coordination of its own.

Publishes exclude each other with a lock on `.lock` in the pool root, held for
the whole call. The index is rebuilt by merging into what the pool already
holds. Without that lock, two publishes would each start from the same prior
index, and the later would drop the earlier's packages.

Readers take no lock, and cannot. A reader reaches the pool through the fetch
transport as an ordinary repository, and does not know a pool is what it is
reading. Instead a publish becomes visible all at once, in three parts:

- Every file is written atomically.
- The indexes are additionally written under `by-hash/SHA256/<digest>`, where
  they are immutable and are never rewritten or removed.
- The `Release` that names those digests is written last.

A bootstrap that has read a `Release` therefore keeps resolving the indexes that
`Release` described, however many publishes land while it works.

One case falls outside this. Republishing a package at a version the pool
already holds, with *different* bytes, writes to the path the older bytes
occupy. So does publishing a higher version that differs from the held one only
by its epoch. The archive layout stores both there. A reader partway through
resolving the older bytes fails its digest check.

In a build pipeline that means two components produced the same package version.
Republishing *identical* bytes is the ordinary incremental case and rewrites
nothing.

## The resolved plan

[`resolve`] reports what a bootstrap would install without installing it. It
runs the read half of the pipeline, meaning the signed release, the package
index, and then dependency resolution. It returns the exact package set, each
with its version, architecture, and archive-verified SHA-256, and downloads
nothing:

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

The plan is the same closure a full bootstrap installs, since both resolve
through one code path. It is therefore a faithful preview and a stable key for a
content-addressed build cache. Every digest chains back to the release
signature, so the key is anchored to the archive rather than to a mirror's word.
Because it runs nothing, `resolve` needs neither a `qemu-user` binfmt handler
nor an establishable identity map, and so serves an architecture the host cannot
execute.

A full bootstrap reports the same plan inline. It emits `DebianEvent::Resolved`
once the closure is resolved and before the first download, carrying the plan it
is about to install. A [progress sink](streaming.md) can read it there, keying a
build cache on what the running bootstrap actually resolved without a separate
`resolve` pass.

### The archive state a plan resolved against

A package set says what was selected, not what it was selected from, and the
same suite resolves to different versions a week apart. `plan.archives` records
the state each repository was in, one entry per configured repository with the
primary first:

```rust,no_run
use ferroday_cage::provision::debian::Debian;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut debian = Debian::builder("trixie").build()?;
let plan = debian.resolve()?;

for archive in &plan.archives {
    println!(
        "{} {} released {} (verified by {})",
        archive.mirror,
        archive.suite,
        archive.date.as_deref().unwrap_or("an unstated date"),
        archive.signed_by.join(", "),
    );
}
// Which archive answered for a package when the plan was resolved.
for package in &plan.packages {
    println!("{} <- {}", package.name, plan.archives[package.archive].mirror);
}
# Ok(())
# }
```

Three details are worth stating.

The **mirror** recorded is the URL that answered, not the configured list. A
repository with a [`mirror_fallback`] snapshot backstop resolves against
whichever URL served. Recording the list would describe a choice rather than the
choice made.

The **release digest** is of the body that was verified. For a signed
repository, that is the cleartext the signature covers, not the `InRelease` armor
around it and not a re-fetch. It therefore identifies the exact archive state
the signature vouched for.

Two fingerprints record **who vouched for it**, both in the uppercase hex the
OpenPGP tools print. Both are empty for a repository configured as
[`trust_unsigned`], where nothing was verified, which is a fact worth recording
rather than an omission.

`signed_by` is the certificate's primary-key fingerprint: the identity a keyring
entry is named by, and the one to pin a repository against. `signing_key` is the
component key that actually made the signature. Debian's archive keys sign with
a dedicated signing subkey, so the two normally differ. Only `signed_by` stays
put when an archive rotates that subkey. A release signed by several archive
keys records the first acceptable signature in the order the release carries
them.

`package.archive` indexes into `plan.archives`. Each name resolves to one
version across the merged repositories, ranked as [Releases ranked below the
rest](#releases-ranked-below-the-rest) describes. With more than one configured,
this is the only thing that says where a package will actually come from.

## Installing a plan without resolving again

[`plan`] hands a previously resolved `Plan` back to the bootstrap. The bootstrap
then fetches exactly the packages it records, by the digests it records, and
never touches a release or a package index:

```rust,no_run
use ferroday_cage::provision::{self, debian::Debian};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Once, when the build is first cut.
let plan = Debian::builder("trixie").include(["build-essential"]).build()?.resolve()?;
# let stored = plan.clone();

// Later, to reproduce it exactly.
let mut debian = Debian::builder("trixie").plan(stored).build()?;
provision::ensure("/srv/images/replay", &mut debian)?;
# Ok(())
# }
```

Ordinarily `resolve` and a bootstrap each run a full resolution. A pipeline that
resolves once to key its cache and then provisions therefore resolves twice. It
has to reconcile the two when the archive publishes in between. Installing the
plan removes both the second resolution and the divergence, along with the
roughly 9 MB index download that dominates it.

### The trust model changes

Skipping the release and the index is the win. It means the package digests no
longer chain to an archive signature at install time. **The plan becomes the
trust anchor.** It was archive-verified when it was produced, and installing
from it asserts that whoever kept it kept it intact. Each `.deb` is still
verified against the digest the plan records, so a tampered mirror is still
caught. What is no longer checked is that the plan still describes what the
archive says.

That is exactly what a reproduce mode wants, and exactly what an ordinary build
must not take. So installing a plan is opt-in by construction. A builder that
sets no plan resolves as it always has, chaining every digest to a repository
signature at install time. Nothing about an ordinary bootstrap changes.

### What a plan fixes, and what it does not

A plan describes a resolution that already happened. Anything that would shape a
resolution therefore contradicts it. `include`, `exclude`, and `base_priority`
are refused at `build` with `DebianError::Config` rather than given a silent
precedence. A plan whose suite or architecture disagrees with the builder's is
refused the same way. So is one naming more archives than there are repositories
to fetch them from. Where the builder names no
architecture the plan's is adopted, since a plan states which architecture it is
for.

Everything that shapes *how* rather than *what* still applies: `cache_dir`,
`identity_map`, `pre_configure_overlay`, `source_date_epoch`, the repositories,
and the fetcher. A
package is fetched from the repository its `archive` index names, so configuring
a snapshot mirror is enough to replay the same plan against one.

A plan installed against an archive that has moved on installs the versions the
plan records, which is the point. Where a `.deb` the plan names is no longer on
the mirror, the fetch fails, naming the URL it asked for. It does not report a
resolution that found nothing: the plan is intact, and the archive no longer
holds what it names.

### Keeping a plan

Handing a `Plan` straight back to `plan` covers one process. Resolve once,
install once, with no second resolution and no divergence when the archive
publishes in between. A reproduce mode instead resolves on Monday and replays in a
month, and for that the plan has to leave the process. `to_document` and
`parse_document` are that form:

```rust,no_run
use ferroday_cage::provision::debian::{Debian, Plan};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Resolve now, and keep what was resolved.
let plan = Debian::builder("trixie").build()?.resolve()?;
std::fs::write("trixie.plan", plan.to_document()?)?;

// Replay later, against a snapshot mirror.
let kept = Plan::parse_document(&std::fs::read_to_string("trixie.plan")?)?;
let mut debian = Debian::builder("trixie")
    .mirror("http://snapshot.debian.org/archive/debian/20260802T000000Z")
    .plan(kept)
    .build()?;
# let _ = &mut debian;
# Ok(())
# }
```

The document is deb822, the archive's own control format and the one a `Release`
and a `Packages` index are written in. It therefore reads in a terminal and
diffs in a review:

```text
Format: ferroday-cage-plan 2
Suite: trixie
Architecture: arm64

Archive: 0
Mirror: http://deb.debian.org/debian
Suite: trixie
Components: main
Release-SHA256: 9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a9f3a
Date: Sat, 02 Aug 2026 08:14:33 UTC
Valid-Until: Sat, 09 Aug 2026 08:14:33 UTC
Signed-By: 04B54C3CDCA79751B16BC6B5225629DF75B188BD
Signing-Key: B8E5F13176D2A7A75220028078DBA3BC47EF2265

Archive: 1
Mirror: file:///srv/pool
Suite: trixie
Components: main
Release-SHA256: 1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f1c0f
Date: Sat, 02 Aug 2026 09:02:11 UTC
Signed-By:
Signing-Key:

Package: base-files
Version: 13.6
Architecture: arm64
SHA256: 7b217b217b217b217b217b217b217b217b217b217b217b217b217b217b217b21
Filename: pool/main/b/base-files/base-files_13.6_arm64.deb
Archive: 0
Installed-Size: 340
Size: 69412

Package: local-tool
Version: 2.4-1
Architecture: all
SHA256: e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5e0d5
Filename: pool/main/l/local-tool/local-tool_2.4-1_all.deb
Archive: 1
Source: local-suite
```

Archive 0 names both the archive certificate and the signing subkey that made
the signature. Archive 1 is a locally published
[pool](#publishing-a-local-pool) configured with `trust_unsigned`, so nothing
verified its release and both fields are empty. They are written bare, with
nothing after the colon, because a line ending in whitespace would not survive
the editors and hooks that strip it. Archive 1 carries no `Valid-Until` either,
an absent optional field being absent rather than empty. `local-tool` names
`Archive: 1`, which is what says it will be fetched from the pool rather than
from the Debian mirror.

`Installed-Size`, `Source`, and `Size` are optional, and the stanzas above carry
them between them to show each.

`Installed-Size` is the archive's own figure, in the kibibytes [Debian Policy
5.6.20](https://www.debian.org/doc/debian-policy/ch-controlfields.html#installed-size)
defines it in rather than normalized to bytes. It can therefore be compared
against a mirror's value directly. It is an estimate. The package's build produces it from
its staged tree, so it neither measures an installed filesystem nor accounts for
the target's block size. A total over a plan is best presented as the archive's
accounting rather than as what an image will weigh.

`Size` is the length of the `.deb` in bytes, as the index states it. Installing
a plan fetches no index, so this is what bounds the download before its digest
is checked. A stanza without one leaves the download bounded by the fetcher's
own ceiling, which is weaker rather than wrong.

`Source` names the source package a binary package was built from, with any
parenthesized source version dropped. It is absent for the common case of a
source that shares the binary package's name, which is how the archive itself
says it. Reading it that way is what lets several binary packages be attributed
to the one source that produced them.

A plan the library resolved never states a `Source` equal to the package's own
name. A plan read back from a document states whatever the document does,
because the reader takes the field verbatim. A hand-written stanza naming a
source that matches therefore reads that way and is written back unchanged.
Attributing a plan by source is a question of the source name where there is
one, and the package's own name where there is not. It is not a question of
whether the field is present.

Both of a plan's lists are already ordered, so two renderings of one plan are
byte-identical. A plan that changes shows the change as a diff rather than as a
different blob.

A field a reader does not know is carried rather than refused. A document
written by a later version of the library therefore still reads here as long as
the `Format` version is unchanged. That version is bumped only for a change an
older reader would misread, and adding a field is not one.

A field that keeps its name and changes its meaning is, and version 2 is what
one of them required. In version 1, `Signed-By` named the key that made the
release signature. In version 2 it names the verifying certificate, and the
signing key has a field of its own.

A version 1 document is therefore refused rather than read. The fingerprint
under `Signed-By` answers a different question. A consumer comparing it against
a recorded one would read the difference as the archive having rotated its key.
Re-resolving against the same archive writes a version 2 document.

Carried on the way in does not mean dropped on the way out. A field this version
does not know is carried with its stanza and re-emitted after the ones it does.
Reading a plan and writing it back therefore preserves every field.

That matters because re-emitting a plan is a thing a consumer does, into a
provenance record or to normalize a file it commits. A round trip that quietly
discarded whatever a newer writer had added would corrupt exactly the record it
was kept for.

Within one version a round trip is byte-identical, carried fields included, so
re-emitting does not churn a committed file. Between two versions of this
library that share a `Format` version it is byte-identical too, in both
directions. A document the newer writes reads and re-writes unchanged through
the older. A field added to the format is written after every field the older
readers knew. That is exactly where those readers put a field they do not know
back. `Installed-Size`, `Source`, and `Size` sit after `Archive` for that
reason rather than beside the fields they describe.

What no round trip can promise is byte identity across *writers*. Another
implementation of this format might interleave its fields with the known ones
rather than append them, and a reader cannot know where they belong. Where you
need bytes that are stable against anything, digest the document you were given
rather than a re-render of it.

No line the format emits ends in whitespace, so a plan survives the editors and
pre-commit hooks that strip it. An empty field is written bare, as `Signed-By:`
with nothing after the colon. That covers `Signed-By` for a repository trusted
unsigned, and `Components` for none.

What is refused is anything that would read back as a *different* plan. That
means a package naming an archive the document does not carry, archive stanzas
numbered out of order, or a missing required field. On the writing side it also
means a value the format cannot carry on one line. So is one whose own leading
or trailing whitespace a reader would strip.

Two fields are also held to their shape, because they are what a plan install
composes rather than merely reports. A package's `Filename` is interpolated
verbatim into the URL its `.deb` is fetched from, so it is held to the same rule
an archive index's. That rule is a relative path, no `..` component, and
printable ASCII only. It holds both as written and as a server that
percent-decodes it would read it. Its `SHA256` must be 64 lowercase hex
characters, since that is the value the fetched bytes are compared against.

A document is a trust anchor, so neither check is a defense against the plan
itself. What they keep out is a plan hand-edited into something unfetchable
being reported as a mirror that served the wrong bytes. Both are checked again
at `build`, since a `Plan` taken from `resolve` and modified in memory reaches
the bootstrap without passing a reader.

## Holding a resolution to a plan's versions

[`pin`] takes the same `Plan` and does something else with it. Where [`plan`]
*replaces* a resolution, `pin` *constrains* one. The bootstrap fetches and
verifies every release and index as it always does, and computes the closure
over what the archives offer now. Each package the pin names is then selected at
the pinned version rather than at the highest offered.

```rust,no_run
use ferroday_cage::provision::debian::{Debian, Plan, Repository};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// The committed document, covering the archives and nothing else.
let kept = Plan::parse_document(&std::fs::read_to_string("archives.plan")?)?;

let mut debian = Debian::builder("trixie")
    .repository(Repository::builder("trixie")
        .mirror("file:///srv/pool")
        .trust_unsigned(true)
        .build()?)
    .include(["build-essential", "kernel-image"])
    .pin(kept)
    .build()?;
# let _ = &mut debian;
# Ok(())
# }
```

### When this is the one that fits

A build whose inputs are not all archives. Where some of the packages are
compiled by the build itself and published to a local
[pool](#publishing-a-local-pool), `plan` requires those compiles to be
byte-reproducible. It installs every package by a recorded digest, and a compile
that differs by a timestamp no longer matches its own plan. Where the compile is
not reproducible, replaying becomes unavailable for exactly the builds that most
want it. The reason has nothing to do with the archive.

Pinning only the archive-sourced packages splits the two apart. The document
fixes the half a mirror controls, meaning the versions it served. That is what a
plan exists to record, and what a source-level lock cannot pin. The locally
built half
resolves at whatever the pool now holds, its digest read from the pool's own
index as any other package's is.

### The trust model does not change

Nothing here leaves the archive signature chain. Every digest installed is still
read from an index whose own digest a verified release records. A pinned
bootstrap therefore has the trust properties of an ordinary one. That is the
difference
from `plan`, where the plan becomes the anchor. The pin narrows which version is
selected, and never becomes the authority for what the bytes are.

A pin whose recorded digest disagrees with the archive's for the same version is
refused rather than preferred. That is one version published twice over
different bytes, which is the event a recorded digest exists to catch.

### What composes, and what is refused

`include`, `exclude`, and `base_priority` all compose with a pin, where a plan
refuses them. That is the whole of what separates the two. A plan names every
package to install, so a selection has nothing to add to it. A pin names the
versions a selection resolves to, and says nothing about what is selected. The
repository list is free to differ from the one the pin was resolved against, and
the pin's own archive records are not read. A pin constrains packages.

A pin alongside a `plan` is refused at `build` with `DebianError::Config`. A
plan resolves nothing, so there is no resolution left to constrain. So is a pin
whose suite or architecture disagrees with the builder's. So is one naming the
same package twice, which states two versions to hold it at.

So is one whose entries fail the shape a plan document's do. A digest that is
not 64 lowercase hex characters is refused as the malformed entry it is. It is
not compared and reported as an archive that had published past the pin. Where
the builder names no architecture the pin's is adopted, as a plan's is.

### Every route to a version

The candidate is not the only route to a version. An `include` entry written
`name/release` takes the release's version, and a versioned dependency it needs
is taken from the same release. A layered build upgrades a name its base holds
where a dependency needs a newer one. A pinned name resolves to its pinned
version by each of these routes.

An entry naming a release that offers a pinned name only at another version
fails the resolution with `DebianError::Pin`. Taking the release's version would
resolve around the pin. Taking the pinned version from another release would
ignore the release the entry names. A versioned dependency the pinned version
does not meet fails it the same way, where no other alternative answers it. The
pin or the install list has to change.

A layered build upgrades a pinned name to its pinned version alone, where that
is above the installed version. That holds whatever the rank of the release
offering it, as it does for the candidate. A name the base holds and nothing
upgrades keeps the base's version. The pin constrains what a resolution
selects, and the base is not selected.

### When the archives have moved past it

A pin the archives cannot supply fails the resolve or the bootstrap with
`DebianError::Pin`, before the closure is computed and before anything is
downloaded. It names every package that could not be held at once, in name
order, since one archive publish moves many together. For each it says which of
three things happened. The archives offer another version, offer no version of
it at all, or record different bytes for the one pinned.

A live mirror serving a single version per suite will move past a pin as soon as
it publishes. A [snapshot mirror](#installing-a-plan-without-resolving-again) is
what holds one open, and it is the same configuration a replayed plan uses.

## A reproducible root

A plan fixes which packages a bootstrap installs. What their configuration
writes is a second input, because the maintainer scripts run tools that date
what they write from the clock. The ones a bootstrap reaches create accounts:
`useradd`, `pwconv`, and `systemd-sysusers` record the day of each account's
last password change in `/etc/shadow`. [`source_date_epoch`] states that date
instead. Every maintainer script receives it as `SOURCE_DATE_EPOCH`, the
reproducible-builds convention, so each account records the epoch's day rather
than the day the bootstrap ran.

An epoch in the first day of 1970 records an empty field instead. A day of zero
is a demand for a new password to `/etc/shadow`. The shadow suite's tools leave
the field empty for that day, and `systemd-sysusers` writes a zero. The
bootstrap empties each zero its run wrote once the scripts have run.

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::{self, Export, debian::{Debian, Plan}};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// One date for the whole build: the time of the source's last change.
const EPOCH: i64 = 1_700_000_000;

let kept = Plan::parse_document(&std::fs::read_to_string("trixie.plan")?)?;
let mut debian = Debian::builder("trixie")
    .plan(kept)
    .identity_map(IdentityMap::Subordinate)
    .source_date_epoch(EPOCH)
    .build()?;
provision::ensure("/srv/images/trixie", &mut debian)?;

Export::new("/srv/images/trixie")
    .identity_map(IdentityMap::Subordinate)
    .clamp_mtime(EPOCH)
    .write_to_path("trixie.tar")?;
# Ok(())
# }
```

The epoch is a plain timestamp, the same number a pipeline gives
[`Export::clamp_mtime`] and [`Pool::date`]. The epoch dates what the scripts
write, and the clamp caps the modification times the archive records. With
both, two bootstraps of one plan export byte-identical archives, even on
different days at different paths. A package that generates a secret of its own
is the exception. A layered build passes the epoch to its increment's scripts in the same
way. At a shell prompt, `--debian-source-date-epoch EPOCH` sets it.

A negative epoch is refused at `build` with `DebianError::Config`, because the
account tools read the variable as unsigned and date from the clock instead.
The epoch is a moment already past: the shadow tools refuse one later than the
build host's clock.

### What a bootstrap does not keep

Some of what configuration writes carries its run whatever the date. Every
bootstrap removes these once its last configure wave has run, with or without an
epoch:

- `/var/log/dpkg.log` and `/var/log/alternatives.log`, which time-stamp every
  action the waves took.
- `/var/cache/ldconfig/aux-cache`, which records the inode and change time of
  every library `ldconfig` read. `ldconfig` rebuilds it on its next run.
- `/var/lib/dbus/machine-id`, D-Bus's copy of the machine id. D-Bus reads
  `/etc/machine-id` when its own copy is absent.

The list matches what `mmdebstrap` removes by default, less the apt logs a
bootstrap that drives dpkg directly never writes. A layered build removes the
same files from its upper. Where the increment's run deleted the base's copy,
the upper records that deletion, and the record is kept so the base's copy stays
hidden.

Where a package wrote `/etc/machine-id`, as `systemd`'s configuration does, the
file is kept and emptied. It is emptied in place, keeping the owner and mode the
package gave it. The id `systemd` writes is random, and every machine
deployed from the root would otherwise share it. An empty file is one of the two
states `machine-id(5)` gives a generic image. From it, `systemd` generates a
fresh id at boot without treating that boot as a first boot. A deployment that
wants first-boot behavior, unit presets and `ConditionFirstBoot=` units, removes
the file.

A sandbox has no such boot, so a program that asks for the machine id inside one
finds none until one is generated. `systemd-machine-id-setup`, run in the root,
writes `/etc/machine-id`, which D-Bus reads as well. In a root without
`systemd`, `dbus-uuidgen --ensure` writes D-Bus's own copy.

### What stays the caller's

A package that generates a secret for its own service during configuration makes
the root differ however the bootstrap is dated. `openssh-server` is the common
one: its configuration generates the SSH host keys, which every machine deployed
from the root would share. Removing them is the deployment's decision, because
something must generate new ones before `sshd` starts. On trixie that is
`sshd-keygen.service`, which runs on a first boot, so a deployment that removes
the keys also removes `/etc/machine-id`.

## Asking what an archive carries

[`available`] answers a different question. Not what a bootstrap would install,
but which names the configured archives offer at all. It runs the same read
half, each repository's signed release and index, merged, and returns the name
set rather than a closure:

```rust,no_run
use ferroday_cage::provision::debian::Debian;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut debian = Debian::builder("trixie").build()?;
let available = debian.available()?;

for name in ["build-essential", "awk", "no-such-package"] {
    println!("{name}: {}", available.contains(name));
}
// A virtual name reports what satisfies it.
for provider in available.providers("awk") {
    println!("awk is provided by {provider}");
}
# Ok(())
# }
```

`resolve` cannot stand in for this, and neither of its behaviors is a defect. A
resolve *fails* where a name cannot be satisfied, rather than answering a
question about it. That covers a top-level `include` that names nothing, and a
transitive dependency nothing supplies. It does name every one of them rather
than the first, so a failed resolve is a usable list of what to correct.

But it is still a failure, and it is a failure about a whole closure. A name
that is perfectly available can appear in one because something else in its
dependency tree is not. Nor is the cost the same. One `available` pass answers
any number of names, where a resolve per name re-fetches and re-parses the index
every time. A `Packages.xz` for trixie amd64 is around 9 MB, and `cache_dir`
caches `.deb` files, not indexes.

Availability is answered at the level of the name. `contains` reports that the
archives offer a name, not that they offer a version satisfying some constraint.
The resolver does enforce a dependency's version constraint, since a layered
resolve closes over a base provisioned at some earlier archive state. But that
is a question about a particular closure, and this query computes none.
Answering it here would mean resolving, which is the cost `available` exists to
avoid.

The builder's `include`, `exclude`, and `base_priority` shape a resolution and
so do not apply. The suite, the architecture, the repositories, and the fetcher
are what the query reads. `Available` is a snapshot. An archive can publish at
any time, so a name it reports is a name that was there when the index was
read.

## Layered build roots

A pipeline that builds many packages against one shared base need not
re-provision the shared part each time. Such a build root is `base + toolchain +
this component's build-dependencies`, rebuilt per component. Provision the base
once, then stage each component's increment over it as a disposable overlay
layer. [`base_layer`] marks the pristine base. [`stage_layer`] resolves and
installs only the packages the base does not already carry into an overlay
upper, leaving the base untouched.

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

The example lives at `crates/ferroday-cage/examples/deb-layer-pipeline.rs`. It
carries the shape above through a whole pipeline: one shared base, and a
disposable layer per component. A local pool lets each component build against
the packages the ones before it produced.

The increment resolves against the base's *already-installed set*, read from the
base's own dpkg status database. Every package the base configured, and the
virtual packages they provide, is treated as satisfied, so the resolution closes
over only the delta. Most components share build-dependencies already present in
`base + toolchain`, so that delta is small, which is the point.
[`resolve_layer`] previews it without staging, the layered counterpart of
[`resolve`], so a build-root cache can be keyed on the increment inline.

A plan reproduces a layer exactly as it reproduces a whole root. Keep the one
[`resolve_layer`] returned and hand it back through [`plan`] alongside the same
[`base_layer`]. `stage_layer` then installs those packages at those versions
without fetching a release or an index. That is the increment's counterpart of
[installing a plan](#installing-a-plan-without-resolving-again) as a whole root.

`stage_layer` installs the delta into the overlay upper and returns a
[`BuildLayer`]. Root a sandbox on [`overlay_rootfs`] with the base as the
read-only lower and the layer's `path()` as the writable upper. The build then
sees the merged view, every write lands in the upper, and the base is never
mutated.

The increment's files land in the upper where the mounted overlay would place
them. A directory of the increment's never hides a link the base holds. The
base decides the layout: no merged-usr links are laid into the upper, and a
package's `/bin` entry goes wherever the base's own `/bin` leads. A base
directory the increment writes beneath keeps its owner, group, mode, and
extended attributes in the upper, as the overlay's own copy-up keeps them.

Dropping the `BuildLayer` removes the upper, and the overlay work directory
beside it, reverting the increment and leaving the base ready for the next
component. A `stage_layer` that fails disposes of an upper it created, since it
hands the caller no handle to drop. An upper that already existed is the
caller's, and a failure leaves it in place.

The base must be a full, configured bootstrap, not an
[`extract_only`](#extract-only-and-foreign-architectures) tree. The overlay's
lower supplies the dpkg database the increment's configuration reads. A base and
its layers must share a suite, an architecture, and an [identity
map](identity-maps.md). A base configured under one map carries ownership a
layer under another would not agree with.

The increment is always configured. Running dpkg over the merged view is what
registers it in the base's database, so `extract_only` alongside `base_layer` is
refused at `build`. An extract-only increment would leave files in the merged
root that no database records.

The increment's configuration runs the target's binaries, so a foreign
architecture needs the same `qemu-user` binfmt handler a full bootstrap does.
Staging roots a sandbox on an unprivileged overlay, which the host must support.
[Overlay-rooted sandboxes](host-requirements.md#overlay-rooted-cages) covers it,
and [`host::overlay_blocker`] reports it. `stage_layer` refuses a host that
cannot establish one before downloading anything.

## The pre-configure overlay

[`pre_configure_overlay`] lays a directory of configuration into the tree once
every package is unpacked and before the configure wave. The configuration
scripts that wave runs therefore observe the injected values, whether those are
a debconf pre-seed, a locale selection, or a hardware-probe guard:

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

The source is a root-shaped tree, so `./rootfs-config/etc/locale.gen` becomes
`/etc/locale.gen`. File modes and symlinks are preserved. A file replaces the
package's own copy of the same path, which is how a shipped conffile is
overridden. The tree is laid with the same kernel-enforced containment as
package extraction, so nothing in it can be written outside the destination.

The overlay does not reach every script. Unpacking runs each package's
`preinst`, so every `preinst` has run before the overlay is laid. A full
bootstrap also installs and configures six core packages first: `base-passwd`,
`base-files`, `dpkg`, `libc6`, `perl-base`, and `mawk`. Every other package's
`postinst` runs after the overlay, essential packages included. A layered build
lays the overlay into its increment the same way, even when the increment
installs nothing. An extract-only bootstrap runs no script and ignores it.

Entries land owned by the calling user, which the identity map presents as root
inside. A tree that has to ship a file owned by some other in-tree id wants
[`CopyIn`](provisioning.md#copying-a-tree-into-a-rootfs) instead, which lays one
in through the map.

## Trust

Authenticity comes from the archive's OpenPGP signature, not the transport, so
packages are fetched over plain HTTP by default. The `InRelease` signature is
verified against an embedded copy of the Debian archive keyring. Every index and
every package is then checked against a SHA-256 digest that chains back to that
signature.

Nothing signed states how large the `InRelease` is, so it is held to a ceiling
of one mebibyte, four times the largest an archive serves. Verification also
refuses a document carrying more than 16 signatures. Each bound keeps a mirror
from choosing how much work checking its answer costs. A release past one is
refused, never read short.

A different keyring is supplied with [`keyring`]. `build` reads and parses it, so
a file that holds no usable key is refused there, before anything is fetched.
[`trust_unsigned`] accepts an unsigned `Release` for a local mirror under the
caller's control, the equivalent of apt's `trusted=yes`. It removes the only
authenticity check, leaving the transport to supply one. So `build` requires a
transport that does: every mirror of an unsigned repository must be `file://` or
`https://`. Any other scheme is refused, `http://` among them.

The rule is an allow-list rather than a refusal of `http://`. A refusal names
only the plaintext scheme it was written for, and a caller-supplied transport
can speak any of them. Schemes are compared case-insensitively, as [RFC 3986
§3.1] defines them. A transport routing on the scheme itself reads it from
[`FetchRequest::scheme`], which applies the same rule. The two layers therefore
cannot disagree about which URLs name which transport.

The signature alone does not say which suite was delivered, because a single
archive key signs every suite. So the release is also bound to the request. Its
`Suite` or `Codename` must equal the requested suite. That stops a mirror from
answering a request for one suite with a genuine, validly-signed release for
another.

Key validity is enforced beyond the cryptographic check, which on its own
accepts a signature from any key whose material fits. A signature by a revoked
archive key is refused, and the refusal names the revocation and the key. A
signature made outside its signing key's validity window is rejected, whether
before the key existed or after it expired. So is one by a key that has expired
since, though dated within the window: the date is the signer's claim. A retired
key therefore cannot vouch for a release. A host whose clock reads before 1970
refuses every release, since no window can be judged against it.

Debian's archive keys sign with a dedicated signing subkey rather than the
primary. A subkey is admitted only on the terms OpenPGP sets for one. The primary must have bound it with the
signing capability, the subkey must have counter-signed that binding, and the
binding must not be revoked.

A primary key signs a release itself only where its certificate grants it the
signing capability. The grant is read from the certificate's own
self-signatures, and one that states no capabilities grants none. A certify-only
primary vouches for its subkeys and is refused as a signer, as GnuPG and Sequoia
refuse it.

Where a subkey has been re-bound over time, the newest binding the primary
issued is the one judged. It is the certificate's latest word on that subkey. A
defect in it therefore refuses the subkey, rather than returning authority to
the superseded and possibly broader grant it replaced. A subkey's authority is
delegated from its primary, so it lapses when the primary's does. The expiry
that governs is whichever of the certificate's, the binding's and the
counter-signature's comes first.

A keyring holding several keys is searched in full, and every signature a key
made is judged. A release is therefore accepted whenever any of its signatures
is acceptable.

Beyond the key, the signature itself has to be worth resting a decision on. It
is a text signature, the type a cleartext-signed document carries. It carries a
creation time, every check being relative to it, no more than 30 minutes ahead
of the host's clock. Its digest is SHA-2 or SHA-3, never MD5, SHA-1 or
RIPEMD-160, whose collisions are within reach. The signing key and the
certificate behind it are each Ed25519, or RSA of 2048 to 8192 bits. A signature
is worth no more than the weaker of the digest it covers and the key material
that binds it.

A certificate's own signatures rest on the same digests. A subkey's binding and
its counter-signature always do. One exception is a self-signature over the
primary key made before 1 February 2023, which is also accepted over SHA-1.
Archive keys of that age were self-signed over SHA-1 alone, and GnuPG accepts
them too. From that date, the one from which Sequoia refuses SHA-1 there, the
self-signature rests on SHA-2 or SHA-3.

It also carries no critical subpacket that cannot be interpreted, which RFC 9580
requires a verifier meeting one to treat as invalidating. Only the signed part
of a signature is searched for such a subpacket, so a relay cannot append one in
transit and fail every fetch.

The release must also be fresh. A `Valid-Until` the release carries must be
parseable and in the future, and the archive signature must not itself have
expired. That refuses a stale but validly-signed release, which a mirror or an
on-path attacker could otherwise replay to deliver superseded, potentially
vulnerable packages.

A release that omits `Valid-Until` carries no freshness bound and is accepted,
as apt accepts it. The Debian stable suite does exactly that, so its release
does not expire between point releases. [`allow_stale_release`] relaxes the
freshness check entirely, the signature still being verified. It is for the
legitimate case of pinning a historical archive state, such as a
`snapshot.debian.org` suite. A key that signed that state must still be in
force. A `trust_unsigned` mirror is never freshness-checked.

The transport is a trait. The built-in fetcher speaks plain HTTP and `file://`,
addressing a mirror by DNS name, IPv4 literal, or bracketed IPv6 literal
(`http://[::1]:8080/debian`). A consumer that needs HTTPS, a proxy, or a private
mirror protocol supplies their own through [`fetcher`].

A `file://` URL names a path on the machine it is read on, in either of RFC
8089's spellings for that: `file:///srv/pool` and `file://localhost/srv/pool`.
One naming any other host is refused rather than read as a path relative to the
current directory. [`file_url`] builds the URL for a local path, and is what
[`Pool::mirror_url`] answers with. It makes a relative path absolute. Such a URL
carries a path from a root and has no way to spell one that is not.

[`file_url`] writes a byte a URL cannot hold as written as a percent escape, so
`/srv/My Pool` becomes `file:///srv/My%20Pool`. The bundled fetcher and apt both
decode it back into the path. A mirror URL is one word of the finished tree's
`sources.list`, so one carrying whitespace or a control character is refused at
`build`.

A transport is `Send`, because the provisioner owns it and is itself `Send`.
[Thread bounds](stability.md#thread-bounds) covers the rule.

The bundled fetcher holds its connection open between requests, as HTTP/1.1 does
by default. A bootstrap installing a few hundred packages from one host
therefore pays one handshake rather than a few hundred.

A bootstrap is nearly all network on a cold cache. The packages it is about to
install are therefore asked for in batches through `Fetch::fetch_all`, before
the package-by-package wave runs. That method has a default body, one `fetch`
per job in order. A transport that overrides nothing therefore behaves exactly
as it did before it existed.

`HttpFetch` overrides it and runs four at once, each on a connection of its own.
`HttpFetch::concurrency` changes how many. The ceiling is deliberately low. An
archive mirror is usually somebody else's bandwidth, and the win is in
overlapping latency rather than in saturating a link.

The batch decides nothing. A job it does not deliver simply leaves the cache
without that package. The wave behind it then downloads that package with every
mirror available to it, exactly as though the batch had not run. Whether a
package is present is still the rename, and the rename happens only over bytes
that verified. A canceled bootstrap stops at the end of a batch, not part way
through it. The transport writes a batch's bodies from threads of its own.

A transport therefore sees calls from more than one thread only when it says so,
by overriding `fetch_all`. The default body, and every `fetch`, run on the
thread that called into the provisioner.

## Ownership

The bootstrap's [identity map](identity-maps.md) decides the ownership the
finished tree carries, and the right map follows from what the tree is for.

The default is the single-identity map. The sandbox maps the calling user to
root and nothing else, so every file in the bootstrapped tree is owned by root.
Debian expects some files to belong to other system users and groups, and those
ownerships cannot be represented under this map. The bootstrap reconciles the
difference by recording the intended overrides in dpkg's database, and
neutralizing the ownership changes that would otherwise fail. Configuration then
completes, and the tree is internally consistent.

The result is a working userland whose files are uniformly root-owned. That is
exactly right for a build or run environment consumed back inside
single-identity sandboxes, which cannot observe the flattening. Its caller-owned
output also needs no extra host support to copy or delete.

Neutralizing substitutes the `chown` and `chgrp` **commands**, so it covers a
maintainer script that shells out to one and nothing further. A script that
changes ownership through a compiled helper reaches the kernel directly and
fails with `EINVAL`. So does any POSIX ACL naming an id the map does not hold.
`setfacl` is not substituted at all: dpkg's database has no record for an ACL,
and a stub would discard the intent rather than defer it.

Packages that do either cannot configure under the single-identity map. The one
most installations meet is `systemd`, whose `postinst` runs `systemd-tmpfiles
--create`. That calls `fchownat()` and `acl_set_file()` itself, reports `Invalid
argument`, and fails the wave. A layered build is no way around it, since an
increment runs under the map of the base it increments. The fix is to give such
a tree a range map, where the ids are real and nothing is substituted.

The overrides are recorded one per path. dpkg treats two records for one path as
an unrecoverable fatal error, and an install set reaches that honestly. Two
selected packages can ship one path, since the resolver reads `Depends` and
`Provides` and never `Conflicts`.

Where that happens the last record wins, which is the extraction's own rule: a
later entry supersedes an earlier one. The record therefore describes the file
that survived. A layered build lays the increment's records over the base's the
same way.

A tree that is itself the product, whether deployed, exported, or run under a
range map, wants real ownership, and
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

Under the subordinate map the system ids genuinely exist. Every `chown` a
maintainer script or compiled tool performs happens for real, and no stub or
override is involved. The tree is a correct Debian system as `dpkg` and
`base-passwd` define one.

The map requires the `subid` feature and a host that can establish it. A
bootstrap that cannot fails before any download, rather than falling back to the
flattened form. A site-specific delegate establishes the map instead where one
is supplied through `id_mapper`, as [Identity maps](identity-maps.md) describes
for a sandbox. Because the ownership is real, it reaches the host. A directory
the system chowns to a non-root id refuses the plain caller's removal.
[`provision::remove`](provisioning.md#removing-a-rootfs) deletes the produced
tree either way, re-entering the map where ownership requires it.

## Extract-only and foreign architectures

The bootstrap targets the host architecture by default, and another is selected
with [`architecture`]. A full bootstrap for a foreign architecture runs that
architecture's dpkg and maintainer scripts. It therefore requires a registered
`qemu-user` binfmt handler, covered in [Host
requirements](host-requirements.md). The bootstrap checks for one and reports an
actionable error when it is absent.

Where the foreign binaries cannot run, `extract_only` lays out the packages'
files without configuring them. An extract-only tree has run no maintainer
scripts and has no configured dpkg database. It is the raw file tree, suitable
for completing the configuration elsewhere.

### Recording which interpreter ran

A changed emulator silently changes compiled output, so a build that publishes
artifacts wants the interpreter in its signature. [`foreign_interpreter`] reports
it, read from the kernel's own `binfmt_misc` registration:

```rust,no_run
use ferroday_cage::provision::debian::foreign_interpreter;

match foreign_interpreter("arm64") {
    Some(interpreter) => println!(
        "{} through {} (enabled: {}, flags: {})",
        interpreter.name,
        interpreter.path.display(),
        interpreter.enabled,
        interpreter.flags,
    ),
    None => println!("nothing emulated: run natively, or no handler registered"),
}
```

The registration is the right source, and a `PATH` lookup is not. The kernel
reaches the interpreter through the registration, so the two can disagree. A
build under a harness that strips `PATH` records no interpreter at all, while
one is executing every target binary.

`None` is returned in three cases, each the honest answer rather than a failure.
The host runs the architecture natively, the architecture is not one a
`qemu-user` handler covers, or no handler is registered. A registered handler
that is switched off reports as present and not enabled, which is the difference
between "turn it on" and "install it".

Two paths are reported because they are two facts. `path` is what the kernel
recorded, and `resolved` is what it canonicalizes to. On the common Debian
layout the registration names a wrapper,
`/usr/libexec/qemu-binfmt/aarch64-binfmt-P`, that is a symlink to the real
binary. Repointing that symlink changes the interpreter without changing the
registration.

**Hash the path rather than probing the binary.** qemu refuses to run under its
binfmt wrapper name:

```console
$ /usr/libexec/qemu-binfmt/aarch64-binfmt-P --version
qemu: /usr/libexec/qemu-binfmt/aarch64-binfmt-P has to be run using kernel
binfmt-misc subsystem
```

So the registered path is good for identity and not for interrogation. Hashing
it works unchanged, since `open` follows the symlink and no canonicalization is
needed. It is the better answer anyway: a version string is a claim the binary
makes about itself, and a digest is what it is. Only executing the interpreter
needs `resolved`.

The digest is the caller's to take. The `F` flag means the kernel opened and
holds the interpreter at *registration* time. The file at that path might have
been replaced since, so a digest taken now can be of something that never ran.
The library reports the path and states the caveat rather than handing back a
digest that can be quietly wrong.

## The command line

`fcage --provision-debian SUITE` bootstraps the `--rootfs` directory before
launching. Given without a command, it provisions and exits. The
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
`--debian-components` take comma-separated lists, and each can be repeated.

[`keyring`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.keyring
[`trust_unsigned`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.trust_unsigned
[`allow_stale_release`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.allow_stale_release
[`fetcher`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.fetcher
[`architecture`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.architecture
[`resolve`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.resolve
[`available`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.available
[`plan`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.plan
[`pin`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.pin
[`foreign_interpreter`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/fn.foreign_interpreter.html
[`pre_configure_overlay`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.pre_configure_overlay
[`source_date_epoch`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.source_date_epoch
[`Repository`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Repository.html
[`repository`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.repository
[`mirror_fallback`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.mirror_fallback
[`name`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.RepositoryBuilder.html#method.name
[`Pool`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html
[`Pool::mirror_url`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.mirror_url
[`file_url`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/fn.file_url.html
[`FetchRequest::scheme`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/struct.FetchRequest.html#method.scheme
[`Pool::release_path`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.release_path
[`Pool::dists_dir`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.dists_dir
[`Pool::date`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Pool.html#method.date
[`Export::clamp_mtime`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/struct.Export.html#method.clamp_mtime
[`base_layer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.base_layer
[`stage_layer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.stage_layer
[`resolve_layer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.resolve_layer
[`BuildLayer`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/struct.BuildLayer.html
[`overlay_rootfs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.overlay_rootfs
[`host::overlay_blocker`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.overlay_blocker.html
[RFC 3986 §3.1]: https://www.rfc-editor.org/rfc/rfc3986#section-3.1
