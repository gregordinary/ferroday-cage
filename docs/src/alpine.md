# An Alpine userland

The `alpine` feature provisions an Alpine Linux root filesystem: it resolves a
package set from an apk repository and installs it, so a sandbox can build or run
software from a userland the library assembles for it. It speaks to the archive
directly — a pure-Rust replacement for `apk add --root` — and runs each package's
install scripts inside a cage of its own.

```rust,no_run
use ferroday_cage::provision::{self, alpine::Alpine};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut alpine = Alpine::builder("v3.23")
    .include(["alpine-base", "build-base"])
    .cache_dir("/var/cache/fcage/apk")
    .build()?;
provision::ensure("/var/lib/machines/alpine", &mut alpine)?;
# Ok(())
# }
```

`Alpine` implements [`Provisioner`](provisioning.md), so `provision::ensure`
publishes the result atomically: the destination directory either does not exist
or holds a complete, configured rootfs.

The surface mirrors [the Debian layer's](debian.md) closely enough that a
consumer of one recognizes the other — the same builder setters, the same
`resolve`/`available`/`plan`/`pin` pair of read and replay modes, the same
layered build, and an `observe()` sink over `AlpineEvent` carrying the same
progress. What differs is listed under [Where the two layers
differ](#where-the-two-layers-differ), and every difference is one the archives
themselves make.

The `musl-build` example works this into a consumer: it provisions a root with
the toolchain and links a C project statically against musl, which is the thing
an Alpine root is most often reached for.

## How it works

A bootstrap runs in stages:

1. **The signed index.** It fetches each repository's `APKINDEX.tar.gz`, verifies
   the RSA signature against the repository's keys, and parses the records. There
   is no release document above the index: the index *is* the signed thing.
2. **The package set.** It resolves the closure over what `include` names —
   dependencies, virtual providers, and `install_if` conditions to a fixed point
   — against the merged records of every configured repository.
3. **Download and verify.** It downloads each package and binds it to the index
   that named it before anything is unpacked. See [Trust](#trust).
4. **Extraction and scripts.** It lays every package's files down in one wave and
   runs the install scripts in a second, both in dependency order, then fires the
   triggers whose watched directories the install changed. The scripts run inside
   a cage rooted at the staging tree, so they need no privilege on the host. When
   they have run, the bootstrap clears [what the run leaves
   behind](#what-a-bootstrap-does-not-keep) and publishes the root filesystem.

The finished root carries `/lib/apk/db/installed`, `/etc/apk/world`,
`/etc/apk/repositories`, `/etc/apk/arch` and the repositories' trusted keys, so
an `apk` inside it reads back the state this bootstrap wrote and can go on
installing. `world` is what `include` named, which is what a later `apk` treats
as wanted; a bootstrap installing a `plan` writes every package the plan names,
since a plan is the whole closure and records no seeds.

## Selecting packages

The install set is exactly what `include` names, closed over its dependencies,
minus what `exclude` removes. There is no base system underneath it.

That is the sharpest practical difference from the Debian layer, and it follows
from the archive: apk records no priority for a package, so there is no band to
seed from and nothing corresponds to `base_priority`. A root that names only a
compiler has only a compiler and its dependencies — no shell, no `apk` binary, no
`/etc/passwd` — because nothing in that closure happens to require one.

```rust,no_run
use ferroday_cage::provision::alpine::Alpine;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// A conventional minimal system, which is a package like any other.
let _system = Alpine::builder("v3.23").include(["alpine-base"]).build()?;

// A build root that is only what a build needs. `busybox-binsh` is named
// because it ships /bin/sh, which the toolchain's closure does not require.
let _build = Alpine::builder("v3.23")
    .include(["build-base", "busybox-binsh"])
    .build()?;
# Ok(())
# }
```

`alpine-base` is the package Alpine's own minimal images are built from, and
naming it gives the familiar system: `busybox`, `apk-tools`, the layout packages,
and the signing keys. Naming nothing at all is refused rather than resolving an
empty root.

`exclude` removes a package from the closure. An excluded package that something
in the closure genuinely requires fails the resolve rather than producing a
broken root.

## Repositories

A bootstrap resolves against one or more repositories. The builder's `mirror`,
`components` and `keys` setters configure the primary — a single-mirror bootstrap
needs no repository at all — and [`repository`] merges in additional sources,
each with its own [`KeySet`], so multiplying repositories repeats the
authenticity check per source rather than weakening it.

Resolution is highest-version-wins across the merged repositories. An exact tie
resolves to the *later* repository, which is what makes an additional repository
an overlay: a package it republishes at the version the primary already offers is
the one that wins.

### Two layouts, one type

Alpine publishes `<release>/<component>/<architecture>`; postmarketOS publishes
`<release>/<architecture>`, with no component level at all. A repository that
names no components takes the second layout, and that is the whole of the
difference between them:

```rust,no_run
use ferroday_cage::provision::{self, alpine::{Alpine, KeySet, Repository}};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let postmarketos = Repository::builder("v26.06")
    .mirror("http://mirror.postmarketos.org/postmarketos")
    .keys(KeySet::postmarketos())
    .build()?;

let mut alpine = Alpine::builder("v3.23")
    .repository(postmarketos)
    .include(["alpine-base", "postmarketos-baselayout"])
    .build()?;
provision::ensure("/var/lib/machines/pmos", &mut alpine)?;
# Ok(())
# }
```

postmarketOS is an overlay rather than a distribution — a postmarketOS root is
Alpine's repositories plus its own — so it is configured as an additional
repository and never as the primary. Its release cycle is its own: `v26.06`
against Alpine's `v3.23`.

Both of its ways of overriding an Alpine package fall out of the merge rather
than needing anything of their own. It republishes `akms` at `99990.3.0-r1`, a
version no Alpine release will reach, so the higher version wins wherever the
repository sits in the order; and `postmarketos-base` *provides*
`alpine-base=1000-r0`, so asking for `alpine-base` with the overlay configured
resolves postmarketOS's base system instead of Alpine's. Both are what `apk`
does with the same two repositories configured.

### Where a package's bytes come from

An apk repository publishes one index per component, and a package is addressed
relative to the directory its own index sits in. So the unit a resolution
attributes a package to is the *index*, not the repository: a repository
configured with `main` and `community` contributes two, and `plan.indexes`
records each one's mirror, component, digest, and the key whose signature over it
verified.

```rust,no_run
use ferroday_cage::provision::alpine::Alpine;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut alpine = Alpine::builder("v3.23").include(["alpine-base"]).build()?;
let plan = alpine.resolve()?;
for package in &plan.packages {
    let index = &plan.indexes[package.index];
    println!(
        "{} {} <- {} ({})",
        package.name,
        package.version,
        index.mirror,
        index.component.as_deref().unwrap_or("no component"),
    );
}
# Ok(())
# }
```

## The package cache

`cache_dir` keeps downloaded packages for reuse across bootstraps. Every entry is
re-verified in full on every read: the control segment's identity against the
plan, and `datahash` over the file tree. Its own signature is read and not
verified, exactly as for a fresh download (see [Trust](#trust)). An entry that
does not read back as the package the plan names is downloaded again rather
than refused.

It has to work that way, and the reason is a real difference from the Debian
pool: an apk index publishes no digest of the whole `.apk` file, so there is no
content address to name a cache entry by. Entries are keyed by published file
name instead, and the full re-verification is what makes that safe.

A package is never held in memory: the bytes are written to a staging file as
they arrive, and installing reads that file back.

## Resolving, replaying, and pinning

[`resolve`] reports what a bootstrap would install without installing it, and a
full bootstrap emits the same plan through `AlpineEvent::Resolved` before the
first download. [`plan`] hands a resolved `Plan` back to the bootstrap, which
then fetches exactly what it records and never reads an index; [`pin`] instead
*constrains* a fresh resolution to the versions a plan recorded. The three behave
exactly as [their Debian counterparts](debian.md#the-resolved-plan) do, including
what a plan refuses to compose with and the trust model a plan carries, so that
chapter is the reference for all of it.

One refusal is this layer's own, and it follows from where an apk package lives.
A package is fetched from the directory of the index that named it, so the
correspondence between a plan's indexes and the configured repositories is
positional: index *i* of the plan is served by whichever repository publishes the
*i*th index. `build` therefore refuses a plan that records more indexes than the
configuration publishes, and one whose index *i* is not the release and component
the configured repository publishes there — both of which would otherwise compose
URLs no mirror serves and fail as an exhausted mirror walk. The mirror a plan
records is deliberately *not* compared: a plan carried to another configuration
fetches over that configuration's mirrors, which is what makes it portable.

A plan is written and read as a document with `to_document` and
`parse_document`. The syntax is the same field-and-stanza form the Debian plan
uses — it reads in a terminal and diffs in a review — but the vocabulary and the
format version are this layer's, and the two are separate formats:

```text
Format: ferroday-cage-alpine-plan 1
Release: v3.23
Architecture: x86_64

Index: 0
Mirror: http://dl-cdn.alpinelinux.org/alpine
Release: v3.23
Component: main
SHA256: 4c1d...
Signed-By: alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub
Description: v3.23.5-112-gd78b27bd62b

Package: musl
Version: 1.2.5-r23
Architecture: x86_64
Control-Identity: Q1G2xQQm08BlbpxaVnpaWWAcf0MHo=
Index: 0
Size: 405504
Installed-Size: 622592
```

An index's stanza records what an apk repository can be pinned to and no more.
There is no `Date` and no `Valid-Until`, because the format carries neither;
`Description` is the archive's own build string, recorded as a fact about the
publication rather than read for meaning. `Component` is absent rather than empty
for the componentless layout, a repository that publishes no component and one
that publishes an unnamed one not being the same repository.

`Size`, `Installed-Size` and `Origin` are optional. `Origin` names the source
package a package was split from and is absent for the common case of a source
that shares its name, which is how the index itself says it — the same reading
the Debian document's `Source` takes.

The rest behaves as the Debian document does, and for the same reasons: a field a
reader does not know is carried and re-emitted after the ones it does, both lists
are already ordered so two renderings are byte-identical, and no line ends in
whitespace.

## A reproducible root

A plan fixes which packages a bootstrap installs. What the install scripts write
is a second input, because the accounts they create are dated. Alpine's scripts
create them with busybox's `adduser`. It records the day it ran as each new
account's last password change in `/etc/shadow`, and it reads no
`SOURCE_DATE_EPOCH`.

[`source_date_epoch`] states that date instead. Every script receives it as
`SOURCE_DATE_EPOCH`, for the tools that read it. Once the scripts have run,
every day the run wrote into `/etc/shadow` becomes the epoch's day. So does every
such day in `/etc/shadow-`, the previous version busybox keeps beside it. The
days a package shipped are kept. An epoch in the first day of 1970 records an
empty field instead, as `useradd` does, because `/etc/shadow` reads a day of
zero as a demand for a new password.

```rust,no_run
use ferroday_cage::provision::{self, Export, alpine::{Alpine, Plan}};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// One date for the whole build: the time of the source's last change.
const EPOCH: i64 = 1_700_000_000;

let kept = Plan::parse_document(&std::fs::read_to_string("v3.23.plan")?)?;
let mut alpine = Alpine::builder("v3.23")
    .plan(kept)
    .source_date_epoch(EPOCH)
    .build()?;
provision::ensure("/srv/images/alpine", &mut alpine)?;

Export::new("/srv/images/alpine")
    .clamp_mtime(EPOCH)
    .write_to_path("alpine.tar")?;
# Ok(())
# }
```

The epoch dates what the scripts write, and [`Export::clamp_mtime`] caps the
modification times the archive records. With both, two bootstraps of one plan
export byte-identical archives, even on different days at different paths. A
package that generates a secret of its own is the exception. A layered build
dates the accounts its increment creates in its upper.

### What a bootstrap does not keep

A bootstrap keeps no machine id its scripts generated. `dbus`'s install script
writes a random `/etc/machine-id`, which every machine deployed from the root
would share. The bootstrap removes it once the scripts and triggers have run,
and a layered build removes it from its upper.

The [Debian layer](debian.md#what-a-bootstrap-does-not-keep) empties the same
file instead, and the init system is the reason. `systemd` generates an id from
an empty file. On Alpine the id comes from `dbus`'s service, which runs
`dbus-uuidgen --ensure=/etc/machine-id` before it starts, and from OpenRC's
`machine-id` service. Both generate an id where the file is missing. An empty
file makes `dbus-uuidgen` fail, and the system bus with it.

A sandbox has no boot, so a program that asks for the machine id inside one finds
none until `dbus-uuidgen --ensure=/etc/machine-id` runs in the root.

## Layered build roots

`base_layer`, `resolve_layer` and `stage_layer` work as [the Debian layer's
do](debian.md#layered-build-roots): provision a shared base once, then stage each
increment over it into a disposable overlay upper, and root a cage on
[`overlay_rootfs`] with the base as the lower.

```rust,no_run
use ferroday_cage::Cage;
use ferroday_cage::provision::{self, alpine::Alpine};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let base = "/var/cache/build/base-alpine";
provision::ensure(
    base,
    &mut Alpine::builder("v3.23").include(["alpine-base", "build-base"]).build()?,
)?;

let layer = Alpine::builder("v3.23")
    .base_layer(base)
    .include(["openssl-dev"])
    .build()?
    .stage_layer("/var/cache/build/component-upper")?;

let status = Cage::builder()
    .overlay_rootfs(base, layer.path())
    .command("/usr/bin/make")
    .build()?
    .run()?;
# let _ = status;

// Dropping the layer discards the increment; the base stays pristine.
drop(layer);
# Ok(())
# }
```

Two things this layer has to do for itself that `dpkg` does for the Debian one,
because nothing here runs a package manager inside the root:

**The database in the upper describes the merged root.** An overlay unions files,
so the `installed` an increment writes shadows the base's outright rather than
adding to it. The base's records are read and carried through byte for byte —
they may be records `apk` wrote — with the increment's sorted in among them, and
`/etc/apk/world`, `/etc/apk/repositories`, `triggers` and the script archive are
merged the same way. `apk audit --system` inside the merged root passes, which is
the check that the file describes the tree.

**The base's own triggers fire.** A trigger belongs to the installed root rather
than to the transaction, so a directory the increment creates runs the base's
watcher for it — `busybox` relinking applets, `ca-certificates` rebuilding its
bundle.

The increment resolves against the base's installed set read at the versions it
records, not merely at its names, because apk spells a soname
`so:libc.musl-x86_64.so.1=1.2.5-r23`. A dependency the base's version cannot meet
is reported as the upgrade it would be, naming both versions and the entry that
forced it: an increment installs over a base rather than replacing part of one.

A file the increment ships over one the base owns simply wins in the merged view.
The base is read-only, and the shadow lives in the disposable upper. A collision
*within* the increment is refused exactly as a full bootstrap refuses one.

Files land where the merged view puts them. Where the base links a directory
elsewhere, as `/var/run` to `../run`, the increment's files land at the link's
target. The link stays the base's. A merged-usr base keeps its `/lib` this way,
and the database is written through it.

## Trust

Authenticity comes from the archive's own signatures, not the transport, so
packages are fetched over plain HTTP by default. Both archives this layer is
written against serve it, and an `https://` mirror needs a transport of the
caller's own supplied through `fetcher`.

The chain has three links, and it is worth stating plainly because two of them
rest on SHA-1:

1. The index is signed with RSA-4096 over **SHA-1** (`.SIGN.RSA.`), verified
   against the repository's key set.
2. The index's `C:` field identifies each package's control segment by **SHA-1**
   of its compressed bytes.
3. `.PKGINFO`'s `datahash` binds the file tree to that control segment by
   **SHA-256**.

So the payload is bound by a strong digest and the two links above it are not.
There is nothing stronger available in the published v2 format, and verifying
less than `apk` does would be worse rather than safer, so the layer verifies
exactly this and offers no knob: a knob would be a choice between verifying and
not verifying. Forging a package against this chain requires a chosen-prefix
SHA-1 collision whose second preimage is a well-formed gzip of a tar containing a
`.PKGINFO` — expensive, but no longer theoretical. The question is revisited when
Alpine publishes apk v3 indexes, which no release does today.

### What binds a package to what was asked for

A signature says that *some* package was signed. Without more, a mirror could
answer a request for `musl-1.2.5-r23` with a validly signed `musl-1.2.5-r0`. So
before anything is unpacked, the layer recomputes the control identity over the
bytes that arrived and compares it to the `C:` the verified index recorded, and
compares the package's own `pkgname`, `pkgver` and `arch` to what was planned.

A package's *own* `.SIGN` member is read but not verified, and this is `apk`'s
rule rather than a relaxation of it. The identity above already fixes exactly the
bytes such a signature would cover, while the signature itself sits in the
segment before them, which no digest in the format accounts for — so whoever
served the file could replace it without anything downstream differing. It is
also the only rule under which postmarketOS can be installed at all: its index is
signed by `build.postmarketos.org`, the key `postmarketos-keys` ships as the
trust anchor, while each of its packages is signed by whichever per-builder key
made it. `apk` installs them from the index and refuses the same file offered as
a bare `apk add ./file.apk`, where no index vouches for it.

### The keyring

The bundled key set is the whole trust anchor for the repository it is attached
to, and it differs from an OpenPGP keyring in a way worth knowing: an Alpine
signing key is a bare RSA public key. It carries no expiry, no self-signature and
no revocation, so none of the freshness and validity rules [the Debian
layer](debian.md#trust) enforces on a certificate has an analogue here. What the
set holds is what is trusted, and the only way to withdraw a key is to stop
shipping it — which means a bundled set is refreshed by a release of this crate.
A caller who needs a different answer sooner assembles a set with
[`KeySet::insert`].

The bundle is partitioned by architecture, because Alpine is: `alpine-keys`
installs three keys on x86_64, two entirely different ones on aarch64, two more
on armv7, and so on — eighteen keys across ten architectures, with only the two
oldest serving more than one. An x86_64 signature does not verify on an aarch64
root under `apk`, and it does not here. [`KeySet::alpine`] takes the architecture
for that reason, and the bundle mirrors that package's own key tree rather than
selecting from it.

### A private repository signs its index

There is no equivalent of the Debian layer's `trust_unsigned`, and none is
planned. apk has no unsigned mode in practice, so admitting one would be this
layer's invention rather than interoperability with anything.

The route for a caller with a repository of their own is the one `apk` itself
takes: sign the index with their own key, as `abuild-sign` does, and pass that key
through the repository's `keys`. Supplying a transport over `file://` is not on
its own enough — an unsigned index fails verification wherever it comes from.

```rust,no_run
use ferroday_cage::provision::alpine::{Alpine, KeySet, Repository};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut keys = KeySet::new();
keys.insert("build@example.com-64f0c0a1.rsa.pub", &std::fs::read_to_string("build.rsa.pub")?)?;

let local = Repository::builder("v3.23")
    .mirror("file:///srv/my-apks")
    .keys(keys)
    .build()?;

let _alpine = Alpine::builder("v3.23")
    .repository(local)
    .include(["my-package"])
    .build()?;
# Ok(())
# }
```

The key's *name* matters as much as its bytes: a signature names its key by
exactly the file name the repository publishes it under, so a set holding the
right key under the wrong name verifies nothing.

### No freshness policy

There is no equivalent of `allow_stale_release` either, because there is nothing
to be stale against. The apk index carries no validity window and no date — its
`DESCRIPTION` member is a build string, not a signed expiry — so a freshness rule
would be this layer's fiction rather than the archive's policy.

The same reasoning is why **the index is never cached**. A cache would need a
staleness rule the format does not express. `cache_dir` holds packages, which are
identified by digests the index states, and indexes are re-fetched.

## Ownership

The [identity map](identity-maps.md) decides the ownership the finished rootfs
carries, and Alpine asks less of it than Debian does.

The default single-identity map maps the calling user to root and nothing else,
and the archive is content with that: every file of every package in an
`alpine-base` closure is owned by root, so extraction needs none of the ownership
emulation the Debian bootstrap installs stubs for. The one place it shows is that
`alpine-baselayout`'s install script gives `/etc/shadow` to the `shadow` group,
which the single map cannot represent. That call fails, harmlessly and exactly as
it fails under `apk` in the same situation — Alpine's scripts tolerate it — and
the resulting root is a working userland with that one group ownership flattened.

A rootfs that is itself the product wants real ownership, and `identity_map`
selects it. Under `IdentityMap::Subordinate` the system ids genuinely exist and
that `chown` succeeds.

## Extract-only and foreign architectures

The bootstrap targets the host architecture by default; `architecture` selects
another. A full bootstrap runs that architecture's install scripts and so needs a
registered `qemu-user` binfmt handler (see [Host
requirements](host-requirements.md)), which the bootstrap checks for before
downloading anything.

Where the foreign binaries cannot run, `extract_only` lays the files down and
**still registers them**. That is a real difference from the Debian layer, where
an extract-only root has no configured `dpkg` database: an apk installed record is
a file format rather than a program's output, so writing it needs nothing
executed. An extract-only Alpine root for a foreign architecture therefore knows
exactly what it holds, and an `apk` running there later reads it back.

## Where the two layers differ

Everything in this table is a difference the archives make, not a gap:

| | Debian | Alpine |
| --- | --- | --- |
| Base set | A priority band, seeded by `base_priority` | None: apk records no priority. The set is exactly `include` closed over its dependencies |
| Signed thing | `InRelease`, which carries the indexes' digests | The index itself; there is nothing above it |
| Digest chain | SHA-256 throughout | SHA-1 to the control segment, SHA-256 to the file tree |
| Trust anchor | An OpenPGP keyring, with expiry and revocation | A set of bare RSA keys, with neither, partitioned by architecture |
| Unsigned mode | `trust_unsigned`, for a local pool | None; a private repository signs its index |
| Freshness | `Valid-Until`, and `allow_stale_release` to relax it | None; the format expresses no validity window |
| Package identity | A SHA-256 of the whole file, from the index | A SHA-1 of the control segment, plus `datahash` over the tree |
| Extract-only | Files only; no configured database | Files *and* the installed database |
| Configuration | `dpkg` runs in a cage | The install scripts run directly, in dependency order |

## The command line

`fcage --provision-alpine RELEASE` bootstraps the `--rootfs` directory before
launching. Given without a command, it provisions and exits; the
already-provisioned case is fast, so the flag can stay in an invocation
permanently.

```console
$ fcage --rootfs ./alpine --provision-alpine v3.23 \
        --alpine-include build-base,busybox-binsh --alpine-cache ./apk-cache
$ fcage --rootfs ./alpine /usr/bin/cc --version
```

The `--alpine-arch`, `--alpine-mirror`, `--alpine-mirror-fallback`,
`--alpine-components`, `--alpine-include`, `--alpine-exclude`,
`--alpine-extract-only`, `--alpine-cache`, `--alpine-keys`,
`--alpine-pre-configure-overlay`, `--alpine-identity-map`,
`--alpine-source-date-epoch` and `--alpine-repository` options map onto the
builder. `--alpine-include`,
`--alpine-exclude` and `--alpine-components` take comma-separated lists and may
be repeated.

`--alpine-keys` takes `alpine`, `postmarketos`, or a directory read the way
`apk` reads `/etc/apk/keys`: every file in it is a PEM public key held under its
own file name. A repository added with `--alpine-repository` must name its keys
the same way, and naming no components selects the shallower layout:

```console
$ fcage --rootfs ./pmos --provision-alpine v3.23 \
        --alpine-include alpine-base,postmarketos-baselayout \
        --alpine-repository 'release=v26.06 keys=postmarketos
                             mirror=http://mirror.postmarketos.org/postmarketos'
```

[`repository`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.AlpineBuilder.html#method.repository
[`resolve`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.Alpine.html#method.resolve
[`plan`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.AlpineBuilder.html#method.plan
[`pin`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.AlpineBuilder.html#method.pin
[`KeySet`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.KeySet.html
[`KeySet::alpine`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.KeySet.html#method.alpine
[`KeySet::insert`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.KeySet.html#method.insert
[`overlay_rootfs`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.overlay_rootfs
[`Export::clamp_mtime`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/struct.Export.html#method.clamp_mtime
[`source_date_epoch`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/alpine/struct.AlpineBuilder.html#method.source_date_epoch
