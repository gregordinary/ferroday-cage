# A Gentoo userland

The `gentoo` feature provisions a Gentoo root filesystem from a stage3: it
resolves which build the archive currently publishes for a variant, verifies the
signed documents that vouch for it, and extracts the tarball. It speaks to the
archive directly, and verifies what it fetches against a keyring the crate
vendors.

```rust,no_run
use ferroday_cage::provision::{self, gentoo::Gentoo};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64")
    .variant("amd64-openrc")
    .cache_dir("/var/cache/fcage/stage3")
    .build()?;
provision::ensure("/var/lib/machines/gentoo", &mut gentoo)?;
# Ok(())
# }
```

`Gentoo` implements [`Provisioner`](provisioning.md), so `provision::ensure`
publishes the result atomically: the destination directory either does not exist
or holds a complete root.

The surface is deliberately smaller than [the Debian](debian.md) and
[Alpine](alpine.md) layers'. There is no plan document, no `resolve` over a
dependency graph, no package cache to replay, and no install-script wave —
because Gentoo publishes none of those things for a stage3. What it publishes is
a signed pointer, a signed digest document, and a tarball, and this layer reads
exactly that.

The `ebuild-sandbox` example works it into a consumer: it provisions a stage3,
binds a portage tree into it read-only, and runs `emerge` in a cage.

## How it works

A bootstrap runs in three steps:

1. **The signed enumeration.** It fetches
   `releases/<arch>/autobuilds/latest-stage3.txt`, a cleartext-signed document
   listing every stage3 that architecture currently offers with the build each
   points at and the exact size of its tarball, and verifies it against the
   vendored keyring.
2. **The signed digest.** It matches the configured variant against that list,
   then fetches the `.DIGESTS` document beside the chosen build — cleartext-
   signed by the same key — and reads the SHA-512 it records for the tarball.
3. **Download and verify.** It downloads the tarball into a cache, bounded by the
   size the enumeration recorded, checks it against that SHA-512, and only then
   extracts it. The bytes are never streamed into the extractor unverified: an
   archive that turned out not to be the one the document named would otherwise
   already have written most of a root filesystem.

The finished root is the stage3 as Gentoo built it — portage, its configuration,
a toolchain and a base system — ready for a cage to run `emerge` in.

## Naming a variant

Gentoo publishes far more than one stage3 per architecture: amd64 alone offers
twenty-one, from a desktop root to hardened, musl, LLVM and `nomultilib` builds.
There is no default among them, so a variant must be named.

The spelling is the whole compound the archive publishes, not a name relative to
the architecture:

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64").build()?;
for variant in gentoo.available()?.variants() {
    println!("{variant}");
}
// amd64-desktop-openrc, amd64-hardened-systemd, amd64-openrc,
// amd64-openrc-splitusr, x32-openrc, ...
# Ok(())
# }
```

`x32-openrc` appears in amd64's own document, as a sibling of `amd64-openrc`:
what sits between `stage3-` and the build id is a sub-architecture and variant
compound rather than a variant of a fixed architecture. A name relative to the
architecture could not reach the `x32` entries at all.

The match is exact rather than by prefix, because `amd64-openrc-splitusr` sits
beside `amd64-openrc` in that same document. A variant the architecture does not
publish is refused before anything is downloaded, and the refusal names what is
on offer — checked against what Gentoo publishes now rather than against a list
compiled into this crate.

Each entry keeps its own build id: a sub-architecture is built on its own
cadence, so one document routinely points different variants at different builds.

## Pinning a build

`build_id` provisions a named build instead of the current one:

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64")
    .variant("amd64-openrc")
    .build_id("20260810T204554Z")
    .cache_dir("/var/cache/fcage/stage3")
    .build()?;
# let _ = gentoo.resolve()?;
# Ok(())
# }
```

A pin skips the enumeration entirely — it is the caller saying which build they
want, and asking the archive which is current would not change the answer — so
the digest document beside that build is what vouches for the tarball.

**A pin is not indefinite.** The autobuilds tree holds about five weeks of
builds and Gentoo publishes no equivalent of `snapshot.debian.org`, so a build id
resolves against the archive for roughly a month and against a populated cache
for as long as the cache lives. Past that the archive answers 404. That is a
difference from the Debian and Alpine layers, whose plan documents replay against
a snapshot service or a repository that keeps old versions, and it is a property
of the archive rather than of this layer.

Within one process, a resolution carries over whole:

```rust,no_run
use ferroday_cage::provision::{self, gentoo::Gentoo};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64").variant("amd64-openrc").build()?;
let stage3 = gentoo.resolve()?;
println!("{} at {}", stage3.build_id(), stage3.sha512());

// A second root from the same answer, with nothing re-fetched.
let mut again = Gentoo::builder("amd64").stage3(stage3).build()?;
provision::ensure("/var/lib/machines/gentoo-2", &mut again)?;
# Ok(())
# }
```

There is no plan document to write. A single tarball does not need a versioned
serialization, and one would name a build the archive deletes in about five
weeks — a document outliving what it describes. A caller who wants to provision
the same root again records the build id and variant however they already record
configuration.

## Trust

The chain has three links, and the first is not fetched at all:

```text
vendored service keyring
  -> latest-stage3.txt      (cleartext-signed)  the variants, their sizes
  -> <tarball>.DIGESTS      (cleartext-signed)  the tarball's SHA-512
  -> <tarball>              (bytes)             verified, then extracted
```

Both documents are cleartext-signed OpenPGP messages, verified by the same
machinery the [Debian layer](debian.md#trust) uses for an `InRelease`: the
signature must verify against a certificate in the keyring, the key must have
been within its validity window when it signed, and the algorithms involved must
be ones this crate rests a trust decision on. Gentoo signs with a dedicated
signing subkey of its Automated Weekly Release Key, so the subkey's binding is
verified back to the primary before the signature it made counts.

The digest document records SHA-512 and BLAKE2B for the tarball *and* for its
`.CONTENTS.gz` sidecar. The layer reads the SHA-512 for the tarball, keyed on the
algorithm and the file name together: keying on the algorithm alone would take
whichever line came first and hold the tarball to the sidecar's digest.

**The `.sha256` sidecar is never read.** One sits beside every tarball, and it is
a trap: nothing signs it, and it is not named in the signed digest document.
Reading it would leave the chain resting on an unauthenticated file.

### The keyring

The crate vendors Gentoo's service keys — the same
`qa-reports.gentoo.org/output/service-keys.gpg` the distribution publishes,
mirrored whole. Vendoring is the security property rather than a saved round
trip: a trust anchor fetched over the same plain-HTTP channel as the artifact it
authenticates authenticates nothing, because whoever can serve a forged stage3
can serve the key that signs it.

It is mirrored mechanically, certificates this layer never meets included. An
unusable key in an anchor weakens nothing — nothing rests on a key until it
produces a signature that passes the gates — and a curated subset would be a
judgement a later reader has to reconstruct rather than a rule they can check.

A vendored anchor has a shelf life, and Gentoo's certificates do not share one
expiry:

```rust
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let gentoo = Gentoo::builder("amd64").build()?;
for held in gentoo.keyring_horizon() {
    println!(
        "{} {} {:?}",
        held.fingerprint,
        if held.signs { "signs" } else { "cannot sign" },
        held.expires,
    );
}
# Ok(())
# }
```

The report is per certificate rather than a single earliest date, because two of
the eleven lapse about twenty months before the rest and neither signs anything
this layer reads: one number would say the keyring is nearly stale while the key
that matters is good for years. `signs` is the other half of reducing the list
honestly — the keyring holds a DSA-1024 release key from 2004 whose expiry reads
like every other certificate's, though the public-key floor refuses it and it
delegates to no signing subkey that would pass. The earliest expiry among the
certificates that *can* sign is the number to act on.

Nothing refreshes the keyring at run time, and nothing should: fetching a trust
anchor at provisioning time would hand the network the power to replace the very
thing vendoring exists to protect. A newer keyring arrives in a release of this
crate.

### Staleness, and what bounds it

Gentoo publishes no deadline of any kind. There is no `Valid-Until` above the
documents and no expiration on the signatures themselves, which leaves a gap the
first two layers do not have: a mirror serving a genuinely signed but months-old
pointer, and its matching digest document, passes every other check there is. The
signature verifies, the key was valid when it signed, and the digest matches the
bytes. That is a rollback, and it is the standard attack on a chain with no
deadline.

The pointer closes it itself. Inside its signed body, above the entries:

```text
# Latest as of Mon, 10 Aug 2026 23:30:01 +0000
# ts=1786404601
```

Every architecture carries the line, and the documents are regenerated on a
common schedule whether or not new builds landed in them — amd64's `x32` entries
can be two months old while the document's own timestamp is minutes old — so the
value measures the pointer's currency rather than the age of what it points at.

A pointer older than thirty days is refused. That is about four regeneration
cycles, so a live archive never approaches it. A pointer stating no timestamp is
refused on the same terms: it is the only bound there is, and reading its absence
as permission would let whoever serves the document disable the check by deleting
a line.

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// A deliberately archived mirror, where a stale pointer is the point.
let gentoo = Gentoo::builder("amd64")
    .variant("amd64-openrc")
    .mirror("http://archive.invalid/gentoo")
    .max_pointer_age(None)
    .build()?;
# let _ = gentoo;
# Ok(())
# }
```

Clearing the bound gives up the only defence against a replayed pointer, and it
accepts an undated one too. It is the right answer for an archived mirror and the
wrong one for a live network.

## The cache

`cache_dir` names a directory the downloaded tarball is kept in across runs. A
stage3 is hundreds of megabytes, so a caller provisioning more than one root from
the same build wants one. Without it the tarball is downloaded beside the tree
being built and removed with it.

A cached tarball is verified on the read, not trusted for having been verified
once: what sits at a cache path is bytes on a disk this crate does not own, so a
cache hit and a fresh download go through the same check. A tarball that does not
match is removed rather than left behind — it is not the archive's file whatever
it is, and keeping it would make every later run of that build fail identically
out of its own cache.

## Mirrors

`mirror` replaces the default `http://distfiles.gentoo.org`, and
`mirror_fallback` adds URLs tried after it. The list is walked in order,
advancing past a mirror that could not serve a document. A mirror that serves one
that does not *verify* is fatal rather than a reason to try the next: what it
served was answered for by the URL that was asked for, and the answer to a
refused signature is never to ask somewhere else.

The archive serves plain HTTP with no redirect to HTTPS, and the bundled client
speaks it. Every byte it brings back is verified against the vendored keyring, so
the transport is not what the trust rests on; a caller who wants TLS, a proxy, or
a private mirror protocol supplies their own `Fetch`.

## Progress

A bootstrap reports through the run's observer, as every provisioner does:

```rust,no_run
use ferroday_cage::provision::gentoo::GentooEvent;
use ferroday_cage::provision::{Provision, ProvisionEvent, gentoo::Gentoo};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64").variant("amd64-openrc").build()?;
Provision::new("/var/lib/machines/gentoo")
    .observe(&mut |event: ProvisionEvent<'_>| match event {
        ProvisionEvent::Gentoo(GentooEvent::Fetching { url, .. }) => {
            eprintln!("fetching {url}");
        }
        ProvisionEvent::Gentoo(GentooEvent::Resolved { stage3, .. }) => {
            eprintln!("build {}", stage3.build_id());
        }
        _ => {}
    })
    .run(&mut gentoo)?;
# Ok(())
# }
```

Four events rather than the other layers' larger sets, because the work is
smaller: the documents fetched, what was resolved, the verification, and the
extraction.

## The command line

`fcage --provision-gentoo ARCH` provisions the `--rootfs` directory:

```console
$ fcage --provision-gentoo amd64 --gentoo-variant amd64-openrc \
        --gentoo-cache ./stage3-cache --rootfs ./gentoo \
        /bin/bash -c 'cat /etc/gentoo-release'
Gentoo Base System release 2.18
```

The architecture is the coordinate rather than a release, since Gentoo publishes
one autobuilds tree per architecture and no suite. `--gentoo-build-id`,
`--gentoo-mirror`, `--gentoo-mirror-fallback` and `--gentoo-max-pointer-age`
mirror the builder setters above; the last takes a count of days or `none`.

Two listings answer without provisioning anything:

```console
$ fcage --gentoo-variants amd64
amd64-desktop-openrc	20260810T204554Z	829735700
amd64-hardened-openrc	20260809T143052Z	496484932
amd64-openrc	20260810T204554Z	495865168
...

$ fcage --gentoo-keyring-horizon
13EBBDBEDE7A12775DFDB1BABB572E0E2D182910	signs	1846022400	Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>
...
earliest expiry among the certificates that can sign	1795718963
```

`--gentoo-variants` reads the signed enumeration; `--gentoo-keyring-horizon`
reaches no network at all.

## Where this layer differs from the other two

Every difference is one the archive itself makes.

| | Debian and Alpine | Gentoo |
| --- | --- | --- |
| What is installed | a package closure this crate resolves | one prebuilt tarball |
| The coordinate | a suite or release, plus an architecture | an architecture, plus a variant |
| Replay | a plan document, versioned and portable | the build id and variant, recorded by the caller |
| How long a pin lasts | as long as the archive or a snapshot service keeps the versions | about five weeks against the archive |
| Freshness | `Valid-Until`, or an index refetched every run | the pointer's own signed regeneration timestamp |
| What runs during a bootstrap | maintainer or install scripts, in a cage | nothing |

Building packages *inside* a provisioned stage3 is `emerge`'s job rather than
this library's, and [the ebuild sandbox](ebuild-sandbox.md) is the worked example
of driving it.

## What is not here

**The binary-package host.** Gentoo publishes prebuilt packages under
`releases/<arch>/binpackages/`, and this layer does not read them. The index
there is unsigned and its per-package digests are MD5 and SHA-1, so version
selection on a hostile mirror is attacker-controlled even though the payloads are
not — each `.gpkg.tar` carries a cleartext-signed `Manifest` of its own. A layer
for it is a resolver's worth of work rather than a cryptographic one.

**Detached signatures.** Gentoo publishes an `.asc` beside every tarball. It is
an alternative path for someone verifying a download by hand, not the only one:
the cleartext-signed digest document binds the same bytes, and that is what this
layer reads.
