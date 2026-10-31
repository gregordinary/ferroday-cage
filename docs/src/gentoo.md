# A Gentoo userland

The `gentoo` feature provisions a Gentoo root filesystem from a stage3. It
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

It also installs prebuilt packages from the archive's binary-package host into
the root it bootstrapped, which is [the second half of this
chapter](#binary-packages). A run that asks for no package is exactly a stage3
bootstrap, byte for byte.

Two examples work it into consumers. `ebuild-sandbox` provisions a stage3, binds
a portage tree into it read-only, and runs `emerge` in a sandbox.
`gentoo-binhost` provisions one and installs prebuilt packages into it
instead.

## How it works

A bootstrap runs in three steps:

1. **The signed enumeration.** It fetches
   `releases/<arch>/autobuilds/latest-stage3.txt` and verifies it against the
   vendored keyring. That document is cleartext-signed. It lists every stage3
   the architecture currently offers, with the build each points at and the
   exact size of its tarball.
2. **The signed digest.** It matches the configured variant against that list,
   then fetches the `.DIGESTS` document beside the chosen build, cleartext-
   signed by the same key. From it the layer reads the SHA-512 recorded for the
   tarball.
3. **Download and verify.** It downloads the tarball into a cache, bounded by the
   size the enumeration recorded, checks it against that SHA-512, and only then
   extracts it. The bytes are never streamed into the extractor unverified. An
   archive that turned out not to be the one the document named would otherwise
   already have written most of a root filesystem.

The finished root is the stage3 as Gentoo built it: portage, its configuration,
a toolchain and a base system. It is ready for a sandbox to run `emerge` in.

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

`x32-openrc` appears in amd64's own document, as a sibling of `amd64-openrc`.
What sits between `stage3-` and the build id is a sub-architecture and variant
compound rather than a variant of a fixed architecture. A name relative to the
architecture could not reach the `x32` entries at all.

The match is exact rather than by prefix, because `amd64-openrc-splitusr` sits
beside `amd64-openrc` in that same document. A variant the architecture does not
publish is refused before anything is downloaded, and the refusal names what is
on offer. That list is what Gentoo publishes now rather than one compiled into
this crate.

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

A pin skips the enumeration entirely. It is the caller saying which build they
want, and asking the archive which is current would not change the answer. The
digest document beside that build is what vouches for the tarball.

**A pin is not indefinite.** The autobuilds tree holds about five weeks of
builds and Gentoo publishes no equivalent of `snapshot.debian.org`. A build id
therefore resolves against the archive for roughly a month, and against a
populated cache for as long as the cache lives. Past that the archive answers
a 404 instead. The Debian and Alpine layers differ here, because their plan documents
replay against a snapshot service or a repository that keeps old versions. That
is a property of the archive rather than of this layer.

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
serialization. One would name a build the archive deletes in about five weeks,
outliving what it describes. A caller who wants to provision the same
root again records the build id and variant however they already record
configuration.

## Binary packages

Gentoo publishes prebuilt packages beside the stage3 tarballs, under
`releases/<arch>/binpackages/`, and this layer installs them. Name the
sub-architecture tree and the atoms to install:

```rust,no_run
use ferroday_cage::provision::{self, gentoo::Gentoo};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64")
    .variant("amd64-openrc")
    .binhost("x86-64")
    .install(["dev-vcs/git", "app-editors/vim"])
    .cache_dir("/var/cache/fcage/gentoo")
    .build()?;
provision::ensure("/var/lib/machines/gentoo", &mut gentoo)?;
# Ok(())
# }
```

A run is then two waves. The stage3 is fetched, verified and extracted. The
packages are then resolved against the root that produced, fetched, verified and
merged into it. A builder that names no package does exactly the first, byte for
byte.

There is no default sub-architecture. amd64 publishes `x86-64`, `x86-64-v3`,
`x86-64_hardened` and `x32` today, and the set moves: it published eight not
long ago. The only thing that enumerates it is an unsigned directory listing.
Reading that as discovery would put an unauthenticated document at the head of
the trust chain, which is the reason the keyring is vendored. So the
sub-architecture is yours to name, and a wrong one is a 404 rather than a
silently different userland.

### Resolution starts from the root

This is the shape neither [the Debian](debian.md) nor [the Alpine](alpine.md)
layer has. Both bootstrap from nothing, so their resolvers start with an empty
root and ask what is *needed*. A Gentoo stage3 unpacks with 296 packages already
installed and a database describing them. Resolution here therefore starts from
a populated root and asks what is *missing*.

That is load-bearing rather than an efficiency. The binhost publishes one of
those 296, `app-crypt/pinentry`, in no version at all, and it sits in
`dev-vcs/git`'s runtime closure. Resolving git against an empty root does not
merely produce a larger plan. It *fails*, on an atom the real root answers. The
general case is the same one, less dramatically: the median closure over four
hundred sampled packages is five, because everything else is already there.

So `resolve_packages` takes the root it would install into:

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64")
    .binhost("x86-64")
    .install(["dev-vcs/git"])
    .build()?;
let plan = gentoo.resolve_packages("/var/lib/machines/gentoo")?;
for package in &plan.packages {
    println!("{}-{} build {}", package.name, package.version, package.build_id);
}
# Ok(())
# }
```

`gentoo::installed` answers the same question on its own, for any Gentoo root
including one this crate never built:

```rust,no_run
use ferroday_cage::provision::gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let installed = gentoo::installed("/var/lib/machines/gentoo")?;
println!("{} packages", installed.len());
# Ok(())
# }
```

### Which build, and why the rule is that rule

The archive publishes a version more than once. `binpkg-multi-instance` gives
2,774 of the index's versions between two and twenty-four builds. Those builds
differ only in the USE flags they were compiled with, and therefore in what they
depend on. `dev-vcs/git` is the clean illustration: the build without `keyring`
pulls twelve packages, and the build with it pulls seventy through the GTK
stack.

Choosing among them is therefore not a tie-break, it decides whether resolution
succeeds at all. Measured over four hundred sampled package names against an
`amd64-openrc` stage3:

| Rule | Resolves cleanly | Unsatisfiable atoms | Conflicts | p90 closure |
| --- | --- | --- | --- | --- |
| newest build time | 262/400 | 884 | 129 | 173 |
| fewest dependencies | 338/400 | 206 | 74 | 148 |
| **fewest USE flags** | **361/400** | **26** | **50** | **126** |

Fewest USE flags wins every column at once, which is the argument for it: it is
not a trade. Portage makes the same choice from a profile's computed USE. This
layer has no profile, so it needs a rule of its own, and this is the one the
numbers chose. Each atom takes the highest version that satisfies it and then
the fewest-flags build of that version.

### A constraint fails loudly; a preference cannot

Two ways to reach a build the default rule would not choose, and they differ in
kind rather than in spelling.

**A USE dependency in the atom is a constraint.** `dev-vcs/git[keyring]` removes
every build without the flag from consideration, and if the archive publishes
none the atom is unsatisfiable and the run says so. It costs no extra API: the
atom grammar the resolver already speaks parses it.

**`prefer_use` is a preference.** It reorders the candidates and removes none,
so it *provably* cannot turn a resolvable request into an unresolvable one. Over
the same four hundred seeds:

| Preference | Resolves cleanly | Unsatisfiable atoms | Conflicts | p90 closure |
| --- | --- | --- | --- | --- |
| none | 361/400 | 26 | 50 | 126 |
| `keyring` | 361/400 | 26 | 50 | 127 |
| `-X` | 361/400 | 26 | 50 | 126 |
| `X` | 354/400 | 26 | 60 | 164 |
| `X`, `gtk`, `qt6`, `systemd` | 284/400 | 26 | 110 | 179 |

The unsatisfiable count is 26 in every row: that is the guarantee stated as a
number. What a *broad* preference does cost is a larger closure, and a larger
closure meets more of the archive's own conflicts. The whole cost lands in that
column. A narrow one costs nothing measurable.

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64")
    .binhost("x86-64")
    // A constraint: this build must have the flag, or the run fails.
    .install(["dev-vcs/git[keyring]"])
    // A taste: prefer builds without X, and never fail because of it.
    .prefer_use(["-X"])
    .build()?;
# let _ = gentoo.resolve_packages("/var/lib/machines/gentoo")?;
# Ok(())
# }
```

State a flag the install must have in the atom. State a flag you would rather it
had as a preference.

### Conflicts are reported, not resolved around

A blocker atom that matches something the root has or the resolution chose is a
conflict, and the run fails naming both sides. The root's own packages state
blockers too, in their database entries. One that matches a chosen build is the
same conflict from the other side.

There is no backtracking, and the evidence is why. An any-of policy that preferred a non-conflicting alternative
changed nothing over the same four hundred seeds. The conflicts that remain are
ones portage refuses too. Almost all are a desktop stack asked for in a root
built against the other init system. The commonest single case, 27 of the 50, is
`!sys-apps/sysvinit` meeting the openrc stage3's own `sys-apps/sysvinit`.

Every refusal is reported before the run fails, so a caller fixing an install
list sees the whole list rather than its first entry. Each names which wall it
hit: the package the binhost does not publish, the version, the slot, or the USE
flag. Where the binhost publishes the package in no version and the root has it
anyway, the refusal names the version the root has. That is the
`app-crypt/pinentry` shape again, and the version is the half a caller can act
on.

### One instance per slot

Portage keeps one instance of each `(package, slot)` and reports a root holding
two as a conflict. A resolution that would produce one is therefore refused with
both builds named, rather than merged. Merging both would lay two images down
with the second overwriting the first's shared paths, and report success.

It is reached by an ordinary install list rather than by a contrived one. Two
atoms constraining one package from opposite directions both select:

```text
--gentoo-install '<dev-libs/foo-2' --gentoo-install '>=dev-libs/foo-2'
```

A closure does the same where one package is constrained upward and another
downward on the same dependency. No caller writes that pair by hand. The
likelier trigger is a USE constraint. Ask for `dev-vcs/git` and for something
that needs `dev-vcs/git[keyring]`: the first takes the build without the flag,
and the second needs the build with it. Both are `git` in slot `0`, so the
second is refused naming both builds. Constrain the first atom the same way, or
state the flag as a `prefer_use` and let one build answer both.

Since nothing backtracks, the resolution keeps the build it chose first and
reports what could not join it. The order is a resolution's own and is stable,
so the same install list is refused the same way every time.

The root holds a slot as firmly as the resolution does. Merging registers a
database entry beside what is already installed and unmerges nothing. So an atom
answered only by a version later than the root's own in that slot is refused the
same way. The refusal names the installed version rather than a second build.
Bootstrap a root whose version the atom admits, or constrain the atom to the
version the root already has.

Two *slots* of one package are a different thing and are not a conflict. The
archive publishes `dev-lang/python` in `3.11` and `3.12`, `llvm`, `gcc`, `ruby`,
`postgresql` and `qt` in several each, and Gentoo installs them side by side.
The install order carries an edge to each of them, so a package depending on two
slots merges after both.

### The plan is the reproducibility story

Unlike the stage3 half, the binhost half has a plan document:

```rust,no_run
use ferroday_cage::provision::gentoo::{Gentoo, Plan};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut gentoo = Gentoo::builder("amd64").binhost("x86-64").build()?;
// Resolve now, and keep what was resolved.
let plan = gentoo.resolve_packages("/var/lib/machines/gentoo")?;
std::fs::write("binhost.plan", plan.to_document()?)?;

// Replay later: nothing is fetched but the packages themselves.
let kept = Plan::parse_document(&std::fs::read_to_string("binhost.plan")?)?;
let mut replay = Gentoo::builder("amd64").binhost("x86-64").plan(kept).build()?;
# let _ = replay;
# Ok(())
# }
```

A plan names each package's build id, path, size and digest, and the order they
merge in. It is worth serializing where a `Stage3` is not, and for the opposite
reason. The autobuilds tree keeps about five weeks of stage3 builds, while the
binhost keeps a published version far longer. A plan therefore replays for as
long as the archive carries what it names.

A plan also names the architecture and the binhost it was resolved for, and
`build()` refuses one that does not agree with the builder. The builder above
names both and they match. Without that refusal, a builder naming a different
architecture would compose its own with the plan's binhost. It would fetch a
directory neither of them names, and report a 404 against a correctly spelled
mirror. A builder that names no binhost takes the plan's, which is what it
resolved against.

The stanza order *is* the install order, which is where this format departs from
the other two layers' plans. That order is a resolution's own output, a
topological sort over runtime dependencies. A plan that lost it would have to
derive it again from the index the plan exists to avoid needing.

### What a merge writes, and what it does not run

Each package's files are laid into the root and a `/var/db/pkg` entry is
registered. A stage3 arrives with a populated database, so a root this layer
installed into without registering would have a database that lies about it.
Portage would rebuild what is present, and `--depclean` would remove it.

An entry is the container's own metadata directory plus the three files portage
computes at merge, `CONTENTS`, `COUNTER` and `BINPKGMD5`. That is exactly what a
stage3's own entries turn out to be. The merge ordinal continues the root's
sequence rather than starting again.

`CONTENTS` uses portage's own line types:

| Line type | What it records |
| --- | --- |
| `dir` | A directory |
| `obj` | A file, with a digest and an mtime |
| `sym` | A symbolic link, with its target |
| `fif` | A named pipe |

A fifo has no contents to digest and is recorded without one. Opening it to look for some would block until something opened the write
end, and inside a provisioning run nothing does. Character and block devices
never appear: laying one down needs privilege the layer does not have, and the
sandbox provides its own `/dev`.

**Phase functions are not run.** Around 30% of packages define a `pkg_postinst`
or a `pkg_preinst`. They live in the container's `environment.bz2` as a
serialized bash environment. Running one therefore means running portage's own
`ebuild.sh` with the eclasses it was built against.

Three consequences are the ones callers meet. An `acct-user` or `acct-group`
package ships a `sysusers.d` fragment and does not create the account.
`ca-certificates` does not regenerate its bundle. Icon and font caches are not
rebuilt.

This is the same seam [the Debian layer](debian.md) has and the opposite
decision. Debian's maintainer scripts are executables that layer can run inside
the sandbox, so it runs them. Gentoo's are bash functions that need the guest's
package manager. What this layer gives you instead is a root portage can act on,
which is the strongest argument for registering the entry properly. Run the
phases with `emerge` inside the sandbox if you need them.

**`CONFIG_PROTECT` is not honored.** An existing file under `/etc` is
overwritten rather than given portage's `._cfg0000_` treatment. The layer builds
roots rather than upgrading live systems, and a root whose configuration depends
on merge order is not reproducible.

### Coverage is a property of the archive

The binhost publishes 6,904 distinct package names across 15,773 builds. That is
most of the tree and not all of it: `dev-build/cmake` is there, `app-misc/jq` is
not, in any version. Around 90% of sampled packages resolve cleanly. So the
binhost installs most things and cannot install everything. The failures are the
archive's shape rather than the resolver's, and the layer says which atom it
could not satisfy and why.

`packages` lists what is on offer before you commit to a resolution:

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64").binhost("x86-64").build()?;
let catalogue = gentoo.packages()?;
println!("{} packages in {} builds", catalogue.len(), catalogue.builds());
for version in catalogue.versions("dev-vcs/git") {
    println!("{version}");
}
# Ok(())
# }
```

### Adding packages to a root that already exists

`provision::ensure` reports a directory that already exists as `Existing` and
does not touch it. So the way to add packages to a root you already have is a
layered build. The base stays pristine, and the increment lives in an overlay
upper that the returned handle removes when dropped.

```rust,no_run
use ferroday_cage::provision::gentoo::Gentoo;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut increment = Gentoo::builder("amd64")
    .binhost("x86-64")
    .install(["dev-vcs/git"])
    .base_layer("/var/lib/machines/gentoo")
    .build()?;
let layer = increment.stage_layer("/var/tmp/build-upper")?;
// Root a cage on overlay_rootfs(base, layer.path()) to build against the
// merged view; drop the handle to revert the increment.
# let _ = layer;
# Ok(())
# }
```

Resolution reads the *merged* view: the base's database and whatever the upper
already holds. That is what a package manager inside the finished sandbox sees.
An increment resolving against its own empty upper would ask the archive for
everything the base already has. It would then fail on the packages the binhost
does not publish.

The merge writes the merged view too. A stage3 is merged-usr: `lib64` and
`sbin` are links into `usr`. A package that still ships `lib64/` or `sbin/`
lands in the upper's `usr`, beside a copy of the base's link. The merged
`/lib64` stays a link, and the loader stays reachable through it. `CONTENTS`
records each path as the package ships it, as portage does.

## Trust

The stage3 chain has three links, and the first is not fetched at all:

```text
vendored service keyring
  -> latest-stage3.txt      (cleartext-signed)  the variants, their sizes
  -> <tarball>.DIGESTS      (cleartext-signed)  the tarball's SHA-512
  -> <tarball>              (bytes)             verified, then extracted
```

Both documents are cleartext-signed OpenPGP messages, verified by the same
machinery the [Debian layer](debian.md#trust) uses for an `InRelease`. Three
things must hold:

- The signature verifies against a certificate in the keyring.
- The key was within its validity window when it signed.
- The algorithms involved are ones this crate rests a trust decision on.

Gentoo signs with a dedicated signing subkey of its Automated Weekly Release
Key. The subkey's binding is verified back to the primary before the signature
it made counts.

The digest document records SHA-512 and BLAKE2B for the tarball *and* for its
`.CONTENTS.gz` sidecar. The layer reads the SHA-512 for the tarball, keyed on
the algorithm and the file name together. Keying on the algorithm alone would
take whichever line came first and hold the tarball to the sidecar's digest.

**The `.sha256` sidecar is never read.** One sits beside every tarball, and it is
a trap: nothing signs it, and it is not named in the signed digest document.
Reading it would leave the chain resting on an unauthenticated file.

### What a binary package's chain proves, and what it does not

A binary package's chain is shorter and it is anchored to the same key:

```text
vendored service keyring
  -> <package>.gpkg.tar/Manifest   (cleartext-signed)  each member's SHA-512
  -> the members                   (bytes)             verified, then read
```

The subkey that signs a `Manifest` is the same one that signs
`latest-stage3.txt` and the `.DIGESTS` documents. The binary-package half
therefore adds no trust anchor, no keyring and no verification path.
`Keyring::verify` is called on one more document.

**The index is not signed, and nothing about that is fixable.** No
`Packages.gpg`, `.asc`, `.sig`, `Manifest` or `.DIGESTS` is published beside it
in any form, and its own per-package digests are MD5 and SHA-1. So a hostile
mirror can decide *which* package a resolution asks for, even though it cannot
forge the package it then serves.

The index is therefore read as a document a mirror composed. The archive
publishes it as gzip and as plain text, and a body in any other compression is
refused before a decoder runs. Decompressed, it is held to 256 MiB, and a larger
one is refused rather than read as far as the limit. Parsing it costs time in
proportion to its length, and dependency groups nest at most 16 deep. A stanza
this layer cannot read is left out and counted rather than failing the whole
index.

It also decides each download's declared size, which is why the layer keeps a
ceiling of its own beside it. The index's `SIZE` bounds a fetch, and an
understated one fails closed: the download stops short and the container fails
its digest. An overstated one only relaxes the bound, since a transport caps at
the smaller of the declared size and its own ceiling. A hundred packages each
declaring `SIZE: 18446744073709551615` would therefore buy that ceiling a
hundred times over before anything was verified.

The layer's own bound is 1 GiB per package. That is above the 796 MB a whole
stage3 weighs and below the bundled client's own 2 GiB, so it binds where the
transport does not. The smaller of the two always wins.

**And a Manifest proves authorship, not identity.** Its lines are `DATA <member>
<size> SHA512 <hex> BLAKE2B <hex>` and there is no field naming the package.
GLEP 78 is explicit that the container's directory prefix cannot supply the
identity either. Matching the file name is only a recommendation there, while
"the implementation must be able to process an archive where the directory name
is mismatched". A conforming reader therefore cannot treat the prefix as a
claim.

Put together, that is a real substitution. A mirror answering a request for one
package with a genuine, correctly signed *other* package passes every signature
check there is. The layer closes it after verification, from the metadata inside
the container: `CATEGORY`, `PF` and `BUILD_ID` compared against the record the
resolution chose. A mismatch is a refusal, not a warning.

The `Manifest` is the container's last member, so the digests arrive after the
bytes they cover and a single forward pass cannot verify before extracting. The
container is already in a cache, so this costs a second pass over a local file
rather than a second fetch. Nothing is decompressed before its digest matches.

The two detached `.sig` members go unread for the reason the stage3's `.asc`
does: the cleartext-signed `Manifest` binds the same bytes. They are digested by
it like every other member, so they are verified *as data* even though they are
not used as signatures.

### The keyring

The crate vendors Gentoo's service keys — the same
`qa-reports.gentoo.org/output/service-keys.gpg` the distribution publishes,
mirrored whole. Vendoring is the security property rather than a saved round
trip. An anchor fetched over the same channel as the artifact authenticates
nothing: whoever can serve a forged stage3 can serve the key that signs it.

It is mirrored mechanically, certificates this layer never meets included. An
unusable key in an anchor weakens nothing, since nothing rests on a key until it
produces a signature that passes the gates. A curated subset would be a judgment
a later reader has to reconstruct rather than a rule they can check.

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

The report is per certificate, and there is no single date it reduces to. Two of
the eleven lapse about twenty months before the rest. One number would therefore
say the keyring is nearly stale while the certificate the archive currently
signs with is good for years.

`signs` separates a second case. Seven of the eleven certificates can sign
nothing, though each one's expiry reads like every other's. One is a DSA-1024
release key from 2004, which the public-key floor refuses. The other six are
certify-only primaries with no signing subkey: the authority keys and two
infrastructure keys. A primary signs a document only where its own
self-signatures grant it the signing flag, as GnuPG and Sequoia require.

What rules out a reduction is that every certificate in the keyring is an
equally trusted anchor. This layer accepts a signature from any of them that can
sign. Which certificate signs a given document is therefore the archive's
choice, and not something the keyring records. `signs` says a certificate
*could* produce an accepted signature, never that anything rests on it today. A
short-dated certificate the archive happens not to use pulls any earliest-expiry
number down to itself. That is the reading the per-certificate report exists to avoid.

The date your own provisioning depends on is the one on the certificate that
verified a document you actually read. This layer reads two: the stage3 pointer
and a binary package's Manifest. Both are signed today by a subkey of the
Release Engineering automated weekly key, which runs to 2028-07-01. That is an
observation about the archive rather than a rule. Gentoo can sign with another
anchor without telling anyone, and the keyring will still verify it.

Nothing refreshes the keyring at run time, and nothing is meant to. Fetching a
trust anchor at provisioning time would hand the network the power to replace
the very thing vendoring exists to protect. A newer keyring arrives in a release
of this crate.

### Staleness, and what bounds it

Gentoo publishes no deadline of any kind. There is no `Valid-Until` above the
documents and no expiration on the signatures themselves, which leaves a gap the
first two layers do not have. A mirror serving a genuinely signed but months-old
pointer, with its matching digest document, passes every other check there is.
The signature verifies, the key was valid when it signed, and the digest matches
the bytes. That is a rollback, and it is the standard attack on a chain with no
deadline.

The pointer closes it itself. Inside its signed body, above the entries:

```text
# Latest as of Mon, 10 Aug 2026 23:30:01 +0000
# ts=1786404601
```

Every architecture carries the line, and the documents are regenerated on a
common schedule whether or not new builds landed in them. So amd64's `x32`
entries can be two months old while the document's own timestamp is minutes old.
The value measures the pointer's currency rather than the age of what it points
at.

A pointer older than thirty days is refused. That is about four regeneration
cycles, so a live archive never approaches it. A pointer stating no timestamp is
refused on the same terms. It is the only bound there is. Reading its absence as
permission would let whoever serves the document disable the check by deleting a
line.

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

Clearing the bound gives up the only defense against a replayed pointer, and it
accepts an undated one too. It is the right answer for an archived mirror and
the wrong one for a live network.

## The cache

`cache_dir` names a directory downloads are kept in across runs: the stage3
tarball, and the binary packages an install merges. A stage3 is hundreds of
megabytes, so a caller provisioning more than one root from the same build wants
one. Without it the downloads land beside the tree being built and are removed
with it.

The tarball is kept under its file name, which names the variant and the build.
A binary package is kept under the path the archive publishes it at:

```text
<cache_dir>/releases/amd64/binpackages/23.0/x86-64/dev-vcs/git/git-2.54.0-5.gpkg.tar
```

That path names the architecture, the generation and the binhost as well as the
package, and it has to. Two binhosts publish builds of one package under one
relative path. The same key signs every `Manifest`, and each binhost numbers its
builds on its own. An `x86-64-v3` container therefore passes every check under
the `x86-64` name. A cache keyed by the relative path alone would merge code
built for newer processors into a root meant for older ones. Keyed this way, one
directory serves several architectures and binhosts.

A cached entry is verified on the read, not trusted for having been verified
once. What sits at a cache path is bytes on a disk this crate does not own. A
cache hit and a fresh download therefore go through the same check. An entry that does not
verify is not the archive's file, whatever it is, and the run downloads it
again. A fresh download that does not verify fails the run. It is removed, so a
later run does not meet the same refusal in its own cache.

What is verified is what is extracted. The tarball is extracted through the
descriptor its digest was taken through, and a container's image through the
descriptor its `Manifest` was checked against. Another run sharing the cache
publishes its downloads by renaming them over these names. A rename leaves an
open descriptor on the file it held.

**The cache directory is inside the trust boundary all the same.** A held
descriptor cannot answer a write *into* the file between the check and the
extraction. Nothing in this crate writes a cache entry in place, but anything
else with write access to the files can. Pointing `cache_dir` at a shared or
world-writable location extends the boundary to whoever can write there.

## Mirrors

`mirror` replaces the default `http://distfiles.gentoo.org`, and
`mirror_fallback` adds URLs tried after it. The two are separate settings, as
they are on the [Debian](debian.md) and [Alpine](alpine.md) builders. The walk
list is the primary followed by its backstops whichever order the calls are
written in. Repeating `mirror` takes the last value, and a backstop on its own
backs the default archive rather than replacing it.

The list is walked in order, advancing past a mirror that could not serve a
document. A mirror that serves one that does not *verify* is fatal rather than a
reason to try the next. What it served was answered for by the URL that was
asked for. The answer to a refused signature is never to ask somewhere else.

The archive serves plain HTTP with no redirect to HTTPS, and the bundled client
speaks it. Every byte it brings back is verified against the vendored keyring,
so the transport is not what the trust rests on. A caller who wants TLS, a
proxy, or a private mirror protocol supplies their own `Fetch`.

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

A read-half call drives no run and so has no run observer to report through.
`Gentoo::observe` binds a `GentooObserver` for one call instead, which is how a
caller previewing an install sees what the resolution refused:

```rust,no_run
use ferroday_cage::provision::gentoo::{Gentoo, GentooEvent};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut gentoo = Gentoo::builder("amd64")
    .binhost("x86-64")
    .install(["dev-vcs/git"])
    .build()?;

let mut sink = |event: GentooEvent<'_>| match event {
    GentooEvent::Conflict { atom, blocks, .. } => eprintln!("{atom} blocks {blocks}"),
    GentooEvent::DependencyCycle { packages, .. } => {
        eprintln!("cycle: {}", packages.join(" -> "));
    }
    _ => {}
};
let plan = gentoo
    .observe(&mut sink)
    .resolve_packages("/var/lib/machines/gentoo")?;
drop(sink);

println!("{} packages", plan.packages.len());
# Ok(())
# }
```

`Conflict`, `DependencyCycle` and `Occupied` describe how a resolution reached
its answer, which is the half a preview is for. `resolve_packages` returns the
plan, and the sink says which atom blocked which, whether the blocker is already
installed, and which packages form a cycle. An observed call reports the same
events a bootstrap does, because both go through one code path.

The same observer stops the run. `ProvisionObserver::cancelled` is consulted at
each step boundary: before a document is fetched, once the resolution is in
hand, and before the digest pass. Unlike the other userlands, it is also
consulted while the tarball is arriving. This layer has no
package boundary to break the work up. A check that ran only around the download
would answer a caller who asked to stop once all of it had been fetched. A run
stopped this way fails with `ProvisionError::Cancelled`, leaves no root behind,
and leaves no partial tarball in the cache.

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
mirror the builder setters above. The last takes a count of days or `none`.

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
11 certificates, 4 can sign	expiring between 1795718963 and 1846022400
```

`--gentoo-variants` reads the signed enumeration. It takes `--gentoo-mirror`,
`--gentoo-mirror-fallback` and `--gentoo-max-pointer-age` with the meanings they
have on a provisioning command line. The archive a listing reads is therefore
the archive an install would. `--gentoo-keyring-horizon` reaches no network at
all.

Binary packages are installed by naming the tree and the atoms:

```console
$ fcage --provision-gentoo amd64 --gentoo-variant amd64-openrc \
        --gentoo-binhost x86-64 \
        --gentoo-install 'dev-vcs/git[keyring]' \
        --gentoo-prefer-use '-X' \
        --gentoo-cache ./gentoo-cache --rootfs ./gentoo \
        /usr/bin/git --version
fcage: the binhost index names 15773 builds, generated at 1787145736
fcage: installing 74 packages (215048192 bytes)
fcage: merging dev-lang/perl-5.42.2
...
git version 2.54.0
```

`--gentoo-install` is repeatable and `--gentoo-plan` installs a plan document
instead of resolving. Two further listings answer without provisioning:

```console
$ fcage --gentoo-packages amd64 --gentoo-binhost x86-64
acct-group/3proxy	0
acct-group/adm	0-r3
...

$ fcage --gentoo-installed ./gentoo
acct-group/audio-0-r3	0	abi_x86_64 amd64 elibc_glibc kernel_linux
...
```

`--gentoo-packages` reads the binhost index. `--gentoo-installed` reads a root's
own package database and reaches no network.

## Where this layer differs from the other two

Every difference is one the archive itself makes.

| | Debian and Alpine | Gentoo |
| --- | --- | --- |
| What is installed | a package closure this crate resolves | a prebuilt tarball, and prebuilt packages over it |
| The coordinate | a suite or release, plus an architecture | an architecture, plus a variant |
| Where resolution starts | an empty root | a root with 296 packages already in it |
| Replay | a plan document, versioned and portable | the build id and variant for the stage3, a plan document for the packages |
| How long a pin lasts | as long as the archive or a snapshot service keeps the versions | about five weeks against the archive |
| Freshness | `Valid-Until`, or an index refetched every run | the pointer's own signed regeneration timestamp |
| What runs during a bootstrap | maintainer or install scripts, in a sandbox | nothing, since phase functions are not run |

Building packages *inside* a provisioned stage3 is `emerge`'s job rather than
this library's, and [the ebuild sandbox](ebuild-sandbox.md) is the worked example
of driving it.

## What is not here

**Building from source.** `emerge` inside a provisioned stage3 is what [the
ebuild sandbox](ebuild-sandbox.md) shows, and it stays that example's job.

**Phase functions.** Named above, with what their absence costs.

**The ebuild tree, and EAPI evaluation.** Neither is needed, because the binhost
index is USE-evaluated. Its dependency strings are the ones that survived the
conditionals at build time, and no `flag? ( ... )` group appears in any of them.
That is the finding the whole binary-package half rests on.

**Unmerging, upgrading and `--depclean`.** The layer installs into a root it is
building. Removing and replacing packages in a root that exists is portage's job,
and the database this layer writes is one portage can do it with.

**Detached signatures.** Gentoo publishes an `.asc` beside every tarball and a
`.sig` beside each container member. They are an alternative path for someone
verifying a download by hand, not the only one. The cleartext-signed digest
document and `Manifest` bind the same bytes, and that is what this layer
reads.

**BLAKE2B.** It sits beside SHA-512 on every `Manifest` line. A second algorithm
agreeing with the first buys nothing the first does not already give.

**A binhost of your own.** The mirror is configurable, so you can point this at
one. What is not here is a second trust configuration for a keyring that is not
Gentoo's.
