# Contributing

Thank you for your interest. ferroday-cage is a personal project maintained in
spare time. This document sets out what is welcome and how it is handled,
alongside what you need to build and test the code.

## Reporting a security issue

Report a containment bypass or another security issue privately, through the
channel [SECURITY.md](SECURITY.md) describes. These are the reports the
project most wants to receive, and they are acted on ahead of everything else.
Please do not open a public issue for one.

## Reporting a bug

Open an issue. The bug template asks for the configuration, the kernel, and
the host probes' output. That is usually enough to tell a defect from a host
that lacks a facility. The build and test instructions below are also what you
need to reproduce a problem locally.

## Proposing a capability

Open an issue describing what you are trying to do and where the library stops
you. The shape is discussable, and a sketch is enough to start from.

## Proposing a change

Open an issue before writing code, so the design can be agreed before anyone
spends time on it. The library's public surface is a compatibility commitment,
guarded by a committed API snapshot and `cargo-semver-checks`. A change to it
decides what the project promises for the rest of the 0.x series. That is
better settled in discussion than in review.

An unsolicited pull request therefore sits for some time, or is declined on
scope or design grounds after the work is done. Agreeing the shape first
spares you that. Once a change is agreed, the sections below are what it needs
to pass.

## Building

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` provisions the
right version and components automatically.

```sh
cargo build --workspace --all-features
cargo test  --workspace --all-features
```

The crate targets Linux only, and the launch mechanism requires rustix's
`linux_raw` backend. A configuration that would select the libc backend fails
the build with an explanatory `compile_error!`, rather than silently
compromising the post-fork discipline.

## Running the tests

The integration tests build real sandboxes. Where a host facility is missing
they **skip explicitly**, printing the reason on stderr rather than passing
quietly. Several environment variables turn a skip into a failure, which is how
CI asserts the security-property suites actually ran:

| Variable | Turns into a failure |
| --- | --- |
| `FERRODAY_CAGE_REQUIRE_USERNS` | Unprivileged user namespaces unavailable |
| `FERRODAY_CAGE_REQUIRE_SUBID` | No delegate can establish a range map, or the subordinate allocation cannot carry a test's map |
| `FERRODAY_CAGE_REQUIRE_TUN` | `/dev/net/tun` or the IPv6 loopback unavailable |
| `FERRODAY_CAGE_REQUIRE_OVERLAY` | Overlay-rooted sandboxes unavailable, or the whiteouts and `user.` attributes an overlay upper holds |
| `FERRODAY_CAGE_REQUIRE_LANDLOCK` | The kernel offers no Landlock LSM, or one that predates network rules (ABI 4, Linux 6.7) |
| `FERRODAY_CAGE_REQUIRE_LANDLOCK_SCOPE` | The kernel's Landlock ABI predates scopes (ABI 6, Linux 6.12) |
| `FERRODAY_CAGE_REQUIRE_SECCOMP` | The kernel offers no seccomp |
| `FERRODAY_CAGE_REQUIRE_CGROUP` | The cgroup suite runs outside a delegated cgroup v2 directory of its own that can hold its sandboxes' cgroups |
| `FERRODAY_CAGE_REQUIRE_NETWORK_TEST` | A network suite was not opted into |

A variable governs every test that needs its facility, including the host tools
such a test drives. A Landlock test that finds no `nc` fails under
`FERRODAY_CAGE_REQUIRE_LANDLOCK` too. A few skips have no variable, because
their premise is how the run was started rather than what the host provides. A
test of what happens without a delegate cannot run where one exists. One that
needs a caller other than root, or one with a controlling terminal, depends on
how it was started.

Every skip goes through the testkit's `require` module, which is what keeps a
variable honored at every site. A new test that skips calls it rather than
printing a skip of its own. `require::USERNS.skip(reason)` and its siblings
report a facility's skip, and `require::premise_unmet(reason)` reports a skip no
variable governs.

A skipped test still counts as passed, and its skip line is captured with the
rest of a passing test's output, so a green summary does not say how much of it
ran. `FERRODAY_CAGE_SKIP_LOG` names a file every skip is also appended to, one
line each: the location that called for it, the test, the variable that governs
it (`premise` where none does), and the reason. Every test binary of a run
appends to the same file, so remove it first:

```sh
rm -f target/skips.log
FERRODAY_CAGE_SKIP_LOG=$PWD/target/skips.log cargo test --workspace --all-features
cut -f3 target/skips.log | sort | uniq -c
```

To exercise the full suite locally you need three things:

- Unprivileged user namespaces enabled. On Ubuntu 23.10 and later, that is
  `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
- The `tun` module loaded.
- A subordinate id allocation for your user, from `usermod --add-subuids
  --add-subgids`.

The cgroup suite, `tests/cgroup.rs`, needs a delegated cgroup with nothing else
in it, which a terminal's own cgroup is not. Cargo's runner setting gives each
test binary a scope of its own, while cargo itself stays outside it:

```sh
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='systemd-run --user --scope --quiet -p Delegate=yes --' \
    cargo test --workspace --all-features --test cgroup
```

### The network suites

Three integration suites bootstrap from a live archive, and all are **off by
default**. `cargo test --workspace --all-features` therefore resolves against no
archive unless it is asked to, CI included. Each is opted into with its own
variable:

| Variable | Runs |
| --- | --- |
| `FERRODAY_CAGE_DEBIAN_NETWORK_TEST` | `tests/debian.rs`'s live bootstraps, against a Debian mirror |
| `FERRODAY_CAGE_ALPINE_NETWORK_TEST` | `tests/alpine.rs`'s live bootstraps, against Alpine and postmarketOS mirrors |
| `FERRODAY_CAGE_GENTOO_NETWORK_TEST` | `tests/gentoo.rs`'s live resolution and stage3 bootstrap, against the Gentoo archive |

These are the proofs that a produced root is one the distribution's own files
and tools agree with:

- Debian: `apt` and `dpkg`.
- Alpine: `apk audit` and `busybox`.
- Gentoo: the release files, and portage's own tooling in the extracted stage3.

Run them before a release, and after any change to a provisioner. They are
happy-path suites by design, and the failure paths are covered by the hermetic
unit tests beside the code, which run always.

`FERRODAY_CAGE_REQUIRE_NETWORK_TEST` turns *not* opting in into a failure. That
keeps a release check that meant to exercise them from coming back green having
run nothing. Every suite also skips when the host cannot build a sandbox at all,
because a missing user namespace is not a repository failure. That skip is
`FERRODAY_CAGE_REQUIRE_USERNS`'s to assert on, as it is everywhere else.

That is narrower than "reaches no network", and deliberately so. Every suite that
builds a sandbox needs a root filesystem to build it in. That is a pinned Alpine
minirootfs, which the first run fetches from a mirror and caches under `target/`.
A cold cache therefore reaches the network whatever is opted into, and a warm one
reaches nothing. `FERRODAY_CAGE_FIXTURE_DIR` points the cache somewhere already
populated, for a build with no network at all.

### Scratch directories

A test that needs a real filesystem tree does not compose a path under the
system temporary directory by hand. It takes one from a shape that removes its
tree when it drops, or reuses one fixed name. Either way a run adds no tree to
what earlier runs left. Four shapes cover every test:

- **A unit test** inside `crates/ferroday-cage/src` uses
  `crate::scratch::Scratch`. It creates a directory with an unpredictable name
  in the system temporary directory, dereferences to its `Path`, and removes the
  tree when it drops.
- **An integration test** uses `common::scratch_dir(name)`. It returns the path
  of an empty directory named for the test, in the fixture cache, and holds no
  guard. The tree outlives the test, and the next run of that test empties it
  before use.
- **A tree of subordinate-owned entries** comes from `common::ranged_scratch`
  instead, as `tests/export.rs` and the removal test in `tests/identity.rs` do.
  Such a tree resists removal by the calling user, `scratch_dir`'s emptying
  included. So it lives in the system temporary directory under a name carrying
  the process id. Its guard removes it through `provision::Remove` under the
  subordinate map when it drops.
- **A network suite's downloads** are not a scratch tree at all. They are kept
  on purpose, so that a second run does not fetch half a gigabyte again.
  `common::download_cache` names one fixed directory per suite. A `cargo clean`
  costing that much to undo is a reason not to run the network suites.

The fixture cache is `test-fixtures` under `target`, which `cargo clean`
clears. It holds the root filesystem fixture and every `scratch_dir` tree.
`FERRODAY_CAGE_FIXTURE_DIR` moves the fixture cache and the download caches
together. Without it, the download caches sit in the system temporary
directory. `ranged_scratch` uses the system temporary directory either way.

Both crates' `tests/common/mod.rs` are mostly re-exports of
`ferroday-cage-testkit`, a workspace member that is never published. It holds
the root filesystem fixture, the scratch directories, and the skip rule. It also
holds the tar, `ar` and `.deb` builders, the pseudoterminal harness, and the
process helpers. The suites and the library's unit tests share them rather than
keeping a copy each.

The testkit enables none of the library's features. Cargo resolves a
dev-dependency's features once for all of a package's tests and examples. A
testkit feature that reached the library would turn it on in every test build.
Where a fixture needs a library feature, the suite's `common` module supplies
that part under its own `#[cfg(feature)]`. Provisioning the fixture root takes
`tarball`, and naming a fixture repository's `file://` URL takes a provisioner
feature. That is what keeps the `features` job's featureless and powerset checks
building exactly the combination they name.

### Feature-gating a test

Every command above selects all features. None of them catches a test that uses
an API the feature selection it runs under does not provide. A new integration
test declares what it needs, one of two ways:

- **A whole binary needing a feature** gets a `[[test]]` entry in
  `crates/ferroday-cage/Cargo.toml` with `required-features`. Cargo then skips
  the target where the features are absent.
- **A binary that is only partly feature-dependent** stays out of that list and
  carries `#[cfg(feature = "...")]` on the imports, helpers, and tests that
  need one. `tests/debug_rendering.rs` is the worked example. What it asserts
  about a publication and a removal is part of a featureless build's public
  API. Gating the whole binary would stop covering it.

The `features` job checks both, so a leak surfaces there rather than in a
consumer's build.

## Before opening a pull request

CI runs all of these, and running them locally first is faster than a round trip.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps   # RUSTDOCFLAGS='-D warnings'
```

Two further gates matter when the public API moves:

- **The API snapshot.** `crates/ferroday-cage/public-api.txt` is committed, so
  any change to the public surface arrives as a reviewable diff. Regenerate it
  with the command in the `api` job of `.github/workflows/ci.yml`, including
  the nightly that job pins, and commit the result. The pin matters. The
  snapshot is rustdoc's JSON rendering, which differs between nightlies, so an
  unpinned regeneration produces a diff that is not an API change. The job
  pins the `cargo-public-api` version too, for the same reason.

  That command needs `cargo-public-api`, whose own build links libcurl and so
  wants `libssl-dev` and `pkg-config` on the machine installing it. The library
  itself needs neither, and nothing in its dependency graph links a C library.
- **Auto traits.** `crates/ferroday-cage/tests/auto_traits.rs` pins `Send` and
  `Sync` for every public type, including the ones that deliberately have
  neither. Losing an auto trait is a breaking change. Where a change withdraws
  one, the assertion and its recorded reason both need updating.

- **Command-line parity.** `tools/check-parity.py` records every public builder
  setting against the flag that reaches it, or the reason it has none, and
  fails on any difference. `fcage`'s own tests read its `FLAGS` table, so a
  library setting the table never learned is absent from both sides of any
  comparison they make. `tools/parity.toml` is the other side. It reads the
  API snapshot above, so regenerate that first when the public surface moves.

- **The provisioning seam.** `tools/check-seam.py` records what each userland
  reaches for outside `provision`, and fails on any difference. The three
  layers sit on a seam they could one day be crates of their own on, and this
  keeps that decision cheap. A new reach past the seam is recorded in
  `tools/seam.toml` with what it would cost. It also refuses a userland naming
  another outright, since the three formats are deliberately not shared. The
  [stability
  chapter](https://gregordinary.github.io/ferroday-cage/stability.html) records
  the decision itself and what would settle it.

One gate deliberately does not run here. `tools/check-keyrings.py` compares each
vendored trust anchor against what its distribution publishes today, and it
reaches the network to do it. The anchors are Debian's archive keyring, Alpine's
and postmarketOS's signing keys, and Gentoo's service keys.

It runs weekly on a schedule of its own and by hand, never on a pull request.
Keyring drift moves on a scale of months, and four archive fetches on every push
would make the always-run checks non-hermetic for nothing. Run it before a
release, and after refreshing a vendored keyring, to confirm the new bytes are
the published ones.

A doc comment on shared code can link a feature-gated item, and the `cargo doc`
above does not catch that. The link resolves under `--all-features` and under
nothing else. The `features` job documents the whole powerset for that reason,
and `cargo hack doc -p ferroday-cage --feature-powerset --depth 2 --no-deps
--no-dev-deps` reproduces it. Where a sentence genuinely names items from two
features, write it once per combination with `cfg_attr(..., doc = "...")`.
`provision::BuildLayer` is the worked example.

If you touch the guide, build it with `mdbook build docs`. That renders it and
does not compile it. The guide's Rust blocks are doctests of the library,
included by `crates/ferroday-cage/src/guide.rs` and compiled by the `cargo test`
above. A block that no longer builds fails there. A new chapter is added to that
module as well as to `docs/src/SUMMARY.md`. A test beside it holds the list to
what the guide publishes.

## Releasing

1. Settle `CHANGELOG.md`. The release's section carries its entries, and its
   heading carries the date. A fresh `Unreleased` section sits above it, with
   the comparison links updated at the foot of the file.

   An entry says what changed, in a paragraph. Why it changed that way belongs
   in the doc comment of the thing it explains, or in the guide chapter that
   covers it. That is where it stays true, and where a reader looking for it
   will be. A changelog entry carrying the reasoning as well makes it three
   places to keep right. It also turns the file a consumer reads to decide
   whether to upgrade into a design record. A **Security** entry and a
   **Breaking.** one get the room to say what a consumer must act on, and
   nothing else needs more.
2. Bump the version. The library and `fcage` version independently, so bump
   only what changed.
3. Tag the release and publish, **library first**:

   ```sh
   cargo publish -p ferroday-cage
   cargo publish -p ferroday-cage-cli
   ```

   `ferroday-cage-cli` depends on the library by version as well as by path, so
   it cannot even be packaged until that version is on crates.io. A
   workspace-wide publish fails with `no matching package named
   ferroday-cage`. Allow a moment between the two for the index to catch up.
4. Confirm the guide published. The `pages` job runs on a push to `main`. The
   site it serves is what `homepage` in `Cargo.toml` names, and what every
   documentation link in `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, and
   `CHANGELOG.md` points at. Publishing requires the repository's Pages source
   to be set to "GitHub Actions".

A published version is immutable. The keywords, description, and README shown on
the registry are recorded at publish time. Correcting any of them takes a new
version, even when no code changes. That metadata is applied by every publish
rather than by the newest version alone. Releasing a patch on an older line
therefore replaces the crate page with that line's metadata.

## Code conventions

- **Documentation is part of the change.** Public items carry rustdoc, and
  internal items carry it wherever the behavior is not obvious. Comments
  explain *why*, not *what*.
- **`unsafe` is confined** to three modules of shipped code, all in the
  library. They are the launch mechanism, the network stack's tap layer, and
  the terminal relay's signals. The relay's signals block the relayed set and
  open the descriptor those signals arrive on, and a provisioning run's
  `Interrupt` blocks `SIGINT` there the same way. `fcage` has none. The only other
  `unsafe` is in test code that drives the kernel directly: `tests/keyring.rs`,
  `tests/relay.rs`, `tests/network_filter.rs`, `tests/process.rs`,
  `tests/cgroup.rs`, and the testkit's pseudoterminal harness and its closing
  of a probe's standard descriptors.
- **Every `unsafe` block states its invariant.** Every crate in the workspace
  denies `unsafe` by default. Each block that needs it carries a `SAFETY:`
  comment stating the invariant it relies on, which
  `clippy::undocumented_unsafe_blocks` enforces.
  Every consumer of the *library* is safe Rust, and nothing in its public API
  requires a caller to write `unsafe`.
- **The post-fork stages must not allocate, lock, panic, or call libc.** They
  run between `fork` and `exec` in a process copied from a possibly
  multithreaded caller. Everything they need is marshaled by the caller
  beforehand. The `mechanism` module documentation states the full rule.
- **Errors are typed and name their subject.** A failure reports what failed and
  what it was operating on, rather than an opaque errno: the mount, the resource
  limit, the command path. An OS failure is carried as an `io::Error` and
  returned from `source()`, never as a raw `errno: i32`. Where a failure
  genuinely carried no OS error, that is an `Option<io::Error>` rather than a
  zero. Constructors take their arguments in one order, operation then locator
  then cause. Each error type has one of them, plus an `at(op, locator)` form
  for the `map_err` sites.

  A message does not repeat its cause. An error whose `source()` returns one
  says what failed and on what, and leaves the cause to `source()`. A variant
  wrapping another error is a layer like any other, with a message of its own.
  A renderer that walks the chain then prints each layer once. The workspace
  prints an error through `ErrorChain`, and the tests in `failure` hold every
  error type to the rule.
- **A new capability arrives additively** where it can: a new builder method,
  a new enum variant behind `#[non_exhaustive]`, a new accessor on an existing
  request type. See the [stability
  chapter](https://gregordinary.github.io/ferroday-cage/stability.html) for the
  promises this keeps and how they are enforced.
- **One name for one thing.** A concept the workspace already has an answer for
  is reached through that answer rather than answered again. The table under
  [The shared vocabulary](#the-shared-vocabulary) is the list of them. Where a
  second answer is warranted, it says so and says why, in the doc comment of
  the thing that is the second answer. The post-fork path checks in
  `mechanism`, which cannot allocate, are the worked example. A second answer
  that says nothing is how the vocabulary comes apart, so an unexplained one is
  a review comment.
- **A shared helper is swept for on arrival.** When a change produces one, the
  change also moves the callers that could have used it, not only the ones it
  was about. The alternative is an abstraction two callers out of five use,
  which is worse than none. A reader learns the mechanism and then finds it
  does not transfer.
- **Profile keys come from `rename_all`.** A serde container carries
  `rename_all = "kebab-case"` and its fields carry no `rename`. The two
  exceptions state themselves, and both are a plural Rust field naming a
  singular TOML table. A test pins every key the format can carry, which is what
  catches a rename, whichever end of it moved.
- **No emoji** in code, comments, documentation, or commit messages.

### The shared vocabulary

Each row is a question the workspace answers once. Before writing something that
answers one of them, reach for the answer. Before adding a row, check that the
question is not already here under different words.

Six rows below name one answer per package format rather than one answer
outright. Three of them are deliberate for one reason. Each format defines its
own version ordering, so a shared comparator would have to be told which set of
rules to apply. That is the format's identity rather than a parameter. The rows
are here so the next constraint question is answered by extending its format's
`version` module, rather than by a fourth mechanism somewhere else.

The three comparators do not share a signature, and that is the formats speaking
rather than three opinions. dpkg's algorithm is defined over every string, so
`debian::version::compare` answers an `Ordering` and has nothing to refuse. An
apk or a portage version is a token grammar instead. A string outside that
grammar is one the mirror had no business publishing, which is what the other
two report as `None`. Each module's own documentation states which it is.

The fourth, `Refusals`, is split for a different reason. Both layers collect
every refusal and fail once, which is the discipline, and what they collect is
not the same set. A portage resolution refuses in three shapes: an atom nothing
answers, a blocker, and two builds contending for one slot. The last two have no
Debian meaning, so a shared type would carry collections that are always empty
on one side. Alpine reports one refusal at a time and has no such type yet. When
it grows one, it is this row it extends.

The fifth, what a bootstrap clears of its own run, is split because each
format's root boots differently. `systemd` generates a machine id from an empty
file, while the D-Bus service that generates one on Alpine refuses an empty
file. The Gentoo layer runs no package script, so it has nothing to clear.

The sixth, what a package's name and version can contain, is split because each
format's own rules define them: Debian policy's, apk's, and the package manager
specification's, whose names differ in case, in `_`, and in where a `.` may fall.
None admits a control character, which is what lets an error or a progress
report name a package and its version bare.

| The question | The answer |
| --- | --- |
| What can a configured absolute path contain? | `path::absolute_components` |
| What can a path naming something inside a tree contain? | `path::tree_components` |
| What can one path component contain? | `path::is_ordinary_component` |
| What directory is a path's final component named in, as a path an `open` takes? | `path::parent_of` |
| Resolve a path the kernel keeps inside a tree, retrying a raced walk | `mechanism::resolve::openat2` |
| Open a directory inside a tree being provisioned | `provision::containment::open_dir`, or `containment::open_dir_path` after a fork |
| Create the missing directories of a chain inside a tree | `provision::containment::create_dirs` |
| Replace whatever holds a name in a tree with a new entry, an empty directory included | `provision::containment::replacing`, over `containment::remove_at`, and `containment::link_replacing` for a hard link, to which a name already holding its target is done |
| Write into an overlay upper where the mounted overlay would place it | `provision::containment::copy_up`, which the extractor and `Rooted::over` take over a base |
| Is this entry an overlay whiteout, or this directory opaque? | `provision::containment::is_whiteout`, `containment::is_opaque` |
| Is this extended attribute the host's rather than the tree's? | `provision::containment::host_assigned_xattr` |
| Read an entry's extended attributes, or restate an access control list or a file capability for the other side of an identity map | `provision::xattr::read_all`, `xattr::Acl` (`Acl::narrowed` where it cannot be restated), `xattr::capability_mapped` |
| Open the regular file a walk just inspected, refusing whatever took its name | `provision::containment::open_typed_file` |
| Open a named pipe just created, to set its metadata through a descriptor | `provision::containment::open_created_fifo` |
| Read or write a host-side file in a tree that is not fully trusted | `provision::rooted::Rooted` |
| What occupies a name in such a tree, without following it? | `Rooted::stat` |
| Read a file in such a tree, bounded, with absence as an answer | `Rooted::read`, `Rooted::read_if_present` |
| Remove or empty a file in such a tree only where what holds the name is approved | `Rooted::remove_if`, `Rooted::truncate_if`, judged by `Rooted::is_file_with_content` or `Rooted::is_whiteout` |
| Rewrite a file in place, keeping the owner and mode a script gave it | `Rooted::overwrite` |
| Lay a host tree into a root | `provision::CopyIn`, or `extract::overlay_tree` between configure waves |
| Give entries a tree already holds the owner only its identity map can express | `provision::copyin::reown`, an `Owed` per entry, `Owner::Host` or `Owner::Tree` |
| Which identity map, and which delegate, is a tree owned through? | `provision::identity::Ownership` |
| Stage a layer into an overlay upper, removing the upper on failure only where this call created it | `provision::layer::Staging` |
| Remove a tree a sandbox wrote, however deep | `provision::remove_tree`, which `provision::Remove` reaches from outside the crate, over the walk in `mechanism::delete_tree` |
| Take a lock file | `provision::lock_exclusive` |
| Write a file beside its destination and publish it by rename | `provision::Staged`, or `provision::write_atomically` for bytes in hand |
| Hold what an untrusted producer writes to a ceiling | `provision::LimitedWriter` |
| How do two versions of a package format compare? | `provision::gentoo::version::compare`, `alpine::version::compare`, `debian::version::compare` |
| Does this candidate satisfy this dependency's version constraint? | `provision::gentoo::atom::Atom::matches`, `alpine::version::Constraint::satisfied_by`, `debian::version::Constraint::satisfied_by` |
| What version does a `Provides`-style entry supply a name at? | `provision::alpine::version::Constraint::exact_version`, `debian::version::Constraint::exact_version` |
| What does a Gentoo root already have installed? | `provision::gentoo::installed` |
| Which targets does a Gentoo root accept a binary package built for? | `provision::gentoo::Installed::targets`, held by `gpkg::check_target` |
| Which slot does a `slot/subslot` value name? | `provision::gentoo::installed::slot_of` |
| Where does a Gentoo `name-version` end its name? | `provision::gentoo::version::version_hyphen` |
| What did one resolution refuse, and how does it read? | `provision::gentoo::resolve::Refusals`, `debian::resolve::Refusals` |
| What does a finished root not keep of the bootstrap that built it? | `provision::debian::bootstrap::clear_run_state`, `alpine::bootstrap::clear_run_state` |
| Does a dpkg `Status` field mean the package is present and configured? | `provision::debian::bootstrap::is_configured` |
| Read or rewrite the days a bootstrap's account tools recorded in `/etc/shadow` | `provision::accounts` |
| Which id does a root's `/etc/passwd` or `/etc/group` give a name? | `provision::accounts::ids` |
| Where does portage keep its database inside a root? | `provision::gentoo::DB_DIR` |
| What can a USE flag's name contain, and what does a candidate answer for one? | `provision::gentoo::atom::is_flag`, `atom::use_flag` |
| What can a package's name and version contain, as an index or a plan states them? | `provision::debian::index::is_package_name` and `debian::version::is_version`, `alpine::index::is_package_name` and `alpine::version::parse`, `gentoo::atom::is_package` and `gentoo::version::parse` |
| What can a release, a component, or an architecture contain? | `provision::coordinate::check` |
| What can a digest of a given algorithm contain? | `provision::digest::Algorithm::is_hex` |
| What must a planned package or a stage3 hash to, what did the release or the index a plan records, and which digests does a refusal name? | `provision::digest::Digest`, an `Algorithm` and lowercase hex `Digest::new` held to its width, which `digest::stream` and `Digest::of` give for bytes the crate digests. An Alpine package's `control_identity` and a Gentoo package's `md5` are not one, nor is what names a control identity, as its documentation says |
| Hold a Debian index or package to every digest its archive records | `provision::debian::digests::Digests`, whose `check_bytes` and `check_stream` compare each, as apt does, and whose `planned` is the one a plan keeps |
| Is this cleartext-signed document authentic against this keyring? | `provision::openpgp::Keyring::verify` |
| What bounds a signed document whose length nothing signed states? | `provision::openpgp::MAX_SIGNED_DOCUMENT_BYTES` |
| Spell bytes in base64, or read base64 back | `provision::alpine::base64::encode`, `base64::decode` |
| Read a field-and-stanza document one stanza at a time, in place, or carry a stanza on whole, or write a plan document and read its header, its number fields and its list fields | `provision::document::parse`, `Stanza::get`, `Stanza::get_each`, `Stanza::text`, `document::header`, `document::number`, `document::list` |
| Which names does a Debian or Alpine index offer, real or virtual? | `provision::Available` |
| Why can a bootstrap for a foreign architecture not run on this host? | `provision::binfmt::preflight` |
| Hold a tar entry whole, bounded | `provision::tar::TarReader::read_entry` |
| Which compression does a stream begin with? | `provision::compress::Codec::of` |
| Fill a buffer from a reader, short only at the end of its input | `provision::compress::read_fully` |
| Which standard stream did a provisioner's in-sandbox output come from? | `provision::Stream` |
| Take the first mirror that serves a resource, past those that do not | `provision::walk_mirrors` |
| Fetch several resources at once, where the transport can | `provision::Fetch::fetch_all` |
| Deliver one job of a batch: what it asked for, and where its body goes | `provision::FetchJob::parts` |
| Join a mirror-relative path onto a mirror | `provision::mirror_url` |
| Is this failure one to ask the next mirror about? | `provision::Failover` |
| Name a local path as a `file://` URL | `provision::file_url` |
| Decode a URL's percent escapes | `provision::fetch::percent_decode` |
| Where does a run keep its downloads, and is that directory its own? | `provision::cache::PackageCache`, and `PackageCache::is_derived` for whether a directory a caller named is the run's own |
| Download into a package cache, checked before it is published there | `provision::cache::download`, or `cache::prefetch` for a batch |
| Create a package cache, or open the regular file at a path in a directory others write, a cache entry or a build's output | `provision::cache::create`, `cache::open_entry` |
| What time is it, as a Unix timestamp? | `provision::now_epoch` |
| What Debian architecture is the host? | `provision::debian::host_architecture` |
| What Alpine architecture is the host? | `provision::alpine::host_architecture` |
| Name a filesystem entry no concurrent caller can collide with | `host::unique_hex` |
| Fill a buffer from the kernel's randomness | `host::fill_random` |
| Fork, exec, exit, change signal state, or read signals from a descriptor, without libc | `mechanism::sys` |
| Has a process exited, or wait until it has, through its pidfd | `mechanism::has_exited`, `mechanism::await_exit`, and `reap_via_pidfd` to collect a child of the caller's own |
| Fork a helper child and signal or reap it whatever else in the caller reaps | `mechanism::sys::fork_with_pidfd`, which hands back a `mechanism::Forked`, or `mechanism::sys::probe` for a probe whose exit code is its answer |
| Write a forked child's own identity map, or take the child into a mapped user namespace of its own | `mechanism::child::establish_map`, and `child::enter_mapped_namespace` for the whole entry, other namespaces beside it included |
| Keep a descriptor the launch creates off the standard streams' numbers | `mechanism::above_stdio` in the caller, and in the sandbox's processes the launch stage's `child::hold_closed_streams`, which holds each number the caller left closed before any stage creates a descriptor |
| Do work in a sandbox's network namespace and get one descriptor back | `mechanism::netns::in_network_namespace`, after `netns::Namespaces::of` |
| Open a socket in the family of the address it connects to or binds | `mechanism::netns::socket_for` |
| Report a `syscalls` errno as the rustix one the crate speaks | `mechanism::sys::errno` |
| Move framed bytes between a helper child and its caller | `mechanism::frame` |
| Write all of these bytes to a descriptor, retrying `EINTR` | `mechanism::frame::write_full` |
| Write a file that takes its content in one write, such as an identity map | `mechanism::frame::write_whole` |
| Fill this buffer from a descriptor, retrying `EINTR` | `mechanism::frame::read_full`, or `read_full_or_eof` where end of input is an ending, and `read_full_or_short` where how much arrived matters |
| Retry one call a signal interrupted | `mechanism::frame::retry_on_intr!` |
| Encode, decode, or read a helper child's outcome record | `mechanism::frame::encode_record`, `decode_record`, `read_record` |
| Encode or decode the supervisor's status record, the command's outcome and what it used | `mechanism::encode_status`, `mechanism::decode_status`, with the usage read by `mechanism::sys::children_usage` |
| Hand a descriptor across a socket, on a message of its own protocol | `mechanism::frame::send_with_fd`, `recv_with_fd` |
| What limits do both ends of that protocol agree on? | `mechanism::bounds` |
| Resolve a range identity map into the extents a delegate writes, validated | `idmap::resolve_delegate`, through the configured delegate or the bundled chain |
| Can a provisioner establish its range map, asked before it downloads anything? | `idmap::establishable` |
| Can the sandboxes a provisioner runs the target's binaries in install their network filter, asked before it downloads anything? | `provision::layer::network_filter_preflight`, over `host::seccomp_available` |
| Can this process install a seccomp filter? | `host::seccomp_available`, which installs one in a forked child through `mechanism::seccomp::installable` |
| Can a sandbox with a PID namespace of its own mount its procfs here, and why not? | `host::procfs_blocker`, which mounts one in a forked child through `mechanism::probe_procfs_mount`, and `host::procfs_refusal` for the explanation alone |
| Give a launch a cgroup of its own beneath a delegated parent, read what its tree used, end its tree, and remove it | `cgroup::Cgroup`, which a launch creates before the fork with the limits on it and a leaf beneath it, which the launch stage joins through the leaf's `cgroup.procs`, and which the running handle and its kill handles share until the last of them drops |
| Would a launch beneath this parent be refused its cgroup, and why? | `host::cgroup_blocker`, which carries out `cgroup::Cgroup::create` and a join through `mechanism::probe_cgroup_join`, with every errno read by `cgroup::refusal` as the launch's own are |
| Which cgroup does this process run in? | `host::own_cgroup`, over `host::MountEntry::parse` |
| Stop a provisioning run on `SIGINT`, removing what it staged | `provision::Interrupt`, which an observer answers `ProvisionObserver::cancelled` from |
| Which cgroup limit does `NAME=VALUE` spell? | `CgroupLimit`'s `FromStr`, whose names are the keys of a profile's `[cgroup]` table |
| Read this process's mount table | `host::MountEntry::parse`, one line of the kernel's `mountinfo` at a time |
| Where does a mount table mount the cgroup v2 hierarchy? | `host::cgroup2_mounts`, over `host::MountEntry::parse` |
| Can a restriction's command write its cgroup's files or start a process in another cgroup? | `restrict::ensure_cgroup_held`, which names the `CgroupReach` left open |
| Can the shadow helpers establish a range map on this host at all? | `host::helper_blocker`, which `SubidMapper` and `host::range_map_blocker` both ask |
| Can this caller write a range map directly, without a delegate? | `idmap::direct_write_refusal`, over `idmap::effective_capabilities`, which `DirectMapper` asks of a request and `host::range_map_blocker` of no extent at all |
| Is a gid map the caller's own gid alone, under which no group list can be set? | `idmap::is_own_gid_alone` |
| What does the single-identity map write? | `idmap::single_identity_lines` |
| Validate the command a sandbox or a restriction executes | `spec::validate_command` |
| Which syscall number, or which errno, does a name spell for a seccomp policy? | `SeccompRules::syscall`, `SeccompRules::errno` |
| Does a seccomp policy answer every call of a syscall with an errno, whatever its arguments? | `SeccompPolicy::answers_with_errno` |
| Write a classic-BPF seccomp program by hand, or install one | `mechanism::seccomp`: its `bpf` opcodes and offsets, its audit architectures, and `seccomp::install` |
| Run a seccomp program over a syscall in a unit test | `mechanism::seccomp::eval` |
| Does a launch install the network filter, and what does the filter refuse? | `mechanism::seccomp::installs_network_filter` and `seccomp::NETWORK_FILTER_REFUSALS`, which the launch and the provenance record both read |
| What does a launch refuse its sandbox where the sandbox keeps the caller's session keyring? | `mechanism::seccomp::KEYRING_FILTER`, which the launch stage installs where the kernel refuses its keyring join |
| Does a kernel at a Landlock ABI enforce this right or this scope? | `hardening::fs_enforced`, `hardening::net_enforced`, `hardening::scope_enforced`, which `host::landlock_enforces_fs`, `host::landlock_enforces_net` and `host::landlock_enforces_scope` ask of the running kernel |
| Can this kernel enforce a Landlock request that is a reach's only bound? | `mechanism::HardeningPlan::ensure_sandbox_enforceable` for a sandbox, `HardeningPlan::net_grant_unenforced` for a network grant a stack attaching to one would carry connections past, and `HardeningPlan::ensure_landlock_enforceable` with `hardening::ensure_scopes_enforceable` for a restriction, and `hardening::settle_resolve_unix` for the unix-socket restriction in either |
| Compose an overlay's mount options | `mechanism::overlay_options` |
| What does a mount op bring to rest on its target, if anything? | `mechanism::MountAction::arrival`, or `Arrival::of_raw` for a raw mount's flags |
| Read a raw mount's flags as `mount(2)` acts on them | `mechanism::raw_mount_flags` |
| Is this path at or under a mount target the launch froze? | `spec::covers` |
| Does a launch bind the host's `resolv.conf`, or has a mount of the caller's claimed it? | `CageBuilder::get_resolv_conf` |
| Does the network stack carry the guest's traffic to this destination? | `NetStack::forwards` |
| Report a step over a wire, by number | `wire::wire_enum!` |
| Declare an enum together with the roster of its own variants | `roster::roster_enum!` |
| State a `poll` deadline | `poll::timeout` for a duration, `poll::until` for an instant, which is zero once the instant has passed |
| Stop watching a channel a `poll` loop has finished with | leave it out of the polled slice, as the `poll` module states |
| Stop watching a channel the running handle's readiness set holds | `running::Readiness::close`, which takes it out of the epoll set before closing it, since a fork's copy of the descriptor would keep the registration |
| Report an OS failure with its operation and its subject | `failure::path_io_error!`, which declares each error type's `io` and `at` constructors |
| Name, in an error or a progress report, a string a mirror, an index, a package, or a sandbox supplied | `{:?}`, which escapes a control character, as the `failure` module states, unless an alphabet without control characters already admitted the value |
| Render an error with every cause beneath it | `ErrorChain` |
| What process exit code does a launcher report? | `ExitStatus::shell_code`, `Error::shell_code`, and `ExitStatus::signaled` for an outcome of the caller's own, such as a reader gone |
| Write a line of `fcage`'s own, deciding what a reader gone means | the CLI's `output` module: `print_stdout`, `say`, `report` |
| Make a scratch tree for a test that leaves nothing to accumulate | `scratch::Scratch`, removed when it drops, or from a test suite `common::scratch_dir`, emptied when the next run reuses it, and `common::ranged_scratch` for a tree of subordinate-owned entries |
| What happens when a run's timeout runs out? | `relay::Escalation` |
| Drive an interactive terminal session from the caller's terminal | `relay::Relay` |
| Parse an argument in an example | `examples/common` |
| Build a fixture a test suite needs | the `ferroday-cage-testkit` crate |
| Skip a test the host cannot run, or fail it where a `REQUIRE` variable says it must run | `ferroday_cage_testkit::require` |
| Play the user at a pseudoterminal in a test | `ferroday_cage_testkit::pty` |
| Wait in a test until a descriptor is readable, failing past a deadline | `ferroday_cage_testkit::fd::readable_by` |
| Run a probe with its standard descriptors closed, and put them back | `ferroday_cage_testkit::fd::with_standard_streams_closed`, and `fd::is_open` to ask of one without opening another |
| Run a host process in a test, failing the test past a deadline | `ferroday_cage_testkit::process::run_bounded`, or `spawn_grouped` then `finish_bounded` |
| How much processor time has a process or a thread used? | `ferroday_cage_testkit::process::cpu_ticks`, `thread_ticks` |

Two guards hold the table to the code, and each covers what the other cannot:

- `clippy.toml` names the primitives whose second *call* is the drift, with the
  answer in the diagnostic. A site the answer genuinely does not cover carries
  `#[expect(clippy::disallowed_methods)]` and a comment saying which part does
  not fit.
- `tools/idioms.toml` records where the shapes clippy cannot see occur today,
  and `tools/check-idioms.py` fails on any difference. Those shapes are an
  operator, a hand-written split, a formatted URL. It is not a ban. A new site is
  sometimes right, and is then recorded there with its reason. That is the same
  convention in a file rather than a doc comment.

Neither guard decides anything. What they buy is that a second answer is
*chosen*, in a diff a reviewer can see.

## Commit messages

Write in the imperative mood, describing the change in the repository's own
terms. Say what the code now does, not what a task list called it. A body
explaining the reasoning is welcome where the reasoning is not obvious.

## License

<!-- prose-lint: off -- license text, quoted verbatim. -->

The project is dual-licensed under Apache-2.0 and MIT. Unless you state
otherwise, any contribution you intentionally submit for inclusion, as defined
in the Apache-2.0 license, is dual-licensed the same way, with no additional
terms or conditions.

<!-- prose-lint: on -->
