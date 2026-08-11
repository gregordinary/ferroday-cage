# Contributing

Thank you for your interest. ferroday-cage is a personal project maintained in
spare time, so this document sets out what is welcome and how it is handled,
alongside what you need to build and test the code.

## Reporting a security issue

Report a containment bypass or another security issue privately, through the
channel [SECURITY.md](SECURITY.md) describes. These are the reports the
project most wants to receive, and they are acted on ahead of everything else.
Please do not open a public issue for one.

## Reporting a bug

Open an issue. The bug template asks for the configuration, the kernel, and
the host probes' output, which is usually enough to tell a defect from a host
that lacks a facility. The build and test instructions below are also what you
need to reproduce a problem locally.

## Proposing a capability

Open an issue describing what you are trying to do and where the library stops
you. The shape is discussable; a sketch is enough to start from.

## Proposing a change

Open an issue before writing code, so the design can be agreed before anyone
spends time on it. The library's public surface is a compatibility commitment
guarded by a committed API snapshot and `cargo-semver-checks`, and a change to
it is a decision about what the project promises for the rest of the 0.x
series — better settled in discussion than in review.

An unsolicited pull request may therefore sit for some time, or be declined on
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
`linux_raw` backend; a configuration that would select the libc backend fails
the build with an explanatory `compile_error!` rather than silently
compromising the post-fork discipline.

## Running the tests

The integration tests build real sandboxes. Where a host facility is missing
they **skip explicitly**, printing the reason on stderr rather than passing
quietly. Several environment variables turn a skip into a failure, which is how
CI asserts the security-property suites actually ran:

| Variable | Turns into a failure |
| --- | --- |
| `FERRODAY_CAGE_REQUIRE_USERNS` | Unprivileged user namespaces unavailable |
| `FERRODAY_CAGE_REQUIRE_SUBID` | No delegate can establish a range map |
| `FERRODAY_CAGE_REQUIRE_TUN` | `/dev/net/tun` unavailable |
| `FERRODAY_CAGE_REQUIRE_LANDLOCK` | The kernel offers no Landlock LSM |
| `FERRODAY_CAGE_REQUIRE_SECCOMP` | The kernel offers no seccomp |
| `FERRODAY_CAGE_REQUIRE_NETWORK_TEST` | A network suite was not opted into |

To exercise the full suite locally you need unprivileged user namespaces
enabled (on Ubuntu 23.10 and later, `sysctl -w
kernel.apparmor_restrict_unprivileged_userns=0`), the `tun` module loaded, and
a subordinate id allocation for your user (`usermod --add-subuids
--add-subgids`).

### The network suites

Three integration suites bootstrap from a live archive, and all are **off by
default**, so `cargo test --workspace --all-features` — CI included — resolves
against no archive unless it is asked to. Each is opted into with its own
variable:

| Variable | Runs |
| --- | --- |
| `FERRODAY_CAGE_DEBIAN_NETWORK_TEST` | `tests/debian.rs`'s live bootstraps, against a Debian mirror |
| `FERRODAY_CAGE_ALPINE_NETWORK_TEST` | `tests/alpine.rs`'s live bootstraps, against Alpine and postmarketOS mirrors |
| `FERRODAY_CAGE_GENTOO_NETWORK_TEST` | `tests/gentoo.rs`'s live resolution and stage3 bootstrap, against the Gentoo archive |

These are the proofs that a produced root is one the distribution's own files
and tools agree with — `apt` and `dpkg` on the Debian side, `apk audit` and
`busybox` on the Alpine one, and on the Gentoo side the release files and
portage's own tooling in the extracted stage3 — so run them before a release and
after any change to a provisioner. They are happy-path suites by design; the failure paths are covered
by the hermetic unit tests beside the code, which run always.

`FERRODAY_CAGE_REQUIRE_NETWORK_TEST` turns *not* opting in into a failure, which
is what keeps a release check that meant to exercise them from coming back green
having run nothing. Both suites also skip when the host cannot build a sandbox at
all — a missing user namespace is not a repository failure — and that skip is
`FERRODAY_CAGE_REQUIRE_USERNS`'s to assert on, as it is everywhere else.

That is narrower than "reaches no network", and deliberately so. Every suite that
builds a sandbox needs a root filesystem to build it in, and that is a pinned
Alpine minirootfs the first run fetches from a mirror and caches under `target/`.
A cold cache therefore reaches the network whatever is opted into; a warm one
reaches nothing. `FERRODAY_CAGE_FIXTURE_DIR` points the cache somewhere already
populated, for a build with no network at all.

### Scratch directories

A test that needs a real filesystem tree takes it from a guard that removes the
tree when it drops, rather than composing a path under the system temporary
directory by hand. A directory that only clears itself on the *next* run leaves
one tree per run behind forever, which a long-lived machine notices.

- **A unit test** inside `crates/ferroday-cage/src` uses
  `crate::scratch::Scratch`, which dereferences to its `Path`.
- **An integration test** uses `common::scratch_dir`, which places its trees
  under `target` so `cargo clean` clears them. Two tests name a tree of their
  own instead — `tests/export.rs` and the removal test in `tests/identity.rs` —
  because both fill it with subordinate-owned entries, which have to be removed
  through `provision::remove` rather than by the calling user. `scratch_dir`
  clears the previous run's tree as the calling user, which is exactly what such
  a tree resists.

Both crates' `tests/common/mod.rs` are re-exports of `ferroday-cage-testkit`, a
workspace member that is never published. It holds the rootfs fixture, the
scratch directories, and the builders for `.deb`, `ar`, and tar fixtures, so the
two suites share them rather than keeping a copy each. Every part of it that
needs a library feature sits behind one of its own that forwards, and a dependent
enables only what it uses — which is what keeps the `features` job's featureless
and powerset checks meaning what they say.

### Feature-gating a test

Every command above selects all features, so none of them can catch a test that
uses an API the feature selection it runs under does not provide. A new
integration test declares what it needs, one of two ways:

- **A whole binary needing a feature** gets a `[[test]]` entry in
  `crates/ferroday-cage/Cargo.toml` with `required-features`. Cargo then skips
  the target where the features are absent.
- **A binary that is only partly feature-dependent** stays out of that list and
  carries `#[cfg(feature = "...")]` on the imports, helpers, and tests that
  need one. `tests/debug_rendering.rs` is the worked example: what it asserts
  about a publication and a removal is part of a featureless build's public
  API, and gating the whole binary would stop covering it.

The `features` job checks both, so a leak surfaces there rather than in a
consumer's build.

## Before opening a pull request

CI runs all of these; running them locally first is faster than a round trip.

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
  the nightly that job pins, and commit the result. The pin matters: the
  snapshot is rustdoc's JSON rendering, which differs between nightlies, so an
  unpinned regeneration produces a diff that is not an API change. That command
  needs `cargo-public-api`, whose own build links libcurl and so wants
  `libssl-dev` and `pkg-config` on the machine installing it. The library
  itself needs neither, and nothing in its dependency graph links a C
  library.
- **Auto traits.** `crates/ferroday-cage/tests/auto_traits.rs` pins `Send` and
  `Sync` for every public type, including the ones that deliberately have
  neither. Losing an auto trait is a breaking change; if a change withdraws
  one, the assertion and its recorded reason both need updating.

One gate deliberately does not run here. `tools/check-keyrings.py` compares
each vendored trust anchor -- Debian's archive keyring, Alpine's and
postmarketOS's signing keys, Gentoo's service keys -- against what its
distribution publishes today, and it reaches the network to do it. It runs
weekly on a schedule of its own and by hand, never on a pull request: keyring
drift moves on a scale of months, and four archive fetches on every push would
make the always-run checks non-hermetic for nothing. Run it before a release,
and after refreshing a vendored keyring, to confirm the new bytes are the
published ones.

If a doc comment on shared code links a feature-gated item, the `cargo doc`
above will not catch it: the link resolves under `--all-features` and under
nothing else. The `features` job documents the whole powerset for that reason,
and `cargo hack doc -p ferroday-cage --feature-powerset --depth 2 --no-deps
--no-dev-deps` reproduces it. Where a sentence genuinely names items from two
features, write it once per combination with `cfg_attr(..., doc = "...")`;
`provision::BuildLayer` is the worked example.

If you touch the guide, build it: `mdbook build docs`.

## Releasing

1. Settle `CHANGELOG.md`: the release's section carries its entries, its
   heading carries the date, and a fresh `Unreleased` section sits above it
   with the comparison links updated at the foot of the file.
2. Bump the version. The library and `fcage` version independently, so bump
   only what changed.
3. Tag the release and publish, **library first**:

   ```sh
   cargo publish -p ferroday-cage
   cargo publish -p ferroday-cage-cli
   ```

   `ferroday-cage-cli` depends on the library by version as well as by path,
   so it cannot even be packaged until that version is on crates.io — a
   workspace-wide publish fails with `no matching package named
   ferroday-cage`. Allow a moment between the two for the index to catch up.
4. Confirm the guide published: the `pages` job runs on a push to `main`, and
   the site it serves is what `homepage` in `Cargo.toml` and every
   documentation link in `README.md`, `SECURITY.md`, `CONTRIBUTING.md`, and
   `CHANGELOG.md` point at. Publishing requires the repository's Pages source
   to be set to "GitHub Actions".

A published version is immutable. The keywords, description, and README shown
on the registry are recorded at publish time, so correcting any of them takes a
new version even when no code changes. That metadata is applied by every
publish rather than by the newest version alone, so releasing a patch on an
older line replaces the crate page with that line's metadata.

## Code conventions

- **Documentation is part of the change.** Public items carry rustdoc, and
  internal items carry it wherever the behavior is not obvious. Comments
  explain *why*, not *what*.
- **`unsafe` is confined** to three modules: the library's launch mechanism and
  the network stack's tap layer, and `fcage`'s terminal relay, which blocks its
  signals and opens the descriptor they arrive on. Both crates deny it by
  default; each block that needs it carries a `SAFETY:` comment stating the
  invariant it relies on, which is enforced by
  `clippy::undocumented_unsafe_blocks`. Every consumer of the *library* is safe
  Rust: nothing in its public API requires a caller to write `unsafe`.
- **The post-fork stages must not allocate, lock, panic, or call libc.** They
  run between `fork` and `exec` in a process copied from a possibly
  multithreaded caller. Everything they need is marshaled by the caller
  beforehand; see the `mechanism` module documentation for the full rule.
- **Errors are typed and name their subject.** A failure reports what failed
  and what it was operating on — the mount, the resource limit, the command
  path — rather than an opaque errno. An OS failure is carried as an
  `io::Error` and returned from `source()`, never as a raw `errno: i32`; where a
  failure genuinely carried no OS error, that is an `Option<io::Error>` rather
  than a zero. Constructors take their arguments in one order — operation,
  locator, cause — and each error type has one of them, plus an `at(op,
  locator)` form for the `map_err` sites.
- **A new capability arrives additively** where it can: a new builder method,
  a new enum variant behind `#[non_exhaustive]`, a new accessor on an existing
  request type. See the [stability
  chapter](https://gregordinary.github.io/ferroday-cage/stability.html) for the
  promises this keeps and how they are enforced.
- **One name for one thing.** A concept the workspace already has an answer for
  is reached through that answer rather than answered again; the table under
  [The shared vocabulary](#the-shared-vocabulary) is the list of them. Where a
  second answer is warranted, it says so and says why, in the doc comment of the
  thing that is the second answer — the post-fork path checks in `mechanism`,
  which cannot allocate, are the worked example. A second answer that says
  nothing is how the vocabulary comes apart, so an unexplained one is a review
  comment.
- **A shared helper is swept for on arrival.** When a change produces one, the
  change also moves the callers that could have used it, not only the ones it
  was about. The alternative is an abstraction two callers out of five use,
  which is worse than none: a reader learns the mechanism and then finds it does
  not transfer.
- **Profile keys come from `rename_all`.** A serde container carries
  `rename_all = "kebab-case"` and its fields carry no `rename`. The two
  exceptions state themselves, and both are a plural Rust field naming a
  singular TOML table. A test pins every key the format can carry, which is what
  catches a rename, whichever end of it moved.
- **No emoji** in code, comments, documentation, or commit messages.

### The shared vocabulary

Each row is a question the workspace answers once. Before writing something
that answers one of them, reach for the answer; before adding a row, check that
the question is not already here under different words.

| The question | The answer |
| --- | --- |
| What may a configured absolute path contain? | `path::absolute_components` |
| What may a path naming something inside a tree contain? | `path::tree_components` |
| What may one path component contain? | `path::is_ordinary_component` |
| Open a directory the kernel keeps inside a tree | `provision::containment::open_dir` |
| Read or write a host-side file in a tree that is not fully trusted | `provision::rooted::Rooted` |
| What may a release, a component, or an architecture contain? | `provision::coordinate::check` |
| What may a digest of a given algorithm contain? | `provision::digest::Algorithm::is_hex` |
| Is this cleartext-signed document authentic against this keyring? | `provision::openpgp::Keyring::verify` |
| Read or write a plan document | `provision::document` |
| Which standard stream did a provisioner's in-cage output come from? | `provision::Stream` |
| Name a local path as a `file://` URL | `provision::file_url` |
| What Debian architecture is the host? | `provision::debian::host_architecture` |
| What Alpine architecture is the host? | `provision::alpine::host_architecture` |
| Move framed bytes between a helper child and its caller | `mechanism::frame` |
| What limits do both ends of that protocol agree on? | `mechanism::bounds` |
| Report a step over a wire, by number | `wire::wire_enum!` |
| State a `poll` deadline, or retire a `poll` slot | `poll::timeout`, `poll::slot` |
| Report an OS failure with its operation and its subject | each error type's `io` and `at` constructors |
| What process exit code does a launcher report? | `ExitStatus::shell_code`, `Error::shell_code` |
| Make a scratch tree that clears itself | `scratch::Scratch`, or `common::scratch_dir` from a test suite |
| What does `fcage` do when `--timeout` runs out? | `escalation::Escalation` |
| Parse an argument in an example | `examples/common` |
| Build a fixture a test suite needs | the `ferroday-cage-testkit` crate |

Two guards hold the table to the code, and each covers what the other cannot:

- `clippy.toml` names the primitives whose second *call* is the drift, with the
  answer in the diagnostic. A site the answer genuinely does not cover carries
  `#[allow(clippy::disallowed_methods)]` and a comment saying which part does
  not fit.
- `tools/idioms.toml` records where the shapes clippy cannot see — an operator,
  a hand-written split, a formatted URL — occur today, and
  `tools/check-idioms.py` fails on any difference. It is not a ban: a new site
  is sometimes right, and is then recorded there with its reason, which is the
  same convention in a file rather than a doc comment.

Neither guard decides anything. What they buy is that a second answer is
*chosen*, in a diff a reviewer can see.

## Commit messages

Write in the imperative mood, describing the change in the repository's own
terms — what the code now does, not what a task list called it. A body
explaining the reasoning is welcome where the reasoning is not obvious.

## License

The project is dual-licensed under Apache-2.0 and MIT. Unless you state
otherwise, any contribution you intentionally submit for inclusion, as defined
in the Apache-2.0 license, is dual-licensed the same way, with no additional
terms or conditions.
