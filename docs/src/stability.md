# Stability and versioning

ferroday-cage publishes two interfaces: the Rust API and the TOML profile
format. This chapter states what each promises, and — as importantly — what
neither covers.

## Versioning

The library follows Cargo's semantic versioning. Before 1.0 the minor position
is the breaking one: releases sharing a minor version are compatible with each
other, and a new minor version may break. A release that breaks says so, entry
by entry, in the [changelog](https://github.com/gregordinary/ferroday-cage/blob/main/CHANGELOG.md).

`fcage`, the command-line interface, versions independently of the library. Its
compatibility contract is its flags, exit codes, and output format, so a
library release does not move it and a library break does not force one.

## What the Rust API promises

Within a compatible release series:

- No public item is removed or renamed, and no signature changes.
- No trait gains a method without a default body.
- No public type loses `Send` or `Sync`. These are pinned by assertions in the
  test suite, because losing an auto trait produces no compiler error inside
  the crate and no diagnostic from a semver checker.
- Cargo features are purely additive: enabling one adds items and never
  changes or removes existing ones. No feature is renamed or removed.

### The two opt-outs

Two settings are promises about what the library will *not* do, and they are
covered here rather than in the uncovered list below:

- **`base_env(false)`.** The command's environment is exactly the pairs the
  caller set. The library supplies no variable of its own, in this release or
  any later one.
- **`managed_mounts(false)`.** The library establishes no mount of its own. A
  managed mount introduced in a later release is suppressed too.

Both exist because the corresponding defaults are *not* covered, and a
consumer cannot pre-empt an addition it cannot yet name. Overriding a base
variable requires knowing its name; disabling a managed mount requires knowing
it exists. The opt-outs are the form of protection that does not require
knowing what comes next, which is why the guarantee has to sit here — an
opt-out the library could later add to would have exactly the defect it exists
to fix.

Neither promises anything about the *defaults*, which remain free to change.

### Matching on a `#[non_exhaustive]` type

Every public enum is `#[non_exhaustive]`, and so is every struct variant. Both
levels are load-bearing, and each needs its own escape in a `match`:

```rust,ignore
match event {
    // `..` absorbs a field added to a variant already matched here.
    DebianEvent::Downloading { package, index, total, .. } => { /* ... */ }
    DebianEvent::Extracting { package, .. } => { /* ... */ }
    // The wildcard absorbs a variant added later.
    _ => {}
}
```

A wildcard arm alone is not enough: without `..`, adding a field to
`Downloading` would still fail to compile. Writing both means new variants and
new fields both arrive as patch releases.

Unit and tuple variants — `DebianEvent::Resolving`, `Network::Host`,
`IdentityMap::Subordinate` — are never marked `#[non_exhaustive]`, because that
attribute makes them unnameable outside the crate rather than merely
unconstructible. They are matched and constructed as ordinary variants.

### Constructing errors

Error types a consumer produces, rather than only inspects, carry
constructors: `FetchError::not_found`, `IdMapError::unsatisfiable`,
`ProvisionError::other`, and their siblings. Use them. The variants themselves
are `#[non_exhaustive]` so they can gain fields, which means struct-literal
construction is reserved to the crate.

### Extension traits

`Provisioner`, `Fetch`, `IdMapper`, and `Observer` are the seams a consumer
implements. Every method added to any of them in a later release will carry a
default body, so an existing implementation keeps compiling.

New *inputs* to an existing method are a separate problem, since adding a
parameter breaks the signature whatever the defaults. `Provisioner::provision`
and `Fetch::fetch` therefore take a request value — `ProvisionRequest`,
`FetchRequest` — rather than loose parameters, and new inputs arrive as
accessors on it.

#### Thread bounds

Which of the four carry `Send`/`Sync` follows one rule: **a seam the library
stores is bounded; a seam it only borrows for the duration of a call is not.**

| Trait | How the library holds it | Bounds |
| --- | --- | --- |
| `IdMapper` | Stored in `IdentityMap` | `Send + Sync` |
| `Fetch` | Stored in `Debian` | `Send` |
| `Provisioner` | `&mut dyn`, for one `ensure` call | None |
| `Observer` | `&mut dyn`, for one run | None |

A stored seam's bounds become the bounds of the type that owns it, so leaving
`Fetch` unbounded would make `Debian` unable to cross a thread. A borrowed seam
has no such reach: the library calls it on the caller's own thread, from inside
a blocking wait, and does not outlive the call. Bounding those would cost
implementations something and buy nothing.

`Fetch` requires `Send` and not `Sync`, because every operation on a `Debian`
takes `&mut self` — a shared reference to one cannot do any work, so requiring
`Sync` would only rule out a transport that caches behind a `Cell`. The
requirement is on *moving* a transport, never on calling it concurrently.

The consequence for a consumer: `Debian` and `DebianBuilder` are `Send`, so a
provisioner can be built on one thread and run on another. `Running`, `Pending`,
and `Debian::observe`'s `Observed` are neither, because each borrows an
unbounded sink; they stay on the thread that created them, and `KillHandle` is
the piece that crosses threads to stop a run.

### Parameter conventions

Settled so that generalising a parameter later is never a breaking change:

| Input | Type |
| --- | --- |
| A filesystem path | `impl AsRef<Path>` |
| An owned string the callee keeps | `impl Into<String>` |
| Borrowed text the callee only reads | `&str` |
| A collection | `impl IntoIterator<Item = ...>` |

## What the profile format promises

A profile is a serialized `CageBuilder`. Every key is the kebab-case form of the
field's name, derived by `rename_all` on the container; the two exceptions are
stated explicitly, and both are a plural Rust field naming a singular TOML table
(`rlimits` becomes `rlimit`, `mounts` becomes `mount`). A test pins the exact
key set the format can carry, so a Rust-side field rename, a changed
`rename_all`, or a newly added field moves a key only where that diff is
reviewed.

Compatibility runs in one direction: **a profile works with the library
version that wrote it, or any later one, and never with an earlier one.**

Unknown keys are rejected rather than ignored. This is deliberate. A profile
key names a security-relevant posture, and silently discarding one the library
does not understand would run a sandbox weaker than the profile asked for — the
same reasoning that makes a `serde`-without-`hardening` build refuse a profile
configuring hardening, rather than drop it. An older library therefore refuses
a newer profile by design; upgrade the library rather than trimming the
profile.

## What is not covered

None of the following is part of either interface. Each can change in any
release, including a patch.

- **`Display` strings on every type.** Error messages are for humans and
  change as diagnostics improve. Match on the variant, never on the text.
- **`SetupStep` discriminants.** The explicit `#[repr(u32)]` values are the
  setup-error pipe's wire encoding, written and read by the same build. A step
  inserted later renumbers the ones after it. Do not persist, transmit, or
  compare them.
- **Event granularity and ordering.** How many `Progress` or `DebianEvent`
  events an operation emits, and in what order, is not fixed. Treat them as
  advisory.
- **The curated seccomp roster's exact contents.** The roster grows, and a
  syscall it comes to deny is a syscall some command needs. Roster additions
  land in minor releases, never patches — but the precise set is not a
  contract, and a consumer that depends on one should pin an explicit
  `SeccompPolicy` instead.
- **The default mount profile.** The six `/dev` device nodes, the five `/dev`
  symlinks, the tmpfs `/tmp`, and the fresh `/proc` are defaults, not
  guarantees. A consumer that needs an exact set should turn the managed
  mounts off with `managed_mounts(false)` and declare its own — mounts apply
  in declaration order, so a `raw_mount` tmpfs followed by the binds that
  populate it reproduces a managed mount's structure as well as its contents.
- **The base environment.** `PATH` and `HOME=/root`, and nothing else, is the
  current default. A build whose output depends on the environment should set
  every variable it cares about explicitly through `env`, and use
  `base_env(false)` so that a variable added to the base later cannot reach
  the command.
- **The embedded Debian archive keyring.** This one is expected to change in
  patch releases: a keyring rotation is a security fix, changes no types, and
  must be shippable without a version bump. A consumer pinning a specific
  keyring should supply its own through `DebianBuilder::keyring`.

The last three matter most to a caller making a reproducibility claim. The
mount profile and the base environment are inputs to what a build inside the
sandbox produces, and a version number alone does not record which ones were
in force. A pipeline whose output must be reproducible has two tools for this,
and they are complements rather than alternatives:

- **Declare, with the two opt-outs above.** `managed_mounts(false)` and
  `base_env(false)` reduce the library's contribution to nothing, so the
  sandbox carries exactly what the consumer declared. This is prevention: the
  inputs cannot drift under a library upgrade.
- **Record, with `Cage::resolved_inputs`.** The built cage reports the
  environment it will apply and the mounts it will establish, as data. Stamped
  into an artifact's provenance beside the library version, it states the
  inputs a build actually ran under rather than leaving them to be inferred.
  This is verification, and it is worth doing even with both opt-outs set,
  because it is what catches the case where a declaration and the sandbox
  disagree.

## Minimum supported Rust version

`rust-version` in `Cargo.toml` is the supported floor. It may rise in a minor
release and never in a patch. CI builds at the declared version on every
change, so the floor is verified rather than asserted.

`rust-toolchain.toml` pins a toolchain for contributors, to keep `rustfmt` and
`clippy` output identical everywhere. That pin is a convenience and may sit
ahead of the floor; the `rust-version` field is the supported minimum.

## How the promises are kept

Policy that only lives in a document decays. These are enforced:

| Promise | Enforcement |
| --- | --- |
| No breaking API change without a version bump | `cargo-semver-checks` against the last published release |
| No unintended public item, path, or re-export | A committed `cargo-public-api` snapshot, diffed in review |
| No public type loses `Send`/`Sync` | `const` assertions in `tests/auto_traits.rs` |
| Every feature combination compiles | `cargo hack --feature-powerset --depth 2`, plus an explicit featureless check |
| The MSRV holds | A CI build at the declared `rust-version` |
| The profile key set is deliberate | Explicit `#[serde(rename)]` on every field, plus a test pinning the key set |
| The untrusted-profile surface cannot widen silently | `check_restricted` destructures `CageBuilder` exhaustively, so a new field fails to compile until it is classified |
