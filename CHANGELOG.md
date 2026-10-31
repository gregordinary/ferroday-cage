# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) under the
pre-1.0 rules the [stability
chapter](https://gregordinary.github.io/ferroday-cage/stability.html)
describes: while the major version is 0, a breaking change bumps the minor
version.

`ferroday-cage` (the library) and `ferroday-cage-cli` (the `fcage` binary)
version independently. Entries below name the component when only one is
affected, and an entry a consumer must act on is prefixed **Breaking.**

An entry says what changed. Why it changed that way lives in the doc comment of
the thing it explains, or in the [guide](https://gregordinary.github.io/ferroday-cage/),
which is where it stays true; a changelog that carried the reasoning too would
be a third copy of it, and the file a consumer reads to decide whether to
upgrade is the wrong place for a design record.

One section is not Keep a Changelog's. **Internal** records changes with no
effect on the public API or on behaviour, kept because this workspace answers
a question once and a reader needs to know where that answer moved to. A
consumer upgrading can skip it.

## [Unreleased]

### Security

- Every launch, of a sandbox or a restriction, gives the command a fresh session
  keyring in place of the caller's. A sandboxed command previously inherited the
  caller's session keyring, so it possessed, and could read through `keyctl`,
  every key the caller's login session held. Key descriptions stay listed in
  `/proc/keys`; their contents are no longer reachable.
- `fcage`: a standard stream that is a regular file or a block device is relayed
  through a pipe rather than handed to the command. A command could previously
  reopen such a file through `/proc/self/fd` with more access than the stream
  carried: rewrite a file given as standard input, or read back and truncate a
  log opened for appending. A relayed standard input puts the command in a
  session of its own, as `--stdin null` does, and a relay that cannot deliver
  the command's output exits 125.

### Added

- `Error::KeyQuotaExhausted`, reported when the calling user's kernel key quota
  leaves no room for the sandbox's session keyring, and
  `SetupStep::ReplaceSessionKeyring`, the step that replaces it.
- `SetupStep::AllocateTerminal` and `SetupStep::SendTerminal`, the steps a
  terminal launch's allocation now reports under.
- `NetStackBuilder::host_loopback_port`, which maps connections to the gateway
  address on one port onto host loopback, where `host_loopback(true)` maps every
  port. The two combine. `fcage`: `--netstack-host-port PORT`.
- `NetStackBuilder::publish`, which publishes a TCP port of the guest on a host
  address: `attach` listens there and carries each accepted connection to the
  guest. `NetStackHandle::published` reports the bound addresses, including a
  port the kernel chose for port 0. `NetStackError::PublishInvalid` refuses a
  publication at build, and `NetStackError::Publish` reports a listener that
  could not bind. The profile keys are `host-loopback-ports` and `[[publish]]`
  tables of `host` and `guest-port`. `fcage`: `--netstack-publish HOST
  GUEST_PORT`, which reports a kernel-chosen port on standard error.
- `DebianBuilder::source_date_epoch`, which gives every maintainer script
  `SOURCE_DATE_EPOCH`, so the accounts a bootstrap creates record the epoch's
  day in `/etc/shadow` rather than the day it ran. A negative epoch is refused
  at `build`. `fcage`: `--debian-source-date-epoch EPOCH`.

### Changed

- **Breaking.** A terminal launch allocates its pseudoterminal inside the
  sandbox, from the `/dev/ptmx` the command sees, rather than on the host before
  the fork. `ttyname` now names the terminal, so `tty`, `who`, and `GPG_TTY`
  work inside, and under a `run_as` identity the replica belongs to that
  identity. The allocation needs the managed `/dev` or a `devpts` instance the
  caller mounts: a terminal launch with `mount_dev(false)` or
  `managed_mounts(false)`, in a root that ships no `/dev/ptmx`, previously ran
  on a host pseudoterminal and now fails with `SetupStep::AllocateTerminal`.
  `spawn_pending_terminal` waits for the terminal, so a setup failure before it
  exists is reported there rather than from `proceed`. A restriction's terminal
  still comes from the host's `/dev/ptmx`.

### Internal

- `mechanism::frame::send_with_fd` and `recv_with_fd` pass a descriptor over a
  socket for every caller that does: the supervisor's pidfd, the network stack's
  tap, and a terminal launch's primary. The shared vocabulary in
  `CONTRIBUTING.md` records them.

## [0.4.5] - 2026-09-26

`fcage` 0.5.0, unchanged. Its dependency on the library is a caret range over
0.4.4, which 0.4.5 satisfies, so a fresh install of it builds against this
release.

### Fixed

- The crate builds against rustix 1.1.5. That release withdrew the module the
  launch mechanism took its fork, exec, exit, and signal calls from. Releases
  up to 0.4.4 fail to compile wherever a fresh resolution selects it. The
  mechanism makes those calls itself.

## [0.4.4] - 2026-09-12

`fcage` 0.5.0. Two of its entries below are breaking, so it takes a new minor
version while the library, whose changes are additions and corrections, takes
a patch. It requires library 0.4.4, for `VERSION`.

### Added

- `VERSION`, the library's own version as its manifest states it. A containment
  defect lives in the library rather than in whatever binary linked it, and a
  consumer versions independently, so a report needs both numbers.
- `fcage`: `--keep-lock`, which leaves the `DIR.lock` sibling in place when
  `--remove-rootfs DIR` deletes `DIR`. It reaches `provision::Remove::remove_lock`,
  which the CLI previously left at its default, so a `DIR.lock` beside a
  directory that merely *holds* rootfs trees was deleted without being named.
- `provision::debian::DebianError::Configure` carries `packages`: the packages
  dpkg named under `Errors were encountered while processing`, in the order it
  listed them, appended to the error's `Display` as `, processing systemd,
  udev`. The variant is `#[non_exhaustive]`, so the field is additive for a
  caller that matches on it. Empty when dpkg failed without naming any package.
  Why each one failed is unchanged: dpkg writes it beside the list, and it
  reaches a `DebianObserver` as `DebianEvent::CommandOutput`.

### Changed

- **Breaking (`fcage`).** `--gentoo-keyring-horizon` no longer prints an
  earliest-expiry summary line. Every certificate in the keyring is an equally
  trusted anchor and the layer accepts a signature from any of them, so which
  one the archive signs with is not something the keyring records; reducing the
  list to its earliest expiry reported the keyring as nearly stale whenever it
  held a short-dated certificate nothing currently signs with. The final line is
  now the spread, `11 certificates, 10 can sign	expiring between ... and ...`.
  The per-certificate lines are unchanged.
- **Breaking (`fcage`).** `fcage --version` prints the library's version after
  its own, as `fcage 0.5.0 (ferroday-cage 0.4.4)`, where it printed only
  `fcage 0.4.1`. A script that took the version from the end of the line now
  reads the library's, and one matching the whole line no longer matches. Read
  `fcage`'s own version as the line's second word.
- `fcage`: provisioning that finds the destination already present now says so,
  on a run that names no command and so provisions and exits. Such a run
  previously exited 0 having done nothing, which an empty directory the caller
  had just created is indistinguishable from. All four provisioning flags now
  state the precondition in `--help`.
- `fcage`: `--export-rootfs` checks its source and destination before the walk
  begins, so a missing directory is reported as `cannot export ./nope` rather
  than from wherever the walk met it.
- `fcage`: `--gentoo-installed` reports an empty listing rather than printing
  nothing, since an absent package database is what a root of another
  distribution looks like.
- `fcage`: the `--netstack` resolver warning names the flags that answer it
  (`--ro-bind FILE /etc/resolv.conf`, `--netstack-host-loopback`,
  `--no-resolv-conf`) instead of phrasing the remedy as a goal.
- `fcage`: a profile error is one diagnostic again. The `toml` crate's `Display`
  ends with a newline of its own, so the three sites that wrapped one left a
  blank line behind.
- The guide's quick start shows the `id` output a sandbox actually produces.
  Under the single-identity map the command keeps its inherited supplementary
  groups, each presenting as the overflow gid, where the example had shown the
  list cleared.
- `docs/src/quick-start.md`, `provisioning.md`, `debian.md` and `gentoo.md` are
  rewritten for readability: long sentences split, one term per concept, and
  the repository's own spellings throughout. Two claims were wrong rather than
  merely long and are corrected with them, namely that `--remove-rootfs` offers
  no control over the lock sibling, and the Gentoo keyring reduction above.
- `docs/src/debian.md` points at `examples/deb-layer-pipeline.rs`, the one
  example no chapter named.
- The single-identity map's ownership coverage is documented where it stops.
  Substituting `chown` and `chgrp` covers a maintainer script that runs one of
  those commands; a compiled helper calling `fchownat()`, and any POSIX ACL
  naming an unmapped id, reach the kernel and fail. `IdentityMap::Single` and
  the guide's Debian chapter say so, and name `systemd` as the package most
  installations meet that needs a range map. No behavior changes.

### Fixed

- `provision::containment`'s directory open bounds its `EAGAIN` retry, which was
  unbounded where the module's own replacement retry is deliberately bounded.
  `openat2` answers `EAGAIN` when a rename races the walk, so something renaming
  components in a loop could spin a walk over a tree the crate does not trust.

### Internal

- `tools/parity.toml` covers `Remove`, `Export`, `CopyIn` and `Tarball`. The
  gate scoped itself to the six launch and provisioning builders, so
  `Remove::remove_lock` was a public setting with no flag and nothing recorded
  that it had none.
- The crate and `mechanism` module documentation named two homes of `unsafe`
  where there are three; `CONTRIBUTING.md` had it right. `mechanism` no longer
  states a count or names the complement, which is what made it go stale.
- `the_command_runs_one_user_namespace_deeper_than_the_sandbox` compares the
  `ns/user` link's content rather than `readlink`'s exit status. Linux 7.1
  withholds the identifier by returning success with an empty result where
  older kernels answer `EACCES`, so the status test read the newer kernel's
  refusal as permission granted and failed.

## [0.4.3] - 2026-08-26

`fcage` 0.4.1, unchanged: the entry filter is code, and no argument carries one.

### Added

- `provision::Export::filter` takes a predicate and writes only the entries it
  answers `true` for, with `provision::ExportEntry` and `provision::ExportKind`
  as what it is offered: where the entry sits inside the tree spelled
  absolutely, the kind, the permission bits, the ownership the rootfs intends,
  the size, and the unclamped modification time. Excluding a directory excludes
  everything under it. An export that names no filter writes what it always
  did.

## [0.4.2] - 2026-08-25

`fcage` 0.4.1. The two crates version independently and this is the first
release where their numbers differ within one section, so the `fcage` entries
below are that version's rather than this heading's.

### Internal

- Dependencies refreshed. `smoltcp` moves to 0.14, whose TCP work is the part
  that reaches this crate: out-of-window receive handling and MSS selection are
  more RFC-compliant, Reno and CUBIC were corrected, and fast retransmit
  improved. `lzma-rust2` moves to 0.20, which fixes an out-of-bounds panic when
  encoding more than about 2 GiB through one stream and decodes LZMA2 chunks as
  they arrive rather than buffering each. Everything else moved within its
  existing range.

  `sha1`, `md-5` and `rand` stay a generation behind on purpose: `pgp` holds the
  RustCrypto 0.10 line and the `rand` 0.8 line, and a crate this one shares with
  `pgp` is better shared than duplicated. They move when `pgp` does.

- The xz dictionary bound is the decoder's own. `lzma-rust2` 0.20 accepts a
  memory limit and checks it against each block header as it parses one, so the
  container walk that applied the bound from outside — a second parser of the
  same format, which could only ever be as accurate as its agreement with the
  first — is gone. The cap and what an archive over it does are unchanged.

### Fixed

- A copy into a rootfs resolves every source entry against the descriptor of
  the directory holding it. The walk typed each entry without following a
  symbolic link and then read, opened, or descended into it by path, resolving
  the name afresh — so an entry replaced by a symbolic link between the two was
  followed: a directory descended out of the source, or a file streamed from
  wherever the link pointed.
- Dropping a `BuildLayer` leaves any `<upper>.lock` sibling alone and removes
  the increment under the identity map it was staged with. An upper is a
  directory a caller named as a build layer rather than a published rootfs, so
  the lock is a path the layer never created — and an explicit range map
  allocates ids the subordinate default's delegate chain would not.
- **`fcage`.** An `--alpine-repository keys=` naming nothing is a usage error
  rather than a directory path. Read as one it named the working directory, and
  the run ended at an io failure about a directory the caller never typed.
- **`fcage`.** A bare `--` draws no flag suggestion. It is every flag's prefix,
  so the abbreviation rule answered it with whichever one sorted first.
- A `binfmt_misc` registration that is present but unreadable is reported as a
  handler that cannot be used, not as one that is not registered. The preflight
  advised installing a handler the kernel already held.
- A plan document carrying a folded field a newer writer added is written back
  folded, rather than refused. The reader accepts one, so refusing to write it
  meant a document this library reads and cannot re-emit — the one thing
  carrying an unknown field exists to prevent.
- `AlpineEvent::Downloading` counts the packages being downloaded rather than
  the plan's. The event fires only for a cache miss, so a fetch of one package
  out of a ten-package plan was reported as reaching nine of ten.
- A layered Alpine build terminates a base's carried `triggers` file before
  appending its own lines, as it already did for the carried package records.
- `Alpine::resolve` refuses a provisioner configured with a `base_layer`, as
  `provision::ensure` already did for the same value. It reported the whole-root
  closure — hundreds of packages the base already carries — where
  `resolve_layer` is the read half of what such a provisioner does.
- An Alpine increment with nothing to install still writes its state, so what a
  caller reads back from the merged view does not depend on whether the delta
  happened to be empty. A request the base already satisfied reached
  `/etc/apk/world` only when something else was installed alongside it.
- An Alpine bootstrap installing a `plan` writes the plan's packages into
  `/etc/apk/world`. `plan()` forbids `include()`, so the world came out empty
  and nothing in the finished root said what it wanted — which is what a later
  `apk fix` acts on.
- `debian::host_architecture` reports `armel` on an ARMv6 machine, not `armhf`.
  armhf's baseline is ARMv7-A, so a bootstrap for it on such a host was taken
  for native — the preflight that demands a qemu handler passing silently — and
  the target's own binaries met a `SIGILL`.
- A Gentoo binary package is extracted from the container its Manifest was
  verified against. The second pass re-opened the path, so two builds sharing a
  cache directory could have one extract bytes the other published between the
  passes.
- A Gentoo container member of exactly the size ceiling is accepted rather than
  refused for holding "more than" it. The refusal now reads the length the
  entry declares, which is the bound the read already had.
- A Gentoo `|| ( )` group asks for nothing rather than for something no
  candidate can answer. Kept as a dependency it refused the whole resolution,
  naming an atom with no name.
- `GentooEvent::Planned` reports a saturating total rather than overflowing on
  the sizes an index published, which are a mirror's own numbers and bounded by
  nothing. A debug build panicked on them.
- A Gentoo index record carrying an `MD5` that is not one is left out of the
  index, as a record with any other unusable field already was. Such a record
  could pass no digest check and projected a plan document this crate emits and
  refuses to read back.
- A decompressor's refusal survives to the caller instead of being reported as
  an unrecognized format. A failure before the first tar header — the xz
  dictionary bound's refusal among them — was reclassified as "not a tar
  archive", discarding the reason the guard exists to produce.
- **`fcage`.** A listing whose reader stops early — `fcage --gentoo-packages
  amd64 | head` — exits 141 in silence, as an export already did, rather than
  panicking with exit 101. Rust ignores `SIGPIPE`, so the write returns `EPIPE`
  and `println!` had nowhere to report it.
- **`fcage`.** A profile's `stop-with-caller = false` holds. `fcage` defaults the
  tie on, and that default was applied as though it were a setting, so it
  overrode the profile's answer and left the key unreachable through `fcage`.
- A mount of the caller's own onto `/etc/resolv.conf` replaces the managed one
  rather than being superseded by it — the library's for a host-network
  sandbox, and the one `fcage --netstack` composes. Both were applied after the
  caller's mounts, so the sandbox's DNS was the host's however explicitly the
  caller said otherwise. Every kind of mount counts: a `Mount::Raw` carries a
  source and the kernel's own flags, so a bind spelled through it claims the
  target as much as `bind_ro` does.
- An empty command path is refused at `build` as `ConfigError::CommandMissing`,
  by a cage and by a restriction alike. Under `path_lookup` a cage read it as a
  bare name, found every `PATH` entry a candidate, and deferred an `execve` of a
  directory to launch.
- A userspace-networking flow whose host side has hung up is reclaimed only
  after the hangup deadline passes with *nothing moving*. The clock ran from the
  moment the guest's transmit buffer filled and consulted nothing after that, so
  a guest draining more slowly than the host queued was reset while it was still
  reading.
- A Gentoo package rebuilt against a new sub-slot replaces the base's copy in a
  layered build's merged view rather than joining it. The merge matched on the
  whole `slot/subslot`, where a slot is the part before the slash, so the view
  described a root holding two instances of one slot.
- A Gentoo `~` atom admits every spelling of the version it names. Two versions
  the format's ordering calls equal were compared as text, so
  `~cat/pkg-1.0_alpha` refused a published `1.0_alpha0` that `=cat/pkg-1.0_alpha`
  accepts.
- A `.deb`'s control member is bounded decompressed as well as compressed, as
  Alpine's control segment already was. The member is a compression format, so
  one comfortably inside the wire bound could decompress to an unbounded
  `./control` and be accumulated in memory.
- A plan set alongside a `base_layer` is the increment a layered build installs.
  The layered path read no plan at all, and `plan()` forbids `include()`, so the
  seed was empty: `stage_layer` returned a build layer over an empty upper
  having installed nothing, and `resolve_layer` reported that same empty
  closure.
- `Debian::resolve` answers with the plan the provisioner was configured with,
  rather than resolving a fresh closure the same value would not install. The
  documentation states the two cannot drift and recommends the plan as a
  build-cache key.
- A pax global extended header no longer states a path, size, owner or digest
  for the entries after it. A global `size` split one archive member into two,
  since the bytes past the declared size were read as the next header, which is
  a member set no other reader agrees with.
- Merging a Gentoo binary package leaves the root's own mode and modification
  time alone. The wrapper directory an image archive is built under stripped to
  the empty path and was read as the archive's root entry, so every merge
  applied that directory's metadata to the rootfs root.
- Serializing a seccomp policy that lists no syscall is a serialization error
  rather than a profile that cannot be read back. `SeccompRules::allowing([])`
  rendered as a bare `[hardening.seccomp]` table, which the reader then refused
  for naming neither side.
- A restriction starts its command in `/` where none is configured, which is
  what `RestrictionBuilder::current_dir` documents as the default. The command
  inherited the caller's own working directory instead, so the same restriction
  ran differently depending on where it was launched from. Note that a
  restriction that resolved a relative path against the inherited directory
  resolves it against `/` now, and does so without an error: this is the one
  fix in the release that relocates a working command rather than turning a
  wrong result into a right one or into a failure. Such a caller sets
  `current_dir` to the directory it was inheriting.
- A `Location: //host/path` redirect resolves to that host, as RFC 3986 defines
  a network-path reference, rather than to a doubled-slash path on the mirror's
  own host. The same-host policy then refuses it unless cross-host redirects are
  enabled.
- An interim `1xx` response is read past rather than reported as the answer. A
  server sending `103 Early Hints` before the response, which RFC 9110 permits
  whether or not the client asked for hints, failed the fetch with a status
  error.
- A redirect's own page is not held to the cap on the resource being fetched. A
  mirror answering a request for a small signed index with an ordinary HTML
  redirect page failed the fetch before the redirect was followed.
- `HttpFetch::request_timeout` bounds the walk over the addresses a host
  resolves to, not only the reads once a connection is open. A host with eight
  addresses and no route to some of them waited the connect timeout for each,
  which multiplies past the ceiling the caller set on the fetch.
- A redirect refused for leaving the mirror's host is a failure a mirror walk
  advances past, as a redirect chain that never arrives already was. One
  CDN-redirecting mirror in a list aborted the whole walk.
- **Security. `fcage`.** `--debian-repository trust-unsigned=false` disabled
  archive signature verification. The field's presence is the whole of its
  meaning and its value was discarded, so a value written to turn it off turned
  it on. A value on `trust-unsigned` or `allow-stale-release` is now a usage
  error; the setting is left out to have it off.
- **`fcage`.** A flag written where a separated value belongs is a usage error
  rather than the value. `fcage --remove-rootfs --identity-map=subordinate`
  took the map's spelling as the tree to delete and reported success having
  removed a path of that name in the working directory instead. A value that is
  genuinely spelled like a flag is written joined, `--remove-rootfs=--odd`, and
  a value that merely begins with a dash is unaffected.
- A rootfs export refuses a symbolic link whose target fills the mechanism's
  link buffer rather than exporting the truncated target as a whole one.
  `readlinkat` truncates and reports success, so the `ERANGE` the export tested
  for is one the kernel never returns.
- The rootfs export builds on every architecture. A lint expectation on the
  link-count field held only where `st_nlink` is already 64 bits, so a clippy
  run on any other architecture failed on the unfulfilled expectation.
- A layered Debian build removes an ownership-tool stub only where the file
  still holds the stub, as the full bootstrap already did. The increment's
  unpack wave runs after the stubs are written, so a real `chown` or `chgrp` the
  increment installed was deleted and the base's copy revealed in its place.
- A Gentoo resolution refuses a build that would occupy a slot the root already
  holds, as it already refused one occupying a slot another chosen build holds.
  Merging registers a database entry beside what is installed and unmerges
  nothing, so a same-slot upgrade over a stage3 laid a second image down over
  the first's paths and left a `/var/db/pkg` portage reads as a conflict.
  `GentooEvent::Occupied` gains `installed`, which says which of the two the
  slot's holder is.
- A subkey re-bound over time is judged on the newest binding its certificate
  issued. The hash floor and the critical-subpacket rule were applied when
  choosing which binding governs rather than to the one that does, so a newer
  binding that narrowed a subkey's authority but rested on a weak hash was
  passed over and the superseded, broader grant governed instead.
- A Debian repository set is refused when an additional repository would write
  the keyring the primary's `sources.list` names, rather than accepted and
  written in the order that leaves the primary archive verified against the
  additional repository's key.
- Debian version comparison reads a version only as far as dpkg would. A
  version carrying an interior NUL made the comparison of two version fields
  spin without either cursor advancing, which a caller's plan document or a
  base layer's own `dpkg/status` could reach.
- A stream that ends before its first tar header is refused as
  `ProvisionError::FormatUnrecognized` rather than read as a complete archive
  holding nothing. An empty file, a download that produced nothing, and a
  compression stream decoding to an empty payload were each published as a
  finished, empty rootfs, which every later `provision::ensure` then returned as
  `Provisioned::Existing` without consulting the source again. An archive
  missing only its final terminator is still tolerated.
- `relay::Signals::install` restores the caller's signal mask when it blocks the
  relayed set and then cannot open the descriptor. The blocked set survived a
  failed call with nothing draining it, so a program that reported the failure
  and carried on no longer answered `SIGINT`, `SIGTERM`, `SIGHUP`, or `SIGQUIT`
  at all.
- **`fcage`.** A failed `--export-rootfs ... --export-to FILE` leaves an
  existing archive at `FILE` as it found it. The destination was opened, and so
  truncated, before the export had established it could produce anything, and
  removing the partial result does not bring the previous archive back.

### Added

- `Remove::remove_lock` sets whether the `<dest>.lock` sibling goes with the
  tree. It defaults to `true`, which is what `provision::remove` does — right
  for a published rootfs, wrong for a destination that merely holds published
  trees, where the sibling is an unrelated path the caller never named as a
  target.
- `Export::write_to_path` writes the archive to a named file, which then appears
  complete or not at all: the bytes go to a staging file beside it, which is
  synced and renamed over the destination. A destination inside the tree being
  exported is refused with the new `ProvisionError::ExportDestInside`.
- **`fcage`.** `--netstack-cidr6`, `--netstack-no-ipv4`, `--netstack-no-ipv6`,
  and `--netstack-interface`, which complete the native network stack's
  command-line surface. A stack running one protocol alone, on a host or for a
  workload where the other is unwanted, was expressible only from a program.
- **`fcage`.** `--debian-plan`, `--debian-pin`, `--alpine-plan`, and
  `--alpine-pin` take the plan documents a previous resolution wrote, as
  `--gentoo-plan` already did, so a reproducible install is expressible at a
  shell prompt for each of the three userlands.

### Internal

- `tools/parity.toml` records every public builder setting against the flag that
  reaches it or the reason it has none, and `tools/check-parity.py` holds the
  record to the API snapshot and to the CLI's flag table. The CLI's own tests
  read that table, so a library setting absent from it was absent from both
  sides of every comparison they could make.

## [0.4.1] - 2026-08-22

### Added

- `FetchJob::parts` is public, so a `Fetch` implementation outside the crate can
  override `Fetch::fetch_all`. A job's sink was reachable only from inside, which
  left the batching seam documented as an extension point that nothing but the
  bundled client could extend.

## [0.4.0] - 2026-08-22

### Added

- The `gentoo` feature installs prebuilt packages from the archive's
  binary-package host into the root it bootstraps. `GentooBuilder::binhost`
  names the sub-architecture tree and `install` takes dependency atoms;
  `Gentoo::packages`, `gentoo::installed`, `Gentoo::resolve_packages`,
  `Gentoo::stage_layer` and `GentooBuilder::base_layer` come with it. A builder
  that names no package does exactly what it did before, byte for byte.
- `gentoo::Plan` is the layer's plan document, `ferroday-cage-gentoo-plan 1`.
- `GentooBuilder::prefer_use` states a preference among the builds of one
  version.
- `GentooError` gains `Index`, `Container`, `Database`, `PlanDocument` and
  `Resolve`, and `GentooEvent` gains `Index`, `Planned`, `Merging`,
  `DependencyCycle`, `Unsatisfiable`, `Conflict` and `Occupied`.
- `fcage` gains `--gentoo-binhost`, `--gentoo-install`, `--gentoo-prefer-use`
  and `--gentoo-plan` on a provisioning command line, and two listings that
  answer without provisioning: `--gentoo-packages` prints what a binhost
  publishes, and `--gentoo-installed` prints what a root already has.
- A `gentoo-binhost` example provisions a stage3, installs prebuilt packages
  into it, and runs a command against the result.
- `md-5` is a new direct dependency of the `gentoo` feature.
- `relay` drives the caller's side of an interactive terminal session:
  `relay::Relay` is the byte loop between the caller's terminal and the
  sandbox's, `relay::Signals` blocks the eight signals such a session handles
  and reads them back as data, and `relay::restore_terminal` with
  `relay::install_panic_restore` undo raw mode on every exit the process can
  observe.
- `relay::Escalation` states the `timeout(1)` policy — terminate at the
  deadline, kill after the grace, report no status either way — as a value a
  waiter drives.
- `FetchRequest::scheme` answers what scheme a request's URL names, so a
  transport that routes on it reaches the crate's own answer instead of
  splitting the URL itself.
- `DebianEvent::Unsatisfiable` reports one dependency the resolver could not
  satisfy, carrying what could not be supplied, who asked for it, and what the
  wall was.
- A `cross-arch-test` example and a guide chapter for it: a sandbox that
  bootstraps a Debian root for an architecture the host cannot execute, then
  compiles and runs a C program inside it through the `qemu-user` binfmt
  handler.
- `Gentoo::observe` binds a `GentooObserver` for one call, as the Debian and
  Alpine layers already allow.
- `Fetch::fetch_all` fetches a batch of resources, answering one outcome per
  job. It carries a default body — one `fetch` per job, in order — so a
  transport that overrides nothing behaves exactly as it did before.
- `HttpFetch::concurrency` sets how many resources one batch fetches at once
  (the default is 4). (library)

### Changed

- A Debian resolution reports every refusal rather than stopping at the first.
- `Signals` documents what dropping the handle costs.
- `Fetch` and `FetchRequest::url` document that a URL's scheme compares case-
  insensitively (RFC 3986 §3.1).
- `DebianEvent::Fetching` documents that it announces an intent to fetch, which
  a batch emits for every URL before asking for any of them.
- `HttpFetch` holds a connection open between requests, as HTTP/1.1 does by
  default, instead of sending `Connection: close` on every one. A response of
  either framing is held; a peer speaking anything older than HTTP/1.1 is not.
- `HttpFetch` fetches four resources at once through `Fetch::fetch_all`, each
  on a connection of its own; `HttpFetch::concurrency` changes how many.
- `HttpFetch::request_timeout` bounds one fetch rather than one request inside
  it: a redirect chain and the retry a reused connection is allowed come out of
  a single budget.

### Fixed

- An xz archive can no longer name its own memory cost. A block declaring an
  LZMA2 dictionary over 128 MiB is refused from the header, before the decoder
  allocates and zeroes it. This is a robustness fix on the provisioning path,
  not a sandbox escape.
- A response that declares both chunked framing and a `Content-Length` is
  refused rather than read by the chunked framing alone.
- The Debian resolver enforces the version constraint a dependency declares,
  where it previously parsed it away.
- A dependency group nothing satisfies fails the resolve rather than being
  dropped from the closure. A resolve that succeeded and should not have now
  fails, which is a behaviour break under the pre-1.0 rule; both refusals reach
  a caller as `DebianError::Resolve`, so no public type changes.
- A resolved-inputs record names the resource limit that was set.
- `fcage` aborts a `--provision-gentoo` run whose rootfs is missing, as it
  already does for the other three provisioners, rather than skipping
  provisioning and launching against a root that was never built.
- A Gentoo resolution previewed through `resolve_packages` no longer discards
  the diagnostics it produces. See the `observe` entry above.
- `fcage` no longer mistakes a mode flag written among a command's own
  arguments for a mode of its own.

### Internal

- A binary package's download is bounded by this layer's own ceiling as well as
  by the size the index published for it.
- `GentooBuilder::build` refuses a plan whose architecture is not the
  builder's, and one whose binhost the builder contradicts.
- A named pipe in a package's image is registered as portage's own `fif` line
  rather than as a file with a digest.
- An atom for a package the binhost publishes in no version names what the root
  has of it.
- A download that cannot stage, write or publish names what it was downloading.
  The stage3 and every binary package share one download path, whose three
  diagnostics named a stage3 whichever of the two had failed.
- `fcage --terminal` drives the library's relay rather than a copy of its own.
- The identity map's overlap check no longer depends on its caller having
  already refused a zero count and an extent running past the last usable id.
- Every clippy suppression the workspace carries is an `expect` rather than an
  `allow`, so one that stops suppressing anything is reported. Three had
  already gone dead.
- The Debian layer's pin holder is `pub(super)`, which is the reach it has and
  the reach its Alpine counterpart already declared.
- `SeccompPolicy` derives `Clone` rather than spelling out the impl `derive`
  would have produced, 470 lines from the type.
- A live resolution builds its plan records as struct literals.
- Feature-gated documentation is one `cfg_attr` per section rather than one per
  line of prose. The crate carried 54 of them for what is now 18.
- `Capability` and the Alpine layer's `ScriptKind` are declared through
  `roster_enum!`, which derives each `ALL` from the variant list instead of
  keeping a second copy of it by hand.
- Each of the three version comparators states whether it is total or partial
  and why, so a reader moving between them meets a rule rather than an
  inconsistency.
- The `io` and `at` constructors four error types carry are declared by
  `failure::path_io_error!` rather than written out four times.
- The three userlands walk their mirrors through one `provision::walk_mirrors`
  rather than eight copies of the same nine lines, and join a mirror-relative
  path through `provision::mirror_url`.
- The three map-assisted helpers declare the seven steps of the shared map
  sequence in a `wire_enum!` `map` block, which supplies the variants and the
  `From<MapStep>` each had written out as a seven-arm translation.
- A bootstrap's configuration, its configure wave, and the site an Alpine
  maintainer script runs at are each one borrowed value rather than up to
  fourteen positional arguments re-threaded through five call levels.
- The four public read-half entry points on each of the Debian and Alpine
  layers hold their body in one place rather than in a private twin beside it.
- Every flag `fcage` accepts is declared once, in one table, with what it
  takes, which invocation it belongs to, what `--help` says about it, and what
  it sets.
- A field added to either the cage builder or the restriction builder is
  refused until it is classified against the other.
- Two decisions are recorded where the code they are about is: why the crate
  writes its `Display` impls out rather than deriving them, and what the xz
  dictionary guard costs by being a second parser of a container the decoder
  also parses.
- What each userland reaches for outside the provisioning seam is recorded in
  `tools/seam.toml`, and `tools/check-seam.py` fails on any difference. A
  userland naming another is refused outright.

## [0.3.0] - 2026-08-11

### Changed

- **Breaking.** The transport seam is `provision::{Fetch, FetchRequest,
  FetchError, HttpFetch, file_url}`, moved out of `provision::debian`. No
  re-export is left at the old paths, and `file_url` reports a `FetchError`
  rather than a `DebianError` — so `Pool::mirror_url` returns
  `DebianError::Fetch` where it returned `DebianError::Config` or
  `DebianError::Io`. It was
  never Debian's: it speaks HTTP and `file://` and knows nothing of an
  archive's format, and every userland provisioner needs one. Under the old
  paths a provisioner built without the `debian` feature had no transport at
  all, not even the built-in client.
- **Breaking.** `BuildLayer` is `provision::BuildLayer`, moved out of
  `provision::debian`: it is the overlay upper a layered build installs into
  and the handle that disposes of it, with nothing in it about any particular
  userland. No re-export is left at the old path. It is the overlay upper a layered
  build installs into and the handle that disposes of it — a path, the work
  directory beside it, and the identity map that decides how both are removed —
  with nothing in it about any particular userland. Every userland provisioner
  that stages an increment returns one. No re-export is left at the old path.
- **Breaking.** `Stream` is `provision::Stream`, moved out of
  `provision::debian` and `provision::alpine`, which each defined their own.
  `DebianEvent::CommandOutput::stream` and `AlpineEvent::CommandOutput::stream`
  both carry the shared type. No re-export is left at the old paths.
  The two definitions were identical, down to the documentation: a provisioner
  that runs a command in a cage has output to attribute to a standard stream
  whichever archive it provisions from, and the attribution says nothing about
  the archive.
- An Alpine bootstrap fetches packages over its repository's whole mirror list,
  not only the mirror that served the index.
- A mirror walk advances only past a failure that says *this* mirror could not
  serve the resource, which is `provision::FetchError`'s own question now
  rather than one each layer answers.
- **Breaking.** Every OS failure a library error carries is now an `io::Error`
  and is returned from `source()`. Each `errno: i32` field on `Error`,
  `ConfigError`, `IdMapError` and `NetStackError` is a `source: io::Error`;
  `io::Error::raw_os_error` gives the number back. `NetStackError::NamespaceJoin`
  and `NetStackError::Pump` hold `Option<io::Error>`, the two failures that
  genuinely carry no OS error. Those four types are consequently no longer
  `UnwindSafe` or `RefUnwindSafe`. `Error`, `ConfigError`, `IdMapError`, and
  `NetStackError` stored a raw `errno: i32` and then rendered it by
  constructing an `io::Error` at each `Display` arm — twenty-odd sites undoing
  the same representation — while `ProvisionError`, `DebianError`, and
  `FetchError` carried the error itself.
- **Breaking.** `FetchError::Io::op` is a `&'static str` and `FetchError::io`
  takes its arguments as `(op, url, source)`. Every error constructor in the
  crate now reads operation, then locator, then cause; this one read locator
  first. Both arguments were `impl Into<String>` before, so a stale call would
  have compiled and silently produced a transposed message — narrowing `op` to
  `&'static str` makes it a compile error instead.
- **Breaking.** `ParseCapabilityError::name` is `ParseCapabilityError::text`,
  matching `ParseFsAccessError::text` and `ParseNetAccessError::text`. Three
  parse errors in one file answered the same question under two names.
- `Debian::observe` takes a `DebianObserver` rather than a bare
  `FnMut(DebianEvent<'_>)` closure. A closure is still an observer — the trait
  carries a blanket impl for one — so existing callers are unaffected.
- `AlpineBuilder::build` validates a `plan()` and a `pin()` against the
  configuration, which `plan()`'s documentation already described and only
  `preflight` partly did.
- An Alpine plan document is held to the index's own grammar as it is read.
- An apk container's signature segment may hold more than one `.SIGN.*` member,
  and the first that names a trusted key and verifies is the one that answers.
- A `k:` provider priority of zero is no priority, as are a negative and an
  unreadable one. A record publishing `k:0` was auto-selectable where an
  unranked one was refused as ambiguous.
- An Alpine resolution takes an alternative provider rather than refusing an
  upgrade it does not need.
- A `.PKGINFO` whose `datahash` is not a SHA-256 in lowercase hex is refused as
  the malformed metadata it is, rather than reaching the data-segment
  comparison and being reported as a digest mismatch — an authenticity-
  flavoured answer to a spelling.
- The Alpine index walk reports `AlpineEvent::Fetching` for each index it asks
  for.
- **Breaking.** `fcage`'s `--debian-repository` and `--alpine-repository`
  refuse a spec whose only mirror field is `mirror-fallback=`, and one that
  gives `mirror=` twice. Both were read positionally, so a lone backstop was
  promoted to primary and a repeated `mirror=` demoted the earlier value to a
  backstop ahead of the declared ones.
- `fcage` exits 125, not 2, when `--alpine-keys` or an `--alpine-repository`'s
  `keys=` names a directory it cannot read at provision time.
- **Breaking.** The shared tar reader refuses an entry whose `APK-
  TOOLS.checksum.SHA1` pax record is not a SHA-1, and that reader serves the
  `.deb` data member and the `Tarball` provisioner too.
- An Alpine resolution reports an increment that breaks a refusal a base
  package declares, where the base breaks the same refusal itself.
- The size-ceiling message says `the stream exceeded the maximum size accepted
  for it` where it said `the response body exceeded the maximum size`.
- Both crates describe the root filesystem as one you supply *or bootstrap*,
  and carry `alpine` among their keywords in place of `container`.
- **`fcage`.** The crate carries a readme of its own rather than the library's.
- The readme and the guide's introduction name the three userlands where they
  describe what the library does.

### Added

- The `gentoo` feature: a provisioner for a Gentoo userland, reached through
  `provision::gentoo::{Gentoo, GentooBuilder, GentooError, GentooEvent, Stage3,
  Available, CertificateHorizon}`.
- `fcage --provision-gentoo ARCH` provisions a root from a signed stage3, with
  `--gentoo-variant`, `--gentoo-build-id`, `--gentoo-mirror`, `--gentoo-mirror-
  fallback`, `--gentoo-cache` and `--gentoo-max-pointer-age` mirroring the
  builder they configure.
- The `ebuild-sandbox` example provisions its stage3 from the archive with
  `--variant`, rather than only from a tarball the caller had already obtained.
- `tools/check-keyrings.py` compares every vendored trust anchor — Debian's
  archive keyring, Alpine's and postmarketOS's signing keys, and Gentoo's
  service keys — against what its distribution publishes today, and fails on a
  key that changed, one that appeared, or one that is vendored and no longer
  published.
- The `alpine` feature: a provisioner for an Alpine Linux userland, reached
  through `provision::alpine::{Alpine, AlpineBuilder, AlpineError,
  AlpineEvent}`.
- `fcage --provision-alpine RELEASE`, with the `--alpine-*` options mapping
  onto the builder as the `--debian-*` set does. The two provisioners are
  mutually exclusive.
- The `musl-build` example: a C build sandbox that bootstraps an Alpine root
  with the toolchain, builds a source tree in a cage over a copy of it, and
  collects the artifacts to a directory the caller names, leaving the host with
  no compiler on it.
- `ExitStatus::shell_code` and `Error::shell_code` return the process exit code
  a launcher reports: the command's own code or `128 + signal` for the first,
  and 127 / 126 / 125 for a command that does not exist, cannot be executed, or
  a launcher failure for the second.
- `provision::debian::host_architecture` reports the Debian architecture name
  for the host — what `DebianBuilder::architecture` and `Pool::architecture`
  default to.
- `provision::debian::DebianObserver`, the bootstrap's progress and
  cancellation sink, shaped like `ProvisionObserver`: one `progress` method,
  one defaulted `cancelled`.
- `Observer` has the closure blanket impl `ProvisionObserver` always had, so
  `cage.run_with(&mut |event: Progress| ...)` works the way
  `Provision::observe(&mut |event| ...)` does.
- `Priority` implements `FromStr` and `Display`.
- `ProvisionError::at`, `DebianError::at`, and `FetchError::at` build the same
  errors as their `io` constructors, as a `map_err` argument.
- `provision::debian::file_url` builds the `file://` URL naming a local path,
  which is how a repository on this machine is addressed:
  `RepositoryBuilder::mirror` reads that form, and `Pool::mirror_url` answers
  with it for the pool it writes.

### Fixed

- A mirror walk advances past an answer that is over the size the resource may
  weigh, and past a redirect chain that never arrives at one.
- A tar entry that names a directory and declares data is refused rather than
  read as one or the other.
- A tar entry whose real path arrived in a GNU long-name entry or a pax record
  is read as the file it is, rather than as a directory when its header's own
  truncated name happens to end in a separator.
- An Alpine root's files agree with the database that records them when two
  packages contest a path.
- An Alpine package is extracted from the file its verification read, not from
  the path that file was at.
- A failed write while downloading an Alpine package is reported as the I/O
  failure it is.
- `fcage` no longer counts `nameserver8.8.8.8` — no separator — as a routable
  nameserver when deciding whether a `resolv.conf` needs the network stack.
  glibc ignores such a line.
- The network stack answers address resolution and ICMP echo only for the
  addresses it holds.
- `fcage --terminal --timeout` acts on the deadline on every wakeup rather than
  only on the one `poll` timed out on.
- A `Filename` or `SHA256` in a Debian plan document is held to its shape. See
  Changed, above.
- The `HttpFetch` transport refuses a URL carrying a space or a control
  character.
- An export child that fails before it reaches its map gate reports the step it
  reached.
- A removal child abandoned at its map gate is reaped once.
- A profile that mounts a procfs, mounts a second, and covers the second is no
  longer refused as having none.
- A raw mount carrying `MS_BIND` is read as the bind it is.
- An `APKINDEX` record whose `C:` field is the right length and the right
  alphabet but not one the encoder can produce — `Q1` followed by padding — is
  refused as the malformed record it is, rather than at fetch time as a mirror
  serving the wrong bytes.
- The copy-in child's outcome record is checked for length before it is
  decoded, as the gate's other two readers already were.
- `fcage --rootfs R --provision-debian trixie --` — a provisioning run ending
  on a bare separator — is accepted. It names no launch setting, and the check
  for one read the separator as a flag.
- A mount-target directory's mode is applied through a descriptor opened
  `O_NOFOLLOW`, not by path.
- The `HttpFetch` transport parses `HTTP://` and `FILE://` as the schemes they
  are.
- A failure the copy-in child hits before it reaches its map gate — its
  descriptor sweep, or its `unshare` — now names the step it reached.
- The provisioning children report `DenySetgroups`, `WriteGidMap`, and
  `WriteUidMap` as the distinct steps they are.
- `fcage --terminal` with a `--timeout` larger than the clock can express no
  longer panics.
- `HttpFetch::request_timeout` with a duration larger than the clock can
  express removes the bound rather than panicking on the same addition, which
  is how every other timeout in the crate reads one.

### Internal

These change no public API and no behaviour; they are recorded because they
change where a reader looks.

- The guide's Rust blocks are compiled by `cargo test`.
- One download cache for the three network suites, in `ferroday-cage-testkit`
  beside the scratch directories.
- The five step enums the forked helpers report through — the launch stage's,
  the copy-in child's, the export child's, the removal child's, and the network
  stack's tap helper's — are declared through one `wire_enum!` macro.
- The three parent-side map-gate drivers are one `drive_map_gate`, and the
  kill-and-reap that ends an abandoned child — with the reasoning for why
  closing the gate cannot release it — is one `abandon_gated_child`.
- The framed byte protocol the copy-in and export children speak has one set of
  primitives in `mechanism::frame`, and the four bounds both sides of it must
  agree on are declared once in `mechanism::bounds`.
- `FsAccess` and `NetAccess` — the same letter-set bitflag type written twice —
  are one macro and two invocations.
- The profile format's keys come from `rename_all` on the container.
- The launch teardown removes its mount-point placeholders through the same
  contained-tree type the Debian bootstrap's host-side steps use, rather than
  through its own `openat2` walk.
- One `Duration`-to-`Timespec` conversion, one poll-slot helper, one absolute-
  path splitter, one `retry_on_intr!`, and one hex encoder, each replacing two
  or three copies.
- The examples share their argument-parsing helpers through
  `examples/common/mod.rs`, and both test suites share their fixtures through a
  new `ferroday-cage-testkit` workspace crate that is never published: one
  rootfs fixture, one scratch directory, one tar writer, one `ar` writer, one
  hex encoder, and one pseudoterminal reader, replacing between two and five
  copies each.
- One splitter for a path that names something inside a tree, over the bytes
  such a path is.
- One `openat2` for opening a directory the kernel keeps inside a tree, with
  the containment flag and the descriptor's access as its arguments.
- `fcage` states the `--timeout` escalation once, as a value both of its waits
  drive: the plain blocking wait and the terminal relay, which must keep moving
  bytes while the escalation happens.
- Two guards hold the workspace to its shared vocabulary, which
  `CONTRIBUTING.md` now lists as a table rather than as prose.
- `provision::digest` digests under a named algorithm.
- Both plan formats are pinned by a golden document as well as by a round trip.
- `deb-layer-pipeline` names each component's output directory and layer upper
  by its position as well as its last path segment. Two `--component` paths
  ending in the same segment — `a/src` and `b/src` — shared both.
- The `features` job documents the whole feature powerset, so a doc link that
  resolves only under `--all-features` fails there rather than in a consumer's
  build.
- `tools/check-idioms.py` scans the crates' examples as well as their `src`
  trees.
- `provision::containment` owns the create-over-what-is-already-there answer,
  which the extractor and the host-side `Rooted` each spelled: the same unlink-
  and-retry, the same attempt bound, the same rationale in both comments,
  differing only in what a failure was called.
- `provision::alpine::version::name_of` is where a dependency entry's name
  ends.

## [0.2.0] - 2026-08-06

### Security

- A read-only bind is a boundary. The command enters a nested user namespace
  before it hardens, and the kernel locks a mount's flags exactly when it
  copies a mount tree into a new user namespace — so past that point no
  restriction on a mount the sandbox established can be lifted.
- The sandbox's root mount carries `nosuid`, so a set-user-ID or set-group-ID
  binary in the rootfs confers nothing on the command that executes it, and a
  file capability recorded on one is ignored. A provisioned rootfs applies the
  tree's permission bits verbatim, so a Debian or Alpine root ships set-user-ID
  binaries owned by in-namespace uid 0; a non-root `run_as` identity could
  otherwise execute its way back through one.
- The Debian bootstrap's host-side steps are contained to the tree they write
  into. They interleave with the dpkg waves — a statoverride seed, the
  ownership stubs, the finished rootfs's apt sources — so most of them run
  after arbitrary maintainer scripts have executed inside a cage rooted at that
  tree, as root of its namespace.
- **Breaking.** `trust_unsigned` requires a transport that authenticates what
  it serves: every mirror of an unsigned repository must be `file://` or
  `https://`, compared case-insensitively, and any other scheme is refused at
  `build`. The guard previously refused the literal prefix `http://`.
- No caller descriptor survives the command's `execve`. A `Stdio::Fd`
  disposition's descriptor is deliberately kept through the launch's sweep so
  the command stage can copy it onto a standard stream, and it was then left as
  it was — surviving the exec at whatever number the caller held it at, which
  contradicts both the crate's "a descriptor table holding only its standard
  streams" and the sweep's own contract.
- A fetch is bounded by the size its verified source declares. The signed
  release records the length of every index and the index the length of every
  package, and both were discarded: an index fetch was bounded only by the
  built-in fetcher's two-gigabyte ceiling, or by nothing at all for a caller-
  supplied transport, while the release that named it said it was a few
  megabytes.
- An index-supplied pool path may not percent-encode a traversal.
  `pool/%2e%2e/%2e%2e/etc/passwd` is non-empty, relative, all-graphic and
  carries no `..` component as written, so it passed a check whose documented
  claim is that a `Filename:` cannot escape a mirror root — and a server that
  decodes before resolving may serve something above that root.

### Added

- `FetchRequest::sized` states the size a resource is expected to be, and
  `FetchRequest::size` reports it.
- `DebianBuilder::pin` holds a resolution to the versions a previously resolved
  `Plan` recorded, where `plan` replaces the resolution outright.
- A plan reports what the archive says each package weighs and which source
  package it was built from.
- A tree written under the single-identity map is removed through that map when
  the plain removal is refused.
- A pseudoterminal of the sandbox's own.
- `Error::Terminal` and `Error::TerminalsExhausted`, the latter for a host that
  has run out — `/proc/sys/kernel/pty/max` states the ceiling — and
  `SetupStep::SetControllingTerminal`.
- `fcage`: `--terminal`, which allocates a pseudoterminal for the sandbox,
  copies this terminal's current size into it, and relays the two.
- `CageBuilder::stdout` and `CageBuilder::stderr`, with `get_stdout` and
  `get_stderr` beside them, and the same pair on `RestrictionBuilder`.
- `ConfigError::StreamAttachmentConflict`, for a launch that attaches a conduit
  of its own to a stream the sandbox directs elsewhere.
- `ResolvedInputs::streams`, reporting where each of the three standard streams
  is wired, as the new `ResolvedStreams` and `ResolvedStdio` types.
- `ConfigError::OverlayDirUnowned`, for an overlay layer directory already
  occupied by something other than a directory the calling user owns, and
  `ConfigError::OverlayUpperIsRoot`, for an upper at the filesystem root —
  which has no parent for the work directory beside it, and would put the
  sandbox's writes over the whole host root.
- `RangeMapBlocker::SubordinateAllocationUnknown`, for a host where the
  subordinate allocation could not be determined at all — `getsubids` failing,
  or `nsswitch.conf` sourcing subordinate ids from a module beyond `files` with
  `getsubids` not installed.
- `SetupStep::NewSession`, naming the launch's session change in a setup error.
- `ProvisionError::EntryRefused`, for an entry that cannot be handled for a
  reason that is not a containment failure: a malformed archive (a path
  component that is not a directory, a symbolic link with no target), a source
  tree past a limit the copy protocol carries, or a source id the destination's
  identity map has no place for.
- A repository's suite and components, and a bootstrap's architecture, are
  checked when the repository or the builder is built.
- A signing subkey is admitted only when its binding carries the subkey's own
  back signature, as RFC 9580 requires.
- A release signature made with a public-key algorithm below the floor is
  refused: DSA outright, and RSA under 2048 bits.
- A signature carrying a critical subpacket that cannot be interpreted is
  refused, as RFC 9580 requires.
- A release signature dated before its signing key existed is refused, closing
  the key's validity window at the end the expiry check does not.
- Release signatures, subkey bindings and back signatures made with MD5, SHA-1
  or RIPEMD-160 are refused.
- `ResolvedArchive` records the component key that made the release signature
  in a new `signing_key` field, written to a plan document as `Signing-Key`.

### Changed

- The Debian bootstrap's host-side steps state the modes they write rather than
  taking them from the process umask: `0755` for a directory it creates, `0644`
  for a file, and the mode already stated for a script or a shadow file.
- The guide gains [what the sandbox does not
  hide](https://gregordinary.github.io/ferroday-cage/how-the-sandbox-is-
  built.html#what-the-sandbox-does-not-hide).
- **Breaking.** `ResolvedArchive::signed_by`, and a plan document's `Signed-
  By`, name the verifying certificate's primary key rather than the subkey that
  made the signature. It is the identity a keyring entry is named by and the
  one to pin a repository against, and unlike the signing key it survives an
  archive rotating its subkey. The subkey is still reported, as `signing_key`.
- **Breaking.** A container requires a procfs wherever its nested user
  namespace's identity map is established through one, by path, and a profile
  that mounts none is then refused at build time with the new
  `ConfigError::NestedUsernsNeedsProcfs`. The managed profile mounts one by
  default; this is reachable only from a profile that sets
  `managed_mounts(false)` or `mount_proc(false)` and declares no procfs of its
  own.
- **Breaking.** The command holds no capability over the namespaces the sandbox
  created, because it is now root of a *child* of the user namespace that owns
  them. In practice: it cannot bind a TCP port below 1024, cannot open a raw
  socket or send ICMP — `ping` no longer works inside a sandbox — and cannot
  change the hostname or reconfigure the network interfaces the setup brought
  up.
- **Breaking.** Every launch holds two user namespaces rather than one, and a
  namespace is charged against `user.max_user_namespaces` at every level up to
  the initial namespace.
- `SetupStep` gains eight variants for the new steps: `NestedUnshare`,
  `NestedDenySetgroups`, `NestedWriteGidMap`, `NestedWriteUidMap`,
  `AwaitNestedIdentityMap`, `OpenSandboxProcfs`, `NestedMapGate`, and
  `NosuidRootfs`.
- **Breaking.** `Stdin` is renamed `Stdio`, and `CageBuilder::stdin`,
  `CageBuilder::get_stdin`, and `RestrictionBuilder::stdin` take and return it.
  One enum now serves all three standard streams, so the name no longer claims
  less than the type covers, and the session rule and the descriptor-sharing
  semantics have one home rather than two.
- The curated seccomp policy denies `ioctl` for the `TIOCSTI` and `TIOCLINUX`
  requests, the two that write to a terminal's input queue, and allows it
  otherwise.
- An overlay work directory on a different filesystem from the upper is refused
  at build time, naming the work directory, rather than failing the mount with
  a bare `EXDEV` from a syscall the caller never issued.
- The subordinate-id helpers are resolved to an absolute path by the same
  lookup `host::range_map_blocker` uses to judge their privilege, and that path
  is what executes.
- `Terminal::size` leaves a zero dimension at its default rather than passing
  it through.
- **`fcage`.** The `--terminal` relay blocks `SIGTTOU`.
- The overlay documentation no longer steers callers at `/var/tmp`, which is
  mode `1777` everywhere.
- A package is downloaded and installed without ever being held in memory.
- A self-signature dated in the future no longer governs a key's expiry.
- A signature refused by a validity gate — a hash or public-key algorithm below
  the floor, a missing creation time, a retired signing key, a signature that
  has itself expired — is now a `DebianError::Signature` rather than a
  `DebianError::Release`.
- A subkey that could not verify a release now says why.
- The zstd decoder bounds each frame's window through `ruzstd` rather than
  reading the window out of the frame header itself.
- `flate2`'s backend is named in the manifest rather than left to the crate's
  default, so a build without the `debian` feature reaches gzip through
  `miniz_oxide`, which forbids unsafe code outright.
- `lzma-rust2` moves to 0.18, `ruzstd` to 0.9, and `sha2` to 0.11. `fcage`
  reads profiles through `toml` 1.1. No public API changes.

### Fixed

- The built-in fetcher reads a response's status line only from a line that
  begins `HTTP/`.
- A run-as identity sets no-new-privileges, in every build of the library and
  whatever else the sandbox requests.
- **`fcage`.** `--terminal` no longer spins at 100% CPU when `fcage`'s own
  standard input is a pipe whose writer has closed, or names no open file at
  all.
- The network stack's tap helper closes its inherited descriptor table before
  joining the sandbox's namespaces.
- **`fcage`.** The `--terminal` relay's signal descriptor decodes the signal
  number in the host's byte order rather than little-endian, and a record
  naming a number the build has no name for is skipped rather than ending the
  drain for that wake.
- The command's standard output and standard error can be directed somewhere,
  which closes the rest of the caller's terminal.
- A sandboxed command that does not inherit the caller's standard input no
  longer reaches the caller's terminal.
- The supervisor waits for any child rather than for any child of its own
  process group.
- A launch that fails after its mount targets are created no longer leaves them
  behind.
- The mount targets a launch creates are judged, and removed, inside the root
  rather than against the host's.
- An overlay's upper and work directories are no longer adopted from an entry
  the calling user does not own.
- `unique_hex` keeps its uniqueness claim when `getrandom` fails or returns
  short. Its result was whatever `getrandom` wrote over a pid seed, so on a
  host without it every call within one process returned the same string.
- A subordinate map no longer emits more extents than a map file can carry.
- One unparsable line in `/proc/self/uid_map` no longer disables
  `DirectMapper`'s coverage check for both id spaces.
- `Running::wait` returns an error rather than panicking if the pump ever
  reports no outcome for an unbounded wait, and the pump checks for its
  observer before reading a captured stream rather than after — where a zero-
  length buffer would have taken the read for end-of-file and discarded the
  output, masking the mismatch the check exists to catch.
- A `.deb` handed to `Pool::publish` no longer chooses where in the pool it is
  written.
- A `.deb`'s control file can no longer dictate its own `Packages` entry.
- The derived dpkg statoverride records each path once. dpkg treats two records
  for one path as an unrecoverable fatal error — `dpkg-statoverride --list`
  aborts, and with it every dpkg wave after the file is written — and an
  install set reaches that honestly: two selected packages can ship one path,
  since the resolver reads `Depends` and `Provides` and never `Conflicts` or
  `Replaces`; one `data.tar` may list a path twice; and a layered build's
  increment may re-ship a path its base already overrode.
- A bootstrap that fails partway no longer leaves its downloaded packages
  beside the rootfs it did not publish.
- A `stage_layer` that fails disposes of the overlay upper it created, and of
  the package cache beside it.
- A pinned `Plan` whose package names an archive index past the plan's own
  archive list is refused when the provisioner is built, rather than panicking
  partway through a download.
- A `file://` URL naming a host other than this one is refused.
- A `SHA256` line of a `Release` whose digest is not 64 lowercase hex
  characters is dropped rather than carried.
- A tar header's mode is refused rather than wrapped when the GNU base-256 form
  carries a negative value, as the uid and gid beside it already were.
- `CopyIn` computes a mapped id in the width its own containment test uses. An
  identity-map extent whose `inside + count` passes `u32::MAX` overflowed — a
  panic in a debug build, a wrapped id in a release one.
- A bootstrapped rootfs's own root directory is mode `0755`, the mode `base-
  files` gives `/`, rather than the mode of whichever package was extracted
  last.
- A file bind whose target the rootfs ships as a symbolic link no longer
  creates a file at the link's destination.
- A file bind's created target carries mode `0644` exactly, rather than that
  mode narrowed by the launching process's umask.
- A copy the in-map child refuses reports the step the child failed at, not the
  broken pipe the walk saw afterwards.
- A copy-in frame naming an entry with a NUL inside it is refused rather than
  read as the prefix before it.
- A symbolic link copied into a rootfs carries the modification time its frame
  names, its own rather than its target's. It was decoded and dropped, so every
  copied link was stamped at the moment of the copy.
- The overlay support probe closes the descriptors it inherited before it runs,
  as the export, copy-in, and removal children each do.
- The export, copy-in, and removal children ignore `SIGPIPE` rather than being
  terminated by it.
- An archive certificate whose primary key has expired no longer verifies a
  release through one of its signing subkeys.
- A release signature that carries no creation time is refused.
- Every signature a keyring key made over a release is judged, not only the
  first that verifies against it.
- A signature expiration of zero seconds no longer expires a signature at the
  instant it was made. Zero and an absent subpacket are the two wire forms of
  "does not expire", as they already were for a key expiration.

## [0.1.4] - 2026-08-03

### Fixed

- An archive whose signing key had its expiration removed by a later self-
  signature verifies again.
- `provision::CopyIn`'s type documentation described the identity translation
  backwards, saying a source tree's ids are interpreted as in-rootfs ids.
- `fcage`: a profile setting `resolv-conf` or `managed-mounts` now governs the
  `resolv.conf` composed for `--netstack`, as the matching flag always has.
- The native network stack no longer holds a flow slot for the ten seconds a
  finished TCP exchange spends in `TIME_WAIT`.
- The native network stack no longer acts on IPv4 fragments.
- A UDP reply is no longer lost when the guest's receive ring is momentarily
  full.
- The native network stack documented every refused TCP destination as answered
  with a reset.

### Changed

- The mirror setters document that the built-in fetcher speaks `http://` and
  `file://` only, so an `https://` mirror needs a transport supplied through
  `DebianBuilder::fetcher`.
- `fcage`: the warning raised when the host's nameservers are all on loopback
  no longer claims the sandbox has no working DNS.
- `fcage`: `--netstack-host-loopback` documents that it maps the gateway onto
  `127.0.0.1` alone, so a resolver on any other loopback address is not reached
  — including systemd-resolved's `127.0.0.53` stub, the configuration that
  raises the loopback-nameserver warning.
- `fcage`: `--no-resolv-conf` records that it opts out of the `resolv.conf`
  `--netstack` composes, not only the bind `--share-net` makes.

## [0.1.3] - 2026-08-03

### Added

- `provision::CopyIn` copies a host directory tree into a rootfs with each
  entry created under the identity map the rootfs is owned through.
- `Plan::to_document` and `Plan::parse_document` are the plan's on-disk form,
  in the archive's own deb822 control format.
- `DebianBuilder::plan` installs a previously resolved `Plan` verbatim. The
  bootstrap fetches exactly the packages the plan records, by the digests it
  records, and never touches a release or a package index.
- `Plan` records the archive state it resolved against, as `Plan::archives`:
  one `ResolvedArchive` per configured repository, carrying the mirror that
  served, the suite and components, the SHA-256 of the verified release body,
  the release's `Date` and `Valid-Until`, and the fingerprint of the key that
  verified it.
- `provision::debian::foreign_interpreter` reports the `qemu-user` interpreter
  a foreign-architecture binary is executed through, as an `Interpreter`
  carrying the qemu target name, the registered path, that path canonicalized,
  whether the handler is enabled, and its flag letters.
- `Debian::available` reports the names a configured set of archives offers, as
  an opaque `Available` answering `contains` and `providers`.
  `Observed::available` is the reporting form.
- `Tarball` reads pre-POSIX v7 archives, alongside the ustar, GNU, and pax
  dialects it already read. v7 is the subset rather than a separate format: a
  header's first 257 bytes are laid out identically, and what v7 lacks is
  everything after them — the magic, the version, `uname`/`gname`, the device
  numbers, and the `prefix`.
- `ResolvedInputs` records the sandbox's root and the posture the launch puts
  the command under: `root`, `identity`, `network`, `rlimits`, and `hardening`,
  alongside the `env` and `mounts` it already carried.
- `Pool::date` pins the `Date` the emitted `Release` carries, in Unix seconds.
- `fcage` gains `--export-rootfs DIR`, which writes a provisioned rootfs to a
  tar archive and exits.
- `fcage` answers an unrecognized option with the nearest flag it knows, where
  one is near enough to be worth offering:
- `Pool::origin`, `Pool::label`, and `Pool::description` set the release's
  identity fields.
- `Debug` on the provisioning types that lacked it: `Pool`, `Export`,
  `Provision`, `Remove`, `Debian`, `DebianBuilder`, `RepositoryBuilder`, and
  `Observed`.

### Changed

- A Landlock grant naming no access at all — `landlock_fs(FsAccess::empty(),
  ..)` or `landlock_net(NetAccess::empty(), ..)` — is refused at build with
  `ConfigError::LandlockGrantEmpty`.
- `Limit` implements `Ord` by hand, so `Limit::UNLIMITED` compares above every
  finite limit as its documentation says.
- A network stack whose helper builds the tap but cannot hand its descriptor
  back reports `NetStackError::TapHandoff` rather than `TapConfigure`.
- `fcage` ties the sandbox to its own lifetime by default: `--stop-with-caller`
  is now on, and `--no-stop-with-caller` opts out.
- `fcage --netstack` composes no `resolv.conf` under `--no-managed-mounts`,
  whose promise is that the sandbox carries exactly the binds the command line
  names.
- A mount target the launch has to create as an empty file does not outlive the
  sandbox.
- A pool stores a `.deb` under a filename without the version's epoch, as the
  archive convention has it, where it previously encoded the epoch's colon as
  `%3a`.
- A `Repository`'s rendering names its trust anchor as `Signed(N bytes)` or
  `Unsigned`, where it previously showed `"signed"` or `"unsigned"`. Debug
  output is not covered by the stability promise.
- `fcage --help` groups its options under section headers — provisioning,
  profiles and mounts, identity and limits, the command's process, networking,
  hardening, the toggles that turn off what is on by default, and help — rather
  than presenting one flat list of roughly two hundred lines.

### Fixed

- The native network stack delivers a transfer that ends in a prompt close.
- The native network stack no longer shuts a flow's host write side down before
  the guest's handshake completes.
- A profile naming both `rootfs` and an `[overlay]` table is refused with
  `ConfigError::RootContradiction`.
- An export or removal child closes the descriptors it inherited, keeping only
  its own stream and gate.
- The Debian mirror walk advances past an unsuccessful HTTP status.
- A UDP reply larger than one packet is dropped at the relay, where the ceiling
  is documented, rather than handed to an interface that discards it at egress
  with no diagnostic at all.
- `fcage` no longer takes a command's own `--export-rootfs` or `--remove-
  rootfs` for its own.
- `fcage` no longer answers an option of another mode by suggesting the flag it
  has just refused: `--export-to` given to a launch now names the mode that
  accepts it.
- `fcage --remove-rootfs --help` prints the help rather than taking `--help` as
  the tree to delete. `fcage --export-rootfs --help` did the same, silently.
- `fcage` refuses a launch flag on a provisioning run that names no command,
  where it previously accepted and dropped every one of them.
- Concatenated gzip members all decode. Only the first was read, and because a
  tar reader tolerates a missing terminator at end of input, a concatenated
  `.tar.gz` provisioned a silently incomplete rootfs.
- A pax `uid` or `gid` record is honoured.
- A held package (`hold ok installed`) counts as installed in a base layer, so
  a layered Debian build no longer re-unpacks it.
- Excluding a package that is also a provided virtual name falls through to a
  provider instead of failing the resolution, which is what apt's own
  deselection does.
- An identity map extent ending exactly at `u32::MAX` is refused at build, as
  the kernel refuses the id `(u32)-1`, rather than failing when the map is
  applied.
- A malformed `Valid-Until` fails freshness rather than reading as a slightly
  wrong deadline: an out-of-range day no longer rolls into the next month, and
  a zone offset past 23 hours is refused.
- An HTTP redirect to another port on the same host is refused with the same-
  origin policy, which previously compared hosts alone.
- A whitespace-only line separates deb822 stanzas, as it does for every other
  reader of the format.
- `Pool::publish` writes the `Release` field `Date`, which the Debian
  repository format requires and which the emitted release previously omitted.
- `Pool::publish` writes a `Release` describing the whole suite.
- A repository declaring more than one component resolved only the first
  package of each component after the first.
- `Pool` refuses a suite, component, or architecture it cannot write.
- The default fetcher refuses a response whose header section ends without the
  blank separator.
- The default fetcher refuses a `Content-Length` it cannot use: one that does
  not parse, one past `u64`, or a repeat contradicting the first.
- The default fetcher tries every address a mirror's host resolves to, rather
  than the first alone, and reports the last failure only when none connects.
- The managed `resolv.conf` placeholder is recorded against the path the file
  is actually created at.
- The tree-copy child refuses a frame stream that ends with directories still
  open.
- A directory the extraction implies but no archive entry names is left
  traversable when it is created for the overlay walk, which runs no later mode
  pass to widen it from the `0700` it is created at.

## [0.1.2] - 2026-07-30

### Added

- `fcage` gains `--remove-rootfs DIR`, which deletes a provisioned rootfs and
  exits, including one a range-mapped sandbox wrote and a plain `rm -rf` cannot
  remove.
- `Pool` reports the layout it owns: `mirror_url` gives the `file://` URL that
  declares the pool as a `Repository`, and `dir`, `dists_dir`, and
  `release_path` give the paths a caller signing the pool needs.

### Changed

- `Pool::publish` removes any `InRelease` or `Release.gpg` the suite carries
  before writing a new `Release`, so a signature made over a superseded release
  cannot outlive it.
- A mount point the sandbox has to create carries the mode of the directory it
  stands for, applied exactly: `1777` for `/tmp` and `/dev/shm`, `0755` for
  `/dev` and `/proc`, and `0755` for a directory created on the way to either.
- The `/etc/resolv.conf` target that host networking creates when the rootfs
  ships no resolver configuration is removed once the sandbox is gone, rather
  than left in the tree.

### Fixed

- A mount point the sandbox creates no longer takes its mode from the launching
  process's umask.

## [0.1.1] - 2026-07-26

### Changed

- Both crates carry keywords chosen for how the registry is actually searched,
  and the README states the boundary against container runtimes.

## [0.1.0] - 2026-07-26

Initial public release. The [README](README.md) describes what the library
does, and the [guide](https://gregordinary.github.io/ferroday-cage/) covers
it in full.

[Unreleased]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.5...HEAD
[0.4.5]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/gregordinary/ferroday-cage/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/gregordinary/ferroday-cage/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gregordinary/ferroday-cage/releases/tag/v0.1.0
