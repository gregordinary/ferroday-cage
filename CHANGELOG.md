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
affected.

## [Unreleased]

### Changed

- The transport seam is `provision::{Fetch, FetchRequest, FetchError,
  HttpFetch, file_url}`, moved out of `provision::debian`. It was never
  Debian's: it speaks HTTP and `file://` and knows nothing of an archive's
  format, and every userland provisioner needs one. Under the old paths a
  provisioner built without the `debian` feature had no transport at all, not
  even the built-in client. The modules now compile for any userland feature,
  and no re-export is left at the old paths.

  `file_url` reports a `FetchError` rather than a `DebianError`, since a path
  that cannot be named is a resource that cannot be addressed, whichever layer
  wanted to address it. `Pool::mirror_url` therefore returns
  `DebianError::Fetch` where it previously returned `DebianError::Config` or
  `DebianError::Io`.

- `BuildLayer` is `provision::BuildLayer`, moved out of `provision::debian` for
  the same reason. It is the overlay upper a layered build installs into and the
  handle that disposes of it — a path, the work directory beside it, and the
  identity map that decides how both are removed — with nothing in it about any
  particular userland. Every userland provisioner that stages an increment
  returns one. No re-export is left at the old path.

- `Stream` is `provision::Stream`, moved out of `provision::debian` and
  `provision::alpine`, which each defined their own. The two definitions were
  identical, down to the documentation: a provisioner that runs a command in a
  cage has output to attribute to a standard stream whichever archive it
  provisions from, and the attribution says nothing about the archive.
  `DebianEvent::CommandOutput::stream` and `AlpineEvent::CommandOutput::stream`
  both carry the shared type, so code that handles one layer's output handles the
  other's. The events themselves stay with their layers, since those do speak
  each archive's own vocabulary. No re-export is left at the old paths.

- An Alpine bootstrap fetches packages over its repository's whole mirror list,
  not only the mirror that served the index. `AlpineBuilder::mirror_fallback`
  backed the index alone, so a package rebuilt to a higher `-r` — which removes
  its predecessor from a live mirror — left a plan naming the predecessor with
  nowhere to go, while the same configuration on the Debian side had a backstop.
  The two builders' methods now mean the same thing.

  A plan resolved against more indexes than the configured repositories publish
  is refused, before anything is downloaded, because its packages name no mirror
  to be fetched over. This is the check the Debian layer already made against its
  archive count.

  Both plan formats recorded the serving mirror and described it as where the
  packages come from. It is provenance: the plan names what to install and holds
  it to a digest, and the configuration names where to fetch it. The Debian layer
  already behaved this way and its documentation did not say so; both are now
  accurate.

- A mirror walk advances only past a failure that says *this* mirror could not
  serve the resource, which is `provision::FetchError`'s own question now rather
  than one each layer answers. The Alpine index walk advanced past every fetch
  failure, so a mistyped primary mirror was reported against whichever mirror
  came last instead of against the one that was wrong.

- Every OS failure a library error carries is now an `io::Error` and is returned
  from `source()`. `Error`, `ConfigError`, `IdMapError`, and `NetStackError`
  stored a raw `errno: i32` and then rendered it by constructing an `io::Error`
  at each `Display` arm — twenty-odd sites undoing the same representation —
  while `ProvisionError`, `DebianError`, and `FetchError` carried the error
  itself. `source()` divergence followed from that split: an error that holds
  only a number has nothing to return, so half the crate's errors terminated a
  caller's error chain early.

  Every `errno: i32` field is now `source: io::Error`. The errno is not lost —
  `io::Error::raw_os_error` gives it back — and the two places where a failure
  genuinely carried no OS error, `NetStackError::NamespaceJoin` and
  `NetStackError::Pump`, hold `Option<io::Error>` rather than the errno `0` that
  previously stood for "none". `Error`, `ConfigError`, `IdMapError`, and
  `NetStackError` implement `source()` for every variant that has one.

  Consequently those four types are no longer `UnwindSafe` or `RefUnwindSafe`,
  which is the same posture `ProvisionError` and `DebianError` already had.

- `FetchError::Io::op` is a `&'static str` and `FetchError::io` takes its
  arguments as `(op, url, source)`. Every error constructor in the crate now
  reads operation, then locator, then cause; this one read locator first. Both
  arguments were `impl Into<String>` before, so a stale call would have compiled
  and silently produced a transposed message — narrowing `op` to `&'static str`
  makes it a compile error instead.

- `ParseCapabilityError::name` is `ParseCapabilityError::text`, matching
  `ParseFsAccessError::text` and `ParseNetAccessError::text`. Three parse errors
  in one file answered the same question under two names.

- `Debian::observe` takes a `DebianObserver` rather than a bare
  `FnMut(DebianEvent<'_>)` closure. A closure is still an observer — the trait
  carries a blanket impl for one — so existing callers are unaffected.

- `AlpineBuilder::build` validates a `plan()` and a `pin()` against the
  configuration, which `plan()`'s documentation already described and only
  `preflight` partly did. A plan resolved for another architecture, one naming an
  index it does not carry, one whose index slot is not the release and component
  the configured repository publishes there, and one naming a package by
  something no repository could publish it under are all refused with
  `AlpineError::Config` before anything is fetched. So are the combinations that
  would have silently dropped half of what was asked for: `plan()` beside
  `include()`, `exclude()`, or `pin()`, each of which describes a resolution that
  a plan already is. The Debian layer made these checks; the two builders now
  refuse the same configurations.

  A Debian `plan()` and `pin()` are validated the same way, over the fields the
  Alpine layer's `unaddressable` covers: a package's `Filename`, which is
  interpolated verbatim into the URL its `.deb` is fetched from, is held to the
  pool-path rule an archive index's is, and its `SHA256` must be 64 lowercase hex
  characters. `Plan::parse_document` refuses a document carrying either, and
  `build` refuses a `Plan` edited after `resolve` returned it. A pin recording an
  uppercase digest was previously tolerated by `pin()` and refused by `plan()` as
  a hash mismatch; it is now refused as the malformed entry it is, wherever it
  arrives.

  An `AlpineBuilder` that names no `architecture()` adopts the plan's or the
  pin's, as `DebianBuilder` already did. A plan states which architecture it is
  for, so refusing one the caller never contradicted — over a host default they
  never chose — would be a rejection they could not act on.

- An Alpine plan document is held to the index's own grammar as it is read.
  `Plan::parse_document` accepted any non-empty `Package:` and `Version:`, and
  those two compose the file name a package is fetched over and cached under — so
  a document naming a package `../../x` wrote mirror-served bytes outside the
  cache directory, before the control identity that would have rejected them was
  checked. The live-resolve path already held every name to this; a plan is a
  document a caller may have edited, which the crate's own comments say, and it
  now passes the same gate.

- An apk container's signature segment may hold more than one `.SIGN.*` member,
  and the first that names a trusted key and verifies is the one that answers.
  A rotation-era artifact carries one member per key so that readers holding
  either can verify it; requiring exactly one refused a container `apk` reads.
  A plan records the key that verified rather than the first listed.

- A `k:` provider priority of zero is no priority, as are a negative and an
  unreadable one. A record publishing `k:0` was auto-selectable where an
  unranked one was refused as ambiguous. Driving `apk.static` 3.0.7 against a
  purpose-built repository settles it: `k:0`, `k:-1` and `k:abc` each leave apk
  refusing to choose against a provider stating no `k:` at all, exactly as two
  unranked providers do, while `k:1` wins outright.

- An Alpine resolution takes an alternative provider rather than refusing an
  upgrade it does not need. Where a base layer carries a package too old for a
  constrained dependency, `WouldUpgrade` fired on the highest-ranked candidate
  before the others were considered — so a closure the repositories could supply,
  and that apk's own solver finds, was refused. Only a dependency every candidate
  for which would upgrade something the base carries is refused now.

- A `.PKGINFO` whose `datahash` is not a SHA-256 in lowercase hex is refused as
  the malformed metadata it is, rather than reaching the data-segment comparison
  and being reported as a digest mismatch — an authenticity-flavoured answer to a
  spelling. This is the shape check the Debian layer makes on every
  archive-supplied digest, now made by both from one place.

- The Alpine index walk reports `AlpineEvent::Fetching` for each index it asks
  for. It is the slowest part of a resolve — one mirror timeout per unreachable
  mirror — and an observer saw nothing between `Resolving` and the first package
  download, while the Debian walk and the Alpine package walk both reported.

- `fcage`'s `--debian-repository` and `--alpine-repository` refuse a spec whose
  only mirror field is `mirror-fallback=`, and one that gives `mirror=` twice.
  Both were read positionally, so a lone backstop was promoted to primary and a
  repeated `mirror=` demoted the earlier value to a backstop ahead of the
  declared ones. A repository's primary mirror is written into the finished
  root — as `/etc/apk/repositories` or `sources.list` — so a typo-dropped
  `mirror=` left that root permanently fetching from a fetch-time backstop.

- `fcage` exits 125, not 2, when `--alpine-keys` or an `--alpine-repository`'s
  `keys=` names a directory it cannot read at provision time. The spelling is
  checked when the command line is parsed; what is left is whether the machine
  can supply the keys, which is what 125 means and what the library reports for
  the same failure. The help text reserves 2 for usage errors.

- The shared tar reader refuses an entry whose `APK-TOOLS.checksum.SHA1` pax
  record is not a SHA-1, and that reader serves the `.deb` data member and the
  `Tarball` provisioner too. Before the Alpine layer every unknown pax key was
  ignored, so a `.deb` or rootfs tarball carrying a malformed record of that name
  was extractable and is now refused. dpkg toolchains do not write the key, and a
  checksum that cannot be read is the safe thing to refuse; it is recorded here
  because the seam is shared and the change reaches archives that are not apk's.

- An Alpine resolution reports an increment that breaks a refusal a base package
  declares, where the base breaks the same refusal itself. Only the first
  breaking offer was consulted and a base layer's offers sort first, so a refusal
  broken by both the base and the increment was excused as the base's own
  business — which it is when the base alone breaks it, and is not when the
  increment does. Reachable only over a hand-assembled base tree that already
  violates its own conflict, which neither this resolver nor apk produces.

- The size-ceiling message says `the stream exceeded the maximum size accepted
  for it` where it said `the response body exceeded the maximum size`. The
  ceiling moved out of the HTTP client with `LimitedWriter` and now bounds a
  compressed segment expanding under a decoder as readily as a mirror ignoring
  its own content length, so what it names is no longer a response body.

### Added

- The `gentoo` feature: a provisioner for a Gentoo userland, reached through
  `provision::gentoo::{Gentoo, GentooBuilder, GentooError, GentooEvent, Stage3,
  Available, CertificateHorizon}`. It resolves a stage3 variant to the build the
  archive currently publishes, verifies the two cleartext-signed documents that
  vouch for it against a vendored keyring, holds the tarball to the SHA-512 one
  of them records, and extracts it. `Gentoo` implements `Provisioner`, so a
  caller drives it through `provision::ensure` as they drive every other one.

  The layer is deliberately smaller than the other two: Gentoo publishes no
  package resolution for a stage3, so there is no plan document, no dependency
  graph, and no install-script wave. `Stage3` is the record a resolution
  produces, and `GentooBuilder::{build_id, stage3}` are how a caller provisions
  the same build again -- for about five weeks, which is how long the archive
  keeps one.

  A variant is the whole compound the archive publishes -- `amd64-openrc`,
  `x32-openrc` -- matched exactly against the signed enumeration
  `Gentoo::available` reports, since amd64's own document lists those two as
  siblings. An unknown one is refused before anything is fetched, naming what
  the architecture does offer.

  Gentoo publishes no `Valid-Until` and signs nothing with an expiration, so the
  regeneration timestamp inside the signed pointer is the only bound on how old
  a correctly signed document may be; without one a mirror could replay a
  months-old pointer indefinitely and pass every other check. It is bounded at
  thirty days, and `GentooBuilder::max_pointer_age` relaxes or clears it.

  `Gentoo::keyring_horizon` reports what each certificate of the vendored
  keyring can still be trusted to do and until when. Per certificate rather than
  as one date: Gentoo's eleven do not share an expiry, and one of them can vouch
  for nothing at all, so a single number would misreport the anchor's shelf life
  in both directions.

- `fcage --provision-gentoo ARCH` provisions a root from a signed stage3, with
  `--gentoo-variant`, `--gentoo-build-id`, `--gentoo-mirror`,
  `--gentoo-mirror-fallback`, `--gentoo-cache` and `--gentoo-max-pointer-age`
  mirroring the builder they configure. `--gentoo-variants ARCH` prints what an
  architecture publishes and `--gentoo-keyring-horizon` prints the keyring; both
  answer without provisioning anything, and the second reaches no network.

- The `ebuild-sandbox` example provisions its stage3 from the archive with
  `--variant`, rather than only from a tarball the caller had already obtained.
  `--stage3 FILE` stays, for an air-gapped host or a locally built stage3; the
  two are alternatives.

- `tools/check-keyrings.py` compares every vendored trust anchor -- Debian's
  archive keyring, Alpine's and postmarketOS's signing keys, and Gentoo's
  service keys -- against what its distribution publishes today, and fails on a
  key that changed, one that appeared, or one that is vendored and no longer
  published. It runs weekly in a workflow of its own and never on a pull
  request: keyring drift moves on a scale of months, and it reaches the network
  to do its job.

- The `alpine` feature: a provisioner for an Alpine Linux userland, reached
  through `provision::alpine::{Alpine, AlpineBuilder, AlpineError, AlpineEvent}`.
  It resolves a package set from one or more apk repositories, verifies each
  index's RSA signature against a bundled key set, binds every package to the
  index that named it, and installs the closure — extraction in one wave, the
  packages' own install scripts in a second, both in dependency order, with the
  scripts running inside a cage rooted at the staging tree. The finished root
  carries `/lib/apk/db/installed`, `/etc/apk/world`, `/etc/apk/repositories`,
  `/etc/apk/arch` and the repositories' trusted keys, so an `apk` inside it reads
  back what the bootstrap wrote.

  The surface mirrors the Debian layer's: the same builder setters, `resolve`,
  `available`, `plan` and `pin` with a plan document of its own, `base_layer` /
  `resolve_layer` / `stage_layer` for layered build roots, and an `observe()`
  sink over `AlpineEvent` carrying the same progress, reported through
  `ProvisionEvent::Alpine`. Where the two differ, the archive is why:
  there is no priority band, so the install set is exactly what `include` names
  closed over its dependencies; there is no unsigned mode and no validity
  window, so nothing corresponds to `trust_unsigned` or `allow_stale_release`;
  and `extract_only` still writes the installed database, an apk record being a
  file format rather than a program's output. The
  [guide chapter](https://gregordinary.github.io/ferroday-cage/alpine.html)
  enumerates the rest.

  postmarketOS is served by the same code: its repositories are byte-identical
  apk on a path one level shallower, so a `Repository` that names no components
  takes that layout, and `KeySet::postmarketos` is the bundled trust anchor for
  it.

  An `alpine`-only build is lighter than a `debian` one — no OpenPGP
  implementation — and adds nothing new to a graph that already has `debian`:
  `rsa`, `sha1`, `pkcs8` and `spki` were transitive dependencies of rPGP
  already.

- `fcage --provision-alpine RELEASE`, with the `--alpine-*` options mapping onto
  the builder as the `--debian-*` set does. The two provisioners are mutually
  exclusive.

- `ExitStatus::shell_code` and `Error::shell_code` return the process exit code
  a launcher reports: the command's own code or `128 + signal` for the first,
  and 127 / 126 / 125 for a command that does not exist, cannot be executed, or
  a launcher failure for the second. Both conventions were written out in the
  `fcage` binary and again in four of the crate's examples, and the second one
  encodes a shell convention that a consumer had no way to know was the intended
  answer. The library owns them now, documented as promises.

- `provision::debian::host_architecture` reports the Debian architecture name
  for the host — what `DebianBuilder::architecture` and `Pool::architecture`
  default to. It was internal, so a consumer composing its own defaults wrote
  the table again, and the crate's own `deb-layer-pipeline` example did: its
  copy read `std::env::consts::ARCH`, which reports `powerpc64` for both
  endiannesses and so mapped big-endian POWER onto `ppc64el`.

- `provision::debian::DebianObserver`, the bootstrap's progress and cancellation
  sink, shaped like `ProvisionObserver`: one `progress` method, one defaulted
  `cancelled`. A bootstrap fetches and verifies indexes, downloads a hundred
  packages, and runs several `dpkg` waves in a cage, and a caller driving one
  through `Debian::observe(...).resolve()` had no way to stop it part-way.

- `Observer` has the closure blanket impl `ProvisionObserver` always had, so
  `cage.run_with(&mut |event: Progress| ...)` works the way
  `Provision::observe(&mut |event| ...)` does. A closure receives the launch's
  milestones; an observer that wants the command's output still implements the
  trait, since a closure has no way to say which stream a chunk came from.

- `Priority` implements `FromStr` and `Display`. The name table was private to
  the index parser, so `fcage` carried a second copy — and the copies disagreed:
  the library's was case-insensitive and the CLI's was not, so
  `--debian-base-priority Required` was refused while a `Priority: Required`
  field in an index was accepted. `ParsePriorityError` is the parse error.

- `ProvisionError::at`, `DebianError::at`, and `FetchError::at` build the same
  errors as their `io` constructors, as a `map_err` argument. Four separate
  closure factories of this shape existed internally, one of them declared
  inside a single function.

- `provision::debian::file_url` builds the `file://` URL naming a local path,
  which is how a repository on this machine is addressed:
  `RepositoryBuilder::mirror` reads that form, and `Pool::mirror_url` answers
  with it for the pool it writes. A caller assembling a repository some other
  way wrote `format!("file://{path}")`, which produces an unusable URL for a
  relative path — a `file://` URL carries a path from a root, and this makes one
  absolute before it does.

### Fixed

- A tar entry whose real path arrived in a GNU long-name entry or a pax record
  is read as the file it is, rather than as a directory when its header's own
  truncated name happens to end in a separator. A header's name field holds at
  most a hundred bytes, so for such an entry it is a truncation of the real
  path, and the trailing-slash rule -- an old convention marking a directory
  where the typeflag predates being reliably set -- was applied to it. A
  directory carries no data, so the file's bytes were then read as the next
  header and the rest of the archive was lost with them. Found in a real Gentoo
  stage3, where one C++ header out of 134,477 members has a path whose hundredth
  byte is the separator.

- An Alpine root's files agree with the database that records them when two
  packages contest a path. Where the earlier package's `replaces` kept the file,
  the record said so and the extractor wrote the later package's bytes over it
  anyway — the per-entry hook had no way to say "do not write this one" — so the
  finished root held a file its own `Z:` digest did not match and `apk audit`
  reported as modified. Where the later package took the path over, the earlier
  record went on claiming it, leaving one path under two packages with two
  digests; which one `apk` read was then a function of the order it walked the
  records in. Both are closed: the hook decides whether an entry is written, and
  a replacement takes the path out of the record it took it from.

- An Alpine package is extracted from the file its verification read, not from
  the path that file was at. The two were independent `File::open`s on the same
  cache entry, so with a `cache_dir` shared across a trust boundary — which the
  atomic staging and rename are written for — a writer swapping the file between
  the two got unverified content extracted into the root. The verified descriptor
  is carried and rewound instead; nothing can be swapped underneath it.

- A failed write while downloading an Alpine package is reported as the I/O
  failure it is. The body went through a `std::io::BufWriter` whose `Drop`
  swallows a failed flush, so a last-buffer failure — `ENOSPC`, `EIO` — renamed a
  truncated file into the cache and surfaced on the following read as a digest or
  container failure, telling the caller their mirror was serving the wrong bytes.
  The Debian download already checked its writer before publishing.

- `fcage` no longer counts `nameserver8.8.8.8` — no separator — as a routable
  nameserver when deciding whether a `resolv.conf` needs the network stack.
  glibc ignores such a line. The `fetch-sandbox` example answers the same
  question for the same purpose and now applies the same rule; the two are
  recorded in `tools/idioms.toml` so a change to either arrives as a diff naming
  the other.

- The network stack answers address resolution and ICMP echo only for the
  addresses it holds. It accepts packets for every destination so that routed
  traffic reaches its sockets, and smoltcp's switch for that also had the
  interface answer ARP for every address on the guest's link and answer an echo
  request for any destination at all, sourced from whatever was pinged. Nothing
  was forwarded that the policy refuses — the destination check is unchanged —
  but a guest ARPing a non-existent neighbour got a completed entry carrying the
  gateway's hardware address, and a ping of an unreachable address succeeded
  against the stack itself. Both requests are now withheld from the interface
  before it can answer them, so an on-link refusal fails when the guest's own
  address resolution gives up, as documented, and a successful ping means the
  gateway answered.

- `fcage --terminal --timeout` acts on the deadline on every wakeup rather than
  only on the one `poll` timed out on. Once the deadline had passed the poll
  timeout was zero, so a sandbox with something to say answered every poll with a
  ready descriptor and the escalation was reached only when the pseudoterminal
  fell quiet. In practice the relay drains faster than a writer can refill, so
  the quiet instant arrived within milliseconds — but the guarantee was the
  scheduler's rather than the clock's, where the non-terminal wait's is
  unconditional.

- A `Filename` or `SHA256` in a Debian plan document is held to its shape. See
  Changed, above.

- The `HttpFetch` transport refuses a URL carrying a space or a control
  character. A redirect `Location` is the one URL reaching the request line that
  has passed no boundary check of its own, and the path was interpolated
  verbatim, so a hostile mirror could put a CRLF in one and write headers into
  the follow-up request. Same-origin redirects are the default and content is
  digest-verified, so the reach was the documented
  `cross_host_redirects(true)` envelope — but a blind GET is a narrower
  primitive than one with attacker-chosen headers.

- An export child that fails before it reaches its map gate reports the step it
  reached. It writes its diagnostic on the frame stream, as it reports every
  other failure, and the caller was blocked on the gate and returned without
  reading it — so an `unshare` an LSM denied surfaced as `EPROTO` from a child
  that vanished. The copy-in path already preserved its child's account.

- A removal child abandoned at its map gate is reaped once. `abandon_gated_child`
  killed and reaped it, and the caller then waited a second time on a pid the
  kernel was free to have reused, where a blocking wait could have collected an
  unrelated child's status. Killing and reaping are separate now, and each caller
  does whichever its own path has left.

- A profile that mounts a procfs, mounts a second, and covers the second is no
  longer refused as having none. The scan for a procfs the nested user namespace
  can establish its map through tracked only the most recent candidate, so a
  covered one erased the memory of an earlier one still standing.

- A raw mount carrying `MS_BIND` is read as the bind it is. `mount(2)` ignores
  `fstype` when that flag is set, so `RawMount::new("/proc").source("/proc")
  .fstype("proc").flags(MS_BIND)` satisfied the fresh-procfs requirement it does
  not meet, and the failure arrived at launch instead of as a build error.

- An `APKINDEX` record whose `C:` field is the right length and the right
  alphabet but not one the encoder can produce — `Q1` followed by padding — is
  refused as the malformed record it is, rather than at fetch time as a mirror
  serving the wrong bytes.

- The copy-in child's outcome record is checked for length before it is decoded,
  as the gate's other two readers already were. A short seqpacket message would
  have decoded against the zero-filled rest of the buffer as a step the child
  never reached, with errno 0.

- `fcage --rootfs R --provision-debian trixie --` — a provisioning run ending on
  a bare separator — is accepted. It names no launch setting, and the check for
  one read the separator as a flag.

- A mount-target directory's mode is applied through a descriptor opened
  `O_NOFOLLOW`, not by path. A path-wise `chmodat` follows a symlink at the leaf,
  so a host process racing the window between the `mkdir` and the mode had a path
  of its choosing chmod-ed instead. There is no privilege delta — such a process
  can chmod those paths directly — but the file bind's target already used
  `fchmod` for exactly this reason, and the directory's did not.

- The `HttpFetch` transport parses `HTTP://` and `FILE://` as the schemes they
  are. A scheme is case-insensitive (RFC 3986 §3.1), which the crate's scheme
  extractor documents and the authenticated-transport allow-list honours, but
  the URL parser matched `http://` literally — so an upper-cased URL passed the
  transport check and was then refused by the parser as though it named TLS,
  advising the caller to supply a transport for a URL that names none.

- A failure the copy-in child hits before it reaches its map gate — its
  descriptor sweep, or its `unshare` — now names the step it reached. The gate
  driver read one byte where the child had sent an eight-byte failure record, so
  the record was truncated away by the seqpacket read and the failure surfaced
  as a child that vanished.

- The provisioning children report `DenySetgroups`, `WriteGidMap`, and
  `WriteUidMap` as the distinct steps they are. All three collapsed into one
  `SelfMap` step, so a copy, export, or removal that failed to write its gid map
  and one that failed to deny `setgroups` produced the same diagnostic. The
  launch stage always kept them apart.

- `fcage --terminal` with a `--timeout` larger than the clock can express no
  longer panics. The relay added the timeout to the current instant, which
  overflows; the wait without a terminal already read such a timeout as a wait
  without a deadline, and that is now what both do.

- `HttpFetch::request_timeout` with a duration larger than the clock can express
  removes the bound rather than panicking on the same addition, which is how
  every other timeout in the crate reads one.

### Internal

These change no public API and no behaviour; they are recorded because they
change where a reader looks.

- The five step enums the forked helpers report through — the launch stage's,
  the copy-in child's, the export child's, the removal child's, and the network
  stack's tap helper's — are declared through one `wire_enum!` macro. Each was
  three or four parallel lists kept in step by hand: the variants with their
  wire values, a decoder restating them, a description arm, and a list of every
  variant for the round-trip test. The decoder's match arms are now the same
  literals the variants are declared with, so a value used twice is a compile
  error rather than a test failure. The tap helper's steps gained descriptions,
  which they had none of, so a tap failure names a step rather than a number.

- The three parent-side map-gate drivers are one `drive_map_gate`, and the
  kill-and-reap that ends an abandoned child — with the reasoning for why
  closing the gate cannot release it — is one `abandon_gated_child`. It was
  written out three times, in three sets of words.

- The framed byte protocol the copy-in and export children speak has one set of
  primitives in `mechanism::frame`, and the four bounds both sides of it must
  agree on are declared once in `mechanism::bounds`. The bounds were declared
  two and three times each, with doc comments noting that the copies had to
  agree and nothing enforcing it.

- `FsAccess` and `NetAccess` — the same letter-set bitflag type written twice —
  are one macro and two invocations.

- The profile format's keys come from `rename_all` on the container. Seventy of
  the seventy-one explicit `serde(rename = ...)` attributes restated exactly
  what `rename_all` derives, so a reader could not tell which were pinning a
  name. Two remain, both the same case: a plural Rust field naming a singular
  TOML table (`rlimits` -> `rlimit`, `mounts` -> `mount`). A new test pins every
  key the format can carry, which guards the format against a Rust-side field
  rename, a changed `rename_all`, a container typo, and a newly added field
  alike — where the attributes guarded only the first.

- The launch teardown removes its mount-point placeholders through the same
  contained-tree type the Debian bootstrap's host-side steps use, rather than
  through its own `openat2` walk. The reasoning for why a rootfs path must be
  resolved against the rootfs rather than joined onto it was written out in both
  places.

- One `Duration`-to-`Timespec` conversion, one poll-slot helper, one
  absolute-path splitter, one `retry_on_intr!`, and one hex encoder, each
  replacing two or three copies. The repository name is checked by the same
  `coordinate::check` its suite and components are, and the `fmt::Display`
  spelling is the same in all twenty-one files that implement it.

- The examples share their argument-parsing helpers through
  `examples/common/mod.rs`, and both test suites share their fixtures through a
  new `ferroday-cage-testkit` workspace crate that is never published: one
  rootfs fixture, one scratch directory, one tar writer, one `ar` writer, one
  hex encoder, and one pseudoterminal reader, replacing between two and five
  copies each. The last example keeping helpers of its own uses the shared ones,
  and the boundary between them and the `fcage` binary's own is documented as
  deliberate: a crate's examples cannot reach another crate's code, so sharing
  four argument-parsing functions would mean publishing a crate for them.

- One splitter for a path that names something inside a tree, over the bytes
  such a path is. Its two callers — the archive extractor and the contained-tree
  writer the host-side steps go through — each had one, agreeing by hand on
  `..`, on NUL, and on dropping `.` and empty components; the single point they
  differ on, whether a leading `/` names the tree's own root or is refused, is
  now the argument the splitter takes. What makes one path component ordinary is
  stated once as well, and is what the copy-in walk's host side and its forked
  child each hold a name to, rather than two lists of the same five shapes.

- One `openat2` for opening a directory the kernel keeps inside a tree, with the
  containment flag and the descriptor's access as its arguments. Three copies
  restated the flags every caller passes and the retry the kernel asks for when
  a rename races the walk, and the difference between the two containment flags
  — re-anchoring an absolute symbolic link at the tree's root, or refusing it —
  was explained in two module docs from one side each.

- `fcage` states the `--timeout` escalation once, as a value both of its waits
  drive: the plain blocking wait and the terminal relay, which must keep moving
  bytes while the escalation happens. Each had its own control flow for
  deadline-then-terminate-then-kill, and they had drifted apart at the
  arithmetic (see Fixed). The sequence has tests of its own now, which it could
  not have had while it lived inside a poll loop.

- Two guards hold the workspace to its shared vocabulary, which
  `CONTRIBUTING.md` now lists as a table rather than as prose. `clippy.toml`
  refuses a direct call to a primitive that has one answer, naming the answer in
  the diagnostic; `tools/idioms.toml` records where the shapes clippy cannot see
  occur, and `tools/check-idioms.py` fails CI on any difference, so a second
  answer arrives as a decision in the diff. Writing the census found the
  `HttpFetch` timeout overflow above.

- `is_sha256_hex` is `provision::digest`'s, beside the functions that produce
  the digests it describes. It lived in the Debian index reader, which is not
  where "is this a digest, and could it be a path segment" is asked from; the
  Alpine layer now asks it too, of a `.PKGINFO`'s `datahash`.

- Both plan formats are pinned by a golden document as well as by a round trip.
  A round trip proves the reader and the writer agree with each other and cannot
  notice the two of them moving together, which is exactly what a format version
  exists to catch.

- `deb-layer-pipeline` names each component's output directory and layer upper
  by its position as well as its last path segment. Two `--component` paths
  ending in the same segment — `a/src` and `b/src` — shared both.

- The `features` job documents the whole feature powerset, so a doc link that
  resolves only under `--all-features` fails there rather than in a consumer's
  build. `cargo doc --all-features` cannot catch one: the link resolves under
  that selection and under nothing else. Where a sentence genuinely names items
  from two features it is written once per combination with
  `cfg_attr(..., doc = "...")`, which `CONTRIBUTING.md` records with
  `provision::BuildLayer` as the worked example.

- `tools/check-idioms.py` scans the crates' examples as well as their `src`
  trees. An example is documentation a reader copies from, so a second answer
  there transfers into a consumer's code exactly as one in `src` would — and the
  census could not see it. Widening it found `deb-multirepo` formatting a
  `file://` URL by hand, which is now `provision::file_url`. Integration tests
  stay outside the census: a test's numbers and paths are its own literals rather
  than a caller's, so the shapes these idioms name are usually not the hazard
  they name.

- `provision::containment` owns the create-over-what-is-already-there answer,
  which the extractor and the host-side `Rooted` each spelled: the same
  unlink-and-retry, the same attempt bound, the same rationale in both comments,
  differing only in what a failure was called. Each now names its own failures
  over one errno-level core.

- `provision::alpine::version::name_of` is where a dependency entry's name ends.
  The bootstrap's install order re-spelled the operator grammar twice rather than
  reach for `version::split`, which it could not: it returns a `Result`, and this
  path reads `.PKGINFO` strings it must write into the installed database
  verbatim.

## [0.2.0] - 2026-08-06

### Security

- A read-only bind is a boundary. The command enters a nested user namespace
  before it hardens, and the kernel locks a mount's flags exactly when it copies
  a mount tree into a new user namespace — so past that point no restriction on
  a mount the sandbox established can be lifted. Previously the sandbox created
  its user namespace and then built the mounts inside it, which locks nothing:
  the command ran as root of that same namespace holding `CAP_SYS_ADMIN`, and
  could clear `MS_RDONLY` on its own read-only bind and write through to the
  host as the calling user. It holds in every build and needs nothing else
  configured — no capability drop, no seccomp filter, no non-root `run_as` — and
  it covers unmounting and atime behaviour as well as the flags. The command
  remains free to mount whatever it likes in its own namespace; those mounts are
  its own, unlocked, and private to it.

- The sandbox's root mount carries `nosuid`, so a set-user-ID or set-group-ID
  binary in the rootfs confers nothing on the command that executes it, and a
  file capability recorded on one is ignored. A provisioned rootfs applies the
  tree's permission bits verbatim, so a Debian or Alpine root ships set-user-ID
  binaries owned by in-namespace uid 0; a non-root `run_as` identity could
  otherwise execute its way back through one. The flag is locked by the nested
  entry like every other. The scope is the root and whatever its bind carried
  along: a caller's own `bind` and `bind_ro` mounts keep inheriting their
  source's flags, since a caller who binds a host tree in order to run what is
  in it is entitled to a different answer.

- The Debian bootstrap's host-side steps are contained to the tree they write
  into. They interleave with the dpkg waves — a statoverride seed, the ownership
  stubs, the finished rootfs's apt sources — so most of them run after arbitrary
  maintainer scripts have executed inside a cage rooted at that tree, as root of
  its namespace. Each composed a host path and handed it to `std::fs`, which
  resolves every component against the *host's* root: a script that left an
  absolute symbolic link at one of those paths redirected the write, the read,
  or the removal that followed out of the tree entirely, performed as the
  calling user. The primitives were overwriting a caller's file with the sources
  line or the keyring bytes, creating host directories, deleting a caller's
  file, and — through a layered build's base tree — reading one into the tree
  the caller then exports.

  Every one of them now goes through a descriptor for the tree, with `openat2`
  and `RESOLVE_IN_ROOT`: an absolute link inside the tree resolves within the
  tree, which is what the same link means to dpkg reading it from inside the
  cage, and nothing resolves outside it. Leaves are opened `O_NOFOLLOW`, so a
  link occupying a name is replaced rather than written through. It is the
  discipline the launch side already applied to the placeholders it removes and
  the extractor to every entry it writes. A layered build's base tree is read
  the same way, so a link there cannot make the base's dpkg status database or
  statoverride an arbitrary host-file read.

  Reaching this through `Debian::ensure` against the archive meant the
  signature had already been defeated, but three shapes did not: the layered
  build the `deb-layer-pipeline` example ships, where a hostile *source*
  package's `postinst` crosses no signature at all; `trust_unsigned` over a
  local pool, which is that shape stated directly; and a caller-supplied base
  layer.

- **Breaking.** `trust_unsigned` requires a transport that authenticates what it
  serves: every mirror of an unsigned repository must be `file://` or
  `https://`, compared case-insensitively, and any other scheme is refused at
  `build`. The guard previously refused the literal prefix `http://`. URI
  schemes are case-insensitive (RFC 3986 §3.1), so `HTTP://` named the same
  plaintext transport and passed — and a caller-supplied `Fetch`, which is the
  configuration this guard exists for and the one the docs recommend for HTTPS,
  will typically normalize the scheme and speak plain HTTP. It was also a
  deny-list of one scheme: any other
  unauthenticated transport a caller's fetcher spoke passed unremarked. An
  unsigned repository over a scheme neither this crate nor the caller can vouch
  for now fails at `build` rather than installing unverified packages over an
  unauthenticated wire.

- No caller descriptor survives the command's `execve`. A `Stdio::Fd`
  disposition's descriptor is deliberately kept through the launch's sweep so
  the command stage can copy it onto a standard stream, and it was then left as
  it was — surviving the exec at whatever number the caller held it at, which
  contradicts both the crate's "a descriptor table holding only its standard
  streams" and the sweep's own contract. It gains the command no access it did
  not already have through 0, 1 and 2, but a command that closes and reopens its
  standard output still held a second handle to the caller's file. Each such
  descriptor is now marked close-on-exec after the copy; the caller's own copy
  is untouched, descriptor flags being per-descriptor and the child's own since
  the fork.

- A fetch is bounded by the size its verified source declares. The signed
  release records the length of every index and the index the length of every
  package, and both were discarded: an index fetch was bounded only by the
  built-in fetcher's two-gigabyte ceiling, or by nothing at all for a
  caller-supplied transport, while the release that named it said it was a few
  megabytes. A mirror could drive that much allocation per index request, and
  the digest check that catches the substitution runs only after the bytes are
  spent. The declared size now travels with the request, through the new
  `FetchRequest::sized` and `FetchRequest::size`, and bounds the provisioner's
  own sink as well — a
  transport is free to ignore the request, and the sink is the one place the
  bound cannot be ignored. A release file carries no size, being the trust root,
  and keeps the fetcher's own ceiling.

- An index-supplied pool path may not percent-encode a traversal.
  `pool/%2e%2e/%2e%2e/etc/passwd` is non-empty, relative, all-graphic and
  carries no `..` component as written, so it passed a check whose documented
  claim is that a `Filename:` cannot escape a mirror root — and a server that
  decodes before resolving may serve something above that root. The same rules
  now run over the decoded form, so a real pool path is unaffected while an
  encoded traversal, an encoded separator, a malformed escape, and an encoded
  `%` are all refused. Nothing unverified could enter the tree either way, since
  whatever comes back is checked against the signed index's digest; the check
  now means what it says.

### Added

- `FetchRequest::sized` states the size a resource is expected to be, and
  `FetchRequest::size` reports it. The provisioner sets it wherever a verified
  source declares one — the signed release for an index, the index for a
  package — so a transport can refuse an oversized framing before reading a
  byte. It is a ceiling rather than a promise: an implementation is free to
  ignore it, and the provisioner bounds its own sink regardless. The built-in
  `HttpFetch` honours it on both the `http://` and `file://` paths.

- `DebianBuilder::pin` holds a resolution to the versions a previously resolved
  `Plan` recorded, where `plan` replaces the resolution outright. The bootstrap
  fetches and verifies every release and index as it always does and computes
  the closure over what the archives offer now; a package the pin names is
  selected at the pinned version rather than at the highest offered, and its
  recorded digest must be the one the archive records for that version.
  Everything else resolves normally.

  This is the shape a build needs when its inputs are not all archives. Where
  some packages are compiled by the build itself and published to a local
  `Pool`, `plan` requires those compiles to be byte-reproducible, since it
  installs every package by a recorded digest; pinning only the archive-sourced
  packages fixes the half a mirror controls and leaves the locally built half
  to resolve at whatever the pool now holds.

  Unlike `plan`, the trust model is unchanged: every digest installed is still
  read from an index whose own digest a verified release records, so the pin
  narrows which version is selected without becoming the authority for what the
  bytes are. `include`, `exclude`, and `base_priority` compose with a pin where
  they contradict a plan, since a pin constrains the versions a selection
  resolves to rather than naming the selection. A pin the archives cannot supply
  fails with the new `DebianError::Pin` before anything is downloaded, naming
  every package that could not be held at once and, through the new `UnheldPin`
  and `UnheldReason`, which of the three happened: another version offered, no
  version offered, or the pinned version recorded over different bytes.

- A plan reports what the archive says each package weighs and which source
  package it was built from. `PlannedPackage::installed_size` carries the
  archive's `Installed-Size` in the kibibytes Debian Policy defines it in,
  rather than normalized to bytes, so it can be compared against a mirror's
  value directly; it is the archive's build-time estimate of a staged tree, not
  a measurement of an installed filesystem, and a sum over a plan should be
  presented as one. `PlannedPackage::source` carries the `Source` field's
  package name with any parenthesized source version dropped, and is `None` for
  the common case of a binary package whose source shares its name, so the
  several binary packages of one source can be attributed to the thing that was
  built. Both are optional, and both are written to a plan document and read
  back. They are written after every field the format's first readers knew,
  which is where those readers put an unknown field back, so between two
  readers of one `Format` version they cost nothing in either direction: a
  document written without them reads with every field intact, and a document
  written with them reads through the older reader and re-writes byte-identical.

- A tree written under the single-identity map is removed through that map when
  the plain removal is refused. `provision::remove` escalated a range map only,
  so a single-mapped tree holding a directory whose own mode denies the write
  the deletion needs — a read-only directory an archive carried in — reported
  that no delegate could establish the map, which is neither the reason nor
  something the caller can act on. The removal child now writes the
  single-identity map itself, as the export and copy-in children already did,
  and deletes the tree with the capabilities root of that namespace holds.

- A pseudoterminal of the sandbox's own. `Cage::spawn_terminal` starts the
  command on one and returns the caller's end beside the running handle;
  `Cage::spawn_pending_terminal` does the same at the userspace-network seam,
  handing the primary over before the command is released, and
  `Restriction::spawn_terminal` gives the fallback the same interactive story. A
  `Terminal` states the window size — 80x24 by default, a stated constant rather
  than anything read from the host — and a `Pty` is the primary, with `Read` and
  `Write` on both `Pty` and `&Pty`, `resize`, and `size`, so an `Arc<Pty>` serves
  a reader thread and a `SIGWINCH` handler at once.

  The replica is wired onto file descriptors 0, 1 and 2 and the launch owns its
  session, so the pseudoterminal is the sandbox's controlling terminal: `isatty`
  is deterministically true, a full-screen program behaves, `/dev/tty` resolves
  to the sandbox's own terminal, and a shell inside the sandbox runs jobs of its
  own — against a terminal the caller does not share. It is the only posture
  under which an interactive sandbox both works completely and reaches nothing
  of the caller's terminal.

  The pseudoterminal is allocated on the host before the fork rather than in the
  sandbox's own `devpts` instance. What that gives up is path resolution:
  `ttyname` fails inside the sandbox, so `tty(1)`, `who`, and `GPG_TTY` do not
  work. Everything that operates on the descriptor does.

  A terminal is a launch mode rather than builder state, so it is not a profile
  key and `resolved_inputs()` does not report one: the record reports the plan,
  and a launch-time attachment supersedes it at the call site that made it.
  Hangup on the primary is reported as end-of-file rather than the `EIO` Linux
  returns, so a drain terminates the way it would from a pipe.

- `Error::Terminal` and `Error::TerminalsExhausted`, the latter for a host that
  has run out — `/proc/sys/kernel/pty/max` states the ceiling — and
  `SetupStep::SetControllingTerminal`.

- `fcage`: `--terminal`, which allocates a pseudoterminal for the sandbox,
  copies this terminal's current size into it, and relays the two. Interactive
  programs work — a shell, an editor, a pager, debconf — and the sandbox reaches
  nothing of the terminal `fcage` was started from: a typed `^C` is a byte the
  relay forwards, which the *sandbox's* line discipline turns into the sandbox's
  own `SIGINT`. It composes with `--restrict` and with `--netstack`, which takes
  the pending path and hands the terminal over before the command runs;
  `--terminal` with `--stdin null` is refused at parse time, naming both flags.
  From a script, where `fcage`'s own input is not a terminal, it degrades to a
  plain byte relay around a sandbox that still has a real terminal of its own,
  at 80x24.

  The relay reads its signals as poll data from a descriptor rather than in
  signal context, forwards `SIGINT`, `SIGTERM`, `SIGHUP`, and `SIGQUIT` to the
  sandbox, follows `SIGWINCH` with a resize, and restores this terminal on every
  exit it can observe: a guard, a panic hook that restores before the backtrace
  prints, and the stop path, which restores before `SIGTSTP` and re-enters raw
  mode on `SIGCONT`.

- `CageBuilder::stdout` and `CageBuilder::stderr`, with `get_stdout` and
  `get_stderr` beside them, and the same pair on `RestrictionBuilder`. They take
  the same `Stdio` the standard-input setter does, so an output stream is
  discarded with `Stdio::Null` or sent to a caller's descriptor with
  `Stdio::from_fd`. A profile carries them as the `stdout` and `stderr` keys,
  which accept the same two names `stdin` does.

- `ConfigError::StreamAttachmentConflict`, for a launch that attaches a conduit
  of its own to a stream the sandbox directs elsewhere. `Stdio::Inherit` states
  no destination, so a capturing launch composes with it and this never arises
  against the default; `Stdio::Null` and `Stdio::from_fd` state one, and a
  capturing launch of such a sandbox is refused rather than silently overriding
  it. Reported by the launch, so the same sandbox still launches through an
  entry point that attaches nothing.

- `ResolvedInputs::streams`, reporting where each of the three standard streams
  is wired, as the new `ResolvedStreams` and `ResolvedStdio` types. What a build
  produces depends on it: `isatty` on the standard streams steers debconf's
  frontend choice, a compiler's color diagnostics, and every progress display. A
  descriptor is reported by kind alone, since it names a live resource of the
  caller's rather than anything a record could carry forward.

- `ConfigError::OverlayDirUnowned`, for an overlay layer directory already
  occupied by something other than a directory the calling user owns, and
  `ConfigError::OverlayUpperIsRoot`, for an upper at the filesystem root — which
  has no parent for the work directory beside it, and would put the sandbox's
  writes over the whole host root. The latter replaces
  `ConfigError::OverlayPathInvalid` for that case, whose message describes the
  `,`/`:` refusal it is actually for.

- `RangeMapBlocker::SubordinateAllocationUnknown`, for a host where the
  subordinate allocation could not be determined at all — `getsubids` failing,
  or `nsswitch.conf` sourcing subordinate ids from a module beyond `files` with
  `getsubids` not installed. That was previously reported as
  `NoSubordinateAllocation`, whose remedy is wrong twice over on such a host:
  the user may well have an allocation, and adding `/etc/subuid` entries does
  not help, because the files are not the authority there.

- `SetupStep::NewSession`, naming the launch's session change in a setup error.

- `ProvisionError::EntryRefused`, for an entry that cannot be handled for a
  reason that is not a containment failure: a malformed archive (a path
  component that is not a directory, a symbolic link with no target), a source
  tree past a limit the copy protocol carries, or a source id the destination's
  identity map has no place for. `ProvisionError::EntryUnsafe` reads "the archive
  entry reaches outside the extraction root", which none of those did — the worst
  of them told a caller whose tree carried an unmapped id that the tree had tried
  to escape. `EntryUnsafe` now means an escape and nothing else.

- A repository's suite and components, and a bootstrap's architecture, are
  checked when the repository or the builder is built. Each becomes a path
  segment of every URL the archive is fetched through and a word of the `deb`
  line written into the finished rootfs, so a `..` segment would climb out of the
  mirror root — for a `file://` mirror, a local read — and a control character
  would split the request line the value is interpolated into, or add a source
  line the caller never wrote. It is the check `Pool` already made of the
  coordinates it publishes under, so the side that writes an archive and the side
  that reads one now agree on what an archive may be called.

- A signing subkey is admitted only when its binding carries the subkey's own
  back signature, as RFC 9580 requires. The binding alone is the primary's claim
  over the subkey; without the counter-signature a certificate could adopt a
  signing subkey it does not hold and present that key's signatures as its own.
  The back signature must carry a creation time and must not predate either key
  it speaks about, and one the subkey holder gave an expiration bounds the
  subkey's authority as the binding's own key expiration does: consent that
  cannot be placed in time is not consent, and consent that has lapsed leaves
  the binding unilateral again. The requirement is applied to whichever binding
  governs rather than used to choose one, so a defective newest binding refuses
  the subkey instead of handing authority back to a superseded binding.

- A release signature made with a public-key algorithm below the floor is
  refused: DSA outright, and RSA under 2048 bits. The rule covers the signing key
  and the primary key of the certificate vouching for it, and names the accepted
  algorithms rather than the refused ones, so key material the crate cannot
  assess is refused rather than admitted by default. It is the companion to the
  hash floor — a signature is worth no more than the weaker of the digest it
  covers and the key material that binds it — and is not applied where the hash
  floor is not, for the same reason.

- A signature carrying a critical subpacket that cannot be interpreted is
  refused, as RFC 9580 requires. Only the hashed area is read, so a relay
  appending one to an `InRelease` in transit cannot fail the fetch. rPGP applies
  the rule only to subpackets of an unknown type and only while signing, which
  leaves critical notations and the experimental range to this crate.

- A release signature dated before its signing key existed is refused, closing
  the key's validity window at the end the expiry check does not.

- Release signatures, subkey bindings and back signatures made with MD5, SHA-1
  or RIPEMD-160 are refused. The floor is not applied to revocations, nor to the
  self-signatures a key's expiry is read from, where discarding a signature
  would extend a key's life rather than curtail it.

- `ResolvedArchive` records the component key that made the release signature in
  a new `signing_key` field, written to a plan document as `Signing-Key`.

### Changed

- The Debian bootstrap's host-side steps state the modes they write rather than
  taking them from the process umask: `0755` for a directory it creates, `0644`
  for a file, and the mode already stated for a script or a shadow file. Two
  runs of one build under different umasks previously produced trees that
  differed in those bits.

- The guide gains [what the sandbox does not
  hide](https://gregordinary.github.io/ferroday-cage/how-the-sandbox-is-built.html#what-the-sandbox-does-not-hide).
  A sandboxed command reads its own `/proc/self/mountinfo`, whose mount-root
  field carries the host path of the rootfs and of every bind source — the
  calling user's name and the build's layout with it. That is what every
  bind-mount-based sandbox exposes, and no code changed, but it sits at odds
  with the determinism the rest of the crate keeps, so it is now stated rather
  than left to be discovered.

- **Breaking.** `ResolvedArchive::signed_by`, and a plan document's `Signed-By`,
  name the verifying certificate's primary key rather than the subkey that made
  the signature. It is the identity a keyring entry is named by and the one to
  pin a repository against, and unlike the signing key it survives an archive
  rotating its subkey. The subkey is still reported, as `signing_key`.

  A plan document's `Format` version moves to `ferroday-cage-plan 2` for it, and
  a version 1 document is refused rather than read. A field that keeps its name
  and changes its meaning is the one shape the format's carried-field rule
  cannot absorb: a reader accepting both versions would hand a fingerprint back
  without saying which of the two questions it answers, and a consumer comparing
  one against a recorded value would see a mismatch it could not tell apart from
  the archive having rotated its key — the event such a comparison exists to
  catch. A kept plan moves across by being resolved again against the same
  archive.

- **Breaking.** A container requires a procfs wherever its nested user
  namespace's identity map is established through one, by path, and a profile
  that mounts none is then refused at build time with the new
  `ConfigError::NestedUsernsNeedsProcfs`. The managed profile mounts one by
  default; this is reachable only from a profile that sets `managed_mounts(false)`
  or `mount_proc(false)` and declares no procfs of its own.

  The requirement follows the route the map takes. A self-written map — the
  single-identity tier — needs one, and a bind of the host's procfs serves,
  since a process reaches its own map files through `self`. A range identity map
  inside a PID namespace of the sandbox's own needs a *fresh* instance: its
  delegate names the command by an in-namespace pid a bound procfs does not
  index. A range identity map with `pid_namespace(false)` needs none, because
  its delegate is the launch stage, outside the sandbox, reading the host's own
  `/proc` — so a range map composes with `managed_mounts(false)`, the
  reproducibility opt-out, and with `mount_proc(false)`.

- **Breaking.** The command holds no capability over the namespaces the sandbox
  created, because it is now root of a *child* of the user namespace that owns
  them. In practice: it cannot bind a TCP port below 1024, cannot open a raw
  socket or send ICMP — `ping` no longer works inside a sandbox — and cannot
  change the hostname or reconfigure the network interfaces the setup brought
  up. Ordinary sockets are unaffected, and everything the userspace network
  stack carries behaves as before.

- **Breaking.** Every launch holds two user namespaces rather than one, and a
  namespace is charged against `user.max_user_namespaces` at every level up to
  the initial namespace. `host::userns_blocker` gains
  `UsernsBlocker::MaxUserNamespacesBelowNesting` for a ceiling of `1`, which
  admits the first namespace and refuses the second; a budget exhausted at
  launch — which no probe can foresee — surfaces as the new
  `Error::NestedUsernsBudgetExhausted`, naming the sysctl.

- `SetupStep` gains eight variants for the new steps: `NestedUnshare`,
  `NestedDenySetgroups`, `NestedWriteGidMap`, `NestedWriteUidMap`,
  `AwaitNestedIdentityMap`, `OpenSandboxProcfs`, `NestedMapGate`, and
  `NosuidRootfs`. They are named apart from the outer namespace's steps so a
  failure says which of the two the launch was establishing.

- **Breaking.** `Stdin` is renamed `Stdio`, and `CageBuilder::stdin`,
  `CageBuilder::get_stdin`, and `RestrictionBuilder::stdin` take and return it.
  One enum now serves all three standard streams, so the name no longer claims
  less than the type covers, and the session rule and the descriptor-sharing
  semantics have one home rather than two. The wire format is unchanged: the
  keys are `stdin`, `stdout`, and `stderr`, and the unit variants still
  serialize as `"inherit"` and `"null"`, so every existing profile loads
  unchanged.

- The curated seccomp policy denies `ioctl` for the `TIOCSTI` and `TIOCLINUX`
  requests, the two that write to a terminal's input queue, and allows it
  otherwise. Denied by request rather than by syscall, because `ioctl` is the
  ordinary way to ask anything of a device.

- An overlay work directory on a different filesystem from the upper is refused
  at build time, naming the work directory, rather than failing the mount with a
  bare `EXDEV` from a syscall the caller never issued. The overlay moves files
  between the two, so the kernel requires them on one filesystem.

- The subordinate-id helpers are resolved to an absolute path by the same lookup
  `host::range_map_blocker` uses to judge their privilege, and that path is what
  executes. `Command::new("newuidmap")` re-resolved the bare name on its own
  terms, so the probe's verdict could describe a different binary from the one
  that ran. The lookup also skips relative `PATH` entries, which name the
  process's working directory — not somewhere to resolve a privileged helper
  from — matching what `path_lookup` already does for the sandbox's own `PATH`.
  The two auxiliary tools the delegate consults, `id` for the caller's user name
  and `getsubids` for the allocation, go through the same lookup for the same
  reason.

- `Terminal::size` leaves a zero dimension at its default rather than passing it
  through. Zero is what a terminal reports when its size is *unknown* — a
  pseudoterminal nobody has sized — and the kernel accepts it silently, leaving
  the sandbox a terminal that answers "no size" to everything that asks: `stty
  size` refuses it and a full-screen program has nothing to draw into. `fcage`
  already guarded against exactly this before calling `size`; a library caller
  plumbing the same reading in now lands in the same place.

- **`fcage`.** The `--terminal` relay blocks `SIGTTOU`. A `tcsetattr` from a
  background process group raises it and its default action stops the process,
  so a backgrounded relay would stop inside the restoration and leave the
  caller's terminal in raw mode with nothing left to fix it. Blocked, the call
  succeeds and the restoration holds from the background as it does from the
  foreground. `SIGTTIN` is deliberately not blocked: a backgrounded relay
  stopping when it tries to read the terminal is the conventional behavior.

- The overlay documentation no longer steers callers at `/var/tmp`, which is
  mode `1777` everywhere. `Overlay::upper`, `Overlay::work`, `overlay`, and
  `overlay_rootfs` carry the parent-directory requirement `rootfs` already
  stated.

- A package is downloaded and installed without ever being held in memory. The
  bytes are written to a staging file as they arrive and digested on the way
  through, and the file is renamed into the cache only once the digest matches
  the one the archive recorded; installing reads it back the same way, streaming
  the `data.tar` through the decompressor into the extractor. Downloading and
  unpacking a 90 MB kernel package now costs what a shell script costs, the
  property `Pool::publish` and the cache's own validation already kept. Nothing
  unverified is ever visible at a cache path either, since the rename is what
  puts it there.

- A self-signature dated in the future no longer governs a key's expiry. Recency
  decides which self-signature is authoritative, so one dated ahead of the clock
  would win outright, and because an absent key-expiration subpacket means "does
  not expire" it would lift a live expiry rather than postpone it.

- A signature refused by a validity gate — a hash or public-key algorithm below
  the floor, a missing creation time, a retired signing key, a signature that has
  itself expired — is now a `DebianError::Signature` rather than a
  `DebianError::Release`. `Release` describes what is wrong with the release
  body; these are statements that the signature over it was not acceptable.

- A subkey that could not verify a release now says why. A subkey carrying no
  valid binding, no counter-signature, no signing capability, or a refused
  algorithm used to surface as the generic "no signature verified against the
  archive keyring", because it never became a candidate and so never recorded a
  reason.

- The zstd decoder bounds each frame's window through `ruzstd` rather than
  reading the window out of the frame header itself. `ruzstd` now refuses a
  declared window over a configurable limit before it allocates, so the
  provisioner sets its 128 MiB bound on every frame's decoder and drops its own
  copy of the frame-header arithmetic. The bound is unchanged and the same
  archives are admitted, including those compressed with a window log of 27.

- `flate2`'s backend is named in the manifest rather than left to the crate's
  default, so a build without the `debian` feature reaches gzip through
  `miniz_oxide`, which forbids unsafe code outright. The resolved backend is
  unchanged; naming it keeps a future change to flate2's default from moving it.

- `lzma-rust2` moves to 0.18, `ruzstd` to 0.9, and `sha2` to 0.11. `fcage` reads
  profiles through `toml` 1.1. No public API changes.

### Fixed

- The built-in fetcher reads a response's status line only from a line that
  begins `HTTP/`. It previously took the second word of any first line that
  parsed as a number, so a mail or SSH server's greeting read as a response.
  The digest chain made that harmless, but a mirror URL pointed at the wrong
  port failed somewhere further along instead of saying what it found.

- A run-as identity sets no-new-privileges, in every build of the library and
  whatever else the sandbox requests. The flag was set only by the hardening
  layer, and only when that layer had something else to do, so a sandbox
  configured with a non-root identity and nothing else ran without it — and a
  build without the `hardening` feature never set it at all, while `run_as`
  worked there. The cleared capability set is only half of the boundary a
  non-root identity draws: the rootfs bind inherits the host mount's flags
  rather than adding `nosuid`, and the provisioners apply a tree's permission
  bits verbatim, so a Debian or Alpine rootfs inside the sandbox ships
  set-user-ID binaries and file capabilities owned by in-namespace uid 0, and
  the non-root command could execute them and be root inside again.

- **`fcage`.** `--terminal` no longer spins at 100% CPU when `fcage`'s own
  standard input is a pipe whose writer has closed, or names no open file at
  all. The relay retired that channel by giving its poll slot an empty events
  mask, and `poll` reports `POLLHUP`, `POLLERR`, and `POLLNVAL` whatever the
  requested events are, so the slot was ready on every pass and the loop stopped
  blocking — for the rest of the session. A retired channel now leaves the
  polled set instead. `producer | fcage --terminal ...` is the shape that
  reached it; `< /dev/null` and a regular-file redirect never did, because
  neither reports a hangup. An invalid standard input (`0<&-`) was additionally
  never diagnosed; it now retires the channel exactly as end of input does,
  which is the same thing it says.

- The network stack's tap helper closes its inherited descriptor table before
  joining the sandbox's namespaces. It was the one process the library forks
  that swept nothing, so for its lifetime it held open every descriptor the
  caller had — among them a concurrently live sandbox's control socket, whose
  last copy closing is what `stop_with_caller` waits on, and a concurrently
  allocated pseudoterminal replica, whose last copy closing is what ends the
  primary's reads.

- **`fcage`.** The `--terminal` relay's signal descriptor decodes the signal
  number in the host's byte order rather than little-endian, and a record naming
  a number the build has no name for is skipped rather than ending the drain for
  that wake. Neither was reachable on any target the crate builds for; both were
  claims about the kernel's format that happened to hold.

- The command's standard output and standard error can be directed somewhere,
  which closes the rest of the caller's terminal. A sandbox in a session of its
  own reached nothing of that terminal *through the session* — `/dev/tty` and
  `TIOCSTI` were already closed — but a launch that captures nothing hands the
  command file descriptors 1 and 2 verbatim, and at a shell prompt those are
  dups of one read-write open of the caller's terminal. A command holding them
  could read what was typed at it, leave the terminal without echo with
  `tcsetattr`, and resize it with `TIOCSWINSZ`. The two streams now carry a
  disposition of their own, and closing the caller's terminal to a sandbox takes
  all three. The documentation said otherwise, in the `Stdin` enum, the
  restriction chapter, and the streaming guide; each is corrected.

- A sandboxed command that does not inherit the caller's standard input no
  longer reaches the caller's terminal. A controlling terminal is reached
  through the session rather than through the filesystem, so no namespace and no
  swapped root affects it: a command with `Stdio::Null` or `Stdio::Fd` — one
  whose caller has said it reads nothing from them — could still open the
  caller's terminal through `/dev/tty`, read what was typed at it, and push
  characters into its input queue with `TIOCSTI` for the caller's shell to run
  afterwards. Such a command now runs in a session of its own, where `/dev/tty`
  fails with `ENXIO` and `TIOCSTI` is refused on every terminal descriptor. A
  command that inherits standard input was handed the caller's terminal along
  with it and is unchanged, so an interactive command keeps its terminal and its
  job control. The rule is the same for a cage and for a restriction.

  The documentation said the opposite: the restriction chapter listed terminal
  injection among four residual host surfaces and then stated that a cage closes
  all four. A cage closes the other three.

- The supervisor waits for any child rather than for any child of its own
  process group. `waitpid` with no pid names process group 0 — the supervisor's
  own — so a supervised command that had left that group answered `ECHILD` while
  sitting there exited, and the supervisor exited without a status record, which
  the caller read as a lost supervisor instead of the exit code the command
  produced. A sandboxed command is free to call `setsid` itself, and with the
  session rule above the launch does too.

- A launch that fails after its mount targets are created no longer leaves them
  behind. The guard that removes them was built only on the success path, so a
  launch that created `/etc/resolv.conf` and then failed at the pivot, the
  working-directory change, or the exec left the empty file in the caller's root
  — the residue the mechanism exists to prevent, in the case a caller getting a
  configuration right hits repeatedly.

- The mount targets a launch creates are judged, and removed, inside the root
  rather than against the host's. Both operations joined the rootfs-relative
  target onto a host directory and walked the result path-wise, so a rootfs
  holding an absolute symbolic link — `./etc -> /etc` in an unpacked tarball, or
  the `/etc/resolv.conf` any image taken from a systemd-resolved host ships —
  had that link resolved against the *host's* root: the presence check answered
  a question about the host's filesystem, and the removal could unlink outside
  the rootfs entirely. Both now resolve against a descriptor for the root with
  `RESOLVE_IN_ROOT`, the containment the sandbox stage already gives every mount
  target.

- An overlay's upper and work directories are no longer adopted from an entry
  the calling user does not own. They were created with `create_dir_all`, which
  succeeds against anything already at the path that resolves to a directory — a
  symbolic link included — and the resolved destination went verbatim into
  `upperdir=`. In a directory shared with other local users, that sent every
  write the sandbox made wherever the link pointed, and handed the caller that
  destination back as the layer its run produced. Each is now created with
  `mkdirat` against a descriptor for its parent, and an existing entry is adopted
  only when `fstatat` reports a directory belonging to the calling user.

- `unique_hex` keeps its uniqueness claim when `getrandom` fails or returns
  short. Its result was whatever `getrandom` wrote over a pid seed, so on a host
  without it every call within one process returned the same string. The
  kernel's randomness is now combined with a seed that is already unique per
  call — the pid, and a process-wide counter — rather than substituted for it.

- A subordinate map no longer emits more extents than a map file can carry. An
  administrator may grant more than 340 separate subordinate ranges, which is
  unusual but legal; the composition is capped at the kernel's ceiling, where it
  previously produced a map that failed validation with a message blaming the
  bundled delegate for the host's allocation.

- One unparsable line in `/proc/self/uid_map` no longer disables
  `DirectMapper`'s coverage check for both id spaces. An outside id the caller's
  namespace does not hold is again named at build time rather than arriving as a
  bare `EPERM` at apply time. A file that cannot be read still leaves the kernel
  as the arbiter, which is what that fallback was for.

- `Running::wait` returns an error rather than panicking if the pump ever
  reports no outcome for an unbounded wait, and the pump checks for its observer
  before reading a captured stream rather than after — where a zero-length
  buffer would have taken the read for end-of-file and discarded the output,
  masking the mismatch the check exists to catch. Both are unreachable today;
  both were guarding an invariant that lives in another function.

- A `.deb` handed to `Pool::publish` no longer chooses where in the pool it is
  written. The pool-relative path, and the `Filename` the index records, are
  derived from the package's own `Package` and `Version`, and `Path::join` does
  not normalize — so a `..` in either survived into the syscall and the kernel
  resolved it, creating directories and writing a file outside the pool root as
  the publishing user. Both fields are now held to the alphabet Debian policy
  gives them, which contains no separator, before any path is built from them.
  The consume side already validated an archive-supplied pool path for exactly
  this reason; this is the produce side of it.

- A `.deb`'s control file can no longer dictate its own `Packages` entry. The
  entry is the control file verbatim with `Filename`, `Size`, and `SHA256`
  appended, and a deb822 reader resolves a field by its first occurrence, so a
  control file carrying one of the three shadowed the archive's value: a digest
  the package chose rather than one taken from the bytes on disk, or a path
  naming another package's file. A control file of several paragraphs did the
  same by another route — the appended fields landed on the last, which was then
  the paragraph that read back as the entry, under whatever name and version it
  declared, while the dedupe that placed it keyed on the first. Because a pool is
  consumed as `[trusted=yes]` and resolution is highest-version-wins across
  repositories, such an entry superseded the primary archive's. Both shapes are
  now refused; no conforming `.deb` carries either.

- The derived dpkg statoverride records each path once. dpkg treats two records
  for one path as an unrecoverable fatal error — `dpkg-statoverride --list`
  aborts, and with it every dpkg wave after the file is written — and an install
  set reaches that honestly: two selected packages can ship one path, since the
  resolver reads `Depends` and `Provides` and never `Conflicts` or `Replaces`;
  one `data.tar` may list a path twice; and a layered build's increment may
  re-ship a path its base already overrode. The last record for a path now wins,
  which is the extraction's own rule, so the record describes the file that
  survived. Records are written in path order, so the file is a function of what
  was extracted rather than of the order it was extracted in.

- A bootstrap that fails partway no longer leaves its downloaded packages beside
  the rootfs it did not publish. Without a `cache_dir` the packages go to a
  sibling of the staging tree, which nothing else clears: the publication's own
  cleanup removes the staging tree, and `provision::remove` removes the
  destination and its lock. The cache is now scoped to the run and disposed of
  on the failure paths as on the success path.

- A `stage_layer` that fails disposes of the overlay upper it created, and of
  the package cache beside it. The upper is created before the increment is
  resolved, and a failure hands the caller no `BuildLayer` to drop, so a
  partly-installed increment — potentially a full package set — was orphaned.

- A pinned `Plan` whose package names an archive index past the plan's own
  archive list is refused when the provisioner is built, rather than panicking
  partway through a download. Reading a plan from a document already refuses
  one, but `Plan` is public and `Clone`, so a caller can take one from
  `resolve()` and edit it.

- A `file://` URL naming a host other than this one is refused. The authority
  between `file://` and the path was stripped only when it was literally
  `localhost`, and unanchored at that, so `file://otherhost/srv/pool` was read as
  the relative path `otherhost/srv/pool` and `file://localhostile/x` as `ile/x` —
  a different file, on this machine, reported as though the URL had been
  honoured. Both spellings of this machine, empty and `localhost`, still read the
  path they name.

- A `SHA256` line of a `Release` whose digest is not 64 lowercase hex characters
  is dropped rather than carried. Where the release declares `Acquire-By-Hash`
  the digest becomes a path segment of the URL its index is fetched from, so one
  carrying `..` could climb out of the mirror root; for a repository trusted
  unsigned nothing has vouched for the text at all. It is the same shape rule a
  package's digest already passes.

- A tar header's mode is refused rather than wrapped when the GNU base-256 form
  carries a negative value, as the uid and gid beside it already were. Wrapped,
  `-1` became `0o7777`: every permission bit plus setuid, setgid, and sticky,
  from a header no archive can have meant. No capability is lost, since an
  archive that means those bits spells them in octal.

- `CopyIn` computes a mapped id in the width its own containment test uses. An
  identity-map extent whose `inside + count` passes `u32::MAX` overflowed — a
  panic in a debug build, a wrapped id in a release one. The id is now computed
  in `u64` and refused where it does not fit back.

- A bootstrapped rootfs's own root directory is mode `0755`, the mode
  `base-files` gives `/`, rather than the mode of whichever package was extracted
  last. Every `.deb` ships a `./` entry describing the root it is unpacked into,
  and one shipping `0700` would have produced a rootfs the caller has to chmod
  before anything could traverse it.

- A file bind whose target the rootfs ships as a symbolic link no longer creates
  a file at the link's destination. The launch resolves mount targets inside the
  root, which scopes a symbolic link's resolution but does not suppress it, so a
  target created through one landed at a path the caller side does not record —
  and therefore never removed, leaving the rootfs holding content it never
  shipped for every later launch and every export to carry. The target is now
  created only where the root has nothing at all, and a root that ships a link
  resolving to nothing has no target to bind onto, which is reported as a failed
  mount naming that bind.

- A file bind's created target carries mode `0644` exactly, rather than that mode
  narrowed by the launching process's umask. A mount point directory already
  compensated for the umask, for the same reason: the mode is part of what a
  launch contributes, and a caller at `umask 077` should not get a different
  tree from one at `umask 022`.

- A copy the in-map child refuses reports the step the child failed at, not the
  broken pipe the walk saw afterwards. The child stops at the entry it could not
  create; the parent, still streaming, learns of it only as a frame write that
  cannot be delivered. Which of the two the caller was told used to depend on the
  size of the tree — one that fitted the pipe's buffer let the walk run to the
  end and the child's record be read, anything larger reported the broken pipe —
  so the diagnostic was lost on exactly the trees where it is worth most.

- A copy-in frame naming an entry with a NUL inside it is refused rather than
  read as the prefix before it. No filesystem holds such a name, so the frame is
  one the walk does not understand; creating the prefix put an entry in the
  destination that the source does not have and reported the tree copied.

- A symbolic link copied into a rootfs carries the modification time its frame
  names, its own rather than its target's. It was decoded and dropped, so every
  copied link was stamped at the moment of the copy.

- The overlay support probe closes the descriptors it inherited before it runs,
  as the export, copy-in, and removal children each do. An inherited copy of a
  live sandbox's control socket holds that socket open, deferring the hangup that
  `stop_with_caller` waits on for as long as the holder runs.

- The export, copy-in, and removal children ignore `SIGPIPE` rather than being
  terminated by it. Each scrubs its inherited signal state first, which restores
  the default disposition — termination — so a child whose parent stopped reading
  was killed before its own error path could observe the failed write, report it,
  and exit on its own terms.

- An archive certificate whose primary key has expired no longer verifies a
  release through one of its signing subkeys. A subkey's authority is delegated
  from its primary, so it lapses when the primary's does; the expiry now applied
  to a subkey-made signature is whichever of the two comes first. Previously a
  subkey whose own binding set a later expiry, or none, outlived the certificate
  that bound it — while the same key signing directly was correctly refused.

- A release signature that carries no creation time is refused. Every validity
  check is relative to that time and the signer chooses it, so reading its
  absence as permission let a signature made with retired key material bypass
  the expired-key check entirely.

- Every signature a keyring key made over a release is judged, not only the
  first that verifies against it. A key that re-signs a release can leave the
  superseded signature in the document alongside the new one, and rPGP returns
  whichever comes first; judging only that one refused the whole release
  whenever the weaker of the two came first, even though an acceptable signature
  from the same key was present.

- A signature expiration of zero seconds no longer expires a signature at the
  instant it was made. Zero and an absent subpacket are the two wire forms of
  "does not expire", as they already were for a key expiration.

## [0.1.4] - 2026-08-03

### Fixed

- An archive whose signing key had its expiration removed by a later
  self-signature verifies again. A key created with a finite lifetime and later
  re-dated to never expire carries two self-signatures, the newer one simply
  omitting the key-expiration subpacket — which is how an expiry is removed. The
  expiry was read from the newest self-signature that *set* one, so the
  superseded lifetime governed forever and every release signed after it was
  refused with "the release signature was made after its signing key expired".
  Extending a key rather than rotating it is the ordinary practice, so the
  archives this made unusable were not unusual ones.

  The expiry is now whatever the governing self-signature says, present or
  absent, and a signature governs the object it was made over: the key itself,
  for a direct-key signature, or one user id, for a certification. Recency is
  compared within an object, so a user id added later does not lift an expiry
  set on another, and where objects disagree the earliest expiry governs. A
  deliberate shortening still takes effect, being the newest signature over its
  object. Self-signatures must now verify cryptographically as issued by the
  primary before they are read, absence of a subpacket carrying as much meaning
  as its presence.

- `provision::CopyIn`'s type documentation described the identity translation
  backwards, saying a source tree's ids are interpreted as in-rootfs ids. They
  are read the other way, through the map, exactly as an export reads them; the
  copy has always behaved that way and the rest of the documentation described
  it correctly. Read the wrong way round, the paragraph implied a caller-owned
  staged tree lands owned by the calling user inside the rootfs rather than as
  root, which is the difference between a working `/etc` and a broken one.

- `fcage`: a profile setting `resolv-conf` or `managed-mounts` now governs the
  `resolv.conf` composed for `--netstack`, as the matching flag always has. The
  composition consulted the command line alone, so a profile opting out of the
  bind was ignored under `--netstack` and `--resolv-conf` could not override a
  profile that had — the one direction the flag exists to cover.

- The native network stack no longer holds a flow slot for the ten seconds a
  finished TCP exchange spends in `TIME_WAIT`. Where the host closes first —
  `Connection: close` HTTP and most short request/response protocols — the stack
  sends the first FIN, so the guest's answer left the flow lingering with its
  slot and its two 64 KiB buffers still held. A guest connecting faster than
  about thirteen times a second filled the 128-flow table with exchanges that
  were already over, and every further connection was refused with a reset and
  no diagnostic. A flow closed on both sides is now finished with at once, which
  also stops a fresh connection reusing the endpoint pair from landing on the
  spent one and waiting out a retransmission timeout.

- The native network stack no longer acts on IPv4 fragments. Reassembly is not
  compiled in, so its interface discards every fragment before one reaches a
  socket — but the classifier that runs ahead of the interface read a first
  fragment's TCP header as a connection attempt and started a real outbound host
  connect for it, holding a flow slot until the establish deadline, and read a
  later fragment's payload bytes as a transport header. Fragments now classify
  as traffic the classifier has nothing to say about, which is what the
  interface then does with them. The forwarding policy was never affected: a
  destination address is read from the IP header and was checked throughout.

- A UDP reply is no longer lost when the guest's receive ring is momentarily
  full. The relay took the datagram off the host socket before asking whether it
  could be handed on, so a refused hand-off discarded the reply already in hand
  while leaving the ones behind it queued. It now asks first, and a reply it
  cannot place stays on the host socket for the next pass, after the interface
  has drained the ring.

- The native network stack documented every refused TCP destination as answered
  with a reset. That holds for the destinations the guest routes through the
  gateway, but not for the guest's own subnet: those addresses are on-link, so
  the guest resolves a hardware address before it sends a segment, and the stack
  answers ARP and neighbor discovery only for the gateway. Such a connection
  fails when the guest's own address resolution gives up, a few seconds later,
  and the module documentation, the policy function, and the guide now say so.

### Changed

- The mirror setters document that the built-in fetcher speaks `http://` and
  `file://` only, so an `https://` mirror needs a transport supplied through
  `DebianBuilder::fetcher`. The fetcher's own refusal names that remedy too,
  rather than reporting an unsupported scheme as though the URL were malformed.

- `fcage`: the warning raised when the host's nameservers are all on loopback no
  longer claims the sandbox has no working DNS. Composing nothing leaves the
  `resolv.conf` the rootfs ships, which may name a routable resolver and resolve
  perfectly well, so the warning states what was not composed and leaves the
  outcome to the run.

- `fcage`: `--netstack-host-loopback` documents that it maps the gateway onto
  `127.0.0.1` alone, so a resolver on any other loopback address is not reached
  — including systemd-resolved's `127.0.0.53` stub, the configuration that
  raises the loopback-nameserver warning. The warning offered the flag as a
  remedy without that condition, and the guide states the requirement where the
  gateway mapping and DNS are described.

- `fcage`: `--no-resolv-conf` records that it opts out of the `resolv.conf`
  `--netstack` composes, not only the bind `--share-net` makes.

## [0.1.3] - 2026-08-03

### Added

- `provision::CopyIn` copies a host directory tree into a rootfs with each entry
  created under the identity map the rootfs is owned through. It is the mirror
  image of `Export`: that forks a child into the map to *read* a tree at the
  ownership it intends, and this forks one to *write* one.

  It replaces the last host tool on the provisioning path. `cp` runs as the
  calling user, which can create a file owned by nobody else, so a tree laid
  into a rootfs by hand arrives owned by the caller — and under a range map that
  reads as root inside, whatever the source intended. A tree that has to ship a
  file owned by a target uid had no way to say so.

  Ownership is read through the map, which is what makes the two exact mirrors:
  a file the host stores at `100000 + 42` is uid 42 as the rootfs means it, and
  the copy stores it back where the map puts it, so a tree an earlier mapped
  sandbox produced copies in with its ownership intact. Under
  `IdentityMap::Single` the same rule lands everything as root, that map having
  only the one inside id. A source id no extent covers is refused with the path
  that carries it, rather than failing inside the forked child with an errno
  naming nothing.

  Directories, regular files, symbolic links, and named pipes are copied.
  Several names for one file are copied as hard links onto the first name, so a
  tree keeps the sharing it was written with and its data is streamed once —
  which is what lets a tree that left through `Export`, itself coalescing hard
  links, come back through `CopyIn` unchanged. Character and block devices and
  sockets cannot be copied: `run` returns a `CopyReport` naming every entry it
  left out and what each one was, rather than dropping it in silence, so a
  rootfs that ends up missing something says so.

  A source file that changes size while it is being read fails the run with
  `ProvisionError::SourceChanged`. The frame's length is committed before the
  data is read, so such a file is written padded or truncated; the copy finishes
  the frame to keep the stream in step and then refuses, rather than reporting
  success for a file it did not reproduce.

  Containment is structural. Every frame names its entry as a single path
  component, never a path, and the child creates each entry relative to the
  directory it holds open, so there is no path for a `..` or a leading `/` to
  appear in. A hard link's anchor is the one exception, since the two names may
  sit in different directories; the child refuses an absolute anchor and any
  `.`, `..`, or empty component in one, and links without following the final
  component. A symlink is recreated rather than traversed, and each directory is
  opened with `O_NOFOLLOW`.

- `Plan::to_document` and `Plan::parse_document` are the plan's on-disk form, in
  the archive's own deb822 control format. A plan could be handed straight back
  to `DebianBuilder::plan` and nowhere else, which covers resolving once and
  installing once in a single process; a reproduce mode resolves on Monday and
  replays in a month against a snapshot mirror, and for that the plan has to
  leave the process.

  A document rather than a serde derive, for what the document survives. A field
  a reader does not know is ignored, so a plan written by a later version of the
  library still reads as long as the `Format` version is unchanged — and that
  version is bumped only for a change an older reader would misread. It is
  readable in a terminal and reviewable in a diff, and since a plan's lists are
  already ordered, two renderings of one plan are byte-identical, so a plan that
  changes shows the change rather than a different blob.

  Ignored on the way in does not mean dropped on the way out: a field this
  version does not know is carried with its stanza and re-emitted after the ones
  it does, so a read-then-write preserves every field. Re-emitting a plan is
  something a consumer does — into a provenance record, or to normalize a file
  it commits — and a round trip that quietly discarded what a newer writer had
  added would corrupt the record it was kept for. Byte identity is promised
  within a version, not across them, since a future writer may interleave its
  own fields rather than append them.

  No line the format emits ends in whitespace, so a plan survives the editors
  and hooks that strip it: an empty field is written bare, as `Signed-By:` with
  nothing after the colon. `Signed-By: ` would have been the only such line the
  format could produce, appearing exactly where a repository is trusted
  unsigned, so stripping it would have changed a committed plan's digest without
  the plan changing.

  What is refused is anything that would read back as a different plan: a
  package naming an archive the document does not carry, archive stanzas
  numbered out of order, a missing or empty required field, and, on the writing
  side, a value the format cannot carry on one line — which a mirror can produce
  by folding an index field across lines — or one whose own leading or trailing
  whitespace a reader would strip. The refusals report
  `DebianError::PlanDocument`.

- `DebianBuilder::plan` installs a previously resolved `Plan` verbatim. The
  bootstrap fetches exactly the packages the plan records, by the digests it
  records, and never touches a release or a package index.

  `resolve` and a bootstrap each ran a full resolution, so a pipeline that
  resolved once to key its cache and then provisioned resolved twice, and had to
  reconcile the two when the archive published in between. Pinning removes the
  second resolution, the divergence, and the roughly 9 MB index download that
  dominates it.

  **The trust model changes, and the change is the point.** Skipping the release
  and the index means the package digests no longer chain to an archive
  signature at install time: the plan becomes the trust anchor, having been
  archive-verified when it was produced, and installing from it asserts that
  whoever kept it kept it intact. Each `.deb` is still verified against the
  digest the plan records, so a tampered mirror is still caught. That trade is
  what a reproduce mode wants and what an ordinary build should not take, so it
  is opt-in by construction: a builder that sets no plan resolves exactly as
  before, and nothing about an ordinary bootstrap changes.

  A reproduce mode also needs the plan to outlive the process that resolved it,
  which `Plan::to_document` and `Plan::parse_document` are for.

  A plan describes a resolution that already happened, so `include`, `exclude`,
  and `base_priority` contradict it and are refused at `build` with
  `DebianError::Config` rather than given a silent precedence, as are a plan
  whose suite or architecture disagrees with the builder's and one naming more
  archives than there are repositories to fetch them from. Where the builder
  names no architecture the plan's is adopted, a plan stating which architecture
  it is for. `cache_dir`, `identity_map`, `pre_configure_overlay`, the
  repositories, and the fetcher all still apply — the plan pins what is
  installed, not how — so the same plan replays against a snapshot mirror by
  configuring one.

- `Plan` records the archive state it resolved against, as
  `Plan::archives`: one `ResolvedArchive` per configured repository, carrying
  the mirror that served, the suite and components, the SHA-256 of the verified
  release body, the release's `Date` and `Valid-Until`, and the fingerprint of
  the key that verified it. `PlannedPackage::archive` indexes into that list.

  A plan named what it selected and nothing about what it selected from, and the
  same suite resolves to different versions a week apart, so a reproducibility
  model that fixes the archive state had to reconstruct a weaker version of this
  by hand. Every input was already in hand when the index was merged and
  discarded straight afterwards.

  The mirror recorded is the URL that answered rather than the configured list:
  a repository with a snapshot backstop resolves against whichever URL served,
  and recording the list would describe a choice rather than the choice made.
  The release digest is of the body that was verified — for a signed repository
  the cleartext the signature covers, not the `InRelease` armor around it and
  not a re-fetch — so it identifies the exact state the signature vouched for.
  `signed_by` is empty for a repository trusted unsigned, where nothing was
  verified, which is a fact rather than an omission; a release may carry several
  signatures, and verification stops at the first valid one, so it names the key
  that was used rather than every key that could have been.

  `PlannedPackage::archive` is the only thing that says where a package will
  actually be fetched from once more than one repository is configured, since
  resolution is highest-version-wins across their union.

- `provision::debian::foreign_interpreter` reports the `qemu-user` interpreter a
  foreign-architecture binary is executed through, as an `Interpreter` carrying
  the qemu target name, the registered path, that path canonicalized, whether
  the handler is enabled, and its flag letters. A changed interpreter silently
  changes compiled output, so a build that folds one into an artifact signature
  needed a way to name it that did not involve re-deriving it.

  The value comes from the kernel's own `binfmt_misc` registration, which the
  foreign preflight already reads. That is the path binaries actually execute
  through, and a `PATH` lookup is not: the two can disagree, and under a harness
  that strips `PATH` a caller records no interpreter at all while one is
  executing every target binary.

  `None` covers three cases, each the honest answer rather than a failure: the
  host runs the architecture natively, the architecture is not one a `qemu-user`
  handler covers, or none is registered. A registered handler that is switched
  off reports as present and not enabled, which is the difference between "turn
  it on" and "install it".

  Both paths are reported because they are two facts. On the common Debian
  layout the registration names a wrapper that is a symlink to the real binary,
  and repointing it changes the interpreter without changing the registration.
  The registered path is good for identity and not for interrogation — qemu
  refuses to run under its binfmt wrapper name — so the documentation points a
  caller at hashing it, which `open` follows the symlink for and which needs no
  canonicalization. The crate takes no digest itself: the `F` flag means the
  kernel opened and holds the interpreter at registration time, so a digest
  taken later may be of something that never ran, and handing back one that can
  be quietly wrong is worse than handing back none.

- `Debian::available` reports the names a configured set of archives offers,
  as an opaque `Available` answering `contains` and `providers`.
  `Observed::available` is the reporting form. It runs the same read half a
  resolve does — each repository's signed release and index, merged — and stops
  there, so it downloads nothing, computes no closure, and serves an
  architecture the host cannot execute.

  Neither resolver behaviour could answer this, and both are right for what they
  are: a top-level `include` naming nothing fails the whole resolve, so a batch
  of names reports whether they were all there and never which were not, and a
  transitive dependency nothing satisfies is dropped rather than reported, since
  dpkg configures with `--force-depends`. The cost differs too — one pass
  answers any number of names, where a resolve per name re-fetches and re-parses
  a 9 MB index each time, `cache_dir` caching `.deb` files rather than indexes.

  A virtual name something `Provides` is `contains`, and `providers` names what
  satisfies it. Availability is answered at the level of the name, matching the
  resolver, which parses version constraints and architecture qualifiers away:
  the library solves no version constraints. `Available` is a projection rather
  than a retained index — a merged trixie amd64 index is on the order of 69,000
  packages with their relation vectors, which is the wrong thing to hold to back
  a membership question.

- `Tarball` reads pre-POSIX v7 archives, alongside the ustar, GNU, and pax
  dialects it already read. v7 is the subset rather than a separate format: a
  header's first 257 bytes are laid out identically, and what v7 lacks is
  everything after them — the magic, the version, `uname`/`gname`, the device
  numbers, and the `prefix`. Refusing it was right while a rootfs tarball was
  the only input, since one comes from contemporary tooling; an upstream release
  tarball comes from whoever released the software, on whatever machine, in
  whatever year, and roughly one in twelve of Debian trixie's `.orig.tar.*`
  files is v7.

  The header checksum is verified before the magic is looked at, since with v7
  accepted it is the only thing separating a header from arbitrary bytes. The
  two rejections stay distinguishable: a block carrying no magic and failing its
  checksum is reported as not a tar header, which is what a caller who named the
  wrong file needs to read, while one carrying magic is reported as a corrupt
  header. A directory marked only by a trailing `/` on its name, the convention
  that predates a reliably-set typeflag, extracts as a directory. Every
  containment rule applies to a v7 entry unchanged, being a property of the
  resolved path rather than of the header format.

- `ResolvedInputs` records the sandbox's root and the posture the launch puts
  the command under: `root`, `identity`, `network`, `rlimits`, and `hardening`,
  alongside the `env` and `mounts` it already carried.

  `root` is a `ResolvedRoot` — the host's own filesystem for a restriction, a
  plain rootfs by path, or an overlay with its whole lower stack, upper, and
  work directory. It is a field rather than an entry in `mounts` because the
  root is not something laid over the sandbox, it is what the profile is laid
  over. Before this, a plain root and an overlay root over the same base
  produced byte-identical records while describing two different builds, since
  `mounts` is projected from the plan's mount actions and the root is not one
  of them.

  The four postures are first-order build inputs on the same argument the type
  exists on. The identity map decides whether a build sees uid 0 or a mapped id,
  which is what a Debian build's `Rules-Requires-Root` handling turns on. The
  network posture is what a reproducibility claim is most often challenged on. A
  build that adapts its parallelism to `RLIMIT_NOFILE`, or fails a link under
  `RLIMIT_AS`, produces different output. And a seccomp policy changes which
  syscalls succeed, so a configure test that probes one reads the refusal as an
  absent feature — the subtlest of the four, recorded as the Landlock grants in
  full plus the filter's instruction count, the program itself being thousands
  of instructions that mean nothing to a reader.

  `hardening` is present whether or not the `hardening` feature is compiled in,
  reporting `ResolvedHardening::Unavailable` when it is not, so the public
  surface does not vary and the record stays self-describing: a key that was
  simply absent could not be told apart from one written before the key existed.
  An `Unavailable` posture and an applied posture with no controls are different
  facts — the second is a build that could have hardened and did not.

  `ResolvedMount::Overlay`, added earlier in this unreleased cycle, is removed:
  the root belongs in `root`, and that variant had to special-case its own
  `get_target` to `/` to fit an enum of mount points, which was the shape
  complaining.

- `Pool::date` pins the `Date` the emitted `Release` carries, in Unix seconds.
  The default is the time of the publish, so pinning it is what makes a publish
  byte-reproducible: the indexes are a function of the package set, and the
  release is a function of the indexes and the date. The value is a plain
  timestamp rather than one read from the environment, so a pipeline pins the
  pool's date with the same number it gives `Export::clamp_mtime`.

- `fcage` gains `--export-rootfs DIR`, which writes a provisioned rootfs to a
  tar archive and exits. The ownership-preserving, byte-reproducible export was
  reachable only from Rust, so `fcage` could make a rootfs and delete one but
  not ship one.

  The archive goes to standard output, so it pipes into a compressor with no
  temporary file; `--export-to FILE` writes to a file instead, and writing an
  archive to a terminal is refused. `--identity-map` names the map the tree was
  provisioned under and defaults to `subordinate`, as removal does.
  `--clamp-mtime EPOCH` caps every recorded modification time, which is what
  makes two exports of one tree byte-identical. Like the removal it is a mode of
  its own, accepting no other option.

  ```
  fcage --export-rootfs ./rootfs --clamp-mtime 1700000000 | zstd -o rootfs.tar.zst
  ```

- `fcage` answers an unrecognized option with the nearest flag it knows, where
  one is near enough to be worth offering:

  ```
  fcage: unrecognized option --rootsf
  Try 'fcage --rootfs'.
  Try 'fcage --help' for usage.
  ```

  The candidates are read out of the help text rather than from a list beside
  it, so the two cannot drift apart: a flag the help does not name is one the
  suggester cannot offer, which is a gap in the help either way. A string that
  resembles no flag draws no guess, and the exit status is 2 as before.

- `Pool::origin`, `Pool::label`, and `Pool::description` set the release's
  identity fields. Each is emitted only when set and none has a default, so a
  pool that names none of them is unchanged: inventing an origin would put a
  name in an archive its owner did not choose.

  They are informational — nothing resolves against them — but a client renders
  a repository under its origin and label, so `apt policy` no longer shows a
  pool with blanks, and `Pin: release o=Example`, the pinning form apt's own
  documentation leads with, can name it. All three are free text, and are
  refused empty or carrying a control character, since a release field ends at
  a newline.

- `Debug` on the provisioning types that lacked it: `Pool`, `Export`,
  `Provision`, `Remove`, `Debian`, `DebianBuilder`, `RepositoryBuilder`, and
  `Observed`. Nearly every other public type in the crate already had one; these
  were the exception because they hold a caller's trait object, not because
  rendering them was unwanted.

  A delegate renders as what it stands for rather than as its contents —
  `fetcher: <dyn Fetch>`, `mapper: Some(<dyn IdMapper>)`, `mapper: None` — since
  what a reader wants from one is whether it is there. A trust anchor is named
  and never dumped: a repository renders its keyring as `Signed(2851 bytes)`,
  keeping the length because a truncated keyring is a real misconfiguration and
  looks identical to a whole one otherwise.

### Changed

- A Landlock grant naming no access at all — `landlock_fs(FsAccess::empty(), ..)`
  or `landlock_net(NetAccess::empty(), ..)` — is refused at build with
  `ConfigError::LandlockGrantEmpty`. It reads as "grant nothing here" and
  behaved as "deny the whole class": enrolling any grant denies everything
  ungranted, and the kernel skips a rule that permits nothing. A restriction
  whose only grant was an empty filesystem one denied its own command binary and
  failed at `execve` with nothing pointing at the cause.

- `Limit` implements `Ord` by hand, so `Limit::UNLIMITED` compares above every
  finite limit as its documentation says. The derived implementation ordered it
  below `Limit::of(0)`, the inverse; internal validation was unaffected, but a
  consumer sorting or clamping through the public operators got the opposite of
  what a limit means.

- A network stack whose helper builds the tap but cannot hand its descriptor
  back reports `NetStackError::TapHandoff` rather than `TapConfigure`. Nothing
  is wrong with the interface in that case, only with the handoff, and a
  diagnostic naming the configuration step sent a reader looking at settings
  that were applied correctly.

- `fcage` ties the sandbox to its own lifetime by default: `--stop-with-caller`
  is now on, and `--no-stop-with-caller` opts out. `fcage` waits for the command
  and exits with it, so a sandbox outliving the process is never what a shell or
  a supervisor meant — and without the tie a SIGTERM to `fcage`, which
  `timeout(1)` sends as a matter of course, killed the waiter and orphaned the
  sandbox.

- `fcage --netstack` composes no `resolv.conf` under `--no-managed-mounts`,
  whose promise is that the sandbox carries exactly the binds the command line
  names. The two flags previously contradicted each other, and the composed bind
  won.

- A mount target the launch has to create as an empty file does not outlive the
  sandbox. It was already true of the managed `/etc/resolv.conf` bind, and is now
  true of a caller's own file bind: the empty `0644` file exists for its mount to
  cover and for nothing else, and dropping the handle removes it. A tree written
  into by a build no longer keeps an empty file wherever a bind was declared for
  the duration, and `fcage --netstack` — which composes its `resolv.conf` as an
  ordinary caller bind — no longer reintroduces the residue the library removes
  for its own. Only an empty regular file is removed, so anything that gained
  content or changed type meanwhile is left alone. A mount point *directory* is
  unaffected: it is part of what a launch contributes to a tree and still stays,
  at the mode of the directory it stands for.

- A pool stores a `.deb` under a filename without the version's epoch, as the
  archive convention has it, where it previously encoded the epoch's colon as
  `%3a`. That is apt's local-cache spelling, not an archive's: it left a pool
  laid out unlike every archive its clients have seen, and made the pool's
  usability rest on each of them treating the `Filename` field as a literal
  string rather than a URL to decode. Following the convention asks nothing of
  the client. A pool holding an epoch-bearing package must be republished.

- A `Repository`'s rendering names its trust anchor as `Signed(N bytes)` or
  `Unsigned`, where it previously showed `"signed"` or `"unsigned"`. Debug
  output is not covered by the stability promise.

- `fcage --help` groups its options under section headers — provisioning,
  profiles and mounts, identity and limits, the command's process, networking,
  hardening, the toggles that turn off what is on by default, and help — rather
  than presenting one flat list of roughly two hundred lines. The options were
  already ordered by subject; the headers name the groups that ordering makes.
  No entry is reworded, moved, or removed.

### Fixed

- The native network stack delivers a transfer that ends in a prompt close.
  `POLLRDHUP` is reported the moment the host peer's FIN arrives, with data
  still queued both in the kernel and in the guest's transmit buffer, and the
  stack read that as a stalled flow and reset the guest — destroying a buffer's
  worth of correct data on any transfer larger than 64 KiB whose server closes
  promptly, a plain `Connection: close` response being the everyday case. A
  hangup now retires the poll watch and keeps draining until the read of zero
  that genuinely ends the stream; only `POLLERR` aborts at once. A guest that
  never drains is still reclaimed, now on a no-progress deadline measured from
  the last byte moved.

- The native network stack no longer shuts a flow's host write side down before
  the guest's handshake completes. A socket still in `Listen`, `SynSent`, or
  `SynReceived` reports that it may not receive, which the half-close read as
  the guest having finished sending; where the host connect concluded first — a
  loopback target against a tap round trip — the host saw an immediate
  end of stream, the guest-to-host copy was disabled for good, and the flow sat
  until the idle timeout with the request never forwarded.

- A profile naming both `rootfs` and an `[overlay]` table is refused with
  `ConfigError::RootContradiction`. The builder's setters keep the two
  exclusive, but nothing stopped a profile from carrying both keys: the launch
  took the `rootfs` and separately built an overlay whose first lower it then
  skipped, so a layer named in the profile was silently never mounted. An
  overlay with no lower at all now reports `ConfigError::OverlayLowerMissing`
  rather than "no rootfs was provided".

- An export or removal child closes the descriptors it inherited, keeping only
  its own stream and gate. A copy of a live sandbox's control socket held that
  sandbox's supervisor open for as long as the child ran — minutes for a large
  rootfs — deferring the hangup detection that `stop_with_caller` is. The export
  child additionally closes the read end of its own frame pipe, without which a
  child orphaned by its caller's death filled the pipe and blocked in `write`
  forever instead of failing with `EPIPE`.

- The Debian mirror walk advances past an unsuccessful HTTP status. A primary
  mirror answering 503 mid-outage, or a CDN answering 403 for an absent object,
  failed the bootstrap outright without the snapshot backstop `mirror_fallback`
  exists for ever being tried.

- A UDP reply larger than one packet is dropped at the relay, where the ceiling
  is documented, rather than handed to an interface that discards it at egress
  with no diagnostic at all. The stack compiles in no IP fragmentation, so a
  datagram must fit the MTU less its headers; a guest needing larger ones needs
  a larger MTU. A zero-length reply is now forwarded as the legitimate datagram
  it is, where it previously ended the drain and held up every reply behind it.

- `fcage` no longer takes a command's own `--export-rootfs` or `--remove-rootfs`
  for its own. Mode detection ran over the whole argument vector, so
  `fcage --rootfs /r -- /bin/mytool --export-rootfs /x` entered export mode and
  exited 2 instead of running the command. The scan now stops at `--`.

- `fcage` no longer answers an option of another mode by suggesting the flag it
  has just refused: `--export-to` given to a launch now names the mode that
  accepts it. A misspelling in `--flag=value` form draws a suggestion, matched
  on the flag rather than on the whole argument; an abbreviation outranks a
  near-miss, so `--net` answers `--netstack` rather than `--dev`; and a mode's
  own parser answers a misspelling of its own vocabulary instead of reporting it
  as a conflict.

- `fcage --remove-rootfs --help` prints the help rather than taking `--help` as
  the tree to delete. `fcage --export-rootfs --help` did the same, silently.

- `fcage` refuses a launch flag on a provisioning run that names no command,
  where it previously accepted and dropped every one of them. A failed
  `--export-to` no longer leaves the truncated file `File::create` made, and a
  closed stdout pipe ends the export quietly rather than as stderr noise and
  exit 125.

- Concatenated gzip members all decode. Only the first was read, and because a
  tar reader tolerates a missing terminator at end of input, a concatenated
  `.tar.gz` provisioned a silently incomplete rootfs.

- A pax `uid` or `gid` record is honoured. GNU tar writes them whenever an id
  will not fit the header's octal field, so an archive of a tree with high ids
  carried its ownership there and nowhere else, and extraction silently applied
  the header's. A negative id in the base-256 header form is refused rather than
  wrapped through `as u32` into an unrelated id, and a negative fractional pax
  `mtime` floors as GNU tar's does.

- A held package (`hold ok installed`) counts as installed in a base layer, so
  a layered Debian build no longer re-unpacks it.

- Excluding a package that is also a provided virtual name falls through to a
  provider instead of failing the resolution, which is what apt's own
  deselection does.

- An identity map extent ending exactly at `u32::MAX` is refused at build, as
  the kernel refuses the id `(u32)-1`, rather than failing when the map is
  applied. A zero-count entry in a subordinate allocation no longer drops every
  range after it, a request spanning contiguous allocation entries is accepted
  as shadow accepts it, and a host granting one block under both the user name
  and the literal uid no longer produces duplicate ranges that fail the build.

- A malformed `Valid-Until` fails freshness rather than reading as a slightly
  wrong deadline: an out-of-range day no longer rolls into the next month, and a
  zone offset past 23 hours is refused.

- An HTTP redirect to another port on the same host is refused with the
  same-origin policy, which previously compared hosts alone.

- A whitespace-only line separates deb822 stanzas, as it does for every other
  reader of the format.

- `Pool::publish` writes the `Release` field `Date`, which the Debian
  repository format requires and which the emitted release previously omitted.
  A client had no way to tell how old a pool snapshot was and no value for its
  clock-skew check, and apt reported the absent field as an invalid one on
  every update against the archive. The optional `Valid-Until` is still not
  written, so a pool's release still never expires.

- `Pool::publish` writes a `Release` describing the whole suite. It previously
  named only the component and architecture the call was made with, so
  publishing a second of either into one suite dropped the first out of the
  release. The indexes stayed on disk but became unreachable: a reader consults
  the release before it knows which digests to ask for, and verifies every fetch
  against a digest the release records, so a section the release does not name
  cannot be resolved, and the by-hash copies are no way around it. Each publish
  now scans `dists/<suite>` and names every index it holds, with `Architectures`
  and `Components` as the unions found. A nested component such as
  `main/debian-installer` records under its full path, which is the name a
  reader has to ask for.

  A release emitted by this version therefore differs from one emitted before it
  for any suite holding more than one component or architecture. That difference
  is the fix.

- A repository declaring more than one component resolved only the first
  package of each component after the first. The components' indexes were
  concatenated without the blank line that separates two deb822 paragraphs, so
  the first stanza of each component folded into the last stanza of the one
  before it and the packages it named vanished from the merged index. Nothing
  reported it, because each component was verified against the release
  individually and only their concatenation was wrong.

- `Pool` refuses a suite, component, or architecture it cannot write. Refused
  are values that would resolve outside the pool — a leading `/`, a `..`
  segment, an empty or `.` segment — and values a release field cannot name,
  which is whitespace and control characters, since `Architectures` and
  `Components` are whitespace-delimited lists. A slash is not itself refused in
  the suite or the component: both may name a subtree, as `buster/updates` and
  `main/debian-installer` do. An architecture is always a single path segment.
  Each refusal is a `DebianError::Config` naming the field and the value.

- The default fetcher refuses a response whose header section ends without the
  blank separator. A mirror that sent a status line and closed — an overloaded
  backend, a proxy dropping a response mid-header — produced a header section
  with no framing at all, which read as a body running to end of stream: a
  successful fetch of nothing. Inside the provisioner the empty body was caught
  one layer up by the digest check, so the operator was told the index digest did
  not match when the response had in fact been truncated, and a mirror walk that
  fails over on a transport error did not. It is now an `UnexpectedEof`, as a
  body short of its `Content-Length` already was.

- The default fetcher refuses a `Content-Length` it cannot use: one that does not
  parse, one past `u64`, or a repeat contradicting the first. Such a value was
  discarded and the body read to end of stream instead, widening the set of
  malformed responses that read as success. The header is framing, not
  decoration.

- The default fetcher tries every address a mirror's host resolves to, rather
  than the first alone, and reports the last failure only when none connects.
  `deb.debian.org` and every CDN-fronted mirror answer with several A and AAAA
  records, so on a host with no working IPv6 egress — a common CI and container
  condition — whether a bootstrap worked depended on the order the resolver
  happened to return. The mirror walk advances to the next *mirror*, not the next
  address, so the default single-mirror configuration had no fallback at all.

- The managed `resolv.conf` placeholder is recorded against the path the file is
  actually created at. A rootfs named relatively recorded a relative path, which
  resolved against whatever directory the process was in when the handle dropped
  — removing the wrong path, or nothing. For an overlay root it named the base
  lower while the file lands in the upper, where the merged view's writes go, so
  the removal was a silent no-op and the upper kept a resolver configuration the
  base never had, into an export of that upper.

- The tree-copy child refuses a frame stream that ends with directories still
  open. Such a stream reported success while every open directory kept its
  creation mode `0700` with no ownership or modification time applied, and the
  caller received a `CopyReport` stating the destination held everything the
  source did. Every other malformed shape in the same loop was already refused.

- A directory the extraction implies but no archive entry names is left
  traversable when it is created for the overlay walk, which runs no later mode
  pass to widen it from the `0700` it is created at.

## [0.1.2] - 2026-07-30

### Added

- `fcage` gains `--remove-rootfs DIR`, which deletes a provisioned rootfs and
  exits, including one a range-mapped sandbox wrote and a plain `rm -rf` cannot
  remove. It carries `provision::remove` to a shell prompt, in place of the
  `unshare --map-auto rm -rf` incantation the guide previously documented.
  `--identity-map` names the map the tree was provisioned under and defaults to
  the subordinate one. The flag is a mode of its own and takes no other option:
  it removes a rootfs rather than running a command in one.

- `Pool` reports the layout it owns: `mirror_url` gives the `file://` URL that
  declares the pool as a `Repository`, and `dir`, `dists_dir`, and
  `release_path` give the paths a caller signing the pool needs. All are
  available before the first publish, and a relative pool root is made absolute
  for the URL.

### Changed

- `Pool::publish` removes any `InRelease` or `Release.gpg` the suite carries
  before writing a new `Release`, so a signature made over a superseded release
  cannot outlive it. A pool is signed after each publish rather than once.

- A mount point the sandbox has to create carries the mode of the directory it
  stands for, applied exactly: `1777` for `/tmp` and `/dev/shm`, `0755` for
  `/dev` and `/proc`, and `0755` for a directory created on the way to either.
  A mount point outlives the sandbox, so a provisioned tree previously carried
  a `/tmp` no unprivileged process could write to. A path the rootfs already
  ships keeps the mode it shipped with.

- The `/etc/resolv.conf` target that host networking creates when the rootfs
  ships no resolver configuration is removed once the sandbox is gone, rather
  than left in the tree. A bind needs its target to exist, so the file has to be
  created; leaving it behind gave a tree a resolver configuration it never had,
  which an export then carried into whatever was made of the tree, and made the
  archive depend on whether the *build* host had a usable `resolv.conf`. The
  bind itself is unchanged, so a command in the sandbox resolves names exactly
  as before. A `resolv.conf` the rootfs ships is never touched.

### Fixed

- A mount point the sandbox creates no longer takes its mode from the launching
  process's umask. A launch under `umask 077` left a `0700` `/tmp` in the
  rootfs, so the same tree exported differently depending on the umask in force
  when it was provisioned.

## [0.1.1] - 2026-07-26

### Changed

- Both crates carry keywords chosen for how the registry is actually searched,
  and the README states the boundary against container runtimes. `fcage` gains
  a description naming the binary and what it does, in place of one that only
  named the library.

## [0.1.0] - 2026-07-26

Initial public release. The [README](README.md) describes what the library
does, and the [guide](https://gregordinary.github.io/ferroday-cage/) covers
it in full.

[Unreleased]: https://github.com/gregordinary/ferroday-cage/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gregordinary/ferroday-cage/releases/tag/v0.1.0
