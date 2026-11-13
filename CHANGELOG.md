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

- **Breaking.** A sandbox with a network namespace of its own, under
  `Network::Isolated` (the default) or `Network::None`, installs a seccomp
  filter that refuses the routes out such a namespace does not cover. An
  `AF_VSOCK` socket is refused with `EAFNOSUPPORT`, `io_uring_setup` with
  `ENOSYS`, and on x86, socket creation through `socketcall` with
  `EAFNOSUPPORT`, whatever the family. A sandboxed command could previously
  open a vsock socket, which reaches a virtual machine guest's hypervisor host,
  and the host's own services where the host runs vsock loopback. A consumer
  must act on three consequences. io_uring is unavailable in such a sandbox. A
  32-bit x86 program built against glibc creates no socket there, and reads
  each address family as one the kernel does not offer. A host that cannot
  install a seccomp filter fails the launch at the new
  `SetupStep::InstallNetworkFilter`, and a Debian or Alpine bootstrap that runs
  its packages' scripts refuses such a host before it downloads anything.
  `Network::Host` is unchanged.
- A sandbox with a PID namespace that inherits the caller's standard input runs
  in a process group of its own, in the caller's session, which its init
  creates before the command exists. A sandboxed command could previously
  signal the caller's whole process group with `kill(0, sig)`, whatever
  hardening applied: `kill -KILL 0` ended the caller and every process beside
  it, and any other signal ran the caller's handler for it. Where the command's
  standard input and output are both the caller's controlling terminal, and the
  caller's group holds its foreground at the launch, the sandbox's group takes
  the foreground for the launch, so a typed `^C` still reaches the command; the
  wait that collects the outcome, or dropping the handle, gives it back. A
  launch that cannot move into its group, take the foreground, or wait for its
  launch stage fails at the new `SetupStep::NewProcessGroup`,
  `SetupStep::TakeForeground`, or `SetupStep::AwaitLaunchStage`. Without a PID
  namespace the command still shares the caller's process group and PID space,
  and `LandlockScope::Signal` is the bound there.
- **Breaking.** A `RestrictedProfile` refuses the `[hardening]` keys
  `landlock-fs`, `landlock-net`, and `keep-caps` with
  `ConfigError::ProfileOperationForbidden`, naming the key, and so does `fcage
  --restricted-profile`. A restricted profile's Landlock grants were added to
  the grants the consumer configured after loading, and its kept capability set
  survived the consumer's switch to a non-root `run_as` identity, so an
  untrusted profile could widen the consumer's own confinement. A seccomp
  policy, `drop-caps`, and the Landlock scopes are still accepted. A consumer
  that loads such a profile restricted moves those keys into its own calls.
- `NetStack::attach`, and `fcage --netstack` with it, refuses a sandbox
  carrying a Landlock network grant the kernel cannot enforce, below Landlock
  ABI 4 or without the LSM, with the new
  `NetStackError::LandlockNetUnenforceable`. The build accepts such a grant in
  an isolated sandbox, whose network namespace bounds the command, and an
  attached stack then gave the namespace outbound TCP with the grant silently
  narrowed away.
- An Alpine index that a key of Alpine's verifies must describe, in its signed
  `DESCRIPTION`, the release it was fetched as: a release of `X.Y` for `vX.Y`,
  a snapshot, pre-release, or `.0` release for `edge`, and some release for
  `latest-stable`. Alpine signs every release of an architecture with one key,
  so a mirror could previously answer a request for one release with a genuine
  index of an older one, or of `edge`. Such an index now fails with
  `AlpineError::Index`, as does an Alpine-signed index fetched under a release
  name Alpine does not publish. The description names no component, and
  postmarketOS writes a timestamp there, so neither is bound; the guide
  recommends an `https://` transport for postmarketOS.
- The Gentoo layer holds each field of a binary-package index record to a
  length (512 bytes for a CPV, 256 for a slot, 16 KiB for each of USE and
  IUSE, 1 KiB for a path) and leaves a record past one out, as it does a
  dependency class past 64 KiB, and holds a plan to the same. A resolution
  records at most 16,384 refusals, charges each comparison of an atom with a
  candidate build what it reads before making it, and stops before reading past
  128 MiB, as it stops past 4,194,304 comparisons. An atom names a package and
  version no longer than a CPV and states at most 64 USE dependencies. Nothing
  signs the index, and a mirror could previously exhaust memory before any
  signature was consulted, or make a resolution take hours.
- The Gentoo layer refuses a binary package whose paths or link targets hold a
  newline or a carriage return, as portage does. Each became a line of the
  database entry's `CONTENTS`, so such a package could register itself as the
  owner of a file it never shipped, which an unmerge inside the root then
  removed.
- The Gentoo layer accepts a signature on a stage3 pointer, a digest document,
  or a binary package's Manifest only from Gentoo's release certificates, the
  four `sec-keys/openpgp-keys-gentoo-release` installs and Gentoo's own tooling
  verifies these documents against. It accepted one from any signing
  certificate in the vendored service-key bundle, which also holds keys Gentoo
  uses for security advisories and infrastructure. `Gentoo::keyring_horizon`
  and `fcage --gentoo-keyring-horizon` report the four.
- A redirect `HttpFetch` refuses is reported against the URL that was fetched,
  with the target's control characters escaped. A mirror, or anyone on a
  plain-HTTP path, could otherwise write terminal escape sequences into an
  operator's error output through a `Location` header.
- The provisioners' errors quote the text an index, a package, or a sandbox
  supplied with its control characters escaped: the member names of a Gentoo
  binary package and of an Alpine signature segment, a Gentoo index's slot, the
  dependencies and provided names Alpine and Debian refusals name, the versions
  a Debian refusal offers as evidence, a `.deb`'s architecture, and the package
  names dpkg's failure list holds. Each reached an error message as written, so
  a mirror, a package's metadata, or a maintainer script writing its own failure
  list could put terminal escape sequences on an operator's terminal. A refusal
  now quotes such text, as `"lib>=2.0"` rather than `lib>=2.0`, and a Debian
  refusal quotes its requirement in double quotes rather than backticks.
- The Debian layer holds the name of a package an index or a plan states to the
  alphabet Debian policy gives a package name: lowercase letters, digits, `+`,
  `-`, and `.`, at least two characters, starting with a letter or a digit. An
  index stanza naming a package any other way is left out and counted in
  `DebianEvent::Index`, as a stanza whose pool path leaves the mirror is. A plan
  naming one is refused with `DebianError::PlanDocument`, or with
  `DebianError::Config` where `DebianBuilder::plan` or `DebianBuilder::pin` is
  handed one. The name reached `fcage`'s progress lines and the layer's errors
  as written, so a mirror could put terminal escape sequences on an operator's
  terminal through it. dpkg also installs a name in upper case, one holding
  `_`, and one of a single character, none of which a Debian or Ubuntu archive
  publishes; a resolution no longer selects such a package.
- A Debian release's refusals quote the architectures and the components it
  lists, and its `Valid-Until`, with their control characters escaped, as they
  already quoted its suite and codename. A trusted-unsigned release is a
  mirror's text, and a deadline the release parser accepts may carry any text
  before its weekday's comma and after its zone.
- A Debian plan or pin stating a suite or an architecture other than the
  bootstrap's is refused quoting what it states, with its control characters
  escaped. A plan document is a file the caller may have taken from elsewhere,
  and nothing holds its header to an alphabet.
- The Alpine layer's plan and pin refusals quote what the plan states, with its
  control characters escaped, as the Debian layer's do: the architecture of a
  plan or a pin the bootstrap is not configured for, the release and component
  of a plan's index, and a plan document's architecture where a package's
  differs. The document reader quotes a package's name until it has held the
  name to apk's alphabet, and `build` holds a plan's package names to that
  alphabet before any refusal names one.
- The Debian layer holds the version of a package an index, a plan, or a base
  layer's status database states to the alphabet Debian policy gives a version:
  alphanumerics and `.`, `+`, `-`, `:`, `~`, which dpkg also holds a package to.
  An index stanza stating one any other way is left out and counted in
  `DebianEvent::Index`, a plan stating one is refused as one naming a package
  outside policy's alphabet is, and a base's status entry stating one is read as
  stating no version. A version reached a pin's refusals, and `fcage`'s report
  of them, as written.
- A launch whose session keyring join is refused with `EPERM` or `ENOSYS`, as a
  seccomp policy the launch runs under can refuse it, installs a seccomp filter
  of its own before it forks anything, which answers `add_key`, `request_key`,
  and `keyctl` with `ENOSYS` for every process of the sandbox or restriction.
  The launch previously proceeded wherever `KEYCTL_GET_KEYRING_ID` was refused
  the same way, so a policy that refused those two operations and allowed
  `KEYCTL_READ` left the command possessing the caller's session keyring and
  able to read its keys. A policy that refuses the join alone no longer fails
  the launch. A launch that cannot install the filter fails at
  `SetupStep::ReplaceSessionKeyring`.

### Added

- `Pending::listen` makes a TCP listener on the sandbox's loopback and hands it
  to the caller, which accepts the connections the command makes there. A
  helper process makes it inside the sandbox's user and network namespaces, so
  a privileged port is available, and nothing of the caller's runs inside the
  sandbox. The address is in `127.0.0.0/8` or `::1`, under `Network::Isolated`;
  anything else is refused with the new `Error::ListenRefused`, whose
  `ListenRefusal` says why, and a failure to make the listener is the new
  `Error::Listen`.
- `fcage --forward-loopback PORT TARGET` listens on the sandbox's loopback at
  `PORT` and carries each connection the command makes there to `TARGET` on the
  host, a unix socket's absolute path or an `ADDRESS:PORT`. A forward is one
  thread however many connections the command makes, and holds at most 128 at
  once; a connection past that is closed at once, and the first such is
  reported. A connection the target refuses, or does not take within 30
  seconds, is reported and reset. A connection that ends any other way than
  with both directions ended in order, a failure of either side or the run's
  end among them, is reset on each side the forward holds, so neither peer
  takes a cut-off stream for a complete one (`ferroday-cage-cli`).
- `CageBuilder::host_rootfs` roots a sandbox on the host's own filesystem,
  read-only: the launch clones the host's mount tree inside the sandbox's mount
  namespace and makes every mount of it read-only and `nosuid`. It hides
  `/home`, `/root`, `/run`, `/var/run`, and `/var/tmp` by default, listed in
  `resolved_inputs`; `CageBuilder::reveal` takes one back. Nothing is created on
  the host: a mount target outside a filesystem the sandbox mounts must exist,
  and the new `ConfigError::MountTargetMissing` refuses one that does not. The
  new `ResolvedRoot::HostReadOnly` reports the root, and a launch whose clone
  fails reports the new `SetupStep::MountHostRoot`. `fcage --host-rootfs` and
  `--reveal`, and the profile keys `host-rootfs` and `reveal`, reach them; a
  `RestrictedProfile` refuses both.
- `CageBuilder::hide` leaves a path inside the sandbox empty, on any root: an
  empty tmpfs over a directory, made read-only once the mount profile is in
  place, or an empty read-only regular file over anything else. A path with
  nothing at it hides nothing. `CageBuilder::read_only` makes a path read-only
  where it stands, mounts beneath it included, such as `.git/hooks` inside a
  writable working tree. They arrive as `Mount::Hide` and `Mount::ReadOnly`,
  the profile kinds `hide` and `read-only`, `ResolvedMount::Hide` and
  `ResolvedMount::ReadOnly`, and `fcage --hide` and `--read-only`, and fail a
  launch at the new `SetupStep::HidePath` or `SetupStep::ReadOnlyPath`.
- `CageBuilder::landlock_resolve_unix` and `RestrictionBuilder::landlock_resolve_unix`
  refuse the command a connection to a pathname unix socket created outside its
  Landlock domain, except beneath a path granted the new `FsAccess::RESOLVE_UNIX`
  (access letter `u`). It is Landlock ABI 9's `RESOLVE_UNIX` right. Off by
  default, and on by default under the host's own root; asked for on a kernel
  below ABI 9 it is refused with the new
  `ConfigError::LandlockResolveUnixUnenforceable`, while the host root's default
  is dropped there. A grant of `RESOLVE_UNIX` alone where the restriction is off
  is refused with the new `ConfigError::ResolveUnixUnhandled`.
  `ResolvedHardening::Applied` reports it as `landlock_resolve_unix`, the
  profile key is `resolve-unix` in `[hardening]`, a `RestrictedProfile` refuses
  `resolve-unix = false`, and `fcage` gains `--landlock-resolve-unix`,
  `--no-landlock-resolve-unix`, and `--landlock-unix`. `FsAccess::all()` now
  includes the new right.
- `host::landlock_enforces_fs`, `host::landlock_enforces_net` and
  `host::landlock_enforces_scope` answer whether the running kernel's Landlock
  enforces a right or a scope, from the same table of which Landlock ABI brought
  each one that a build refuses an unenforceable request by.
- `CageBuilder::present_as` presents the caller to the command as another
  identity under the single-identity map. The command sees the caller as the
  given uid and gid rather than as root, or, with `PresentedIdentity::Own`, as
  the ids the host knows the caller by. Only the nested user namespace's map
  changes, so the command runs as that identity without a switch, holds no
  capability across its `execve` beyond a kept set, and has no-new-privileges
  set. It is a presentation, not a boundary: on the host the command is still
  the caller. `fcage --present-as UID:GID|own` and the profile key `present-as`
  reach it, and `ResolvedInputs::present_as` reports it. A range map refuses
  it, and so does a presented uid of 0, with `ConfigError::PresentAsRoot`,
  including `own` for a caller that is the host's root.
- `Running::usage` reports what the command and its descendants used once a
  wait has returned the outcome, as a `ResourceUsage`: user and system processor
  time, and the largest peak resident set size one process reached. `Output`
  carries it as `usage`. The supervisor reads it after collecting the command's
  exit, so it covers every process collected by then, which under a PID
  namespace includes the orphans the init collected. A kill under a PID
  namespace leaves these three fields `None`. The peak is never below the
  resident set the calling process had at the launch: the command's image
  before its `execve` is a copy of the caller, and the kernel counts the
  replaced image's peak toward the command.
- `CageBuilder::empty_rootfs` roots a sandbox on an empty tmpfs of its own, for
  a sandbox composed from binds that needs no root directory on the host. The
  launch writes nothing on the host, and the root itself becomes read-only once
  the mount profile is in place, while each mount in it keeps its own flags.
  `fcage --empty-rootfs` and the profile key `empty-rootfs` reach it,
  `ResolvedRoot::Empty` reports it, and a launch that fails to mount or seal it
  reports `SetupStep::MountEmptyRoot` or `SetupStep::ReadOnlyEmptyRoot`. A
  profile naming it beside another root is refused with
  `ConfigError::RootContradiction`.
- `CageBuilder::symlink` and `Mount::Symlink` make a symbolic link in its place
  in the mount sequence, such as `/bin` pointing at `usr/bin` beside a bind of
  the host's `/usr`. A link already standing with the same target is kept, so a
  launch over a plain rootfs repeats. `fcage --symlink TARGET PATH` and a
  `[[mount]]` entry with `kind = "symlink"` reach it, and a target that is empty
  or too long for a path is refused with `ConfigError::SymlinkTargetInvalid`. A
  `RestrictedProfile` refuses a link, as it refuses a bind.
- `ResolvedInputs::network_filter` reports what the network filter refuses, as
  a `ResolvedNetworkFilter` holding one `ResolvedSyscallRefusal` per refused
  call: the syscall's name, the value of its first argument where that decides
  the refusal, and the errno it answers. It is `None` under `Network::Host` and
  for a restriction, which install no filter, so their records render as
  before; a record of an isolated or a denied network carries a
  `network-filter` table.
- `CopyReport::attributes` names every extended attribute a `CopyIn` run did not
  give an entry it copied, as a `SkippedAttribute` with an `AttributeSkip`
  reason: one the sandbox's root cannot set (a `trusted.` attribute, a
  `security.` one other than a capability, a `system.` one other than an access
  control list, anything a symbolic link holds), or one naming an id the
  identity map has no id for.
- `UnheldReason::Release`, for a pinned Debian package an `include` entry asks
  of a release that offers it only at another version, and
  `UnheldReason::Requirement`, in the Debian and the Alpine layers alike, for a
  pinned package at a version a selected package's dependency rules out.
- `Error::ProcfsRefused`, reported in place of `Error::Setup` when the kernel
  refuses the fresh procfs a sandbox with a PID namespace of its own mounts, as
  it does inside a container started with its runtime's defaults. Its
  `host::ProcfsBlocker` names the mounts lying on the procfs and the remedies:
  unmasking the runtime's procfs, or `pid_namespace(false)`.
  `host::procfs_blocker` answers the same question before a launch, by mounting
  a procfs in a short-lived child's namespaces.
- `ConfigError::NestedUsernsProcfsReadOnly`, reported in place of
  `ConfigError::NestedUsernsNeedsProcfs` where the only procfs that could serve
  the nested user namespace's identity map is read-only, naming where it is
  mounted.
- The guide's "Running inside a container" chapter: what a container runtime's
  default seccomp profile, AppArmor profile, masked procfs and host sysctls
  each refuse a sandbox, and the remedies for Docker and for Kubernetes.
  `tools/seccomp-additions.toml` lists the syscalls a launch makes that a
  runtime's default seccomp profile refuses, and `tools/seccomp-profile.py`
  adds them to the runtime's own default profile.
- `ExitStatus::core_dumped`, whether the kernel dumped the command's core when a
  signal terminated it, as the supervisor read it from the wait status, and
  `ExitStatus::signaled_with_core_dump` for a caller reporting an outcome of
  its own. A status that dumped core displays as `terminated by signal 11 (core
  dumped)`. `shell_code` is unchanged.
- `Running` implements `AsFd`: a readiness descriptor, readable whenever the
  handle has output to deliver, an outcome to read, or a teardown to observe.
  `Running::try_wait` does that work without blocking and returns the outcome
  once it is known, so an event loop drives a sandbox's wait without parking a
  thread on it. The embedding chapter gives the recipe for tokio.
- Cgroup limits and whole-tree accounting. `CageBuilder::cgroup_parent` and
  `RestrictionBuilder::cgroup_parent` place each launch in a cgroup of its own
  beneath a delegated cgroup v2 directory, which the launch stage joins before
  it creates any namespace. `cgroup_limit` holds the whole tree to a
  `CgroupLimit`: `memory.max`, `memory.swap.max`, `pids.max`, `cpu.max`, or
  `cpu.weight`. `ResourceUsage` gains the tree's processor time, peak memory,
  peak process count and OOM kills, read from the cgroup, and reported for a
  killed sandbox as well. `Running::kill` and `KillHandle::kill` also write
  `cgroup.kill`, which reaches descendants that left the command's process tree,
  before the outcome or after it. The handle removes the cgroup once the outcome
  is known and nothing is left in it. Where a process the command left behind
  still holds it then, the last of the handle and its kill handles to drop
  removes it after a kill, once the tree has emptied, waiting up to five seconds
  for it. A cgroup still holding a process nothing killed stays beneath the
  parent. A launch the parent cannot serve fails with `Error::CgroupRefused` and
  a `CgroupRefusal`: a parent that is missing, outside a cgroup v2 hierarchy,
  read-only, not delegated to the caller, lacking a controller, or holding
  processes, a kernel without a limit's file, or a caller the launch cannot move
  from into the parent's subtree. A host failure preparing the cgroup fails with
  `Error::Cgroup`, and a value the kernel would refuse with
  `ConfigError::CgroupLimitInvalid`. `SetupStep::JoinCgroup` is the step that
  joins it. A limit with no parent is refused at build, unless
  `cgroup_required(false)` on either builder says the limits are not required:
  the launch then runs without them, `ResolvedInputs::cgroup` reports them as
  `ResolvedCgroup::NotApplied`, and `fcage` says so on standard error.
  `ResolvedInputs::cgroup` reports an applied cgroup and its limits as
  `ResolvedCgroup::Applied`. `host::cgroup_blocker` answers whether a launch
  beneath a parent with given limits would be refused, and why, by the launch's
  own steps, and `host::own_cgroup` names the cgroup the calling process runs
  in. Profiles take a `[cgroup]` table, `required` among its keys, which
  `RestrictedProfile` refuses where it names a parent, and `fcage` takes
  `--cgroup-parent DIR`, `--cgroup LIMIT=VALUE`, and `--cgroup-required` and
  `--no-cgroup-required`.
- An `agent-tools` example and a guide chapter for it: a sandbox for a coding
  agent's tool commands, over the host's own root or an empty one, with the
  working tree writable and its hooks read-only, the caller's own identity, one
  loopback port the example serves, the curated seccomp roster and the
  unix-socket restriction, and cgroup or per-process limits.
  `examples/agent-tools.toml` gives `fcage` the same sandbox.
- `DebianEvent::Index` reports, once a resolution has read every configured
  repository's index, how many packages the merged index offers and how many
  stanzas it left out as ones the layer cannot act on, which it left out
  without a word before. `fcage` prints both, as it prints a Gentoo binhost
  index's (`ferroday-cage-cli`).

### Changed

- **Breaking.** The Debian layer reads a package's or an index's SHA-512 beside
  its SHA-256, in a release and in an index stanza, and holds an index and a
  download to every one the archive records, refusing the bytes where any
  differs, as apt does. Either alone suffices, and a stanza stating neither is
  left out and counted in `DebianEvent::Index`. Ubuntu's development series
  records SHA-512 alone, and its release was refused as listing no index.
  `PlannedPackage::sha256` is replaced by `PlannedPackage::digest`, a `Digest`:
  the SHA-256 where the index records one, and otherwise the SHA-512, which is
  what installing the plan checks the package against and names its cache entry
  by. A plan document states one of `SHA256` and `SHA512`, refusing a package
  stating both or neither; Debian's and Ubuntu's archives record a SHA-256, so
  their plans are written as before. The format stays `ferroday-cage-plan 2`,
  and 0.5 refuses a package stating `SHA512` as missing its `SHA256`. A pin is
  compared with the archive's digest under the pinned one's algorithm, and is
  refused with the new `UnheldReason::DigestNotOffered` where the archive no
  longer records one. `Pool::publish` refuses a control file naming `SHA512`, as
  it refuses one naming `SHA256`.
- **Breaking.** `provision::digest` is public, with `Algorithm`, `Sha256` or
  `Sha512` and `#[non_exhaustive]`, and `Digest`, an algorithm and a value that
  `Digest::new` holds to the algorithm's lowercase hex, so a digest a plan
  records can never be malformed. Every such digest is one:
  `debian::PlannedPackage::digest`, `debian::ResolvedArchive::release_sha256`,
  and `alpine::ResolvedIndex::sha256`, the last two a `String` before. A plan
  document stating a release's or an index's SHA-256 in another shape is now
  refused rather than carried. Neither layer's plan document changes.
- **Breaking.** The digests the Debian and Gentoo layers' refusals name are a
  `provision::digest::Digest`, each a `String` of lowercase hex before, and the
  messages name the algorithm: `debian::UnheldReason::Digest`'s `pin` and
  `archive`, and the `expected` and `actual` of `debian::DebianError::Digest`
  and `gentoo::GentooError::Digest`. `gentoo::Stage3::sha512` returns a
  `&Digest` rather than a `&str`. The Alpine layer's refusals are unchanged.
- **Breaking.** The base environment carries `HOME=/root` only for a command
  that runs as uid 0 of its namespace. A command under `CageBuilder::present_as`,
  or a `run_as` identity naming another uid, gets `PATH` alone, and a program
  that needs a home falls back to its passwd entry. A `run_as` caller that
  relied on `/root` sets `HOME` with `CageBuilder::env`; `base_env(false)` is
  unchanged.
- **Breaking.** `SeccompPolicy::Curated` is removed. The curated roster is
  `SeccompRules::curated()`, a deny-list a caller extends with `rule` and
  `errno_for`, so `SeccompPolicy::Rules(SeccompRules::curated())` replaces it.
  An errno given for a syscall the roster lists answers that syscall in place
  of the roster's entry. A profile writes the plain roster as `seccomp =
  "curated"`, as before, and an extended one as a `[hardening.seccomp]` table
  with `curated = true`, which names the roster rather than listing it. `fcage
  --seccomp curated` now combines with `--seccomp-deny`, `--seccomp-deny-rule`,
  and `--seccomp-errno`, which extend it, and is still refused beside an allow
  side. `--seccomp-errno` beside a profile's curated policy joins it rather than
  being refused.
- **Breaking.** A sandbox with a PID namespace that inherits the caller's
  standard input is no longer one of the caller's shell's jobs. A `^Z` typed at
  the caller's terminal no longer suspends it. In an interactive run, where the
  sandbox holds the terminal, the kernel discards the stop, or, where the
  caller's reaper is a subreaper in the caller's session, the init continues the
  command. A run whose standard output is piped, redirected, or captured leaves
  the terminal with the caller's job, so the far end of a pipeline reads it as
  before. The sandbox then runs as a background group: its reads of the terminal
  fail, and a typed `^C` or `^Z` reaches the caller's job rather than the
  command. `fcage` ends such a sandbox with itself, and a library caller decides
  for itself. An interactive command whose output goes elsewhere runs as a
  terminal launch instead. Without a PID namespace the sandbox is the shell's
  job as before.
- `host::seccomp_available` is available without the `hardening` feature, and
  answers whether this process can install a seccomp filter, by installing one
  in a short-lived child. It answered `true` on a kernel built without
  `CONFIG_SECCOMP_FILTER` and under a seccomp policy refusing the `seccomp`
  syscall, where a launch with a network namespace of its own fails.
- A run-as identity naming another id than the single-identity map's one is
  refused with the new `ConfigError::RunAsOutsideSingleMap`, which names
  presenting the caller as that id as the remedy, rather than with
  `ConfigError::RunAsUnmapped`. A run-as identity naming a presented identity
  is accepted, and switches nothing.
- The init collects an orphaned process as soon as it exits, rather than on a
  once-a-second tick. `SetupStep::WatchCommand` names the descriptors the
  supervisor watches the command through, a pidfd and the descriptor its
  children's `SIGCHLD` arrives on.
- `HttpFetch` asks for a resource's own bytes with `Accept-Encoding: identity`,
  and refuses a response that applies a content coding regardless as a
  transport failure, so a mirror walk asks the next mirror. A server compressing
  on the fly previously produced a digest failure, which no other mirror is
  asked about.
- **Breaking.** An Alpine dependency the pinned version of a package does not
  meet, where nothing else answers it, fails the resolution with
  `AlpineError::Pin` and `UnheldReason::Requirement`, naming the requirement, as
  the Debian layer reports it. It failed with `AlpineError::Resolve`.

### Fixed

- **Breaking.** A Debian `pin` holds the version of every name it names by
  every route a resolution takes to a version. An `include` entry written
  `name/release`, a versioned dependency such an entry takes from its release,
  and an upgrade of a package a `base_layer` holds each selected a pinned name
  at another version without reporting it. Each now takes the pinned version
  alone, an upgrade doing so whatever the rank of its release. Where the pinned
  version cannot answer what is asked, the resolution fails with
  `DebianError::Pin` rather than resolving around the pin, as it now also does
  for a versioned dependency the pinned version does not meet, which failed
  with `DebianError::Resolve`. Every refusal is still reported as a
  `DebianEvent::Unsatisfiable`.
- `Pool::publish` no longer replaces the `.deb` a pool's index names with a
  lower version that differs from it only by its epoch, such as `1.0-1`
  published after `1:1.0-1`, which share a file name. The index kept the
  higher version's digest, so every bootstrap selecting the package failed its
  digest check. A `.deb` below the version the index keeps for its name is now
  neither indexed nor copied into the pool.
- Publishing a pool syncs each index and `Release` it writes, and the directory
  holding it, before the publish returns. A crash could leave a pool's
  `Packages` short, and the next publish, which merges into it, then dropped
  every package published before.
- **Breaking.** `Pool::publish` refuses, with `DebianError::Deb`, to replace a
  pool file with other bytes, by a same-version republish or an epoch-only
  upgrade, where another index names the bytes the file holds. A pool path is
  shared by every suite publishing a package into one component, and by every
  architecture's index for an `Architecture: all` package. The replacement
  updated only the index the publish wrote, and the others went on naming a
  digest the file no longer had, so a bootstrap from them failed its digest
  check. A refused publish changes nothing: every `.deb` is staged and checked
  before any lands.
- A layered Debian resolution, through `resolve_layer` or `stage_layer`, no
  longer reports a plan whose upgrades break a dependency of another selected
  package or of a package the base keeps. Upgrading a base package replaces the
  base's version, together with every name that version supplied, its own and
  those it provides. A base package whose dependency an upgrade breaks is
  upgraded too, where apt would upgrade it. A dependency still unmet fails the
  resolution with `DebianError::Resolve`, whichever order `include` names
  packages in, and its `DebianEvent::Unsatisfiable` names the package, the
  dependency, and the upgrade that replaced what met it. Such a plan was
  installed under dpkg's `--force-depends`, leaving the root with a package
  whose dependency nothing satisfied.
- An Alpine bootstrap refuses two packages that ship one path as a directory
  and as an entry that is not one, whichever is unpacked first and whatever
  their `replaces` say, as `apk` does. The later one previously replaced the
  earlier silently, so the tree depended on the unpack order. A link that
  resolves to a directory still satisfies a later directory entry.
  `AlpineError::Collision` gains `directory`, naming the package that ships the
  path as a directory.
- An Alpine resolution no longer depends on the order `include` names packages
  in, and `/etc/apk/world` lists them sorted. A closure no longer holds two
  packages for a name only one may answer, a package's own name or a name
  provided at a version, which `apk` never installs together: it is resolved
  again keeping each in turn, and refused naming them where none holds. A
  layered build refuses an increment whose provider contends with a package the
  base carries.
- An Alpine closure leaves out a package whose `install_if` condition it meets
  where taking it, or what it requires, breaks a `!` entry in either direction,
  as `apk` does. The closure was refused instead, so `rofi-wayland` and five
  `rofi` plugins could not be resolved. A provider its own `install_if`
  condition brings in now answers a name ahead of the others, whatever version
  it offers, as in `apk`, so a `rofi` plugin, which requires `cmd:rofi`, takes
  `rofi-x11-wayland`.
- A Gentoo plan replayed over a root refuses, before merging anything, a build
  with a runtime or post-merge dependency that neither the root nor the plan
  answers, as a resolution would have. Such a plan was installed without the
  dependency.
- `GentooBuilder::build` refuses a `Stage3` resolved for another architecture
  than the builder's, or whose variant or build id differs from one the builder
  names, as it refuses a plan resolved for other coordinates. Such a `Stage3`
  fetched its tarball from under the builder's architecture, or, from a cache
  shared with the other architecture, provisioned a root for it.
- An overlay root whose upper or work directory lies inside a lower is refused
  at build with the new `ConfigError::OverlayLayersOverlap`, before anything is
  created on the host. The kernel mounted such an overlay, and every write the
  sandbox made landed in that lower. The overlaps the kernel refuses at mount
  are refused at build the same way: a lower inside the upper or the work
  directory, the upper and the work directory nested, and two lowers nested or
  the same.
- A command whose exit a tracer holds no longer keeps the supervisor polling in
  a loop. Under a PID namespace the init ends the namespace's other processes
  once the command has exited, so a tracer no longer holds the outcome from
  `run` and `wait`; without one the launch stage waits until the tracer lets
  go.
- A launch takes its launch stage's pidfd from the fork that creates the stage,
  and so does every helper process the library forks: an export's, a copy-in's,
  and a removal's, the overlay and seccomp probes, and the network stack's tap
  helper. Each is signalled and reaped through that pidfd, so a caller that
  reaps its children elsewhere, with `waitpid(-1)`, can no longer have the
  library signal or wait for an unrelated process that took one's pid.
- A capability drop removes every capability the running kernel defines from
  the bounding set. A capability past the last one rustix names, as a later
  kernel adds, stayed in it.
- A TCP flow the network stack aborts at its establish deadline or its hangup
  deadline resets the guest. The reset was discarded with the flow's socket, so
  a guest whose connection to an unanswering destination had already
  established on its side waited indefinitely.
- A reset from the guest, and every other way a TCP flow ends short of both
  sides closing in order (a timeout, a deadline, a host-side failure, the stack
  stopping), reaches the host peer as a reset. The guest's reset reached it as
  an orderly end of stream, so a server reading an upload to its end accepted a
  truncated one as complete. A published connection the guest refuses is
  likewise reset on the host side rather than closed. A guest that finishes
  while a slow host is still taking its last bytes no longer loses them.
- A TCP flow whose host side closes first forwards the guest's last bytes
  however long the host takes to read them. Where the guest sent them with the
  FIN that answers the host's, and the host had not taken them within ten
  seconds, the network stack discarded them as the guest's socket left
  TIME_WAIT, and then reset the host.
- `relay::restore_terminal`, and the hook `relay::install_panic_restore`
  installs, restore the caller's terminal during a panic only where the panic
  ends the session or the process: on the thread the session runs on, on the
  main thread, or in a build that aborts on panic. A panic on any other thread,
  the network stack pump's among them, which the library catches, restored the
  terminal under a session that went on, so `fcage --terminal --netstack`
  carried on in cooked mode with the caller's `^C` ending the command.
- The network stack reclaims a TCP flow, with a reset to each peer, once one
  peer has finished sending and the other has taken nothing of what it sent
  for 100 seconds, whichever peer finished. A guest that never read the tail of
  a host's stream once all of it, the host's end included, fit in the stack's
  buffer, and a host that never read what a guest sent before its FIN or reset,
  each held a flow slot, its buffers, and a host descriptor until the sandbox
  ended.
- `NetStackBuilder::build` refuses an interface name holding `%`. The kernel
  took such a name as a template and named the interface itself, so the stack's
  configuration of it failed at attach with "No such device".
- `NetStackHandle::stop`, and dropping a handle, reach the stack's pump at
  once. The stop was the close of a pipe, which a process forked while the stack
  ran kept open with its copy: another launch's stage until it closes the
  descriptors it inherited, or a child of the caller's own until it executes.
  The stop waited on the pump for that long.
- A terminal session in the background no longer reads the caller's terminal.
  A line typed at the shell stopped it with `SIGTTIN`, and the `fg` that
  continued it left it inside a read of a cooked terminal, relaying nothing and
  answering neither a deadline nor an interrupt until another line was typed.
- `CopyIn` copies extended attributes the rootfs's root can set: `user.`
  attributes, POSIX access control lists, and file capabilities. A list's named
  users and groups and a capability's root are read through the identity map
  as an owner is. Every attribute was dropped before, while the report said the
  copy was complete, and a dropped list with a mask left the owning group with
  the mask's access. A list that cannot be copied is now reported and the entry
  given the list's narrowing, so the owning group keeps only what the list gave
  it.
- The tar extractor applies the POSIX access control lists an `Export` records
  (`SCHILY.xattr.system.posix_acl_access` and `..._default`), their named ids
  read through the identity map, a directory's once its contents are written. A
  list it cannot apply is given as its narrowing. The pre-configure overlay,
  which lays no attributes, gives an entry whose source carries a list the same
  narrowing.
- `Export` spells an extended attribute whose name holds `=` or `%` as GNU tar
  spells it in a `SCHILY.xattr.` keyword, `%3D` and `%25`, so the name reads
  back whole.
- A hard link onto a name that already holds its target is taken as done, as
  GNU tar takes it, by the extractor and by `CopyIn`. A link naming itself, as
  GNU tar writes for a path listed twice, or reaching its target through a
  merged-usr alias, removed the file and then failed; `CopyIn` failed part-way
  through a tree.
- The Debian and Alpine pre-configure overlay lays a source directory its owner
  cannot write, `0555` or `0500`, together with its contents, and gives it its
  mode once they are written. It failed with a permission error for a caller
  other than root. A directory a layered build carries up from its base meets
  the same rule.
- The tar reader retries a read a signal interrupted. An archive streamed
  through `Tarball::from_reader` over a pipe or a socket failed on the first
  signal whose handler does not restart the calls it interrupts.
- A `file://` fetch through `HttpFetch` no longer waits on a named pipe at the
  path: anything that is not a regular file is refused at once, as a transport
  failure a mirror walk advances past. The fetch is held to `request_timeout`
  as an `http://` one is.
- A bootstrap given a `source_date_epoch` reads an account `/etc/shadow` names
  twice by its first line, as `getspnam` does.
- The `hardening` feature builds for x86, where the curated roster named
  `kexec_file_load`, which i386 lacks. The build refuses a `Rules` policy there
  with `ConfigError::SeccompUnsupportedArch`, as on every 32-bit target, and the
  layer's Landlock rules and capability drops apply.
- A launch keeps its own descriptors off the standard streams' numbers. A
  caller that had closed one of descriptors 0, 1 and 2 had a launch channel
  take the number, and wiring the command's streams replaced the channel in
  the command process: a command that failed to execute was reported as
  running, with the setup's failure record in its captured output. A launch
  with a cgroup was refused with `Error::StreamIsDirectory` where the cgroup's
  directory took a closed stream's number. A standard stream the caller has
  closed now reaches the command closed unless the launch wires it, and stays
  closed in the caller through the launch.
- `fcage --help` names `--no-stop-with-caller` among the counterpart toggles,
  where it named `--stop-with-caller`.
- `fcage --seccomp-allow` and `--seccomp-deny` refuse a value that names no
  syscall, such as the empty value an unset variable expands to, as a usage
  error. Such a value launched with no seccomp filter from the flag, or under a
  profile's policy beside a profile.
- A launch whose supervisor's pidfd does not reach the caller ends with the
  new `Error::SupervisorUnreceived`. The kernel delivers the launch stage's
  message without the descriptor where the caller has no descriptor number
  free, or a security module refuses it. Such a launch was handled as one
  whose supervisor was never published: `Cage::spawn_pending` without a PID
  namespace never returned, `Cage::spawn` without one returned only once the
  command had run to completion, and with a PID namespace the sandbox ran on
  with no handle. The launch now asks the supervisor to end the sandbox over
  the control socket, and returns once the launch stage has exited.
- A file bind beneath a hidden path with nothing at it no longer leaves its
  target in the root. The hide mounts nothing there, so the launch created the
  target in the root itself, and the build had counted it as created inside
  the hide's own tmpfs and kept it from the targets removed once the sandbox is
  gone. A hidden path now covers a later target only where the root holds an
  entry at it when the sandbox is built. On the host's own root, such a target
  is refused at build with `ConfigError::MountTargetMissing` where the host
  lacks it, rather than failing the launch.

### Internal

- CI runs `fcage` inside Docker, from a stock image, under the generated
  seccomp profile, Docker's own profiles, and an unmasked procfs, and asserts
  what the container chapter says of each.
- The classic-BPF vocabulary, the seccomp install, and the unit tests'
  interpreter of a seccomp program moved from the hardening layer to
  `mechanism::seccomp`, which the network filter and the hardening layer share.
- The pre-configure overlay walks its source by descriptor, as `CopyIn` does,
  and opens each file with `containment::open_typed_file`.
- The Gentoo layer spells a database entry's `COUNTER` file once, beside
  `DB_DIR`, and reads a container's metadata files through the one conversion
  the root's reader uses.
- The relay and the supervisor open their signal descriptors through one
  `mechanism::sys::signalfd`.
- The network stack's tap helper and the listener `Pending::listen` makes run on
  one helper, `mechanism::netns`, which joins the sandbox's user and network
  namespaces and hands one descriptor back. `NetStack::attach` refuses a
  `Network::Host` sandbox by the network it was built with rather than by
  comparing namespace links.
- CI runs clippy over every target for x86, 32-bit arm, aarch64, and riscv64,
  the architectures beside the runner's that the library builds for.
- The relay suite reads the caller's terminal to its end once a session
  returns. It stopped reading as the session ended, so a test of all of a
  command's output failed whenever the relay ran ahead of the reader.
- A digest the crate takes of a stream, through `digest::stream`,
  `digest::stream_each` or a `DigestWriter`, is a `Digest`, as one of bytes in
  hand through `Digest::of` is.
- The test of a reaped child's processor time measures the child's work in
  processor time, as its own `/proc` record states it, rather than in wall
  time, which a preempted or throttled child is charged less than.
- Every test skip is also appended to the file `FERRODAY_CAGE_SKIP_LOG` names,
  one line each, and CI lists the skips its test steps logged.
- The restriction suites take the grants a host binary runs under from one
  `common::grant_system_trees`.

## [0.5.2] - 2026-11-10

`fcage` 0.6.1, which requires library 0.5.2 and changes nothing else.
`cargo install --locked` builds `fcage` from the lockfile it was published with,
which for 0.6.0 names irongall 0.1.1 and for 0.6.1 names 0.1.2.

### Security

- The library requires irongall 0.1.2, with which the Debian and Gentoo layers
  verify an archive's signed documents. irongall 0.1.0 and 0.1.1, which earlier
  releases admitted, could disregard a revocation, or a newer self-signature
  narrowing an older one, that an unsigned change to its certificate left in
  place, and so accept a signature made with a key the certificate withdraws.
  The library reads certificates only from the keyrings it embeds and the files
  its caller names, so earlier releases were exposed only through a keyring
  file that someone other than the caller could alter.

## [0.5.1] - 2026-11-02

`fcage` 0.6.0, unchanged. Its dependency on the library is a caret range over
0.5.0, which 0.5.1 satisfies, so a fresh install of it builds against this
release.

### Fixed

- A Debian release that lists a component under a prefix, as the security
  archive lists `updates/main`, offers it under the part after the last `/` as
  well, as apt reads the field. A repository naming `main` against
  `debian-security` was refused before any index was read.
- A Debian release with no `Architectures` field offers every architecture,
  and one with no `Components` field every component, as apt reads them. Such a
  release, which `apt-ftparchive release` writes unless configured otherwise,
  was refused. An index the release lists no digest for is still refused.

## [0.5.0] - 2026-11-01

`fcage` 0.6.0. Entries below marked **Breaking.** change the library's API and
behaviour and `fcage`'s flags, exit codes and output, so both take a new minor
version. `fcage` requires library 0.5.0.

### Security

- Every launch, of a sandbox or a restriction, refuses a directory on a standard
  stream it hands to the command, with the new `Error::StreamIsDirectory`. A
  directory descriptor, inherited or given through `Stdio::from_fd`, let the
  command walk the host's filesystem from it by path, past the sandbox's root.
  The launch refuses one before it creates anything.
- **Breaking.** Every launch, of a sandbox or a restriction, gives the command a
  fresh session keyring in place of the caller's. A sandboxed command previously
  inherited the caller's session keyring, so it possessed, and could read
  through `keyctl`, every key the caller's login session held. It possesses none
  of them now, and a command that used one no longer finds it. Each running
  command's keyring counts against the calling user's kernel key quota, and a
  launch that finds the quota exhausted fails with `Error::KeyQuotaExhausted`.
  Two reaches remain. A key whose permissions grant its owner read stays
  readable, since the command runs as that owner. A restricted command can also
  link the calling user's user, user session, and persistent keyrings into its
  own and read their keys, which a sandbox's own user namespace prevents. The
  curated seccomp policy, which denies `keyctl`, closes both. Key descriptions
  stay listed in `/proc/keys`.
- **Breaking.** A restriction confines its command's signals, and its
  connections to abstract sockets, to the processes it started, on a kernel
  with Landlock ABI 6 (Linux 6.12) or later. A restricted command could
  previously signal every process of the calling user, and reach the session
  bus and the X server through their abstract sockets. On such a kernel every
  restriction also has a Landlock domain, which refuses it ptrace access to
  processes outside it, `/proc/<pid>/environ` among them. A caller whose
  command needs either reach names fewer scopes through
  `RestrictionBuilder::landlock_scope`, or `fcage --landlock-scope`. On an
  older kernel, or one without Landlock, the default scopes are dropped, and a
  scope named that way is refused at `build` with
  `ConfigError::LandlockScopeUnenforceable`. An empty list names none and builds
  on every kernel.
- **Breaking.** `fcage`: a standard stream that is a regular file or a block
  device is relayed through a pipe rather than handed to the command. A command
  could previously reopen such a file through `/proc/self/fd` with more access
  than the stream carried: rewrite a file given as standard input, or read back
  and truncate a log opened for appending. Input the command does not read is
  returned to the file, so the next reader starts where the command stopped, and
  two output streams on one file keep the order the command wrote in. A relayed
  standard input puts the command in a session of its own, as `--stdin null`
  does, so it has no controlling terminal and `/dev/tty` fails to open. A stream
  that is neither a pipe, a socket, a character device, nor a file, such as a
  directory, is refused. A refused stream, and a relay that cannot read the
  input or deliver the output, exit 125. `fcage` is not dumpable during a
  restricted run, so a restricted command cannot reopen the file through
  `fcage`'s own descriptors.
- An overlay layer path holding a `\` names the directory it names. Overlayfs
  unescapes every layer path it is given, so an upper written `up\x` was
  mounted as `upx`, and the sandbox's writes landed in a directory other than
  the one whose ownership the build had checked. Layer paths are escaped in the
  mount options.
- A seccomp `Dword` condition whose value or mask is wider than 32 bits is
  refused at `build` with `ConfigError::SeccompInvalid`. It was truncated, so
  `masked_eq_dword(0, 1 << 32, 0)` masked with zero and matched every call, a
  filter more permissive than the one configured.
- **Breaking.** The curated seccomp policy denies creating a namespace. It also
  denies `open_tree_attr`, the mount API's newest call, and `pidfd_getfd`, which
  copies a descriptor out of another process under the same check
  `process_vm_readv` makes. `unshare`, and `clone` whenever its flags create a
  namespace, fail with `EPERM`. `clone3` is answered `ENOSYS`, from which the C
  library falls back to `clone`, so processes and threads start as before. A
  command that builds a sandbox of its own, such as a browser, a container
  runtime, or `fcage`, needs a policy of its own.
- On x86_64, the guard a denylist seccomp filter carries against the x32
  syscall ABI answers every x32 syscall `ENOSYS`. It answered with the policy's
  listed action, so a listed action that lets a syscall run, such as
  `SeccompAction::Log`, let every x32 call through, past an errno the policy
  gave that syscall.
- **Breaking.** A sandbox's Landlock filesystem grant no longer follows a
  symbolic link on its path. A grant whose path crosses a link, at any
  component, fails the launch with `ELOOP` at `SetupStep::LandlockAddRule`,
  reported against the grant, rather than covering wherever the link points. On
  a root where `/lib` is a link to `usr/lib`, grant `/usr`. A restriction's
  grants are host paths and still follow the host's links.
- A read-only bind is made read-only before it is attached: the host tree is
  cloned detached, restricted, and moved onto the target the setup resolved. It
  was attached and then remounted by path, so a sandbox sharing a writable root
  could rename between the two and leave the bind writable. Before Linux 5.12
  the remount still follows the attach, through the bind's own descriptor
  rather than its path.
- The network stack refuses AWS's IPv6 instance-service block, `fd00:ec2::/32`,
  whose metadata service at `fd00:ec2::254` serves the instance role's
  credentials. The IPv4 metadata service was already refused as link-local.
- The network stack holds an address under NAT64's well-known prefix,
  `64:ff9b::/96`, to the rules for the IPv4 address it embeds. A guest could
  reach `169.254.169.254`, the host's loopback, or its own IPv4 subnet through a
  NAT64 translator on the host. Every other IPv4 destination stays reachable
  that way.
- Verifying a signed document no longer recurses without bound. rPGP 0.20, which
  irongall replaces, parsed nested embedded signatures by unbounded recursion. A
  signed document fetched from a mirror (a Debian `InRelease`, a Gentoo pointer,
  digest document or binary package Manifest) could exhaust the stack and abort
  the process before any signature was checked.
- The `ruzstd` floor moves to 0.9.1. ruzstd 0.9.0 let a crafted zstd block
  decode past the format's block size, outside the window cap
  (RUSTSEC-2026-0344), which `Tarball` and the unsigned Gentoo binary-package
  index reached.
- A zstd stream of many frames decodes in time linear in their number. Each
  frame wrapped the stream in one more reader, so a stream of a hundred thousand
  empty skippable frames took seconds to decode, and exhausted the stack in a
  build without tail-call optimization. The unsigned Gentoo binary-package index
  reached it.
- Verifying a signed document is bounded before it is parsed: at most one
  mebibyte and 16 signatures. A cleartext document is framed in time linear in
  its length. Framing one and checking each signature against each key cost more
  than the document's length, so a mirror serving a crafted `InRelease`, Gentoo
  pointer, digest document or binary package Manifest could make the host spend
  minutes of CPU before any signature was accepted. A Debian `InRelease`, and the
  `Release` of a mirror trusted unsigned, is fetched under the same one-mebibyte
  ceiling, where nothing bounded it but the bundled client's body limit. The
  Gentoo pointer document's ceiling drops from one mebibyte to 64 KiB, and a
  binary package's Manifest from four mebibytes to one.
- A certificate's primary key verifies a document only where the certificate's
  own self-signatures grant it the signing capability, and a self-signature that
  states no key flags grants none. A certify-only primary, as several of
  Gentoo's vendored service keys are, was accepted as a signer for the stage3
  pointer, digest documents and binary package Manifests. Six of Gentoo's
  eleven vendored certificates can no longer sign, and `Gentoo::keyring_horizon`,
  and so `fcage --gentoo-keyring-horizon`, reports four that can.
- Only a text signature verifies a cleartext-signed document. A standalone or
  timestamp signature by an archive key covers no document, and rPGP verified
  one against any body sharing its first byte.
- The Debian provisioner bounds a package index's decompression by the
  uncompressed length the signed release states for it, or by 256 MiB where the
  release states none, and refuses an index that expands past it. A few
  megabytes of compressed index could expand without bound in memory.
- The Gentoo binary-package index, which nothing signs, is read only as gzip or
  plain text, the two forms the archive publishes. It is refused rather than
  truncated when it decompresses past 64 MiB, three times the largest the
  archive publishes, where the ceiling was 256 MiB. It is read one stanza at a
  time, in place, and a dependency class is parsed only for a build a
  resolution chooses; a record whose class runs past 64 KiB is skipped. Reading
  it cost up to about 47 times its length in memory, some 12 GB at the old
  ceiling, and now costs at most about three times. Its parser bounds how
  deeply dependency groups nest, at 16 levels, skipping a stanza that nests
  deeper as it skips any other unreadable stanza, and splits a
  `category/name-version` in time linear in the line's length. A few tens of
  kilobytes of parentheses from a mirror overflowed the stack and aborted the
  host process, and a line of hyphens cost the square of its length.
- Ordering a Gentoo install takes memory linear in the resolution. An unsigned
  binhost index could make it quadratic: a chain closed by a two-package loop
  made every round report every package still waiting as a cycle, 1.8 GB for
  8,000 index records. Each cycle is now found once, and
  `GentooEvent::DependencyCycle` names its members once, in name order. A cycle
  is broken only where it waits on nothing outside itself, and a runtime
  dependency orders its dependent after the build that answered it.
- A Gentoo resolution is bounded in the work an unsigned index can make it do.
  An atom nothing answered was matched against every build of its name twice,
  once to choose and once to explain. Many builds of one package and many
  distinct atoms naming it cost their product: minutes of CPU for under a
  megabyte of index. What the index offers an atom is now worked out once per
  spelling. A resolution refuses an index that makes it choose more than 16,384
  builds, choose builds stating more than 262,144 dependency atoms, or hold
  atoms against more than 4,194,304 candidates, each far past what resolving the
  whole archive takes.
- An Alpine bootstrap matches a trigger's path pattern in time bounded by the
  pattern's and the path's lengths. A pattern of many `*`s, from a package's
  signed metadata or a layered base's `triggers` file, could hold the bootstrap
  for minutes per directory.
- A layered Alpine build reads its base's trigger state in time and memory in
  proportion to the base. One package is one trigger however many lines name it,
  and a base watching more than 4096 paths is refused. A base whose scripts had
  rewritten `lib/apk/db/triggers` and `scripts.tar` could exhaust the host's
  memory or CPU in the next `stage_layer`. A trigger matching more than 16,384
  directories is refused, naming the package.
- A package or tarball downloaded into a cache is checked before it is renamed
  into place, in every layer, so another run sharing the cache never reads
  unverified bytes there. The Alpine and Gentoo layers published a complete body
  first and checked it on the read that followed. A cache entry is opened only
  when it is a regular file: a symbolic link or a named pipe planted at a cache
  path reads as a missing entry and is replaced, rather than followed out of the
  cache or waited on.
- The Gentoo stage3 is extracted from the descriptor its SHA-512 was taken
  through, so another run renaming a download over a shared cache entry between
  the check and the extraction cannot substitute unverified bytes.
- The Gentoo binary-package cache keys each container by its full archive path,
  architecture, generation and binhost included, so binhosts sharing a
  `cache_dir` no longer serve each other's builds: an `x86-64-v3` build could
  reach an `x86-64` root. Containers cached under the previous layout are not
  read again and can be deleted.
- A Gentoo binary package is held, once its Manifest verifies, to the root it
  merges into and to what the resolution read about it. Its signed `CHOST` must
  be one the root's own packages were built for. A root whose database states
  none takes the first package's, so a replayed plan naming two targets merges
  nothing. Its `SLOT`, `USE`, `IUSE`, `RDEPEND`, `PDEPEND` and `BUILD_TIME` must
  be what the unsigned index stated, and its MD5 the index's. A mirror could
  substitute another architecture's or C library's genuine build, or describe a
  build other than the one it served. Binhosts sharing a target, such as
  `x86-64` and `x86-64-v3`, cannot be told apart by anything Gentoo signs, and
  the guide states that limit.
- A Gentoo binary package holding more than 16 entries is refused as the
  entries arrive, before its Manifest is read. A mirror could make the scan
  that precedes verification spend hours of CPU on millions of empty members.
- A Debian bootstrap with a `cache_dir` installs from a copy of each package in
  a directory only the run writes, so dpkg reads the bytes the extraction
  verified. It re-read each package from the shared cache, by path, minutes
  after verifying it. A `cache_dir` that is that directory itself, under
  whatever path names it, is used as it stands and kept.
- A Debian bootstrap initializes the dpkg database through the tree's own root,
  so a package that ships `var/lib/dpkg` or `var/lib/dpkg/status` as a symbolic
  link out of the tree cannot make the bootstrap create files on the host.
- A Debian repository's mirror URL holding whitespace or a control character is
  refused at `build`. It is written verbatim into the finished root's
  `sources.list`, where a space split the line and a newline added a source of
  its own.
- Publishing into a `debian::Pool` follows no symbolic link and waits on no
  named pipe. `Pool::publish` opens each `.deb` it is given only where its path
  holds a regular file, and refuses anything else as `DebianError::Io` naming
  the path. A build pipeline publishes from a directory its build sandbox wrote.
  A planted `x.deb` link there made the host copy a file of the sandbox's
  choosing into the pool, and a planted pipe hung the publish. Inside the pool,
  a link or a pipe where a package or an index copy belongs is replaced, and one
  where the index being merged into belongs fails the publish.
- Laying a tree down sets no mode by name. A chmod by name follows a symbolic
  link at the entry, so a process racing the tree between an entry's creation
  and its mode could have the mode applied to a file of its choosing.
  Extraction, the pre-configure overlay, the host-side writes into a provisioned
  root, and overlay layer creation set each mode through a descriptor for the
  entry they created. `CopyIn` applies the source tree's modes from inside the
  identity map, and removing a tree sets none.

### Added

- `Error::KeyQuotaExhausted`, reported when the calling user's kernel key quota
  leaves no room for the sandbox's session keyring, with the `EDQUOT` as its
  source, and `SetupStep::ReplaceSessionKeyring`, the step that replaces it.
- `SetupStep::AllocateTerminal` and `SetupStep::SendTerminal`, the steps a
  terminal launch's allocation now reports under.
- `LandlockScope`, `ParseLandlockScopeError`, `CageBuilder::landlock_scope`, and
  `RestrictionBuilder::landlock_scope`, which confine a command's signals or
  abstract-socket connections to the processes of its own Landlock domain. A
  sandbox takes none by default and needs one only where `pid_namespace(false)`
  or `Network::Host` exposes the host's processes. A scope nothing else bounds,
  a sandbox's there or any a restriction names, is refused at `build` with
  `ConfigError::LandlockScopeUnenforceable` on a kernel below Landlock ABI 6.
  Profile key `landlock-scope`; `fcage`: `--landlock-scope LIST`.
- `SeccompRules::errno_for`, which answers one syscall with an errno of its own
  ahead of the policy's actions. Profile: an `errno` table in
  `[hardening.seccomp]`; `fcage`: `--seccomp-errno SYSCALL=ERRNO`, which joins
  the seccomp policy the other flags or a profile set, and is refused beside the
  curated one.
- `SeccompRules::syscall`, which reads a syscall's number on the host
  architecture from its name, and `SeccompRules::errno`, which reads an errno
  from its name, in any letter case, or from its number. A profile's seccomp
  table and `fcage`'s seccomp flags read names the same way. `errno` refuses a
  value no failed syscall reports, outside 1 to 4095.
- `CageBuilder::mount` and `CageBuilder::mounts`, which add a `Mount` of either
  kind to the one mount sequence, so a sequence read back through `get_mounts`
  carries over to another builder whole.
- `RestrictionBuilder` reports its configuration through the getters
  `CageBuilder` has for the settings the two share: `get_command`, `get_args`,
  `get_envs`, `get_base_env`, `get_current_dir`, `get_stdin`, `get_stdout`,
  `get_stderr`, `get_stop_with_caller` and `get_rlimits`.
- `CageBuilder::get_landlock_fs`, `get_landlock_net`, `get_landlock_scope`,
  `get_seccomp` and `get_keep_capabilities`, which read a builder's hardening
  posture as the other getters read its settings. A consumer vetting a profile
  it did not write can read it whole, and extend its seccomp rules rather than
  replace them. `get_keep_capabilities` answers for both capability setters:
  `None` leaves the capabilities alone, and an empty list drops them all.
- `RestrictedProfile` implements `TryFrom<CageBuilder>`, which holds a builder
  to the restricted policy and returns `ConfigError::ProfileOperationForbidden`
  as a value. Deserializing a `RestrictedProfile` reports the same refusal
  through the serde format's own error.
- `ResolvedInputs::run_as`, the `Identity` the command switches to,
  `ResolvedInputs::no_new_privileges`, `ResolvedInputs::pid_namespace`, and
  `ResolvedInputs::hostname`, the name the command sees, the host's own where
  none is configured. A hardening posture that requests Landlock records
  `ResolvedHardening::Applied::landlock_abi`, the kernel's ABI its requests are
  narrowed to. A record previously read the same for two builds that differed
  in any of these.
  `Identity::get_uid`, `get_gid` and `get_groups` read the identity it reports,
  as they read `CageBuilder::get_run_as`.
- `ConfigError::OverlayOptionsTooLong`, refusing an overlay whose mount options
  exceed the 4095 bytes `mount(2)` passes on whole. The kernel cut a longer
  string short, and the remainder could mount a different work directory.
- `ConfigError::IdentityMapUnavailable::source`, the configured identity-map
  delegate's own error, which `source()` now returns.
- `RangeMapBlocker::NoNewPrivileges`, which `host::range_map_blocker` reports for
  a caller running under `no_new_privs`.
- `Error::KillHandle`, which `Running::kill_handle` returns where it cannot
  duplicate the handle's descriptors. It returned `Error::Signal`, though nothing
  was signalled.
- `ExitStatus::exited` and `ExitStatus::signaled`, which build the status a
  command would report, for a caller that reports an outcome of its own in the
  same convention.
- `ErrorChain`, which renders an error and every cause beneath it on one line,
  as `error: cause: cause`. `fcage` and the examples print every error through
  it.
- `NetStackBuilder::host_loopback_port`, which maps connections to the gateway
  address on one port onto host loopback, where `host_loopback(true)` maps every
  port. The two combine. `fcage`: `--netstack-host-port PORT`.
- `NetStackBuilder::publish`, which publishes a TCP port of the guest on a host
  address: `attach` listens there and carries each accepted connection to the
  guest. Published connections count against a budget of their own, 128 at
  once, so a peer holding them open cannot exhaust the guest's outbound
  connections. `NetStackHandle::published` reports the bound addresses,
  including a port the kernel chose for port 0. `NetStackError::PublishInvalid`
  refuses a publication at build, and `NetStackError::Publish` reports a
  listener that could not bind. The profile keys are `host-loopback-ports` and
  `[[publish]]` tables of `host` and `guest-port`. `fcage`: `--netstack-publish
  HOST GUEST_PORT`, which reports a kernel-chosen port on standard error and
  refuses a guest port of 0 as a usage error.
- `NetStack::forwards`, which answers whether the stack carries the guest's
  traffic to a destination: the forwarding policy every attachment applies,
  asked of one address.
- `provision::Remove::overlay_upper`, which removes the upper layer of an
  overlay root together with the work directory the library manages beside it,
  and leaves the publication lock alone. `provision::remove`, which the guide
  had named for this, leaves the work directory behind. `fcage`:
  `--remove-overlay-upper DIR`, which takes `--identity-map` as
  `--remove-rootfs` does.
- `ProvisionError::RemoveDestInvalid`, with which `provision::remove` and
  `Remove` refuse a destination that names no tree: an empty path, or one with
  no final component such as `.`. An empty path succeeded having removed
  nothing, and `.` was refused in a publication's words, "cannot publish a
  rootfs".
- `DebianBuilder::id_mapper` and `AlpineBuilder::id_mapper`, which supply the
  delegate that establishes a range identity map: for the preflight, for every
  sandbox the bootstrap's package scripts run in, and for the removal of a
  staged layer. A map only a site-specific delegate establishes could not be
  provisioned before.
- `Box<F>` implements `Fetch` for any transport `F`, and `Arc<M>` and `Box<M>`
  implement `IdMapper` for any delegate `M`, each forwarding every method. A
  transport or a delegate chosen at run time is passed as a `Box<dyn ..>`, and
  one delegate instance is named to several builders as an `Arc`.
- `DebianBuilder::source_date_epoch`, which gives every maintainer script
  `SOURCE_DATE_EPOCH`, so the accounts a bootstrap creates record the epoch's
  day in `/etc/shadow` rather than the day it ran. An epoch in the first day of
  1970 records no day, as `useradd` does; the zero `systemd-sysusers` writes for
  it is emptied once the scripts have run. A negative epoch is refused at
  `build`. `fcage`: `--debian-source-date-epoch EPOCH`, which refuses a negative
  epoch as a usage error.
- `AlpineBuilder::source_date_epoch`, which gives every install script
  `SOURCE_DATE_EPOCH` and dates the accounts a bootstrap creates by the epoch's
  day. busybox's `adduser` reads the clock whatever the environment says, so the
  days the run wrote into `/etc/shadow` and `/etc/shadow-` are rewritten once
  the scripts have run. An epoch in the first day of 1970 records no day, as
  `useradd` does. A negative epoch is refused at `build`. `fcage`:
  `--alpine-source-date-epoch EPOCH`, which refuses a negative epoch as a usage
  error.
- `debian::PlannedPackage::size` records the length of the `.deb`, written as
  `Size` in a plan document. Installing a plan holds each download to it.
- `DebianError::Cancelled`, which `Debian::observe(..).resolve()` and
  `.available()` return when the observer cancels. They stop at each mirror the
  release and index walks ask, and a bootstrap also stops before each dpkg wave.
- `debian::Priority::ALL`, every Debian priority band, most essential first.
- The Debian provisioner recognizes `loong64`: a `loongarch64` host maps to it,
  a foreign bootstrap's preflight looks for the `qemu-loongarch64` handler, and
  the root gets the `/lib64` link the architecture's loader lives under.
- `AlpineError::Ownership`, which fails an Alpine bootstrap whose entry could
  not be given the owner its package states.
- A Gentoo provision keeps the stage3's signed digest document beside the
  tarball in `cache_dir`. A resolution reads that copy before asking the
  archive, and verifies it at every use. A pinned build id then provisions from
  a populated cache after the archive has dropped the build, for as long as the
  key that signed the document is in force.

### Changed

- **Breaking.** irongall verifies OpenPGP signatures in place of `pgp`. It
  accepts keys of Ed25519, and of RSA from 2048 to 8192 bits, over SHA-2 and
  SHA-3 digests. A signature by an ECDSA or Ed448 key no longer verifies. A
  caller's keyring holding no other key is refused by `DebianBuilder::build`
  and `debian::RepositoryBuilder::build`. A signature naming such a key as its
  issuer is refused as one, naming the key.
- A signature dated more than 30 minutes after the host's clock is refused, and
  on a host whose clock reads before 1970 every signature is. A future-dated
  signature was accepted, and a clock before 1970 skipped the expiration checks.
- **Breaking.** A signature by a key that has since expired is refused, though it
  is dated within the key's lifetime. It was accepted, so `allow_stale_release`
  could resolve a historical archive state whose signing keys had all expired;
  apt refuses it. Installing a kept Debian plan verifies no release, and is
  unaffected. A Gentoo plan, a pinned stage3, and a cached binary package are
  verified at every use, and stop verifying once the key that signed them
  lapses.
- A certificate whose governing self-signature rests on SHA-1 and was made on
  or after 1 February 2023 verifies nothing. One made over SHA-1 before that
  date still grants what it states, as every SHA-1 self-signature did.
- Where a release carries several acceptable signatures, a Debian plan's
  `Signed-By` and `Signing-Key` record the first in the order the release
  carries them. They recorded the signature of the first certificate in the
  keyring that had made one. A plan for Debian 12 names its archive automatic
  signing key, where it named its stable release key.
- A `debian` build depends on 23 crates, counting this one, where it depended on
  163, and a `gentoo` build on 24: irongall has no dependencies of its own. Both
  decode gzip through `miniz_oxide` alone, where `pgp` had selected `flate2`'s
  zlib-rs backend. An `alpine` build depends on 23, where it depended on 52: it
  verifies an apk index's signature through irongall too, and no longer depends
  on `rsa` or `sha1`.
- **Breaking.** An Alpine signing key is read and verified by irongall, where
  the `rsa` crate read it. `alpine::KeySet::insert` refuses a key whose modulus
  is narrower than 2048 bits, the floor every RSA key the crate verifies with is
  held to, or whose exponent is even, and accepts one up to 8192 bits, where the
  ceiling was 4096. Every key Alpine and postmarketOS publish is 2048 or 4096
  bits. A key is read only as `abuild-keygen` writes it, an RSA
  `SubjectPublicKeyInfo` in a PEM `PUBLIC KEY` block.
- **Breaking.** A terminal launch allocates its pseudoterminal inside the
  sandbox, from the `/dev/ptmx` the command sees, rather than on the host before
  the fork. `ttyname` now names the terminal, so `tty`, `who`, and `GPG_TTY`
  work inside, and under a `run_as` identity the replica belongs to that
  identity. The allocation needs the managed `/dev` or a `devpts` instance the
  caller mounts: a terminal launch with `mount_dev(false)` or
  `managed_mounts(false)`, in a root that ships no `/dev/ptmx`, previously ran
  on a host pseudoterminal and now fails with `SetupStep::AllocateTerminal`. A
  restriction's terminal still comes from the host's `/dev/ptmx`.
- `Cage::spawn_pending`, `spawn_pending_with` and `spawn_pending_terminal`
  return once the command is at its gate, with every namespace and mount in
  place. A setup step that fails before the gate is reported by the pending
  launch rather than by `Pending::proceed`. `Pending::netns_pid` names a process
  that stays alive until the handle is consumed or dropped.
- `Running::wait` and its deadline forms return once the supervisor has exited,
  rather than as soon as the command's status arrives. With a PID namespace that
  is after the kernel has torn the namespace down.
- **Breaking.** A working directory, for a sandbox or a restriction, is held to
  the rule every configured absolute path is: a `..` component is refused at
  `build` with `ConfigError::WorkdirNotAbsolute`. Its message now reads "not a
  normal absolute path".
- **Breaking.** A seccomp policy that answers a syscall with errno 0, or with a
  number past 4095, is refused at `build` with `ConfigError::SeccompInvalid`.
  That covers a `SeccompAction::Errno` listed or default action and
  `SeccompRules::errno_for`. Zero made a syscall report a success it never
  performed, and the C library reads a larger number as the value the syscall
  returned.
- A profile naming `identity-map = "subordinate"` loads in a build without the
  `subid` feature, and `build` decides. A configured `id_mapper` that reports an
  allocation establishes it, and without one the build refuses it, naming the
  feature. It was refused as it loaded, so such a profile could not round-trip.
- **Breaking.** A Debian bootstrap, and a layered build's increment, keeps no
  record of its run. Once its last configure wave has run it removes
  `/var/log/dpkg.log`, `/var/log/alternatives.log`,
  `/var/cache/ldconfig/aux-cache`, and `/var/lib/dbus/machine-id`, and empties,
  in place, an `/etc/machine-id` a package wrote, keeping the owner and mode the
  package gave it. In a layered build's upper, a record the run deleted from the
  base stays deleted rather than reappearing from the base. A program that asks
  for the machine id in a sandbox, with no boot to generate one, now finds none
  until `systemd-machine-id-setup` or `dbus-uuidgen --ensure` runs in the root.
- **Breaking.** An Alpine bootstrap, and a layered build's increment, removes
  the `/etc/machine-id` its scripts generated once the last trigger has run.
  `dbus`'s service generates a fresh id from the missing file before it starts.
  A program that asks for the machine id in a sandbox now finds none until
  `dbus-uuidgen --ensure=/etc/machine-id` runs in the root.
- **Breaking.** A Debian bootstrap no longer writes its trust anchor over the
  `debian-archive-keyring` package's own file, where the package's next upgrade
  replaced a caller's keyring with Debian's. A keyring given with
  `DebianBuilder::keyring` is written to
  `/usr/share/keyrings/fcage-archive-keyring.gpg`, a path no package ships, and
  the root's `sources.list` names it. With the embedded keyring, `sources.list`
  names the package's `/usr/share/keyrings/debian-archive-keyring.gpg` where dpkg
  records the package as installed and owning that file, so the root follows
  the archive's key rotation; a root without it gets the embedded keyring at the
  `fcage-archive-keyring` path. An additional repository whose keyring would
  take either path is refused.
- **Breaking.** A Debian root carries no apt source, and no keyring, for a
  repository whose first mirror is a `file://` URL. A sandbox rooted at the tree
  does not see that host path, and a `file://` primary leaves no `sources.list`.
  A repository allowing a stale release writes `check-valid-until=no` into its
  source, so the root's apt accepts the release the bootstrap accepted. The
  guide shows how to make a local pool visible to the root's apt.
- **Breaking.** `DebianBuilder::build` and `debian::RepositoryBuilder::build`
  refuse a keyring named together with `trust_unsigned(true)`, with
  `DebianError::Config`. The keyring was ignored.
- **Breaking.** A Debian resolution ranks repositories as apt does by default. A
  release marked `NotAutomatic`, such as `experimental`, or `NotAutomatic` with
  `ButAutomaticUpgrades`, such as a backports suite, supplies a package only
  where no higher-ranked repository offers it. It supplied one wherever its
  version was higher. An `include` entry written `name/release`, in
  `fcage --debian-include` as well, installs the package from the repository
  configured with that suite, with the versioned dependencies it needs. `build`
  refuses an entry naming a suite no repository is configured with. The base
  system is seeded from the primary repository alone, and a layered build
  upgrades what its base holds only as apt would, never downgrading it.
- **Breaking.** `debian::DebianError::HashMismatch { path, .. }` is
  `DebianError::Digest { subject, expected, actual }`, the shape the Alpine and
  Gentoo errors use: `subject` is the URL the bytes were fetched from, or the
  path of a cached package. `Signature`, `Release`, and `Index` gain a
  `subject`, the URL of the release or of the index. A release that lists no
  index for a component is reported as `Release`, and an index that does not
  decompress as `Index` rather than `Io`, with the decoder's failure as its
  `source`. An index that expands past its stated length is reported apart from
  one that does not decode.
- **Breaking.** A host failure on the download path, in staging, writing,
  reading back, or publishing a download, and a package cache that cannot be
  created, are `ProvisionError::Io` in every layer. Gentoo reported both, and
  Debian and Alpine the download steps, as the layer's own `Io`.
- **Breaking.** No error's message repeats its cause. Each error type's
  `Display` says what failed and what it was operating on, and the cause
  underneath, an OS error or another of the library's errors such as the
  `ConfigError` inside `Error::Config`, is reached only through `source()`. A
  chain renderer such as anyhow's `{:#}` prints each layer once, where it printed
  the OS error two or three times. A consumer that prints an error with `{}` now
  prints its outermost layer alone, and renders the chain to keep the cause:
  through `ErrorChain`, or its own error-reporting crate.
- **Breaking.** `alpine::KeySet::insert` reports a key that is not a usable RSA
  public key as `AlpineError::Config`, naming the key once, rather than as
  `AlpineError::Signature`. `AlpineError::Container` gains `source`, the failed
  read where a container could not be read, which its reason no longer repeats.
- **Breaking.** `DebianBuilder::fetcher`, `AlpineBuilder::fetcher` and
  `GentooBuilder::fetcher` take the transport by value, as `impl Fetch +
  'static`, rather than as a `Box<dyn Fetch>`: pass the transport itself, or a
  `Box` of one chosen at run time. `Debian` and `DebianBuilder` no longer carry
  a lifetime parameter, and `debian::Observed` carries one, as Alpine's and
  Gentoo's do.
- **Breaking.** `Export`, `CopyIn` and `Remove` name the identity map and its
  delegate as `CageBuilder` does: `map` is now `identity_map`, and `mapper` is
  now `id_mapper`, which takes the delegate by value, as `impl IdMapper +
  'static`, and keeps it. Pass the mapper itself, cloned or shared through an
  `Arc` for each builder that needs it. `CopyIn` and `Remove` no longer carry a
  lifetime parameter. `BuildLayer`, which keeps the delegate it was staged with,
  is no longer `UnwindSafe` or `RefUnwindSafe`.
- **Breaking.** `debian::Available` and `alpine::Available` are one type,
  `provision::Available`, which `Debian::available` and `Alpine::available`
  return. Gentoo's type of that name, the stage3 variants a pointer document
  publishes, is `gentoo::Variants`, and `Gentoo::available` and
  `gentoo::Observed::available` are `variants`. `Variants::names` replaces
  `Available::variants`.
- **Breaking.** `debian::build_depend_names` takes the architecture the root is
  built for, and evaluates each alternative's architecture restriction against
  it: literal names, `any`, `<os>-any`, and `any-<cpu>`. It takes each
  alternative that applies, in order, up to the first that no build profile
  restricts, so its answer covers every profile selection. The restrictions were
  ignored, so a control file with a `[hurd-any]` dependency failed to resolve. A
  comment line in `debian/control` is skipped rather than read as a field.
- **Breaking.** The Gentoo plan document is `ferroday-cage-gentoo-plan 2`.
  `gentoo::PlannedPackage` gains `slot`, `use_flags`, `iuse`, `rdepend`,
  `pdepend` and `build_time`, which the document records as `Slot`, `Use`,
  `Iuse`, `Rdepend`, `Pdepend` and `Build-Time`. A version 1 document is
  refused for its format; resolve it again. A merged package's `BINPKGMD5` is
  the container's own MD5 rather than the index's.
- **Breaking.** An archive coordinate holding a character a URL path cannot
  carry as written, such as `%`, `?`, `#`, or one outside ASCII, is refused at
  `build`. That covers a Debian or Alpine suite, release, component or
  architecture, a pool's coordinates, and a Gentoo architecture, build id or
  binhost. Such a value passed the builder and then failed every fetch, or
  reached the server decoded as something else.
- **Breaking.** `ConfigError::OverlayUpperIsRoot` is
  `ConfigError::OverlayLayerIsRoot`, which names the layer, so a work directory
  at `/` is no longer reported as an upper. It also covers a layer path ending
  in `..`.
- **Breaking.** `ConfigError::EmbeddedNul` and `ConfigError::HostnameInvalid`
  are struct variants naming the value they refuse, and
  `ConfigError::MountFlagsInvalid` names the raw mount's target. A NUL in an
  environment variable's name is `EnvNameInvalid`, and a NUL in the hostname is
  `HostnameInvalid`.
- **Breaking.** `Error::NestedUsernsBudgetExhausted` is
  `Error::NamespaceLimitReached`, with a `step` naming the creation the kernel
  refused. It reports `ENOSPC` from creating the sandbox's own namespaces as
  well as the command's nested ones. It names the limits it can stand for: a
  `user.max_*_namespaces` count, or the nesting depth of user and PID
  namespaces. It and `Error::TerminalsExhausted` carry the kernel's error as
  `source`, returned from `Error::source`. Match them with `{ .. }`.
- **Breaking.** The struct variants of `ResolvedRoot`, `ResolvedIdentity`,
  `ResolvedHardening`, `ResolvedMount`, and both `UnheldReason`s are
  `#[non_exhaustive]`, as every other struct variant is. A pattern naming their
  fields needs `..`, and they cannot be constructed outside the crate.
  `ResolvedHardening::Applied` gains `landlock_scope`.
- **Breaking.** `RangeMapBlocker::HelperCannotMapRoot` is removed, and
  `host::range_map_blocker` no longer reports a `newuidmap` whose file
  capabilities lack `CAP_SETFCAP`. Match on the remaining variants.
- **Breaking.** `fcage --no-base-env` no longer passes the host's `TERM`, so the
  command gets only the variables the run names. Pass it with `--setenv` where
  the command needs it.
- **Breaking.** A plan given beside a setting that shapes a resolution is
  refused. `GentooBuilder::build` refuses a `plan` given with `install` atoms or
  `prefer_use` preferences, with `GentooError::Config`, as the Debian and Alpine
  builders refuse theirs; the plan superseded both in silence. `fcage` refuses
  each such pair as a usage error: `--debian-plan` beside `--debian-include`,
  `--debian-exclude`, `--debian-base-priority` or `--debian-pin`,
  `--alpine-plan` beside `--alpine-include`, `--alpine-exclude` or
  `--alpine-pin`, and `--gentoo-plan` beside `--gentoo-install` or
  `--gentoo-prefer-use`. The Debian and Alpine pairs failed at `build`, exiting
  125.
- `fcage` refuses an `https://` mirror on every mirror flag, as a usage error,
  since it fetches over `http://` and `file://` only.
- An Alpine or Gentoo fetch failure names the bootstrap it stopped, as a Debian
  one does: `the Alpine bootstrap could not fetch a resource`, with the fetch's
  own error beneath it. A Gentoo host failure reads `a Gentoo bootstrap step
  failed while ...`, as Debian's and Alpine's do, rather than repeating
  `ProvisionError::Io`'s words.
- Extraction resolves a symbolic link in the tree as the root filesystem does:
  an absolute link re-anchors at the destination, so `var/run -> /run` carries
  an entry beneath it to the root's own `run/`, and the pre-configure overlay
  merges through such a link rather than replacing it. A link naming a path the
  root does not hold no longer reads as an escape: an entry beneath it is
  refused with `ProvisionError::EntryRefused`. Nothing is written outside the
  destination either way, and an entry whose own path is absolute or contains
  `..` is still `EntryUnsafe`.
- `CageBuilder::get_resolv_conf` also answers `false` where a mount of the
  caller's claims `/etc/resolv.conf`: one at the path, or a host tree bound or
  moved over a directory above it. Those mounts replace the library's bind, and
  the getter now says so.
- An export leaves out the extended attributes the host assigns rather than the
  tree carries: security-module labels (`security.selinux`, `security.SMACK64*`,
  `security.apparmor`), integrity measurements (`security.ima`, `security.evm`),
  and overlayfs bookkeeping (`user.overlay.*`, `trusted.overlay.*`). An archive
  of one tree is then the same from any host.
- An overlay layer path may hold a `:`, which is escaped in the mount options. A
  `,` is still refused with `ConfigError::OverlayPathInvalid`.
- A Landlock rule the kernel refuses at launch, such as a grant on a path the
  sandbox does not have, is reported with the grant it came from in
  `Error::Setup`'s detail, as a failed mount or resource limit is.
- An Alpine install script runs with exactly the environment `apk` gives one:
  `PATH`, `APK_SCRIPT` and `APK_PACKAGE`, plus `SOURCE_DATE_EPOCH` where one is
  set. It also received `HOME=/root`.
- An Alpine `include` or `exclude` naming a repository tag, such as
  `busybox@edge`, is refused at `build`. Repository tags are not supported, and
  such a name failed the resolution as a package nothing offers.
- A Debian bootstrap and a layered build replace `start-stop-daemon` with a
  stand-in that starts nothing while packages configure, as debootstrap does,
  and restore it afterwards. A maintainer script that starts its daemon
  directly no longer runs it during the build.
- `DebianBuilder::build` and `debian::RepositoryBuilder::build` parse a caller's
  keyring and refuse one holding no key whose signatures can be verified, such
  as one of DSA keys alone, with `DebianError::Config`. A bad keyring failed
  only after the first release had been fetched. A certificate the verifier
  cannot read, such as a version 3 or 5 key or an exported secret key, is passed
  over, as `gpgv` passes it over, and a refusal names the first one passed over.
  A keyring whose packet framing is damaged is refused whole.
- A signature by a revoked certificate is refused with the revocation and the
  key named. The certificate was dropped as the keyring was read, so the refusal
  said only that no key in the keyring had made a signature. A caller's keyring
  whose every certificate is revoked passes `build`, and the first verification
  refuses it.
- `DebianBuilder::build` refuses `extract_only` alongside `base_layer`.
  `stage_layer` configured the increment regardless, so the setting was ignored.
- `provision::file_url` percent-encodes every byte outside the unreserved set
  and `/`, so a path holding a space, a newline, or a non-UTF-8 byte names one
  URL, and the bundled fetcher decodes it back. It no longer fails for a
  non-UTF-8 path.
- A plan document's numbers are read only as the writer spells them: digits,
  with no leading zero, and a sign only where the field can be negative. A
  `Size` of `+5` or `0010`, a `-0`, or an archive or index stanza numbered
  `+1`, is refused rather than read and written back differently.
- The guide's recipe for a reproducible provenance record declares the procfs a
  container needs, and the doctests run it. As written it failed `build`.
- **Breaking.** `CertificateHorizon::expires` is a `gentoo::Expiry`: a date,
  `Expiry::Never` where nothing bounds the certificate, or `Expiry::Unknown`
  where no date of it can be established. A certificate whose self-signatures
  this crate cannot verify, as for Gentoo's 2004 DSA-1024 release key, reports
  `Expiry::Unknown` and no user id, where it reported both.
  `fcage --gentoo-keyring-horizon` prints `unknown` for such a certificate.

### Fixed

- A foreign-architecture bootstrap's preflight reads `binfmt_misc`'s host-wide
  switch, and refuses a host where `/proc/sys/fs/binfmt_misc/status` reads
  `disabled`, before anything is downloaded. Where `binfmt_misc` is not mounted,
  as in a container that never mounted it, the preflight lets the bootstrap
  proceed rather than refusing it: the kernel holds the host's registrations
  either way, and a missing handler fails the first foreign binary with
  `ENOEXEC`.
- A launch no longer fails now and then with `SetupStep::OpenMountTarget` and
  `EAGAIN` when a rename or a mount elsewhere on the host races the lookup of a
  mount target reached through a `..` symbolic link, such as `etc/resolv.conf ->
  ../run/systemd/resolve/stub-resolv.conf`. The kernel's request to retry such a
  lookup is honored wherever the crate resolves a path inside a tree.
- Without a PID namespace, and under every restriction, the launch stage that
  supervises the command from outside the sandbox ignores signals as a PID
  namespace's init does. It keeps only `SIGCHLD` and the signals that report a
  fault. A `^C`, a hangup, or a shell's `kill %1` sent to the caller's process
  group ended it. The command's outcome was then lost, and a command in a
  session of its own ran on unsupervised, past `stop_with_caller`. The command
  still starts with every signal at its default, and `SIGKILL` still ends the
  launch stage.
- Every process the library forks starts with every signal blocked, and the
  caller's signal mask is restored as soon as the fork returns. A signal handler
  the caller installed could run in a forked child before the child had reset
  its dispositions.
- A launch that is torn down signals and reaps its launch stage through a pidfd
  taken at the fork. In an application that reaps child processes of its own,
  the launch's `SIGKILL` could reach an unrelated process that had reused the
  stage's pid.
- A Landlock grant on a file or a device node, such as `--landlock-ro
  /etc/hostname` or `--landlock-rw /dev/null`, no longer fails every launch with
  `EINVAL`. The grant is narrowed to the rights that act on a file, which are
  the only ones the kernel accepts there.
- A seccomp policy naming a syscall number below zero, or at or above
  `0x4000_0000`, is refused at `build` with `ConfigError::SeccompInvalid`. A
  number past 32 bits panicked inside `build`.
- A range identity map the bundled delegates cannot write is refused at `build`
  rather than failing every launch with `EPERM`. `DirectMapper` refuses a uid map
  naming outside uid 0 without `CAP_SETFCAP`. `SubidMapper` refuses any map on a
  host whose shadow helpers cannot establish one: a helper missing from `PATH`
  or without its setuid bit or file capability, a symbolic-link `/etc/subuid` or
  `/etc/subgid`, or a caller under `no_new_privs`. The Debian and Alpine
  provisioners' preflight refuses the same before it downloads anything.
- A subordinate allocation read from `/etc/subuid` and `/etc/subgid` takes in
  every entry under the caller's user name or uid, as `newuidmap` honours them.
  It took only the entries under whichever of the two matched first.
  `IdentityMap::Subordinate` maps the whole allocation, and an outside id two
  entries grant is mapped once.
- A run-as identity under a range map whose gid map is the caller's own gid
  alone now launches. `newgidmap` denies `setgroups` when it writes such a map,
  so the launch failed at `SetupStep::SetGroups`. The command keeps the group
  list it inherited, as under the single-identity map, and a run-as group list
  under such a map is refused at `build` with
  `ConfigError::RunAsGroupsWithSingleMap`.
- An export, a copy in, or a removal given a malformed range identity map, or a
  delegate that resolves one, refuses it by name, as `build` does. It reached
  the kernel and failed with `EINVAL` at the write.
- A file bind onto a path an overlay's upper had deleted, or that lies in a
  directory the upper made opaque, no longer leaves an empty file in the upper
  after the run. The target was judged present because a lower held it, so the
  empty file the launch created was never removed, and it hid the deletion. A
  target created over a deletion has the deletion restored.
- A file a launch creates in the root as a file bind's target, such as a
  host-network sandbox's `/etc/resolv.conf`, is removed only once the sandbox is
  gone. Even then it is removed only while the name still holds that file.
  Dropping a `Running` while the sandbox ran unmounted the sandbox's bind; the
  file now stays in the root instead. Two sandboxes on one root that bind onto
  the same such target no longer unmount each other's bind.
- With host networking, a bind of a host directory over `/etc` no longer
  receives an empty `resolv.conf` from the launch, and a read-only one no longer
  fails the launch with `EROFS`. The managed bind yields to such a bind as it
  does to a mount at `/etc/resolv.conf` itself.
- A refused build leaves no overlay upper or work directory behind. They are
  created once the rest of the configuration is accepted, and removed again when
  the overlay itself is refused.
- A command of `.` or `..` under `path_lookup` is refused at build as the
  relative path it is, rather than failing at launch with `EACCES`.
- A restriction's refusal of a bare command name no longer suggests path
  lookup, which a restriction does not offer. `ConfigError::CommandNotAbsolute`
  carries `lookup_offered`, which is `false` for a restriction.
- `build` judges the procfs a nested user namespace needs as the launch uses it.
  A raw remount or propagation change at `/proc` no longer makes it refuse the
  profile with `NestedUsernsNeedsProcfs`, since neither mounts anything over the
  procfs. A raw move is read as `mount(2)` reads it. A procfs serves only where
  it is the writable root of one, which the nested identity map is written
  through. A read-only procfs, or a bind or move of anything else, such as
  `/proc/sys`, is refused rather than failing at launch.
- A raw mount whose flags carry the legacy `MS_MGC_VAL` magic number is read as
  `mount(2)` reads it, with the magic discarded. Its bits overlap `MS_PRIVATE`
  and `MS_SLAVE`, so `build` took such a mount for a propagation change. A
  procfs mounted that way failed the procfs requirement, and a mount at
  `/etc/resolv.conf` did not replace the managed bind.
- Waiting on a sandbox without a PID namespace no longer spins at full CPU while
  a process the command left behind holds its captured output open. The wait
  watched the exited command's pidfd in place of each finished channel, and a
  pidfd reports a hangup once its process is reaped.
- `Relay::run`, and so `fcage --terminal`, honors the `Escalation` deadline and
  the relayed signals until the command's exit is collected. End-of-file on the
  sandbox's terminal ended the session's supervision, so a command that closed
  its standard streams outlived `--timeout` and ignored `SIGINT` and `SIGTERM`
  until it exited on its own. The caller's terminal is restored as soon as the
  relaying ends, before that wait.
- A terminal session ends when its command does, once what the terminal still
  held is delivered. Without a PID namespace, and under every restriction, a
  process the command left behind could hold the terminal open. The session, and
  `fcage --terminal --timeout`, then ran on past a timeout, a kill, or an
  interrupt. What such a process writes after the command exits is not relayed.
- A terminal relay started in the background, `fcage --terminal ... &`, no
  longer puts the shell's terminal into raw mode. Raw mode is entered only while
  the relaying process is in the terminal's foreground process group, at the
  start and on each `SIGCONT`, so `fg` enters it and `bg` does not.
- `relay::restore_terminal`, and the panic hook `install_panic_restore`
  installs, restore only a terminal whose raw session is in force, with the
  settings that session found, and only while the process is in that terminal's
  foreground. The hook rewrote the first session's terminal, discarding its
  type-ahead, at any later panic in the process. It now also reaches a session
  relayed on another terminal.
- The network stack no longer spins at full CPU when a UDP reply cannot be
  delivered to the guest: a host socket is waited on only while the guest's side
  has room for its reply. TCP and UDP are carried only from the guest's own
  address, and a frame from any other source is dropped, since nothing sent back
  to it can be delivered.
- The network stack no longer answers IPv6 neighbor solicitations for addresses
  on the guest's subnet other than the gateway, as it already withheld ARP and
  ICMP echo for them. A connection to such an address now fails silently, as the
  guide describes, rather than with a reset. A request behind a hop-by-hop
  options header is held to the same rule, and TCP and UDP behind one are
  carried like any other.
- `NetStackBuilder::build` refuses an interface name holding a vertical tab or
  the byte `0xA0`, which the kernel refuses, rather than failing at `attach` as
  `TapCreate`.
- `fcage --netstack` binds the host's `resolv.conf` only when it names a
  nameserver the stack forwards to. A link-local resolver, such as AWS's
  `169.254.169.253`, was counted as reachable and bound into a sandbox that
  could not reach it. A host directory bound over `/etc` replaces the composed
  bind, as it replaces the library's own.
- `fcage` no longer panics, exiting 101, when the reader of its standard output
  or standard error goes away. Output that is the run's purpose, `--help`,
  `--version` and the Gentoo listings, exits 141, as a writer to a closed pipe
  does. A warning before a launch, or a provisioning run's progress, stops the
  work at its next clean point and exits 141, so a bootstrap piped into `head`
  stops. A diagnostic of a failure keeps the failure's exit code. A `--terminal`
  session whose output reader goes away exits 141 rather than 125.
- `fcage` checks a launch's profile, network-stack configuration and standard
  streams before it provisions the root. A mistake in any of them was reported
  only after a bootstrap, and a refused run now provisions nothing.
- `fcage --export-rootfs` and `--export-to` refuse a value spelled as another
  flag, as every other flag does. `--export-to --clamp-mtime=0` wrote an archive
  named `--clamp-mtime=0`, without the clamp, and exited 0.
- A provision-and-exit `fcage` run no longer refuses a flag's value that looks
  like a flag, such as `--rootfs --mydir`, as a launch flag.
- `fcage --remove-rootfs` and `--remove-overlay-upper` refuse, as usage errors,
  an empty destination, which removed nothing and exited 0, and a path with no
  final component such as `.`. `--gentoo-installed` refuses an empty root, which
  it read as a root with nothing installed.
- `fcage` no longer suggests a joined `--flag=VALUE` form for `--bind`,
  `--ro-bind`, or `--setenv`, which take two values and have none.
- `fcage --timeout` and `--kill-after` refuse a number of seconds too small to
  be a nanosecond, which rounded to no time at all.
- `fcage --help` states what `--restrict` requires, that `--restricted-profile`
  refuses an overlay root, and that `--path-lookup` relaxes the absolute-command
  rule. It names `--debian-include`'s `NAME/RELEASE` form, and its synopsis
  lists the Gentoo listing modes.
- A layered build no longer hides the links its base holds to directories. A
  package shipping `lib64/` or `sbin/` over a merged-usr base, as the Gentoo
  binhost's lvm2 does over a stage3, made real directories in the upper that hid
  the base's `lib64 -> usr/lib64` and `sbin -> usr/bin`, and the merged root
  lost its dynamic loader. Every entry an increment extracts, and every file the
  layer writes into the upper, is placed where the mounted overlay would place
  it, in all three layers and in the pre-configure overlay. A Debian increment
  lays no merged-usr links of its own, since the base decides the layout. An
  entry that is not a directory is refused over a directory the base holds, and
  one beneath a base directory the calling user cannot search fails naming the
  entry.
- A base directory a layered build writes beneath arrives in the upper with the
  base's owner, group and extended attributes, as the overlay's own copy-up
  carries it. Its POSIX access control lists are among them. It arrived owned by
  the calling user, with no attributes. Under the single-identity map an owner
  other than the caller's cannot be represented, and the directory arrives owned
  by root.
- A layered build's `stage_layer`, in all three layers, removes the overlay
  upper on failure only where the call created it. An upper that already
  existed is the caller's and stays, holding whatever the failed call wrote into
  it. Any failure removed it, and the earlier increments it held.
- A layered Gentoo build reads the base's package database as the overlay shows
  it. An entry the upper whites out, or hides under an opaque directory, no
  longer counts as installed, and an entry a command in the sandbox changed one
  file of is read from both layers, the changed file from the upper and the rest
  from the base. It was read from the upper alone and refused for carrying no
  `SLOT`.
- `CopyIn` lays a source's `bin/`, `sbin/`, `lib/` and `lib64/` into a
  merged-usr root through the root's aliases, resolving each from the root as
  the sandbox would, and leaves the owner, mode, and modification time of a
  directory the root already has as they are. It failed on every merged-usr
  root, and a source staged under umask 077 left the root's `/etc` at `0700`. A
  file or dangling link at a directory's name is replaced, as `overlay_tree` and
  the extractor replace it. So is an empty directory at the name of a file, a
  link, or a named pipe, while a directory holding anything still fails the
  copy.
- `CopyIn` follows a symbolic link at the source path itself, as it does at any
  other component of the caller's path. The pre-check followed it and the walk
  then refused it.
- An export fails with `ProvisionError::SourceChanged`, naming the file, when a
  file grows or shrinks while it is read, as `CopyIn` does. It archived the file
  cut or zero-padded and succeeded.
- An export and a `CopyIn` no longer hang when a named pipe takes a regular
  file's place between the walk inspecting the name and opening it, and neither
  reads another file under the first one's metadata. A copy reports it as
  `ProvisionError::SourceChanged`, and an export fails naming the step.
- An export sorts each directory in memory set aside before it starts, so a
  directory of a hundred thousand entries exports in under a second rather than
  minutes. A tree whose open directories together hold more entries than that
  memory, several hundred thousand, fails the export rather than being written
  out of order.
- `Export` writes an owner or group id larger than 2097151 in a pax record, as
  GNU tar does, rather than failing the export. The header's own field holds
  2097151, so a reader that ignores pax records does not take the entry for
  root's.
- Two threads exporting to the same path with `Export::write_to_path` each
  publish a complete archive. They shared a staging file name, so one could
  publish the other's archive while it was still being written.
- Removing a tree no longer recurses. `provision::remove`, `Remove`, `ensure`'s
  staging cleanup, and a `BuildLayer`'s disposal walk the tree iteratively with
  a few descriptors at any depth. A tree a sandbox nested deeply could abort the
  host process on a stack overflow, from `BuildLayer`'s drop, or fail with too
  many open files and stay unremovable.
- `provision::remove` and `Remove` hold the publication lock while they run, and
  `ensure` checks after taking the lock that the lock file it holds is still the
  one at the path. A removal running beside a publication of the same
  destination could let two provisioners run at once.
- `provision::ensure` removes its staging tree when the tree cannot be synced or
  published, as it does when the provisioner fails. Its final rename no longer
  replaces an empty directory another process made at the destination after the
  check: the publication fails and leaves that directory in place.
- The Debian package pool's publish lock is close-on-exec, so a process spawned
  during a publish no longer keeps the pool locked after the publish returns.
  The export's internal duplicate of its frame stream is close-on-exec as well.
- A provisioner's host-side read of a file inside a tree no longer waits on a
  named pipe left at that path, or holds a file a script made arbitrarily large.
  Nothing but a regular file is opened, and each read refuses a file past a
  ceiling suited to what it reads, so `truncate -s 1T /etc/shadow` in a
  maintainer script fails the step rather than exhausting the host's memory.
- A Debian or Gentoo cache entry that does not verify is downloaded again in the
  same run, as an Alpine one already was. A corrupt `.deb` the batched prefetch
  did not deliver was kept, and every later run failed extracting it; a Gentoo
  stage3 or binary package failed the run.
- A write the package cache refuses while a download arrives, such as on a full
  disk, is reported as `ProvisionError::Io` naming the staging file, and stops
  the mirror walk. It was reported as the mirror's failure, so each mirror in
  turn downloaded as much as fitted and the last was blamed. A batched download
  stops at the same failure.
- A `DebianObserver` or `AlpineObserver` bound with `observe` stops a
  provisioning run when its `cancelled` answers true. A Debian run consulted only
  the `Provision` observer, and an Alpine one only for a layered build. A Debian
  or Alpine run asks while a package downloads, not only between packages, as a
  Gentoo run already did for its tarball. A batch of downloads fetched at once
  still stops at the batch's end.
- `DebianEvent::Downloading` counts the packages being downloaded rather than the
  plan's, as `AlpineEvent::Downloading` does.
- A Debian repository whose release declares `Acquire-By-Hash` is read from a
  mirror or a proxy that serves only the named index files, as apt reads it. An
  index the by-hash path does not serve is asked for by name, and one served
  there with the wrong digest is still refused.
- `Debian::stage_layer` lays the pre-configure overlay into an increment that
  installs nothing, as it does into any other.
- A Debian or Alpine pin holding a version two repositories offer over different
  bytes selects the repository recording the pinned bytes. Debian took the
  earlier repository's copy and Alpine the later one's, and refused the pin
  where that copy was a rebuild.
- Alpine versions compare as apk 3 compares them where a suffix carries no
  number: `1.0_p` orders below `1.0_p0`, rather than equal to it. This affects
  which of two repositories' records is selected, `=` constraints, and pins.
- An Alpine plan whose package states an architecture other than the plan's or
  `noarch`, or a control identity that is not a `Q1` digest, is refused when the
  document is read and at `build`. The architecture was written verbatim into
  the root's installed database.
- An Alpine plan naming one package twice is refused at `build`, as a pin naming
  one twice already was. Installing it wrote two installed records for the
  package and ran its scripts twice.
- An Alpine root built under a range identity map gives each entry the owner its
  package states, as apk does. The archive's user and group names are looked up
  in the root's own `/etc/passwd` and `/etc/group` after the package's
  pre-install, with the archive's ids where the root has no such account. The
  installed database records the ids given. `dbus-daemon-launch-helper`, which
  is setuid and `root:messagebus`, arrived owned by root, so the bus could not
  run it. Under the single-identity map, and in an extract-only root, every
  entry is owned by root, and the database now records that rather than the
  archive's ids.
- An Alpine package an `install_if` brings in is installed after the packages
  its condition names, as apk orders it.
- Where two Alpine packages built from one source package ship the same path,
  the one installed later takes it, whatever their `replaces` fields say, as apk
  decides it. A `replaces` priority on the earlier one kept the file.
- A layered Alpine build finds a base package's archived trigger script by its
  whole name. A package whose name and version began another's, such as `a` at
  `1` and `a-1.5`, could be handed the other's script.
- An Alpine container segment past its compressed-size ceiling stops the read
  once the ceiling is crossed, rather than once the gzip member ends.
- Gentoo atoms follow portage and the package manager specification. A
  `=cat/pkg-1.2*` atom matches only at a version-part boundary, so
  `=dev-lang/python-3.1*` no longer admits 3.12. A package name may not contain
  `.`, a slot may not begin with `-`, `.` or `+`, and a USE flag must begin with
  a letter or digit. `cat/pkg::repo` is refused as a repository dependency
  rather than as a malformed slot.
- Gentoo resolution honors the blockers that packages already in the root
  state, refusing a build one of them blocks as portage does.
  `GentooEvent::Conflict` gains `stated_in_root`. A root whose database holds a
  runtime dependency class that does not parse is refused by
  `gentoo::installed`.
- A Gentoo any-of dependency is taken as portage takes it. An alternative that
  lists several packages together, such as `virtual/zlib`'s zlib-ng with
  minizip-ng, is satisfied only by all of them, rather than by any one. An
  alternative that would take a slot the root or the resolution already holds
  gives way to the next, rather than refusing the group.
- Replaying a Gentoo plan holds it to the root it installs into. A package the
  root already has at the planned version is skipped. The rest are verified,
  and their signed metadata is checked for an occupied slot and for blockers
  either way, before anything is merged. A plan replayed over a newer stage3
  registered two versions of one package in one slot.
- A Gentoo merge continues the merge ordinal from the greater of the root's
  counter file and every ordinal its package database records, as portage does.
  A removed or rolled-back counter file reissued an ordinal. A root whose
  counter cannot take another ordinal is refused before anything is merged,
  rather than panicking or wrapping.
- A Gentoo binary package holding a member twice, or two image or metadata
  archives, is refused. So is one whose metadata archive inflates past 16 MiB,
  whichever of its entries hold the bytes. A symbolic link whose target is not
  UTF-8 is refused rather than recorded with the target altered.
- A Gentoo binary package that is cut short, or that ships a path its database
  entry cannot record, is reported as `GentooError::Container` naming the
  package. It was reported as a host I/O failure, or as the root's database
  being unreadable.
- A mirror that redirects to an `https://` URL, which the bundled client cannot
  follow, is a mirror that could not serve the request, so a walk over several
  mirrors asks the next one. It ended the walk as a malformed URL. The refusal
  names the remedy without naming one layer's builder.
- A `Tarball` is read to the end of its stream, past the archive's
  end-of-archive marker, so a compressed stream's final integrity check is
  compared, and a zstd frame's content checksum is compared as each frame ends.
  A damaged final block was extracted as though it were sound. More than a
  mebibyte after the marker is refused.
- A tar member in one of GNU's pax sparse formats, 0.0, 0.1 or 1.0, is refused
  with `ProvisionError::EntryUnsupported`, as an old-format sparse member
  already was. Such a member's header claims a regular file, and it was
  extracted as its packed data, or as a `GNUSparseFile.*` directory with the
  real path missing.
- A tar archive is refused as malformed where a pax header or a GNU long name is
  followed by the end-of-archive marker, with no entry for it to describe. One
  ending without the marker already was.
- A malformed archive is reported for what is wrong with it. A corrupt first
  header, or a first entry the reader refuses, is `ProvisionError::Archive` with
  the reason, rather than `FormatUnrecognized`, whose message no longer says the
  compression went unrecognized. An empty hardlink target, or a NUL byte in a
  symbolic link's target, is `EntryRefused` rather than `EntryUnsafe`, which
  asserts an escape attempt.
- The bundled HTTP client reads a response's framing to its grammar: a
  `Content-Length` or chunk size with a sign is refused, `Transfer-Encoding` is
  read as a list in which only one `chunked` is accepted, and a folded header
  line continues the field before it rather than starting a new one. The tar
  reader refuses a pax number with a sign.
- The bundled HTTP client keeps a connection after a refusal whose page is
  framed and small, such as a 404, as it already did after a redirect. Falling
  back to another index encoding on one mirror no longer opens a new connection.
  A server may answer `408 Request Timeout` as it closes an idle connection. On a
  reused connection the request is then retried once on a fresh one, where the
  mirror was reported as failed.
- `HttpFetch::timeouts` takes a zero timeout as none, for connecting or for each
  read, where it failed every connection. Every step is also held to the
  fetch's `request_timeout`, which now bounds a fetch's total time.
- `HttpFetch::fetch_all` no longer panics when the host refuses to start a
  worker thread, as a task limit does. It fetches with the workers that started,
  and on the calling thread where none did.
- An xz block that chains more than one filter before LZMA2 decodes. Since
  0.4.2 such a block was refused. `xz` writes at most one such filter, so no
  archive it produced was affected.

### Internal

- `mechanism::resolve::openat2` is the one `openat2` call, retrying a raced walk
  for every caller, the post-fork stages included, up to 64 times.
  `provision::containment::open_dir` is built on it, and `open_dir_path` is its
  allocation-free form for the copy-in child.
- `mechanism::frame::send_with_fd` and `recv_with_fd` pass a descriptor over a
  socket for every caller that does: the supervisor's pidfd, the network stack's
  tap, and a terminal launch's primary.
- `mechanism::frame` holds the rest of the helper children's wire as well:
  `write_whole` for a file that takes its content in one write, `retry_on_intr!`
  for every single interrupted call, and `encode_record`, `decode_record` and
  `read_record` for the outcome record every helper child sends.
  `frame::read_full_or_short` fills a buffer and reports how much arrived, and
  `read_full_or_eof` is built on it. `idmap::single_identity_lines` formats the
  single-identity map's two lines before a fork. A short identity-map write in a
  sandbox stage reports `EMSGSIZE`, as the host side already did.
- `mechanism::has_exited` and `mechanism::await_exit` ask whether a process has
  exited, or wait until it has, through its pidfd, for any process rather than
  only a child of the caller's. The placeholder guard and every failed launch
  ask them.
- Every range identity map passes through `idmap::resolve_delegate`, which takes
  the configured delegate, whose refusal is final, or the bundled chain, and
  validates the request and the delegate's answer: a build, an export, a copy
  in, a map-assisted removal, and the Debian and Alpine preflights, which ask it
  through `idmap::establishable`. `host::helper_blocker` is the one answer to
  whether the shadow helpers can establish a map, which `SubidMapper::resolve`
  and `host::range_map_blocker` both ask. `idmap::is_own_gid_alone` is the one
  reading of a gid map no group list can be set under.
- `ErrorChain` is the one walk of an error's causes, recorded in the idiom
  census, and every place the library turns one of its own errors into a text
  reason renders it through `ErrorChain`.
- `path::parent_of` names the directory a path's final component is in, `.` for
  a bare name. A publication and its lock, a removal, the staging file, a cache
  entry, the export, an overlay layer, and a build layer's upper ask it. The
  idiom census records it.
- The host side's reading and writing of a tree is `provision::containment` and
  `provision::rooted`. `containment::create_dirs` creates a chain of missing
  directories for the extractor and `Rooted` alike, and `containment::copy_up`
  is the layered walk both take over a base. `containment::is_whiteout` and
  `is_opaque` are the one definition each of the overlay's markers, which the
  launch's placeholder checks, the layered walk, the Gentoo database view and
  both bootstraps ask. `containment::open_typed_file` opens a file a walk just
  inspected for `Rooted`, the export child and `CopyIn`, and `open_created_fifo`
  opens a named pipe just created for the extractor and the copy-in child.
  `containment::replacing` replaces whatever holds a name for the copy-in child
  as well, and `containment::host_assigned_xattr` is the one list of the
  attributes the export and a layered carry leave out.
- The copy-in child's `COPY_OWN` frame gives an entry the tree already holds its
  owner from inside the identity map, provided the name still holds the entry
  recorded. `provision::copyin::reown` sends it, through the
  `provision::identity::Ownership` a tree is written under, for a layered
  build's carried directories and an Alpine package's declared owners alike.
- `provision::layer::Staging` takes a build layer's upper for the `stage_layer`
  of all three layers, and removes it on failure only where it created it.
- `provision::cache` holds the package cache: `PackageCache`, the one way a
  cache directory is created, the one way an entry is opened, and the one
  staged, verified download path, mirror walk and batch alike, for all three
  layers. `Pool::publish` opens its `.deb` inputs through `cache::open_entry`
  too. `provision::Staged` is the one staging file, which every download,
  `write_atomically`, the Debian pool, and `Export::write_to_path` write
  through.
- `provision::lock_exclusive` takes every lock file, and `provision::remove_tree`
  over `mechanism::delete_tree` removes every tree. `clippy.toml` refuses
  `rustix::fs::flock`, `rustix::io::dup`, `std::fs::remove_dir_all`,
  `rustix::fs::chmodat`, `rustix::fs::chmod`, and `rustix::rand::getrandom`,
  each with the answer that replaces it. `host::fill_random` is the
  `getrandom` answer.
- `TarReader::read_entry` is the one bounded read of a tar entry into memory,
  for Debian control files, Alpine metadata members, Gentoo container members and
  tar's own long names. `compress::read_fully` is the one filling read under
  the decoders, and `compress::Codec` names the formats `decompress` recognizes.
- `provision::document::parse` reads every field-and-stanza document, a Debian
  index, release or status file, the Gentoo binhost index and every plan, one
  stanza at a time, in place. `document::header` and `document::number` read
  every plan document's header and number fields, in all three layers.
- `provision::accounts` is the shadow-file mechanism the Debian and Alpine
  bootstraps share, and `accounts::ids` reads the id a root's `/etc/passwd` or
  `/etc/group` gives a name. `binfmt::preflight` is the one refusal of a foreign
  bootstrap. `provision::fetch::percent_decode`, moved out of the Debian index
  reader, decodes a URL's escapes for that reader and the bundled fetcher alike.
- `provision::debian::bootstrap::is_configured` is the one reading of a dpkg
  `Status` field, for a bootstrap's verification and a layer's view of its base.
- `mechanism::overlay_options` composes an overlay's mount options for a build
  and for the host probe, `spec::validate_command` validates the command for both
  builders, and `MountAction::arrival` reads what a mount op brings to rest on
  its target, for the placeholder, procfs and `resolv.conf` checks alike.
  `mechanism::raw_mount_flags` reads a raw mount's flags as `mount(2)` acts on
  them, and `spec::covers` answers whether a path lies at or under a mount
  target the launch froze.
- The Gentoo layer checks a path component with `path::is_ordinary_component`,
  and splits a name from its version through one `version::version_hyphen` that
  the package-name rule shares.
- `limits::Resource` and Debian's `Priority` are declared through
  `roster_enum!`, and the `roster` module is unconditional.
- `poll::slot` is gone. A `poll` loop leaves a finished channel out of the
  polled slice, as the `poll` module states.
- `fcage` and the examples state their exit codes once each. `fcage`'s
  `output` module makes every write of its own and decides what a reader gone
  means for it. `fcage` reads its seccomp flags' syscall names through
  `SeccompRules::syscall`, and no longer depends on the `syscalls` crate.
- The `orchestrator`, `gentoo-binhost` and `fetch-sandbox` examples set
  `test = true`, so `cargo test` runs the tests that hold their documented
  invocations to the build.
- `lzma-rust2` moves to 0.25, whose own reader accepts the memory limit. The xz
  decode runs through that reader, and the reader this crate wrote over the
  sans-I/O decoder to apply the limit is gone. The cap, and what an archive over
  it does, are unchanged.
- Dependencies refreshed within their ranges. The `alpine` feature no longer
  enables `rsa`'s `std` feature, so an Alpine-only build carries neither
  `getrandom` nor `libc`.
- `md-5` moves to 0.11, the `digest` generation `sha2` is on, so a `gentoo` build
  carries one `digest` and the MD5 hasher is driven through the same `Digest`
  trait as the SHA-2 ones.
- `tools/rust_source.py` is the one reading of a source file the census tools
  take: every comment and every test-only item removed. It finds an item's end
  by matching delimiters, and reads a `cfg` predicate rather than matching its
  spelling. `tools/check-seam.py` expands grouped imports and resolves `super::`
  paths, and finds 40 reaches past the provisioning seam, twelve of them
  internal. `tools/check-parity.py` finds every builder in the API snapshot
  rather than a list of them, which brings it to 23. It holds a launch builder's
  setting to a flag a launch takes. `tools/check-keyrings.py` reports a keyring
  Debian adds. `docs/check-links.py` builds a heading's anchor as mdBook does,
  and checks it against a build's own. `tests/stability.rs` fails on a public
  enum or struct variant without `#[non_exhaustive]`, and on a forwarding
  implementation of `Fetch` or `IdMapper` that leaves out one of the trait's
  methods.
- Every test skip goes through the testkit's `require` module, which honors its
  `REQUIRE` variable at every site, and `FERRODAY_CAGE_REQUIRE_LANDLOCK_NET` is
  folded into `FERRODAY_CAGE_REQUIRE_LANDLOCK`. The testkit holds one copy of
  each fixture and harness, the tar writer, the pseudoterminal and the process
  helpers among them, and enables none of the library's features. Its bounded
  process runner starts a child in a process group of its own through
  `spawn_grouped`, and ends the whole group past the deadline.
- CI pins every action by commit and every installed tool by version, checks
  mdBook's download against its digest, and builds the semver baseline from the
  last release tag with its own lockfile. It sets
  `FERRODAY_CAGE_REQUIRE_OVERLAY` and `FERRODAY_CAGE_REQUIRE_LANDLOCK_SCOPE`,
  installs the pinned toolchain with `rustup toolchain install`, and checks out
  without persisting credentials.
- The profile-format pin covers every key the format can carry, a pin of the
  resolved provenance record's serialized keys covers every key the record can
  carry, and `NetStackBuilder`'s keys have a pin of their own.
- `provision::openpgp`'s tests hold what the module adds over irongall: the
  bound on a document's size and signatures, the split between keyring and
  signature errors, the fields of `Verified`, the freshness flag, the refusal of
  a keyring that could vouch for nothing, and the policy choices the module
  makes. The acceptance rules are tested in irongall, which states them.

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

[Unreleased]: https://github.com/gregordinary/ferroday-cage/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/gregordinary/ferroday-cage/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/gregordinary/ferroday-cage/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/gregordinary/ferroday-cage/compare/v0.4.5...v0.5.0
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
