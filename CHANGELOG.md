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

### Changed

- **Breaking.** A container requires a procfs. The nested user namespace's
  identity map is established through one, by path, from inside the sandbox, so
  a profile that mounts none is refused at build time with the new
  `ConfigError::NestedUsernsNeedsProcfs`. The managed profile mounts one by
  default; this is reachable only from a profile that sets `managed_mounts(false)`
  or `mount_proc(false)` and declares no procfs of its own. A bind of the host's
  procfs serves, except under the one combination that needs the sandbox's own
  pids to index it — a range identity map inside a PID namespace of the
  sandbox's own — where a fresh instance is required.

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

### Fixed

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

### Added

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
  built. Both are optional, both are written to a plan document and read back,
  and neither changes the document's `Format` version: a document written
  without them still reads. They are written after every field the format's
  first readers knew, which is where those readers put an unknown field back, so
  a plan that makes the round trip through an older reader of this library
  returns byte-identical.

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

- `ResolvedArchive::signed_by`, and a plan document's `Signed-By`, now name the
  verifying certificate's primary key rather than the subkey that made the
  signature. It is the identity a keyring entry is named by and the one to pin a
  repository against, and unlike the signing key it survives an archive rotating
  its subkey. The subkey is still reported, as `signing_key`.

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

[Unreleased]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gregordinary/ferroday-cage/releases/tag/v0.1.0
