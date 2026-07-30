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

Nothing yet.

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

[Unreleased]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/gregordinary/ferroday-cage/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/gregordinary/ferroday-cage/releases/tag/v0.1.0
