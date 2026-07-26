# Provisioning a rootfs

A sandbox runs against a root filesystem directory the caller provides. The
`provision` module covers how that directory comes to exist: a `Provisioner`
produces a root filesystem, and `provision::ensure` publishes it atomically
at a destination.

```rust,no_run
use ferroday_cage::provision::{self, Tarball};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let rootfs = "/var/cache/myapp/alpine-rootfs";
provision::ensure(rootfs, &mut Tarball::new("alpine-minirootfs-3.24.1-x86_64.tar.gz"))?;

let status = ferroday_cage::Cage::builder()
    .rootfs(rootfs)
    .command("/bin/sh")
    .args(["-c", "cat /etc/alpine-release"])
    .build()?
    .run()?;
# Ok(())
# }
```

## Atomic publication

`ensure` guarantees that the destination directory either does not exist or
holds a complete rootfs — never a partial one:

- If the destination already exists, it is reused and the provisioner does
  not run. The first launch pays for provisioning; the rest are free.
- Otherwise the provisioner fills a staging directory beside the
  destination, the staging tree's filesystem is synced, and a single
  `rename` publishes it. An interrupted run leaves no destination for a
  later caller to trust, and a crash cannot leave truncated files behind a
  completed rename.
- Concurrent calls, including from other processes, serialize on a
  `<name>.lock` file beside the destination: exactly one provisions, the
  rest observe the published result. Locking uses `flock`, so the
  destination belongs on a local filesystem.

The return value says which happened: `Provisioned::Created` or
`Provisioned::Existing`.

The lock file persists after the call, so a later publication of the same
destination serializes on the same inode. `provision::remove` deletes it along
with the rootfs, so create and destroy round-trip cleanly — and, because
removal is idempotent, `remove` also clears the lock a *failed* provision left
beside no rootfs at all.

## Progress and cancellation

Provisioning is the slow part of a first run. `Provision` — the configurable
form of `ensure` — takes an observer that receives what the provisioner is
doing and can stop it:

```rust,no_run
use ferroday_cage::provision::{Provision, ProvisionEvent, Tarball};

# fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
Provision::new("/var/cache/myapp/alpine-rootfs")
    .observe(&mut |event: ProvisionEvent<'_>| match event {
        ProvisionEvent::Read { done, total: Some(total), .. } => {
            eprint!("\r{}%", done * 100 / total.max(1));
        }
        ProvisionEvent::Entry { path, .. } => eprintln!("{}", path.display()),
        _ => {}
    })
    .run(&mut Tarball::new("alpine-minirootfs-3.24.1-x86_64.tar.gz"))?;
# Ok(())
# }
```

A closure is an observer that reports and never cancels. To cancel as well,
implement `ProvisionObserver` and answer its `cancelled` method:

```rust,no_run
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ferroday_cage::provision::{Provision, ProvisionObserver, Tarball};

struct Watch {
    stop: Arc<AtomicBool>,
}

impl ProvisionObserver for Watch {
    fn cancelled(&mut self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

# fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
# let stop = Arc::new(AtomicBool::new(false));
let outcome = Provision::new("/var/cache/myapp/trixie")
    .observe(&mut Watch { stop: Arc::clone(&stop) })
    .run(&mut Tarball::new("rootfs.tar.zst"));
# let _ = outcome;
# Ok(())
# }
```

The check is consulted where stopping is clean — an archive entry boundary, a
package boundary — and a cancelled run fails with `ProvisionError::Cancelled`.
`ensure` then removes the staging tree exactly as it does for any other
failure, so the destination is left absent rather than half-built. Setting the
flag from a signal handler or a watchdog thread is the usual way to drive it;
`Arc<AtomicBool>` is the shape that fits both.

Every provisioner reports through this one channel, so a consumer wiring
provisioning into a logging system writes one adapter. The `Tarball`
provisioner reports each entry and its progress through the archive; the
[Debian provisioner](debian.md) reports its own richer events —
fetches, resolution, downloads, and dpkg's output — through the
`ProvisionEvent::Debian` variant, and honours the same cancellation check
between packages.

## Removing a rootfs

`provision::remove` is `ensure`'s counterpart: it deletes a rootfs
directory, including one a sandbox under a [range identity
map](identity-maps.md) has written. Such a tree can hold directories owned
by subordinate ids, whose contents the plain caller cannot unlink; `remove`
starts plain and, when refused, re-enters the same map — a forked process
unshares a user namespace, the bundled delegates establish the subordinate
map for it, and the tree is deleted from inside, where the ids are the
caller's own. It is the rootless container runtimes' `unshare rm` pattern as
a library call, and `ensure` uses the same escalation for its own staging
cleanup, so a crashed range-mapped provisioning run cannot wedge the
destination. Removing a path that does not exist is not an error.

`remove` escalates through the bundled delegate chain, which covers a tree
written under the subordinate map or a bundled-delegate range map. A tree whose
ownership a site-specific delegate established — one supplied through
`CageBuilder::id_mapper` that allocates ids the bundled delegates would not —
is removed through the `Remove` builder, whose `mapper` re-enters the map using
that same delegate:

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Remove;

# let mapper = ferroday_cage::DirectMapper::new();
Remove::new("/var/lib/myapp/rootfs")
    .map(IdentityMap::Subordinate)
    .mapper(&mapper)
    .run()?;
# Ok::<(), ferroday_cage::provision::ProvisionError>(())
```

`provision::remove(dest)` is the shorthand for the common case: the bundled
chain, and nothing to configure.

## Exporting a rootfs

With the `tarball` cargo feature, `provision::export_tar` writes a provisioned
rootfs to a POSIX/pax tar. It is the range-map counterpart of taring the
directory: under a [range identity map](identity-maps.md) the finished tree
carries real system ownership stored on the host at an offset — a file the
rootfs means as uid 42 is owned `100000 + 42` — so a host-side `tar` would
record the offset id, and could not read the `security.*` extended attributes a
setcap'd binary carries at all. `export_tar` re-enters the map the tree was
built under, exactly as `remove` does: a forked child reads every entry as root
of the mapped namespace, where the intended ids and attributes are its own.

The map is named explicitly and must be the one the tree was built under, so
the host offset ids round-trip to the ids the tree intends. Under the
single-identity map — the default — the export records every entry as root, the
identity the sandbox runs everything as.

```rust,no_run
use std::fs::File;
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Export;

let mut archive = File::create("rootfs.tar")?;
Export::new("/var/lib/myapp/rootfs")
    .map(IdentityMap::Subordinate)
    // A fixed SOURCE_DATE_EPOCH makes the archive byte-reproducible; without
    // it, real modification times are recorded.
    .clamp_mtime(1_700_000_000)
    .write_to(&mut archive)?;
# Ok::<(), ferroday_cage::provision::ProvisionError>(())
```

`provision::export_tar(rootfs, writer, map)` is the shorthand, carrying only
what every export needs.

The archive is written to any `Write` sink, so it can stream directly into a
compressor or an archive reader with no intermediate file. Regular files,
directories, symlinks, and hardlinks are emitted with their mode, ownership,
modification time, and extended attributes — ACLs and file capabilities
included. Character and block devices, FIFOs, and sockets are skipped, as a
deployed image's runtime provides its own. When no delegate can establish a
range map the export fails with `ProvisionError::ExportUnprivileged`, naming
what the host is missing.

Member names match `tar -C rootfs .`: the archive leads with a `./` directory
entry for the root and every other member is `./`-prefixed (`./etc/`,
`./etc/hostname`). A consumer that selects a member by path or strips leading
components sees the same layout GNU `tar` produces, so the export is a drop-in
for it.

The archive is byte-reproducible given the tree and a `clamp_mtime`.
Entries are emitted in sorted order — directory children by name, extended
attributes by name — so the output does not depend on the order the filesystem
stores entries in. `clamp_mtime(epoch)` records each entry's modification time
as `min(mtime, epoch)`, capping the wall-clock stamps a bootstrap writes while
preserving any earlier time a package sets; unset, the real time is recorded. A
build that pins its inputs and clamps to a fixed epoch produces a byte-identical
archive on any host.

As with removal, a tree built under a `CageBuilder::id_mapper` delegate is
exported through `Export::mapper`, which re-enters the map using that same
delegate rather than the bundled chain.

## The tarball provisioner

With the `tarball` cargo feature, `Tarball` provisions from a tar archive.
The archive may be uncompressed or compressed with gzip, xz, or zstd —
detected from the content, never the file name — and may use the POSIX
ustar, GNU, or pax dialect. Decoding is pure Rust throughout.

The archive comes from a path or from any reader:

```rust,no_run
use ferroday_cage::provision::{self, Tarball};

# fn fetch(url: &str) -> std::io::Result<std::fs::File> { unimplemented!() }
# fn main() -> Result<(), Box<dyn std::error::Error>> {
// From a file on disk, opened afresh on each run.
provision::ensure("/var/cache/alpine", &mut Tarball::new("alpine.tar.gz"))?;

// From a stream, extracted as it arrives.
let body = fetch("https://example.invalid/alpine-minirootfs.tar.gz")?;
provision::ensure("/var/cache/alpine-net", &mut Tarball::from_reader(body))?;
# Ok(())
# }
```

`from_reader` is the mirror image of `export_tar`, which writes to any `Write`:
a rootfs fetched over the network is provisioned as it arrives, with no
intermediate file on either side. A stream can be read only once, so the reader
is consumed by the first run and a second run against the same `Tarball` says
so rather than publishing an empty rootfs; `new` is the form that provisions
repeatedly.

Extraction is unprivileged and designed for archives that describe a root
filesystem:

- **Containment is kernel-enforced.** Entry paths and hardlink targets
  resolve through `openat2` strictly beneath the destination. In-tree
  relative symlinks resolve normally — a merged-usr archive whose `bin`
  is a symlink to `usr/bin` extracts correctly — while an entry that
  reaches outside through `..`, an absolute path, or a symlink chain fails
  with `ProvisionError::EntryUnsafe` before anything is written.
- **Ownership maps to the calling user.** Every extracted entry belongs to the
  calling user, whom the sandbox's identity map presents as root, so
  extracted files appear root-owned inside the sandbox. Ownership recorded
  in the archive is ignored.
- **Permission bits apply verbatim**, setuid, setgid, and sticky bits
  included. Modification times are applied from the archive; directory
  times are applied after their contents, so they survive extraction.
- **Device nodes and sockets are skipped.** They cannot be created without
  privilege, and the sandbox assembles its own minimal `/dev` at launch.
  FIFOs are extracted. Extended attributes are not applied.
- A later entry for the same path replaces the earlier one, matching tar's
  behavior. Sparse and multi-volume members are not supported and fail
  with a typed error.

Extraction imposes no size or entry-count quota; when the archive comes
from an untrusted source, bound disk usage externally.

A setuid bit applying verbatim is what a root filesystem needs — `/usr/bin/sudo`
without it is not `sudo` — and it grants nothing inside the sandbox, where the
extracting user is already root. On the host it is a live bit: the extracted file
is setuid **to the calling user**, so another local user who can reach the
destination directory, on a filesystem not mounted `nosuid`, can run it as the
calling user. Extract an untrusted archive into a directory only the calling user
can reach, or onto a `nosuid` filesystem.

[An ebuild development sandbox](ebuild-sandbox.md) works this into a consumer:
it provisions a Gentoo stage3 through `Tarball`, then runs a package build in
the provisioned root.

## Keeping a provisioned rootfs pristine

A provisioned rootfs is a durable cache: the first run pays for it and every
later run finds it published. But a sandbox writes into the root it is given,
and a bind mount creates its target inside the rootfs when the target does not
exist — a `bind("/host/data", "/work")` makes `/work` in the rootfs, and the
directory stays there on the host after the sandbox exits. Over many runs with
different binds, a shared root accretes empty mount-point directories. This
project's own test fixture shows it: an Alpine root the tests treat as
read-only has picked up `/candidates`, `/raw`, and `/work` from bind targets.

Nothing is broken by this — the directories are empty, and the next run reuses
them — but a root meant to be pristine no longer is, and it drifts from what
provisioning produced.

`overlay_rootfs` is the answer. It roots the sandbox on an overlay whose lower
layer is the provisioned tree and whose upper takes every write:

```rust,no_run
use ferroday_cage::Cage;

# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .overlay_rootfs("/var/cache/myapp/alpine-rootfs", "/var/tmp/run-42")
    .bind("/home/user/project", "/work")
    .command("/usr/bin/make")
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

The mount points, the command's writes, and anything a build leaves behind all
land in `/var/tmp/run-42`; the provisioned root is untouched and byte-identical
to what `ensure` published. Discarding the upper reverts the run, which is also
what makes the pattern a clean-root-per-build — see [the ebuild
sandbox](ebuild-sandbox.md#a-note-on-clean-builds). Keeping the upper instead
gives an incremental root layered over a shared base.

An unprivileged overlay needs Linux 5.11 or later and an upper on a filesystem
that records `user.*` extended attributes, which an on-disk filesystem (ext4,
xfs, btrfs) does; a tmpfs upper needs Linux 6.6. A host that cannot establish
one is refused at build time, naming what is missing, rather than silently
falling back to writing into the base. The kernel creates a directory in the
overlay's work area with mode `0`, so discard the upper with
`provision::remove`, which restores traversable permissions as it descends,
rather than a plain `rm -rf`.

On the command line, `--overlay-lower` and `--overlay-upper` stand in for
`--rootfs`.

## Custom provisioners

`Provisioner` is one method:

```rust,ignore
pub trait Provisioner {
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError>;
}
```

An implementation fills `request.staging()` and must not assume that directory
is the rootfs's final location — `ensure` moves it into place afterward. A
provisioner outside this crate wraps its own failures with
`ProvisionError::other`.

The inputs arrive as a `ProvisionRequest` rather than as loose parameters so
that context a provisioner comes to need can be added as accessors without
changing the method's signature; see [Stability and
versioning](stability.md#extension-traits).

The [Debian userland](debian.md) add-on is a provisioner of this kind: with
the `debian` feature it bootstraps a Debian suite from the archive, and
[Building a Debian package](building-a-debian-package.md) works it into a
consumer that builds a `.deb` from source in a cage.

## The command line

`fcage --provision-tar FILE` provisions the `--rootfs` directory from a
tar archive before launching. The already-provisioned case is silent and
fast, so the flag can stay in an invocation permanently:

```console
$ fcage --provision-tar alpine-minirootfs-3.24.1-x86_64.tar.gz \
        --rootfs ./alpine /bin/sh -c 'cat /etc/alpine-release'
3.24.1
```
