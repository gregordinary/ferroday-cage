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
holds a complete root filesystem, never a partial one:

- If the destination already exists, it is reused and the provisioner does
  not run. The first launch pays for provisioning, and the rest are free.
  Any existing directory counts, including an empty one the caller just
  made, so a destination created ahead of time is never provisioned into.
- Otherwise the provisioner fills a staging directory beside the
  destination, the staging tree's filesystem is synced, and a single
  `rename` publishes it. The rename replaces nothing, so a directory made at
  the destination meanwhile fails the run and stays as it was. An interrupted
  run leaves no destination for a later caller to trust, and a crash cannot
  leave truncated files behind a completed rename.
- Concurrent calls, including from other processes, serialize on a
  `<name>.lock` file beside the destination: exactly one provisions, the
  rest observe the published result. Locking uses `flock`, so the
  destination belongs on a local filesystem.

The return value says which happened: `Provisioned::Created` or
`Provisioned::Existing`.

The lock file persists after the call, so a later publication of the same
destination serializes on the same inode. `provision::remove` deletes it along
with the root filesystem, so create and destroy round-trip cleanly. Removal is
idempotent, so `remove` also clears the lock a *failed* provision left beside no
tree at all.

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

The check is consulted where stopping is clean, meaning an archive entry
boundary or a package boundary. A run stopped there fails with
`ProvisionError::Cancelled`. `ensure` then removes the staging tree exactly as
it does for any other failure, so the destination is left absent rather than
half-built. Setting the flag from a watchdog thread is one way to drive it, and
`Arc<AtomicBool>` is the shape that fits.

`Interrupt` is the way for `^C`. Held for the run, it blocks `SIGINT` on the
thread that holds it, reads the signal from a thread of its own, and answers
whether one arrived, so a program stops a run on `^C` without a signal handler.
The first `SIGINT` asks the run to stop, the next acts as `SIGINT` does, and
nothing is held where the process ignores `SIGINT`. Hold it before the program
starts a thread of its own, since a thread started earlier would take the
signal and end the process. `fcage` holds one for each provisioning run:

```rust,no_run
use ferroday_cage::provision::{Interrupt, Provision, ProvisionObserver, Tarball};

struct StopOnInterrupt(Interrupt);

impl ProvisionObserver for StopOnInterrupt {
    fn cancelled(&mut self) -> bool {
        self.0.requested()
    }
}

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut observer = StopOnInterrupt(Interrupt::hold()?);
let outcome = Provision::new("/var/cache/myapp/trixie")
    .observe(&mut observer)
    .run(&mut Tarball::new("rootfs.tar.zst"));
# let _ = outcome;
# Ok(())
# }
```

Every provisioner reports through this one channel, so a consumer wiring
provisioning into a logging system writes one adapter. The `Tarball` provisioner
reports each entry and its progress through the archive. The [Debian
provisioner](debian.md) reports its own richer events through the
`ProvisionEvent::Debian` variant: fetches, resolution, downloads, and dpkg's
output. It honors the same cancellation check at each mirror, between packages,
while each package downloads, and between dpkg waves. The [Alpine
provisioner](alpine.md) reports the same progress through
`ProvisionEvent::Alpine`, and the [Gentoo provisioner](gentoo.md) through
`ProvisionEvent::Gentoo`. A consumer reports any of the userlands by changing
the type it matches on.

Where the clean stopping points are is the provisioner's own question. A package
boundary answers it wherever there is one. A download is the exception, since a
Gentoo stage3 is a single file of several hundred megabytes. Every userland
therefore also consults the check while a download is being written, and a
download stopped there leaves nothing behind in the cache. A batch of downloads
fetched at once is the one place it is not consulted mid-body. The transport
writes those from threads of its own, so the check waits for the batch's end.

## Removing a rootfs

`provision::remove` is `ensure`'s counterpart. It deletes a root filesystem
directory, including one a sandbox under a [range identity
map](identity-maps.md) has written. Such a tree can hold directories owned by
subordinate ids, whose contents the plain caller cannot unlink. So `remove`
starts plain and, when refused, re-enters the same map. A forked process
unshares a user namespace and the bundled delegates establish the subordinate
map for it. The tree is then deleted from inside, where the ids are the caller's
own.

It is the rootless container runtimes' `unshare rm` pattern as a library call.
`ensure` uses the same escalation for its own staging cleanup, so a crashed
range-mapped provisioning run cannot wedge the destination. Removing a path that
does not exist is not an error. A path that names no tree, an empty one or one
with no final component such as `.`, is refused.

Both attempts walk the tree iteratively and never follow a symbolic link. A walk
holds a few descriptors whatever the depth, where a recursive removal holds one
per level. A tree a sandbox nested deeper than the caller's descriptor limit is
therefore removed like any other.

`remove` escalates through the bundled delegate chain, which covers a tree
written under the subordinate map or a bundled-delegate range map. Some trees
need more. Where a site-specific delegate established the ownership, the tree is
removed through the `Remove` builder instead. Such a delegate is supplied
through `CageBuilder::id_mapper` and allocates ids the bundled delegates would
not. `Remove::id_mapper` re-enters the map using that same delegate:

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Remove;

# let mapper = ferroday_cage::DirectMapper::new();
Remove::new("/var/lib/myapp/rootfs")
    .identity_map(IdentityMap::Subordinate)
    .id_mapper(mapper)
    .run()?;
# Ok::<(), ferroday_cage::provision::ProvisionError>(())
```

`provision::remove(dest)` is the shorthand for the common case: the bundled
chain, and nothing to configure.

A tree written under the single-identity map escalates too, named with
`Remove::identity_map(IdentityMap::Single)`, and there the child writes the map
itself with no delegate involved. Its ids are the caller's own either way, so the
escalation looks redundant and is not. Root of the mapped namespace holds the
capabilities that clear a directory whose own mode denies the write. A read-only
directory an archive carried in is the everyday case.

At a shell prompt, `fcage --remove-rootfs DIR` removes the tree and its lock
together, which is the default above. The mode names a published root
filesystem, which is the case the round-trip is right for. `--keep-lock` spells
the other case, where `DIR` merely holds such trees. `fcage` takes
`--identity-map` for the map the tree was provisioned under, defaulting to the
subordinate one. It is a mode of its own that accepts no other option:

```sh
fcage --remove-rootfs /var/lib/myapp/rootfs
fcage --remove-rootfs /var/cache/myapp/work --keep-lock
```

### The lock beside the tree

A removal takes the `<dest>.lock` `ensure` wrote beside the destination, so a
published root filesystem and its lock round-trip together. Some callers mean
the other thing. Where `dest` *contains* published trees rather than being one,
such as a scratch directory or a cache holding several, pass `false` to
`Remove::remove_lock`:

```rust,no_run
use ferroday_cage::provision::Remove;

Remove::new("/var/cache/myapp/work").remove_lock(false).run()?;
# Ok::<(), ferroday_cage::provision::ProvisionError>(())
```

Only the caller can tell the two apart. Both are directories, and a containing
directory with no `.lock` sibling today looks exactly like a published one whose
lock was already cleared. The library cannot probe for the answer. The tree
itself is removed identically either way, and the flag governs the sibling file
alone.

A removal that takes the lock also holds it while it runs. It waits for a
publication of the same destination to finish, and a publication that starts
meanwhile waits for the removal. The lock file is deleted while it is still
held. A publication waiting on it finds that the path no longer names the file
it locked, and locks the file there now instead.

## Exporting a rootfs

With the `tarball` cargo feature, `provision::export_tar` writes a provisioned
root filesystem to a POSIX/pax tar. It is the range-map counterpart of taring
the directory. Under a [range identity map](identity-maps.md) the finished tree
carries real system ownership stored on the host at an offset. A file the tree
means as uid 42 is owned `100000 + 42`.

A host-side `tar` would record the offset id, and could not read the `security.*`
extended attributes a setcap'd binary carries at all. `export_tar` re-enters the
map the tree was built under, exactly as `remove` does. A forked child then
reads every entry as root of the mapped namespace, where the intended ids and
attributes are its own.

The map is named explicitly and must be the one the tree was built under. The
host offset ids then round-trip to the ids the tree intends.

The kernel reports an owner the map does not hold as its overflow id, 65534
unless the host sets another, and an access control list naming one the same
way. Under a map that holds no id 65534, the single-identity map among them,
that id can only be one the map does not hold. The export then refuses the entry
with `ProvisionError::EntryRefused`, naming it, since the tree was built under
another map. A map that holds 65534, as the subordinate map does, cannot tell
such an entry from one the tree means as `nobody`, and records it owned by 65534.

Under the single-identity map, which is the default, the export records every
entry as root. That map gives its one id, the calling user who wrote the tree,
uid 0.

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Export;

Export::new("/var/lib/myapp/rootfs")
    .identity_map(IdentityMap::Subordinate)
    // A fixed SOURCE_DATE_EPOCH makes the archive byte-reproducible; without
    // it, real modification times are recorded.
    .clamp_mtime(1_700_000_000)
    .write_to_path("rootfs.tar")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`provision::export_tar(rootfs, writer, map)` is the shorthand, carrying only
what every export needs.

### Choosing what the archive holds

`Export::filter` takes a predicate and writes only the entries it answers
`true` for. Some trees hold more than the artifact is meant to carry. A build
cache, a resolver's package lists, and the contents of a mount point the
deployed runtime fills in for itself are the usual three. The filter exports
such a tree without editing it first, which matters when a later build will
reuse it.

**Excluding a directory excludes everything under it**, without the predicate
being consulted about the descendants, so a rule names the top of a subtree
once. This keeps `/dev` as a mount point and drops the package cache outright:

```rust,no_run
use std::path::Path;
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Export;

let dev = Path::new("/dev");
let cache = Path::new("/var/cache/apt/archives");

Export::new("/var/lib/myapp/rootfs")
    .identity_map(IdentityMap::Subordinate)
    .filter(move |entry| {
        !entry.path().starts_with(cache)
            && (entry.path() == dev || !entry.path().starts_with(dev))
    })
    .write_to_path("rootfs.tar")?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The entry is offered with its path spelled as a location *inside the tree*,
meaning `/etc/hostname`, and `/` for the tree itself. That is how a mount target
or a Landlock grant names one, rather than the `./`-prefixed member name the
archive carries. It is a `Path`, so `starts_with` compares whole components and
`/dev` does not match `/devices`. Beside the path it carries the entry's kind,
its permission bits, the ownership the tree intends, the file's size, and its
unclamped modification time. Refusing the tree's root is allowed and produces an
empty archive, since the root is an entry like any other.

A hardlink is offered as `ExportKind::File`, and dropping one name of an inode
does not lose the file. The next kept name carries the data and later ones link
onto it. Character and block devices, FIFOs, and sockets are never offered at
all, because the export skips them before any filter runs.

The filter runs on the parent side of the export, where the paths are assembled.
The walking child is a post-fork reader that cannot call a caller's code. An
excluded subtree is therefore read from the tree and discarded rather than never
visited.
The archive is what the filter says, and the walk is not made cheaper by it.

The archive stays byte-reproducible as long as the predicate is a pure function
of the entry, which every input it is given already is.

### Where the archive goes

`write_to_path` names a file, and that file appears complete or not at all. The
bytes go to a staging file beside it, which is synced and then renamed over the
destination. An export that fails part-way therefore leaves whatever archive was
already there. The cause might be an unreadable source entry, an identity map no
delegate can establish, or a filesystem that filled up. Opening the destination
directly would instead destroy a previous archive to make a partial one, before
the export had established that it could produce anything.

The staging file is created afresh, so the destination's inode is replaced
rather than rewritten. A hard link to the previous archive keeps it, and a
symlink at the destination is replaced rather than followed. The new file's
permissions are `0o666` less the process umask, as an ordinary shell redirection
produces.

A destination *inside* the tree being exported is refused with
`ProvisionError::ExportDestInside`. The walk would reach the file it is being
written to. What landed in the archive would then depend on how far the encoder
had got when the walk arrived.

`write_to` takes any `Write` sink instead, so an export can stream directly into
a compressor or an archive reader with no intermediate file. It writes what it
is given and cannot stage onto anything. That is the right shape for a pipe, a
socket, or a buffer in memory. It is the wrong one for a file a previous archive
already occupies.

Regular files, directories, symlinks, and hardlinks are emitted with their mode,
ownership, and modification time. Extended attributes come with everything but
symlinks, ACLs and file capabilities included. The kernel confines a symlink's
attributes to the `security` and `trusted` namespaces. An unprivileged export
cannot read those in full, and an unprivileged extraction cannot restore
them.
Character and block devices, FIFOs, and sockets are skipped, as a deployed
image's runtime provides its own. When no delegate can establish a range map the
export fails with `ProvisionError::ExportUnprivileged`, naming what the host is
missing.

The attributes the host assigns rather than the tree carries are left out.
Those are a security module's labels, such as `security.selinux`, the integrity
subsystem's `security.ima` and `security.evm`, and overlayfs's own `overlay.*`
bookkeeping. They describe the host the tree sat on, and they differ between two
hosts holding the same tree.

Each attribute is a `SCHILY.xattr.` pax record. A record's keyword ends at its
first `=`, so a name holding one is spelled as GNU `tar` spells it. An `=` is
written `%3D` and a `%` is written `%25`, and GNU `tar` restores the name
whole.

Member names match `tar -C rootfs .`. The archive leads with a `./` directory
entry for the root and every other member is `./`-prefixed (`./etc/`,
`./etc/hostname`). A consumer that selects a member by path or strips leading
components sees the same layout GNU `tar` produces. The export is a drop-in for
it.

The archive is byte-reproducible given the tree and a `clamp_mtime`. Entries are
emitted in sorted order, directory children by name and extended attributes by
name. The output therefore does not depend on the order the filesystem stores
entries in. `clamp_mtime(epoch)` records each entry's modification time as `min(mtime,
epoch)`. That caps the wall-clock stamps a bootstrap writes while preserving any
earlier time a package sets, and unset, the real time is recorded. A build that
pins its inputs and clamps to a fixed epoch produces a byte-identical archive on
any host.

Each directory is read whole and sorted in memory the export sets aside before
it starts. That holds several hundred thousand entries across the directories
the walk is inside at once. A tree that needs more fails the export rather than
being written out of order. A file that grows or shrinks while it is read
fails the export with `ProvisionError::SourceChanged`, naming the file, rather
than archiving it cut or padded.

A file is archived at its length, and a sparse file's holes as the zeros they
read as. A file can cost the command that wrote it nothing: `truncate -s 16T`
writes no data and takes no space, yet its member holds sixteen tebibytes. The
export sets no ceiling of its own, as extraction sets no quota. Where untrusted
code wrote the tree, bound the sink. `write_to` takes any `Write`, and one that
refuses past a ceiling fails the export at that point.

As with removal, a tree built under a `CageBuilder::id_mapper` delegate is
exported through `Export::id_mapper`. That re-enters the map using the same
delegate rather than the bundled chain.

At a shell prompt, `fcage --export-rootfs DIR` is the same export. It takes
`--identity-map` for the map the tree was provisioned under, defaulting to the
subordinate one. `--clamp-mtime` names the epoch that makes the archive
byte-reproducible. Like the removal, it is a mode of its own that accepts no
other option.

The archive goes to standard output, so it pipes into a compressor without a
temporary file:

```sh
fcage --export-rootfs /var/lib/myapp/rootfs --clamp-mtime 1700000000 \
    | zstd -o rootfs.tar.zst
```

`--export-to FILE` writes to a file instead, with the staging and rename above,
so a failed run leaves an existing archive at that path untouched. Writing an
archive to a terminal is refused rather than filling the screen, which is the
only case where the default would surprise anyone.

### What a launch leaves in the tree

An export records the tree as it is, so what a provisioning sandbox contributed
to the tree is what the archive carries. A launch over a plain root filesystem
leaves its mount points behind, and the links its `symlink` mounts make, and
nothing else:

| Path | What is left | Mode |
| --- | --- | --- |
| `/proc` | the mount point, empty | `0755` |
| `/dev` | the mount point, empty | `0755` |
| `/tmp` | the mount point, empty | `1777` |

A mount point is created only when the tree does not already have the path. A
path the tree ships keeps the mode it shipped with. The tree owns what it ships,
and the sandbox owns what it creates. The mode is the directory's own,
independent of the launching process's umask, so the same tree exports the same
way from any host.

Nothing survives *inside* those directories. The `/dev` the sandbox assembles is
built inside the tmpfs that covers the mount point, so it goes with the mount
namespace. That is the six device nodes, the five symlinks, the `devpts` on
`/dev/pts` and the tmpfs on `/dev/shm`. An exported tree holds `./dev/` and
nothing under it.

A mount that contributes a *file* rather than a directory takes it back. A bind
needs its target to exist, so the `/etc/resolv.conf` bind that host networking
performs creates an empty file when the tree ships none. It removes that file
once the sandbox is gone, leaving the tree without the resolver configuration it
never had.

A caller's own file bind is treated the same way. The empty `0644` target it
needs is present for the mount to cover and for nothing else. Its mode is exact,
independent of the launching process's umask. A tree that does ship an
entry at that path keeps it untouched, whether it is a file or a symbolic link.
The bind covers it for the sandbox's life and reveals it again afterwards.

A caller's own `bind` or `raw_mount` is the case where a *directory* target is
created and stays, as `0755`. A caller's `symlink` mount stays too. It is a
link made in the tree rather than a mount over it, so nothing takes it back.
That is worth knowing when the tree being written into is the one being
shipped. A bind declared for the duration of a build leaves its mount point in
the artifact, and a link leaves its link.

Where a launch must leave the tree untouched entirely, root it on an overlay.
Every mount point, and every write the command makes, lands in the upper rather
than in the base:

```rust,no_run
# use ferroday_cage::Cage;
# fn main() -> ferroday_cage::Result<()> {
Cage::builder()
    .overlay_rootfs("/var/lib/myapp/rootfs", "/var/lib/myapp/build-42")
    .command("/usr/bin/make")
    .build()?
    .run()?;
# Ok(())
# }
```

Discarding the upper reverts the run, base included, and exporting the base
afterwards gives an archive of a tree no sandbox has written to.

## Copying a tree into a rootfs

`CopyIn` lays a host directory tree into a root filesystem, with each entry
created under the identity map that tree is owned through:

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::CopyIn;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let report = CopyIn::new("./overlay", "/srv/images/trixie")
    .identity_map(IdentityMap::Subordinate)
    .run()?;

for entry in &report.skipped {
    eprintln!("not copied: {} ({})", entry.path.display(), entry.kind);
}
for attribute in &report.attributes {
    eprintln!(
        "not given: {} on {} ({})",
        attribute.name.display(),
        attribute.path.display(),
        attribute.reason,
    );
}
# Ok(())
# }
```

It is the mirror image of the export. An export forks a child into the map to
*read* a tree at the ownership it intends, and this forks one to *write* one.
That is what `cp` structurally cannot do. `cp` runs as the calling user, which
can create a file owned by nobody else. A tree laid in by hand therefore arrives
owned by the caller, whatever the source intended.

Ownership is read through the map, which is what makes the two exact mirrors. A
file the host stores at `100000 + 42` is uid 42 as the tree means it. The copy
stores it back at the host id the map puts it at. A tree an earlier mapped
sandbox produced therefore copies into a root filesystem owned through the same
map with its ownership intact.

Under `IdentityMap::Single` the same rule lands everything as root, that map
having only the one inside id. That is what such a sandbox sees, and what it
could have written itself. A source id no extent covers is refused, naming the
path that carries it: the tree has no id for it.

The destination must already exist, and entries are added to it. A directory the
tree already carries is kept as it stands: the copy does not set its owner,
mode, or modification time. A source staged under a restrictive umask
therefore leaves the tree's `/etc` as it was. Anything else at a directory's
name is replaced. A file, symlink, or named pipe replaces whatever is at its
own, an empty directory included. A directory with something in it fails the
copy.

A symbolic link that resolves inside the tree to a directory counts as a
directory. A copy into a merged-usr tree therefore lands through
`/bin -> usr/bin` rather than replacing it. The link resolves from the tree's
root, as it does inside the sandbox.

Directories, regular files, symbolic links, and named pipes are copied, with
their modes and modification times. A symbolic link's modification time is its
own rather than its target's. Its mode is the one thing not carried, the kernel
fixing every symbolic link's at `0777`.

A sparse file is copied sparse. The copy finds a file's data with `SEEK_DATA`
and `SEEK_HOLE` and leaves each hole a hole. A file can cost the command that
wrote it nothing: `truncate -s 16T` writes no data and takes no space. Its copy
costs its data rather than its length, where writing what it reads as would fill
the destination's disk with zeros. A source filesystem that cannot report where
a file's holes are has the file copied as the zeros it reads as.

Several names for one file are copied as hard links onto the first name. A tree
therefore keeps the sharing it was written with, and its data is streamed once.
That is what lets a tree exported by `Export`, which coalesces hard links of its
own, come back through `CopyIn` unchanged. A second name that the tree already
holds as the first, as `bin/x` and `usr/bin/x` are one name through
merged-usr's `bin -> usr/bin`, is already copied.

Extended attributes are copied where the tree's root can set them. Those are
`user.` attributes, POSIX access control lists, and a file's capabilities. Each
is given after the entry's ownership and mode, so the `chown` that clears a
capability comes first. A directory's are given once its contents are written.
Nothing the copy creates inside it then inherits its default list.

A list names users and groups, and a capability names the user it is rooted at.
Those ids are read through the map as an owner is, so the copy names whom the
source named. A capability the source holds in its plain form lands rooted at
the tree's root. That is the most a user namespace's root can grant.

What the tree's root cannot set is left off and named in the report. That covers
a `trusted.` attribute, and a `security.` attribute other than a capability. It
covers a `system.` attribute other than an access control list, and anything a
symbolic link holds. It also covers a list or a capability naming an id the map
has no id for.

A list left off is not dropped as though it were never there. Where a list has
a mask, the group bits of a mode are the mask. The mode alone would then give
the owning group what the mask allows. The entry is given the list's narrowing
instead. The owning group keeps what the list gave it, and the named entries
lose what they had. A directory's default list is narrowed the same way.

The attributes the host assigns are left for the destination's host to assign,
as an export leaves them out.

Character and block devices and sockets cannot be copied. A device node needs a
privilege the copy does not hold whatever map it is under. A socket's inode is
created by the process that binds it, and is meaningless without it. Rather
than dropping those in silence, the run returns a `CopyReport`. It names every
entry the copy left out and what each one was, and every attribute it did not
give. A tree that ends up missing something therefore says so.

A source file that changes size while it is being read fails the run with
`ProvisionError::SourceChanged`. The frame's length is committed before the data
is read, so such a file is written padded or truncated. The copy finishes the
frame to keep the stream in step and then refuses, rather than reporting success
for a file it did not reproduce. A name that stops holding the file the walk
inspected, before the walk opens it, is refused the same way. A named pipe put
there does not hold the copy waiting.

Containment is structural rather than checked. Every frame the parent sends
names its entry as a single path component, never a path. The child creates each
entry relative to the directory it currently holds open. There is then no path
for a `..` or a leading `/` to appear in.

Two steps resolve a path from the tree's root instead. One is an alias the copy
lands through. The other is a hard link's anchor, a path because the two names
can sit in different directories. Both resolve with `RESOLVE_IN_ROOT`, so no
component, absolute or not, can take the resolution out of the tree. The link
is made without following the anchor's final component. The child refuses an
anchor that is absolute or holds a `.`, `..`, or empty component.

A symlink in the source is recreated as a symlink and never traversed. The walk
does not descend through one, and the child follows no link at a leaf. A link
at the source path itself is followed, as the path is the caller's own. A link
pointing out of the tree therefore lands inside the destination as a link, and
nothing is written through it.

## The tarball provisioner

With the `tarball` cargo feature, `Tarball` provisions from a tar archive. The
archive is either uncompressed or compressed with gzip, xz, or zstd, detected
from the content and never the file name. It uses the POSIX ustar, GNU, or pax
dialect, or the pre-POSIX v7 one that predates all three. Decoding is pure Rust
throughout.

v7 is worth naming because it still turns up. It carries no magic, no
`uname`/`gname`, no device numbers, and no `prefix` field. A v7 path therefore
fits the 100-byte name field or does not exist. A directory is marked by a `5`
typeflag, a trailing `/` on the name, or both.

Contemporary tooling does not write it. But an upstream release tarball was
written by whoever released the software, on whatever machine, in whatever year.
A sample of Debian trixie's `.orig.tar.*` files finds roughly one in twelve is
v7.

Two of the three compressions let the archive name its own memory cost, in a
header far smaller than the memory it asks for. A zstd frame declares the
window the decoder buffers, and an xz block declares the dictionary the decoder
grows as output arrives, so any input that decodes to a long enough run pays
for all of it. Both are capped at 128 MiB, which is twice the largest either
uses in the archives this library reads.

Each decoder is given its cap and checks the header against it before
allocating. An archive over the cap therefore fails the provisioning run rather
than being paid for and then reported. The check is per block and per frame,
not on the first alone. A hostile declaration in the last block of an otherwise
ordinary archive costs exactly as much as one in the first. Nothing
published by Debian, Alpine, postmarketOS, or Gentoo comes close to the cap.

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

`from_reader` is the mirror image of `export_tar`, which writes to any `Write`.
A root filesystem fetched over the network is provisioned as it arrives, with no
intermediate file on either side. A stream can be read only once, so the reader
is consumed by the first run. A second run against the same `Tarball` says so
rather than publishing an empty tree, and `new` is the form that provisions
repeatedly.

A stream that ends before its first header block holds no archive, and is
refused with `ProvisionError::FormatUnrecognized`. An empty file, a download
that produced nothing, and a compression stream whose decoded payload is empty
all arrive that way.

The reader does tolerate an archive whose final two-block terminator never
arrived, as GNU `tar` does. But it tolerates that only once at least one entry
has been read, because a publication is durable. A stream taken for a complete
archive of nothing would publish an empty tree. Every later `ensure` then
returns that as `Provisioned::Existing` without consulting the source again.

A source that fails to deliver what it holds, a file that cannot be read or a
stream whose connection resets, fails the run with `ProvisionError::Io` naming
the archive, wherever in the stream the failure comes. A compressed stream its
decoder refuses fails with `ProvisionError::Archive`, which names the archive
too, the decoder's own failure its cause. A caller that retries a transport failure tells the two apart by the
variant, since retrying a malformed archive fetches the same bytes again.

The stream is read to its end, past the archive's end marker. A gzip member
always ends with a CRC. An xz block and a zstd frame carry a check where the
encoder wrote one, as the `xz` and `zstd` tools do by default. The last check
follows the end marker, and reading on is what compares it. A damaged final
block that a check covers therefore fails the run rather than extracting. More
than sixteen mebibytes after the marker, once decompressed, is refused. That
leaves room for the record padding `tar` writes, up to a GNU `tar` blocking
factor of 32768 and every one `bsdtar` takes. A plain archive has no check to
read on for, and is read to its marker and no further.

Extraction is unprivileged and designed for archives that describe a root
filesystem:

- **Containment is kernel-enforced.** Entry paths and hardlink targets
  resolve through `openat2` inside the destination. A symbolic link resolves
  as the root filesystem resolves it, so a merged-usr `bin -> usr/bin` and an
  absolute `var/run -> /run` both lead inside the destination. An entry whose
  own path is absolute or climbs with `..` fails with
  `ProvisionError::EntryUnsafe` before anything is written. That error
  means an escape attempt and nothing else. Any other refusal is a
  `ProvisionError::EntryRefused`, such as a path through a file or a link
  whose target is empty or holds a NUL.
- **Ownership maps to the calling user.** Every extracted entry belongs to the
  calling user, which the sandbox's identity map gives uid 0, so extracted
  files appear root-owned inside the sandbox. A command with a presented
  identity sees them as that identity's instead. Ownership recorded in the
  archive is ignored.
- **Permission bits apply verbatim**, setuid, setgid, and sticky bits
  included. Modification times are applied from the archive, and directory
  times are applied after their contents, so they survive extraction.
- **Device nodes and sockets are skipped.** They cannot be created without
  privilege, and the sandbox assembles its own minimal `/dev` at launch.
  FIFOs are extracted. Of the extended attributes an archive records, only
  the POSIX access control lists an `Export` writes are applied, as below.
- A later entry for the same path replaces the earlier one, matching tar's
  behavior. Sparse members fail with `ProvisionError::EntryUnsupported`,
  whichever GNU format wrote them. That is the old `S` type, and the pax
  formats 0.0, 0.1 and 1.0, whose headers claim a regular file. Multi-volume
  members fail the same way.

An archive records an access control list as
`SCHILY.xattr.system.posix_acl_access`, and a directory's default list as
`SCHILY.xattr.system.posix_acl_default`. A list is applied after the entry's
mode, and a directory's once its contents are written. Its named users and
groups are the ids the tree means, as an export reads them inside the map. Each
is read through the map to the host's id. The single-identity map holds only
root inside, which is the calling user.

A list naming an id the map has no host id for is given as its narrowing. So is
a list the destination's filesystem cannot hold. The owning group then keeps
what the list gave it, rather than the mask the mode's group bits show. No
other extended attribute is applied. A capability needs a privilege the
extraction does not hold.

Extraction imposes no size or entry-count quota. Where the archive comes from an
untrusted source, bound disk usage externally.

A setuid bit applying verbatim is what a root filesystem needs, since
`/usr/bin/sudo` without it is not `sudo`. It grants nothing inside the sandbox,
where the extracting user is already root. On the host it is a live bit. The
extracted file is setuid **to the calling user**. Another local user who can
reach the destination directory, on a filesystem not mounted `nosuid`, can
therefore run it as the calling user. Extract an untrusted archive into a
directory only the calling user can reach, or onto a `nosuid` filesystem.

[An ebuild development sandbox](ebuild-sandbox.md) works this into a consumer.
Given a stage3 tarball already on the host, it provisions the root through
`Tarball`, then runs a package build in it.

## Keeping a provisioned root pristine

A provisioned root filesystem is a durable cache: the first run pays for it and
every later run finds it published. But a sandbox writes into the root it is
given. A bind mount creates its target inside the tree when the target does not
exist. A `bind("/host/data", "/work")` therefore makes `/work` there, and the
directory stays on the host after the sandbox exits. Over many runs with
different binds, a shared root accretes empty mount-point directories, one for
each bind target it did not already hold.

Nothing is broken by this, since the directories are empty and the next run
reuses them. But a root meant to be pristine no longer is, and it drifts from
what provisioning produced.

`overlay_rootfs` is the answer. It roots the sandbox on an overlay whose lower
layer is the provisioned tree and whose upper takes every write:

```rust,no_run
use ferroday_cage::Cage;

# fn main() -> ferroday_cage::Result<()> {
let status = Cage::builder()
    .overlay_rootfs("/var/cache/myapp/alpine-rootfs", "/var/cache/myapp/run-42")
    .bind("/home/user/project", "/work")
    .command("/usr/bin/make")
    .build()?
    .run()?;
# let _ = status;
# Ok(())
# }
```

The mount points, the command's writes, and anything a build leaves behind all
land in `/var/cache/myapp/run-42`. The provisioned root is untouched and
byte-identical to what `ensure` published. Discarding the upper reverts the run,
which is also what makes the pattern a clean-root-per-build, covered in [the
ebuild sandbox](ebuild-sandbox.md#a-note-on-clean-builds). Keeping the upper
instead gives an incremental root layered over a shared base.

An unprivileged overlay needs Linux 5.11 or later, and an upper on a filesystem
that records `user.*` extended attributes. An on-disk filesystem (ext4, xfs,
btrfs) does, and a tmpfs upper needs Linux 6.6. A host that cannot establish one
is refused at build time, naming what is missing, rather than silently falling
back to writing into the base.

The overlay also needs a work directory beside the upper, which the library
creates as a hidden sibling. The kernel creates a directory inside it with mode
`0`, which a plain `rm -rf` cannot read into. Discard an upper with
`Remove::overlay_upper`, which removes the work directory with it:

```rust,no_run
use ferroday_cage::IdentityMap;
use ferroday_cage::provision::Remove;

# fn main() -> Result<(), ferroday_cage::provision::ProvisionError> {
Remove::overlay_upper("/var/cache/myapp/run-42")
    .identity_map(IdentityMap::Single)
    .run()?;
# Ok(())
# }
```

Name the identity map the sandbox ran under. A sandbox's default is the single
map, while a removal's default is the subordinate one. The removal starts as the
calling user and escalates through the map only where it is refused. An upper is
not a published root filesystem, so the removal leaves any `.lock` beside it in
place. An overlay that names its own work directory removes it with a
`Remove::new` of its own, with `remove_lock(false)`.

Put the upper under a directory the calling user controls, not a world-writable
one such as `/var/tmp`. That is the same requirement `rootfs` carries, for a
sharper reason. The upper is where the sandbox's writes land, and where the
caller reads its result back afterwards.

The library creates the upper and its work directory with `mkdirat` against
their parent. It adopts an existing entry only when it is a directory the
calling user owns. A symbolic link another local user planted at the path is
therefore refused rather than followed. That closes the create. It does not make
a shared parent safe: the mount options name the layers as paths, and the kernel
resolves them again at mount time.

On the command line, `--overlay-lower` and `--overlay-upper` stand in for
`--rootfs`, and `--remove-overlay-upper` discards the upper with its work
directory:

```sh
fcage --remove-overlay-upper /var/cache/myapp/run-42 --identity-map single
```

## Custom provisioners

`Provisioner` is one method:

```rust,ignore
pub trait Provisioner {
    fn provision(&mut self, request: &ProvisionRequest<'_>) -> Result<(), ProvisionError>;
}
```

An implementation fills `request.staging()` and must not assume that directory
is the tree's final location, since `ensure` moves it into place afterward. A
provisioner outside this crate wraps its own failures with
`ProvisionError::other`.

The inputs arrive as a `ProvisionRequest` rather than as loose parameters. That
way, context a provisioner comes to need can be added as accessors without
changing the method's signature. [Stability and
versioning](stability.md#extension-traits) covers the rule.

The [Debian userland](debian.md) add-on is a provisioner of this kind. With the
`debian` feature it bootstraps a Debian suite from the archive. [Building a
Debian package](building-a-debian-package.md) works it into a consumer that
builds a `.deb` from source in a sandbox. The [Alpine userland](alpine.md) is
the second, and provisions an Alpine or postmarketOS root the same way.

The [Gentoo userland](gentoo.md) is the third. It verifies a signed stage3 and
extracts it, then installs prebuilt packages into the result from the archive's
binary-package host. Uniquely among the three, it resolves against a root that
already has 296 packages in it.

## The command line

`fcage --provision-tar FILE` provisions the `--rootfs` directory from a
tar archive before launching. The already-provisioned case is silent and
fast, so the flag can stay in an invocation permanently:

```console
$ fcage --provision-tar alpine-minirootfs-3.24.1-x86_64.tar.gz \
        --rootfs ./alpine /bin/sh -c 'cat /etc/alpine-release'
3.24.1
```
