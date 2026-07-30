# Identity maps

Every sandbox runs inside a user namespace, and the namespace's identity map
decides which uids and gids exist there and which host ids they are. The map
is part of who the sandbox *is*: it governs what `chown` can name, which
users a build can drop to, and what ownership the sandbox's writes leave on
the host.

The default map is the **single-identity map**: root inside is the calling
user outside, and no other id exists. It costs nothing and works everywhere
the sandbox itself works. Its limits follow directly from having one id:
reads of host files owned by anyone else present the overflow id (`nobody`),
and changing a file's ownership to any other id fails with `EINVAL`, because
the namespace cannot represent the id at all. Most commands never notice.
Packaging tools do — a Debian maintainer script's `chown root:mail`, or
portage chowning its state to the `portage` user, fails outright.

A **range map** removes the limit by giving the sandbox more ids:

```rust,no_run
use ferroday_cage::{Cage, IdentityMap};

# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .rootfs("/srv/rootfs/gentoo")
    .command("/usr/bin/emerge")
    .identity_map(IdentityMap::Subordinate)
    .build()?;
# Ok(())
# }
```

Inside a subordinate-mapped sandbox, root is still the calling user, and
inside ids from 1 onward are the user's subordinate allocation — 65536 ids
on a typically configured host. `chown` succeeds, `setgroups` works, and
users other than root genuinely exist.

## What the kernel permits

The map shapes the design because the kernel constrains who may write it:

- An unprivileged process writing its own map may write **exactly one line,
  of exactly one id, naming its own effective id** — the single-identity
  map, and nothing else.
- Any richer map must be written **from outside** the new namespace, by a
  process holding `CAP_SETUID` and `CAP_SETGID` over its parent. This is
  true even of a process that was privileged before it unshared:
  capabilities extend to a namespace's descendants, never to its ancestors.
- The map files are **write-once**. There is no establish-then-extend path,
  so whichever party applies the map applies all of it, once.

The launch accounts for this internally. The single-identity map is written
by the launch stage itself, in process. For a range map, the launch stage
unshares and then blocks at an internal gate while the caller's side writes
the map against its pid, and only then proceeds — so by the time a launch is
observable, its namespace is always fully mapped.

## Delegates

Who writes a range map is a public seam: the `IdMapper` trait. An
implementation answers two questions — `resolve`, called at `build`, reports
the ranges it can provide, so an unsatisfiable map is a configuration error
rather than a launch failure; `apply`, called during each launch, writes the
map against the gated launch stage. The library bundles two delegates and
consults them in order when none is configured:

- **`DirectMapper`** writes the map itself — pure Rust, in process.
  It works when the caller already holds `CAP_SETUID` and `CAP_SETGID` over
  its own user namespace: running as root, or running inside another
  range-mapped namespace. The second case matters more than it may appear —
  a cage nested inside a range-mapped cage, or inside a rootless container,
  establishes its range map this way, entirely on its own.
- **`SubidMapper`**, behind the `subid` feature, executes the shadow suite's
  privileged `newuidmap` and `newgidmap` helpers — the standard
  subordinate-id mechanism every rootless container runtime uses, and the
  only route to a range map for an ordinary unprivileged caller on an
  ordinary host. This is the one place the crate executes an external
  binary, which is why it is a non-default feature: it keeps the default
  build self-contained.

A caller with site-specific machinery — a privileged broker of its own, a
different helper — supplies its own implementation through
[`CageBuilder::id_mapper`], and the bundled delegates step aside.

The fallback is **between delegates, never between tiers**. A range request
no delegate can satisfy fails at `build`, naming each delegate's refusal and
the host condition responsible; it is never quietly downgraded to the
single-identity map. An identity posture that silently becomes something
weaker is worse than one that fails — a caller who wants the single-identity
map asks for it by name.

## The subordinate allocation

`IdentityMap::Subordinate` requests root plus the caller's whole subordinate
allocation, as the delegate reports it. The composed map is the caller's own
id at inside-id 0, then inside ids from 1 onward covering each allocated
range in order.

The allocation is the administrator's delegation, granted per user in
`/etc/subuid` and `/etc/subgid` (`usermod --add-subuids` manages it) — or by
a site's directory service, since subordinate ids are an NSS database like
`passwd`. The library therefore does not simply parse the files: it queries
`getsubids`, which consults the same sources the helpers do, and reads the
files directly only on hosts whose `nsswitch.conf` names no other `subid`
source — the same rule the shadow suite itself follows, so the fallback can
never miss a directory-provided allocation.

Explicit ranges are the alternative when the exact shape matters:

```rust,no_run
use ferroday_cage::{Cage, IdRange, IdentityMap};

# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .rootfs("/srv/rootfs")
    .command("/bin/sh")
    .identity_map(IdentityMap::ranges(
        vec![
            IdRange { inside: 0, outside: 1000, count: 1 },
            IdRange { inside: 1, outside: 100000, count: 999 },
        ],
        vec![
            IdRange { inside: 0, outside: 1000, count: 1 },
            IdRange { inside: 1, outside: 100000, count: 999 },
        ],
    ))
    .build()?;
# Ok(())
# }
```

Both lists must map inside-id 0 — the sandbox is built as root inside — and
stay within the kernel's limits, which `build` checks: no overlaps, no zero
or wrapping extents, at most 340 extents per map.

## Host requirements

The single-identity map has no requirements beyond the sandbox's own. The
delegated tier needs the shadow suite's subordinate-id helpers, whose
package differs by distribution:

| Host | Package |
| --- | --- |
| Debian, Devuan, Ubuntu | `uidmap` |
| Alpine | `shadow-subids` |
| Gentoo | `sys-apps/shadow` |
| Void | `shadow` |

The helpers are not always setuid: several distributions grant them file
capabilities instead, which works equally well, and
[`host::range_map_blocker`] probes for a *working* helper rather than a mode
bit. The probe names whichever condition blocks a range map — a missing
helper (commonly a container runtime installed without its recommended
packages), a helper stripped of its privilege, a file-capability helper too
old to map uid 0 (shadow before 4.11.1), a symlinked subordinate file, or an
absent allocation — with the remedy in the message. `Subordinate` on a build
without the `subid` feature is refused the same way, at `build` for code and
at load time for a profile.

## Ownership on the host

Range-mapped ids are real, and that reaches the host: a file the sandbox
chowns to inside-id 250 is owned by the 250th subordinate id outside —
`100249`, say. That is the point, and it has one operational consequence.
Deleting a file needs write permission on its containing directory, so a
*directory* the sandbox chowned to a non-root id — portage's state
directories, a service's `/var/lib` tree, a user's home — refuses the plain
caller's `rm -rf`, which is how rootless container storage has always
behaved. [`provision::remove`] handles it: plain removal first, and where
ownership refuses it, the same map is re-entered and the tree deleted from
inside, where the ids are the caller's own. At a shell prompt, `fcage` removes
the same tree:

```sh
fcage --remove-rootfs ./rootfs
```

The flag takes the map the tree was provisioned under and defaults to the
subordinate one, so `--identity-map` is needed only for a tree written under
another. Without either, the manual form every rootless runtime documents is
`unshare --map-auto rm -rf ./rootfs`.

## Running as a non-root identity

A range map makes non-root identities exist; `run_as` makes the command one
of them:

```rust,no_run
use ferroday_cage::{Cage, Identity, IdentityMap};

# fn main() -> ferroday_cage::Result<()> {
let cage = Cage::builder()
    .rootfs("/srv/rootfs")
    .command("/usr/bin/id")
    .identity_map(IdentityMap::Subordinate)
    .run_as(Identity::new(250, 250).groups([250, 100]))
    .build()?;
# Ok(())
# }
```

The switch sits within the hardening layer, after securebits, no-new-privileges,
and Landlock and before the capability drop and the seccomp filter, so the
command holds the identity from its first instruction and its descendants
inherit it. Every id must be contained in the identity map —
`build` rejects one that is not — and supplementary groups additionally
require a range gid map, because establishing the single-identity map denies
`setgroups` permanently.

Capabilities interact with the switch in three ways:

- **No keep request.** The kernel clears the command's capabilities across
  the transition to a non-zero uid. This is the boundary a non-root
  identity exists to draw, and the default.
- **A kept capability set.** The launch locks `SECBIT_NO_SETUID_FIXUP`
  before the switch, so the kept set survives it: the command runs as the
  non-root identity holding exactly the kept capabilities, in its permitted,
  effective, and ambient sets. The securebit is locked, so the command
  cannot restore the default fixup behavior.
- **A kept set-id capability.** Retaining `CAP_SETUID`, `CAP_SETGID`, or
  `CAP_SETPCAP` alongside a non-root identity would let the command return
  to the mapped uid 0 — an identity that is not a boundary at all — and is
  rejected at `build` by name.

## Profiles

With the `serde` feature the identity map and run-as identity are part of
the profile format:

```toml
rootfs = "/srv/rootfs/gentoo"
command = "/usr/bin/emerge"
identity-map = "subordinate"

[run-as]
uid = 250
gid = 250
groups = [250]
```

Explicit ranges spell out their extents:

```toml
[identity-map.ranges]
uid = [
    { inside = 0, outside = 1000, count = 1 },
    { inside = 1, outside = 100000, count = 65536 },
]
gid = [
    { inside = 0, outside = 1000, count = 1 },
    { inside = 1, outside = 100000, count = 65536 },
]
```

A profile requesting `subordinate` on a build without the `subid` feature is
refused when it loads: a profile's identity posture is never silently
downgraded by a library that cannot establish it. The delegate itself is
code, not configuration, and is never part of a profile.

[`CageBuilder::id_mapper`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/struct.CageBuilder.html#method.id_mapper
[`host::range_map_blocker`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/host/fn.range_map_blocker.html
[`provision::remove`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/fn.remove.html
