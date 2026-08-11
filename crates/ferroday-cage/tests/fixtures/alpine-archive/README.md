# Alpine archive fixtures

Real apk containers, committed so the reader is tested against bytes a
repository actually published rather than against bytes this crate wrote. A
writer that agrees with its own reader proves nothing about either.

Each was fetched from the URL below on 2026-08-09. To refresh one, fetch it
again and record the new digest here; the tests assert the digest, so a fixture
that changes without this file changing fails rather than passing quietly.

| File | Source | SHA-256 |
| --- | --- | --- |
| `alpine-base-3.23.5-r0.apk` | `http://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/alpine-base-3.23.5-r0.apk` | `36a759418940efa2ba49b783e1286ffc675366b1cea9a2e7e2bb508ccea68e76` |
| `alpine-keys-2.6-r0.apk` | `http://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/alpine-keys-2.6-r0.apk` | `a6d92d54856452e1d442e1d20820215c4829e6049c1944a5e65d8dacc55a07ed` |
| `musl-1.2.5-r23.apk` | `http://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/musl-1.2.5-r23.apk` | `4f3c4a7bf9f51d2c91007e333b17459362ffd881b4a343e8da07b6c50c4f4a0d` |
| `alpine-baselayout-3.7.2-r0.apk` | `http://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/alpine-baselayout-3.7.2-r0.apk` | `6e55ad7baa87468244e7919c7556e96abc5da05576cabd8b879a019c6d43e1b6` |
| `pmos-baselayout-62-r0.apk` | `http://mirror.postmarketos.org/postmarketos/v26.06/x86_64/postmarketos-baselayout-62-r0.apk` | `66692c0f6859bb53d39bf1fccff97397fa51b5faf11de7f02438d898af684a1a` |
| `minirootfs-installed` | `http://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/alpine-minirootfs-3.23.5-x86_64.tar.gz`, `./lib/apk/db/installed` | see below |
| `APKINDEX.tar.gz` | `http://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz` | see below |
| `pmos-APKINDEX.tar.gz` | `http://mirror.postmarketos.org/postmarketos/v26.06/x86_64/APKINDEX.tar.gz` | see below |

The three packages are chosen for the shapes they carry, not for what they
install:

- **`alpine-base`** is the degenerate case: 1320 bytes, and its data segment is
  an empty tar. A reader that treats an empty third segment as a missing one
  fails on it.
- **`alpine-keys`** carries a data segment of directories and regular files, and
  is `arch = x86_64` rather than `noarch`.
- **`musl`** carries a symbolic link, and is large enough that its data segment
  spans many decoder buffers — the case where a reader that hashes the wrong
  bytes, or loses a boundary, is caught.
- **`alpine-baselayout`** carries four install scripts, a `replaces` with a
  priority, and a file tree deep enough to exercise every line an installed
  record can hold: directories with their own modes, files with theirs, and a
  digest on each.
- **`pmos-baselayout`** is signed by a key no trust anchor publishes. Its
  repository's index is signed by `build.postmarketos.org`, which
  `postmarketos-keys` installs, while the package itself is signed by
  `pmos@local-6a50011b` — a key that varies from one postmarketOS package to the
  next. It is committed because it is the case that decides how a package is
  authenticated: by the control identity its index or its plan recorded, and not
  by its own signature.

`minirootfs-installed` is the two records `apk` itself wrote for those last two
packages, lifted verbatim from the `installed` database of Alpine's published
minirootfs. The database writer is measured against it byte for byte, which is
the strongest form the question takes: not "does this look like a record" but
"is this the record the tool we have to agree with produced". It is not pinned
by digest, since it is an excerpt of a file that is rebuilt whenever the
minirootfs is; what pins it is that the writer reproduces it.

The two indexes are the same container with two segments rather than three, one
from each repository the layer speaks to. Their digests are not pinned: an index
is republished whenever anything in the repository moves, so pinning one would
be pinning the day it was fetched. What the tests assert about them is the
container shape, the signature, and the record grammar, all of which survive a
refresh.

None of this ships. `exclude` in the crate's manifest keeps `tests/fixtures` out
of the packaged tarball, and the tests that read these files are `#[cfg(test)]`,
so a build from the registry never looks for them.
