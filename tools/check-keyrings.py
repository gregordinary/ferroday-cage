#!/usr/bin/env python3
"""Check the vendored keyrings against what their distributions publish.

Each userland provisioner rests on a trust anchor this crate ships: the Debian
archive keyring, Alpine's and postmarketOS's signing keys, Gentoo's service
keys. They are vendored rather than fetched, and that is the security property
rather than a saved round trip -- an anchor fetched over the same channel as the
artifact it authenticates authenticates nothing, because whoever can serve a
forged artifact can serve the key that signs it.

The cost of vendoring is that the bytes go stale silently. A distribution adds
an architecture's key, rotates a signing key, or retires one, and the crate goes
on trusting exactly what it shipped. This compares each vendored file against
what the distribution publishes today and fails on any difference, so drift
arrives as a build failure with the diff in it rather than as a bootstrap that
stops verifying months later.

This is a maintainer's check and must never become a runtime refresh. Fetching a
trust anchor at provisioning time would hand the network the power to replace
the very thing vendoring exists to protect.

Mechanical mirroring is what makes the comparison possible at all: the vendored
sets are their upstreams key for key, including keys no layer ever meets. A
hand-picked subset would make this diff permanently noisy, so the guard and the
curation cannot both exist.

Usage:

    python3 tools/check-keyrings.py

Exits non-zero, naming every difference, when a vendored keyring and its
upstream disagree. It reaches the network, so it runs on a schedule rather than
on a pull request.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import lzma
import sys
import tarfile
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
KEYRINGS = REPO / "crates" / "ferroday-cage" / "src" / "provision"

# HTTPS throughout. The library reads these archives over plain HTTP because it
# ships no TLS stack and gains nothing from one -- every byte it fetches is
# verified against a vendored key. Nothing here is: this compares bytes against
# bytes to decide whether a human should look, so the transport is the only
# integrity there is, and Python has TLS for free.
GENTOO_KEYS = "https://qa-reports.gentoo.org/output/service-keys.gpg"
DEBIAN_ARCHIVE = "https://deb.debian.org/debian"
DEBIAN_SUITE = "stable"
ALPINE_ARCHIVE = "https://dl-cdn.alpinelinux.org/alpine/latest-stable/main/x86_64"
POSTMARKETOS_ARCHIVE = "https://mirror.postmarketos.org/postmarketos/master/x86_64"

# A courtesy to the archives, and what crates.io taught the fetcher: a request
# with no user agent is one an operator cannot attribute when it misbehaves.
USER_AGENT = "ferroday-cage-keyring-check (https://github.com/gregordinary/ferroday-cage)"

# Nothing fetched here is large -- the biggest is Debian's package index at
# about 10 MB -- so a body past this is a redirect to something that is not the
# resource, and reading it would be the check hanging rather than failing.
MAX_BYTES = 64 * 1024 * 1024


def fetch(url: str) -> bytes:
    """The body at `url`, bounded."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        body = response.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise RuntimeError(f"{url} served more than {MAX_BYTES} bytes")
    return body


def vendored(directory: Path, pattern: str) -> dict[str, bytes]:
    """Every vendored key under `directory` matching `pattern`, by file name."""
    return {path.name: path.read_bytes() for path in sorted(directory.glob(pattern))}


def apk_members(apk: bytes, prefix: str) -> dict[str, bytes]:
    """The files under `prefix` in an `.apk`, by their base name.

    An `.apk` is independent gzip segments laid end to end, each holding a tar
    archive; `gzip.decompress` reads the whole run, which concatenates the tars,
    and a tar reader walks that as one archive. The layer's own reader keeps the
    segments apart because it verifies each one; nothing here does, so the
    simpler reading is the right one.
    """
    archive = tarfile.open(fileobj=io.BytesIO(gzip.decompress(apk)))
    return {
        Path(member.name).name: archive.extractfile(member).read()
        for member in archive.getmembers()
        if member.isfile() and member.name.startswith(prefix)
    }


def apk_version(index: bytes, package: str) -> str:
    """The version an `APKINDEX.tar.gz` states for `package`."""
    archive = tarfile.open(fileobj=io.BytesIO(gzip.decompress(index)))
    records = archive.extractfile("APKINDEX").read().decode("utf-8", "replace")
    for stanza in records.split("\n\n"):
        fields = dict(
            line.split(":", 1) for line in stanza.splitlines() if ":" in line
        )
        if fields.get("P") == package:
            return fields["V"]
    raise RuntimeError(f"the index names no package {package}")


def deb_data_member(deb: bytes) -> bytes:
    """The `data.tar` of a `.deb`, decompressed.

    A `.deb` is an `ar` archive: a magic line, then a 60-byte header per member
    carrying the name and the size, then the member padded to an even length.
    """
    if not deb.startswith(b"!<arch>\n"):
        raise RuntimeError("the package is not an ar archive")
    at = 8
    while at + 60 <= len(deb):
        header = deb[at : at + 60]
        at += 60
        name = header[0:16].decode("ascii", "replace").strip().rstrip("/")
        size = int(header[48:58].decode("ascii", "replace").strip())
        member = deb[at : at + size]
        at += size + (size % 2)
        if name.startswith("data.tar"):
            if name.endswith(".xz"):
                return lzma.decompress(member)
            if name.endswith(".gz"):
                return gzip.decompress(member)
            return member
    raise RuntimeError("the package holds no data member")


def gentoo() -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Gentoo's service keys, which are published as one file.

    The only one of the four that is a plain fetch: the rest are inside a
    package, which is why this is a tool rather than a line in another one.
    """
    held = vendored(KEYRINGS / "gentoo" / "keyring", "*.gpg")
    return held, {"service-keys.gpg": fetch(GENTOO_KEYS)}


def debian() -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Debian's archive keyring, out of the `debian-archive-keyring` package.

    Resolved through the archive's own index rather than fetched from a guessed
    path, because the version is in the file name and the package is rebuilt
    whenever a suite's key changes -- which is exactly the event this exists to
    notice.

    The keyring is matched by stem rather than by file name: the package ships
    it as `.pgp` today and shipped `.gpg` before, and the vendored copy keeps
    the older spelling. What is compared is the bytes.
    """
    held = vendored(KEYRINGS / "debian" / "keyring", "*.gpg")
    index = lzma.decompress(
        fetch(f"{DEBIAN_ARCHIVE}/dists/{DEBIAN_SUITE}/main/binary-amd64/Packages.xz")
    ).decode("utf-8", "replace")
    filename = None
    for stanza in index.split("\n\n"):
        fields = dict(
            line.split(":", 1)
            for line in stanza.splitlines()
            if ":" in line and not line.startswith(" ")
        )
        if fields.get("Package", "").strip() == "debian-archive-keyring":
            filename = fields["Filename"].strip()
            break
    if filename is None:
        raise RuntimeError("the index names no debian-archive-keyring")

    data = deb_data_member(fetch(f"{DEBIAN_ARCHIVE}/{filename}"))
    archive = tarfile.open(fileobj=io.BytesIO(data))
    published = {}
    for member in archive.getmembers():
        path = Path(member.name)
        if member.isfile() and path.parent.name == "keyrings":
            for name in held:
                if Path(name).stem == path.stem:
                    published[name] = archive.extractfile(member).read()
    return held, published


def alpine() -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Alpine's signing keys, out of the `alpine-keys` package.

    The vendored set is that package's `usr/share/apk/keys/` tree flattened:
    which key serves which architecture is recorded in the crate, and the crate's
    own tests hold that partition, so what this compares is the keys themselves.
    Alpine keeps superseded keys in the package, so one release's copy holds
    every key the archive still serves.

    postmarketOS's key sits in the same directory in this crate and comes from
    elsewhere, so it is excluded here and checked on its own.
    """
    held = {
        name: body
        for name, body in vendored(KEYRINGS / "alpine" / "keyring", "*.rsa.pub").items()
        if name.startswith("alpine-devel@")
    }
    version = apk_version(fetch(f"{ALPINE_ARCHIVE}/APKINDEX.tar.gz"), "alpine-keys")
    apk = fetch(f"{ALPINE_ARCHIVE}/alpine-keys-{version}.apk")
    return held, apk_members(apk, "usr/share/apk/keys/")


def postmarketos() -> tuple[dict[str, bytes], dict[str, bytes]]:
    """postmarketOS's signing key, out of the `postmarketos-keys` package.

    One key for every architecture it publishes, and it ships the same bytes at
    two paths; only the one `apk` reads is compared.
    """
    held = vendored(KEYRINGS / "alpine" / "keyring", "build.postmarketos.org.rsa.pub")
    version = apk_version(
        fetch(f"{POSTMARKETOS_ARCHIVE}/APKINDEX.tar.gz"), "postmarketos-keys"
    )
    apk = fetch(f"{POSTMARKETOS_ARCHIVE}/postmarketos-keys-{version}.apk")
    return held, apk_members(apk, "usr/share/apk/keys/")


SOURCES = (
    ("Gentoo", gentoo),
    ("Debian", debian),
    ("Alpine", alpine),
    ("postmarketOS", postmarketos),
)


def differences(held: dict[str, bytes], published: dict[str, bytes]) -> list[str]:
    """Every way the vendored set and the published one disagree."""
    changes = []
    for name in sorted(set(published) - set(held)):
        changes.append(f"    added    {name} ({len(published[name])} bytes upstream)")
    for name in sorted(set(held) - set(published)):
        changes.append(f"    removed  {name} (vendored, no longer published)")
    for name in sorted(set(held) & set(published)):
        if held[name] != published[name]:
            changes.append(
                f"    changed  {name}\n"
                f"      vendored  {hashlib.sha256(held[name]).hexdigest()}"
                f" ({len(held[name])} bytes)\n"
                f"      published {hashlib.sha256(published[name]).hexdigest()}"
                f" ({len(published[name])} bytes)"
            )
    return changes


def main() -> int:
    failures = []
    checked = 0
    for name, source in SOURCES:
        try:
            held, published = source()
        except Exception as err:  # noqa: BLE001 -- the reason is what a reader needs
            # A source that cannot be reached is a failure rather than a skip: a
            # check that goes quiet when an archive moves is one that reports
            # "unchanged" about bytes it never looked at.
            failures.append(f"{name}: could not be checked: {err}")
            continue
        if not held:
            failures.append(f"{name}: nothing is vendored, so nothing was compared.")
            continue
        checked += len(held)
        changes = differences(held, published)
        if changes:
            failures.append(
                "\n".join(
                    [f"{name}: the vendored keyring and the published one disagree."]
                    + changes
                )
            )

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(
            "\nRefresh the vendored bytes from the source above, and check what "
            "changed before committing them: a keyring is a trust anchor, and a "
            "key that appeared is a key this crate would begin to trust.",
            file=sys.stderr,
        )
        return 1
    print(f"{len(SOURCES)} keyrings, {checked} keys: unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
