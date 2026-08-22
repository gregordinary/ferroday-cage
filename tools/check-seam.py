#!/usr/bin/env python3
"""Check what each userland reaches for outside the provisioning seam.

`provision` is a seam three archive layers sit on: the `Provisioner` trait,
`Fetch`, `ProvisionError`, `BuildLayer`, and the shared tar, compress, extract,
digest, document and OpenPGP machinery. Two hundred and ten of the library's
public functions are behind that seam, driven by three external archives'
formats -- the part of the surface most likely to have to move, tied to the
version number of the part least likely to.

Whether those layers ever become crates of their own is a decision for later;
`docs/src/stability.md` records it and what would force it. What this keeps true
in the meantime is that the decision stays cheap. A layer that reaches only
through `provision` is one that could move; every other name it uses is a thing
that would first have to move with it, become public, or be copied.

`tools/seam.toml` records those reaches, one per name, with what each would
cost. This compares the record against the tree and fails on any difference. It
is not a ban -- several are the library's own public API, which a separate crate
would depend on anyway. What it buys is that a new reach past the seam is
*chosen*, in a diff a reviewer can see.

It also refuses one thing outright: a userland naming another. The three formats
are deliberately not shared, and a layer reading another layer's module is how
that stops being true.

Usage:

    python3 tools/check-seam.py

Exits non-zero, naming every difference, when the tree and the record disagree.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RECORD = REPO / "tools" / "seam.toml"
LAYERS = REPO / "crates" / "ferroday-cage" / "src" / "provision"


def code(path: Path) -> str:
    """The file's own code: no trailing test module, no comment lines.

    The same reading `tools/check-idioms.py` takes, and for the same reason: a
    doc link naming another layer is prose about it rather than a use of it,
    and a test may reach for whatever it needs to build a fixture.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.startswith(("#[cfg(test)]", "#[cfg(all(test")):
            lines = lines[:index]
            break
    return "\n".join(line for line in lines if not line.lstrip().startswith("//"))


def reaches(layer: str) -> dict[str, int]:
    """Every crate-level name `layer` uses that is not `provision`."""
    found: dict[str, int] = {}
    for path in sorted((LAYERS / layer).rglob("*.rs")):
        for match in re.finditer(r"\bcrate::([A-Za-z_][A-Za-z0-9_]*)", code(path)):
            name = match.group(1)
            if name == "provision":
                continue
            found[name] = found.get(name, 0) + 1
    return found


def crossings(layer: str, others: list[str]) -> list[str]:
    """Where `layer`'s code names another userland."""
    found = []
    for path in sorted((LAYERS / layer).rglob("*.rs")):
        body = code(path)
        for other in others:
            for pattern in (f"provision::{other}", f"super::super::{other}"):
                if pattern in body:
                    found.append(f"{path.relative_to(REPO)} names {other}")
    return found


def differences(recorded: dict[str, int], found: dict[str, int]) -> list[str]:
    """How the tree differs from the record, one line each."""
    lines = []
    for name in sorted(set(recorded) | set(found)):
        was, now = recorded.get(name, 0), found.get(name, 0)
        if was == now:
            continue
        if not was:
            lines.append(f"    new      crate::{name}: {now}")
        elif not now:
            lines.append(f"    gone     crate::{name}: was {was}")
        else:
            lines.append(f"    changed  crate::{name}: {was} -> {now}")
    return lines


def main() -> int:
    record = tomllib.loads(RECORD.read_text(encoding="utf-8"))
    names = [layer["name"] for layer in record["layer"]]
    failures, total = [], 0

    for layer in record["layer"]:
        name = layer["name"]
        recorded = {reach["name"]: reach["count"] for reach in layer.get("reach", [])}
        total += sum(recorded.values())
        changes = differences(recorded, reaches(name))
        if changes:
            failures.append(
                "\n".join(
                    [f"{name}: the record and the tree disagree about the seam."]
                    + changes
                )
            )
        crossed = crossings(name, [other for other in names if other != name])
        if crossed:
            failures.append(
                "\n".join(
                    [f"{name}: a userland names another, which is never right."]
                    + [f"    {line}" for line in crossed]
                )
            )

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(
            "\nReach through provision, or record the reach in tools/seam.toml "
            "with what it would cost.",
            file=sys.stderr,
        )
        return 1
    internal = sum(
        reach["count"]
        for layer in record["layer"]
        for reach in layer.get("reach", [])
        if reach["kind"] == "internal"
    )
    print(
        f"{len(names)} userlands, {total} recorded reaches past the seam "
        f"({internal} of them internal): unchanged."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
