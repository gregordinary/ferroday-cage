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

A reach is counted however it is spelled: `crate::host`, a `super::` chain that
climbs out of `provision`, or one name of a grouped `use crate::{...}`. Every
path is resolved against the module its file defines before it is judged.

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

# The reading `tools/check-idioms.py` takes, and for the same reason: a doc
# link naming another layer is prose about it rather than a use of it, and a
# test may reach for whatever it needs to build a fixture. The reader is found
# beside this script, which names its own directory since `python3 -I` does
# not, and a run leaves no bytecode beside it.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rust_source import code  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RECORD = REPO / "tools" / "seam.toml"
SRC = REPO / "crates" / "ferroday-cage" / "src"
LAYERS = SRC / "provision"

# A `use` declaration, whatever its visibility, up to the semicolon that ends
# it; a grouped one spans lines. Anchored at the start of a line, where
# `cargo fmt` puts every declaration, so the word in a string is not one.
USE = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?use[ \t]+([^;]*);", re.S | re.M)

# A path in an expression or a type that starts from the crate root or climbs
# out of the current module. `$crate` in a macro body is the crate root too.
ROOTED = re.compile(r"\b(?:crate|super|self)(?:::[A-Za-z_][A-Za-z0-9_]*)+")

# The tokens a `use` tree is written in.
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|::|[{},*]")


def module_of(path: Path) -> list[str]:
    """The module a source file defines, as its path from the crate root."""
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    return parts[:-1] if parts[-1] == "mod" else parts


def use_paths(tree: str) -> list[list[str]]:
    """Every path a `use` tree names, a grouped one expanded.

    `crate::{IdentityMap, provision::{self, Fetch}}` names three paths:
    `crate::IdentityMap`, `crate::provision`, and `crate::provision::Fetch`.
    An alias is dropped, since the path is what is reached; a glob keeps its
    prefix.
    """
    tokens = TOKEN.findall(tree)

    def subtree(at: int, prefix: list[str]) -> tuple[list[list[str]], int]:
        segments = list(prefix)
        while at < len(tokens):
            token = tokens[at]
            if token == "{":
                at += 1
                paths: list[list[str]] = []
                while at < len(tokens) and tokens[at] != "}":
                    found, at = subtree(at, segments)
                    paths += found
                    if at < len(tokens) and tokens[at] == ",":
                        at += 1
                return paths, at + 1
            if token == "*":
                return [segments], at + 1
            if token != "self":
                segments.append(token)
            at += 1
            if at < len(tokens) and tokens[at] == "::":
                at += 1
                continue
            if at < len(tokens) and tokens[at] == "as":
                at += 2
            return [segments], at
        return [segments], at

    return subtree(0, [])[0]


def absolute(segments: list[str], module: list[str]) -> list[str] | None:
    """`segments` as a path from the crate root, or `None` for one that is not
    rooted in this crate (another crate's, or a child module's by its name)."""
    if not segments:
        return None
    if segments[0] == "crate":
        return segments[1:]
    if segments[0] == "self":
        return module + segments[1:]
    if segments[0] == "super":
        climbs = 0
        while climbs < len(segments) and segments[climbs] == "super":
            climbs += 1
        if climbs > len(module):
            return None
        return module[: len(module) - climbs] + segments[climbs:]
    return None


def paths_in(path: Path) -> list[list[str]]:
    """Every crate-rooted path a source file names, from the crate root.

    A `use` declaration contributes each path its tree names, and every other
    `crate::`, `super::`, or `self::` path in the code contributes itself.
    Resolving `super::` against the file's own module is what makes a reach
    written as `super::super::host` count the same as one written as
    `crate::host`.
    """
    module = module_of(path)
    body = code(path)
    found = []
    for declaration in USE.finditer(body):
        found += use_paths(declaration.group(1))
    rest = USE.sub(lambda match: "\n" * match.group(0).count("\n"), body)
    found += [match.group(0).split("::") for match in ROOTED.finditer(rest)]
    resolved = (absolute(segments, module) for segments in found)
    return [segments for segments in resolved if segments]


def reaches(layer: str) -> dict[str, int]:
    """Every crate-level name `layer` uses that is not `provision`."""
    found: dict[str, int] = {}
    for path in sorted((LAYERS / layer).rglob("*.rs")):
        for segments in paths_in(path):
            name = segments[0]
            if name == "provision":
                continue
            found[name] = found.get(name, 0) + 1
    return found


def crossings(layer: str, others: list[str]) -> list[str]:
    """Where `layer`'s code names another userland."""
    found = []
    for path in sorted((LAYERS / layer).rglob("*.rs")):
        named = {
            segments[1]
            for segments in paths_in(path)
            if len(segments) > 1 and segments[0] == "provision"
        }
        for other in others:
            if other in named:
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
