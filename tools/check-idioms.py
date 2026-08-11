#!/usr/bin/env python3
"""Check the recorded census of idioms the workspace answers once.

Some concepts have one answer in this workspace and are meant to keep having
one: how a path is split into components, how a deadline is computed, how a
local path becomes a `file://` URL. A second implementation of one of those is
not a compile error and not something a reviewer reliably spots -- the copies
drift apart later, at the point where the two disagree.

`tools/idioms.toml` records where each idiom appears and how many times. This
compares the record against the tree and fails on any difference. It is not a
ban: a new site is sometimes right, and then it is recorded with the reason it
is a second answer. What the check buys is that the decision is *made*, in a
diff a reviewer can see, rather than arrived at by nobody.

This watches the shapes `clippy.toml` cannot: an operator, a hand-written
split, a formatted string. A concept clippy can express as a disallowed method
belongs there instead, so that each has exactly one guard.

Only the crates' own `src` trees are scanned, and within them only code: a
trailing `#[cfg(test)]` module and every comment line are cut first, so a test
constructing the shape under test and a comment naming it are not sites.

Usage:

    python3 tools/check-idioms.py

Exits non-zero, naming every difference, when the tree and the record disagree.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INVENTORY = REPO / "tools" / "idioms.toml"


def code(path: Path) -> str:
    """The file's own code: no trailing test module, no comment lines."""
    lines = path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.startswith(("#[cfg(test)]", "#[cfg(all(test")):
            lines = lines[:index]
            break
    return "\n".join(line for line in lines if not line.lstrip().startswith("//"))


def census(pattern: str) -> dict[str, int]:
    """Where `pattern` occurs in the crates' source, and how often."""
    found = {}
    for path in sorted(REPO.glob("crates/*/src/**/*.rs")):
        occurrences = len(re.findall(pattern, code(path)))
        if occurrences:
            found[str(path.relative_to(REPO))] = occurrences
    return found


def differences(recorded: dict[str, int], found: dict[str, int]) -> list[str]:
    """How the tree differs from the record, one line each."""
    lines = []
    for path in sorted(set(recorded) | set(found)):
        was, now = recorded.get(path, 0), found.get(path, 0)
        if was == now:
            continue
        if not was:
            lines.append(f"    new      {path}: {now}")
        elif not now:
            lines.append(f"    gone     {path}: was {was}")
        else:
            lines.append(f"    changed  {path}: {was} -> {now}")
    return lines


def main() -> int:
    inventory = tomllib.loads(INVENTORY.read_text(encoding="utf-8"))
    failures, sites = [], 0

    for idiom in inventory["idiom"]:
        recorded = {site["path"]: site["count"] for site in idiom.get("site", [])}
        sites += sum(recorded.values())
        missing = [path for path in recorded if not (REPO / path).exists()]
        changes = differences(recorded, census(idiom["pattern"]))
        if missing:
            changes = [f"    absent   {path}" for path in sorted(missing)] + changes
        if changes:
            failures.append(
                "\n".join(
                    [f"{idiom['name']}: the record and the tree disagree."]
                    + changes
                    + [f"    The answer: {idiom['answer']}"]
                )
            )

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(
            "\nReach for the answer, or record the site in tools/idioms.toml "
            "with the reason it is a second one.",
            file=sys.stderr,
        )
        return 1
    print(f"{len(inventory['idiom'])} idioms, {sites} recorded sites: unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
