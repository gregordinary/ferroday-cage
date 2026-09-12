#!/usr/bin/env python3
"""Check that every public builder setting is spelled on the command line.

`fcage` is a consumer of the library and nothing else, and its help, its README,
and the guide say what it covers. The CLI's own tests cannot check that claim:
they read the `FLAGS` table, and a library method absent from the table is
absent from both sides of the comparison. Only a record naming both surfaces
can catch a builder that grew a setting `fcage` never learned.

`tools/parity.toml` is that record -- every configuration method the committed
public API snapshot holds for each builder, against the flag or flags that reach
it, or the reason it has none. This compares the record against the snapshot and
against the CLI's flag table, and fails on any difference.

It is not a demand that everything have a flag. Some settings genuinely cannot,
for one of three reasons: the setting takes executable behavior an argument
cannot carry, it is spelled somewhere other than a flag, or it belongs to a
capability the tool does not offer. `tools/parity.toml` records which reason
applies to each, and the run prints how many there are; a count stated here as
well would be a third copy of a number that moves.

Usage:

    python3 tools/check-parity.py

Exits non-zero, naming every difference, when the record and the two surfaces
disagree.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RECORD = REPO / "tools" / "parity.toml"
SNAPSHOT = REPO / "crates" / "ferroday-cage" / "public-api.txt"
CLI = REPO / "crates" / "ferroday-cage-cli" / "src" / "main.rs"

# Not settings. Three roles, none of which configures anything:
#
#   A constructor    `new`, `from_reader`, `default`. It produces the builder
#                    that the settings then configure.
#   A terminal       `build`, `run`, `write_to`, `write_to_path`, `provision`.
#                    It consumes the builder and does the thing.
#   An accessor      `get_*`, which reads back what a setting wrote. These are
#                    what a consumer inspecting a loaded profile needs, and no
#                    flag corresponds to one.
#
# Named rather than described because the test is a method name and the set is
# the mechanism: a builder growing a terminal this does not list reads as an
# unflagged setting, which is the direction that fails loudly rather than
# quietly.
NOT_SETTINGS = {
    "build",
    "default",
    "new",
    "from_reader",
    "run",
    "write_to",
    "write_to_path",
    "provision",
}

KINDS = {"code", "positional", "library"}


def settings(path: str) -> list[str]:
    """Every configuration method the snapshot records for the builder at `path`.

    Only the builder's own inherent methods: a snapshot lists a trait impl's
    methods the same way it lists an inherent one, so `Debug::fmt` and
    `Default::default` would otherwise read as settings. The impl line above
    each block is what separates them -- an inherent one names the type alone.

    The rendering is rustdoc's, so a generic builder appears as
    `Type<'a>::method` and the same method may be listed under more than one
    impl block; the lifetime and generic arguments are dropped and the order of
    first appearance is kept.
    """
    inherent = re.compile(
        r"^impl(?:<[^>]*>)? " + re.escape(path) + r"(?:<[^>]*>)?$"
    )
    method = re.compile(
        r"^pub fn " + re.escape(path) + r"(?:<[^>]*>)?::([A-Za-z_][A-Za-z0-9_]*)"
    )
    found: list[str] = []
    own = False
    for line in SNAPSHOT.read_text(encoding="utf-8").splitlines():
        if line.startswith("impl"):
            own = bool(inherent.match(line))
            continue
        if not own:
            continue
        match = method.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in NOT_SETTINGS or name.startswith("get_") or name in found:
            continue
        found.append(name)
    return found


def flags() -> set[str]:
    """Every long flag the CLI's own table declares."""
    return set(re.findall(r'long: "(--[a-z0-9-]+)"', CLI.read_text(encoding="utf-8")))


def check(builder: dict, offered: set[str]) -> list[str]:
    """How the record for one builder differs from the two surfaces."""
    recorded = {setting["name"]: setting for setting in builder.get("setting", [])}
    present = settings(builder["path"])
    problems = []

    for name in present:
        if name not in recorded:
            problems.append(
                f"    unrecorded  {name}: give it a flag, or record why it has none"
            )
    for name in recorded:
        if name not in present:
            problems.append(f"    gone        {name}: the builder no longer offers it")

    for name, setting in recorded.items():
        named = setting.get("flags", [])
        kind = setting.get("kind")
        if named and kind:
            problems.append(f"    both        {name}: a setting has flags or a kind")
        elif not named and not kind:
            problems.append(f"    unspelled   {name}: name its flags, or its kind")
        elif kind and kind not in KINDS:
            problems.append(f"    kind        {name}: {kind!r} is not one of {sorted(KINDS)}")
        if kind and not setting.get("why"):
            problems.append(f"    unexplained {name}: a setting with no flag says why")
        for flag in named:
            if flag not in offered:
                problems.append(f"    missing     {name}: the CLI has no {flag}")
    return problems


def main() -> int:
    record = tomllib.loads(RECORD.read_text(encoding="utf-8"))
    offered = flags()
    failures, total, unflagged = [], 0, 0

    for builder in record["builder"]:
        total += len(builder.get("setting", []))
        unflagged += sum(1 for s in builder.get("setting", []) if "kind" in s)
        problems = check(builder, offered)
        if problems:
            failures.append(
                "\n".join(
                    [f"{builder['name']}: the record and the surfaces disagree."]
                    + problems
                )
            )

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(
            "\nAdd the flag, or record the setting in tools/parity.toml with why it "
            "has none. Regenerate crates/ferroday-cage/public-api.txt first if the "
            "public API moved.",
            file=sys.stderr,
        )
        return 1

    print(
        f"{len(record['builder'])} builders, {total} recorded settings "
        f"({unflagged} of them deliberately without a flag): unchanged."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
