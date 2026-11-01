#!/usr/bin/env python3
"""Check that every public builder setting is spelled on the command line.

`fcage` is a consumer of the library and nothing else, and its help, its README,
and the guide say what it covers. The CLI's own tests cannot check that claim:
they read the `FLAGS` table, and a library method absent from the table is
absent from both sides of the comparison. Only a record naming both surfaces
can catch a builder that grew a setting `fcage` never learned.

`tools/parity.toml` is that record -- every setting the committed public API
snapshot holds for each builder, against the flag or flags that reach it, or the
reason it has none. This compares the record against the snapshot and against
the CLI's flag table, and fails on any difference.

A builder is found rather than listed. A setting is an inherent method that
takes the type by value and returns it, which is the shape every configurable
type in the crate gives its settings, and any public type with one is a builder
the record must name. A constructor, a terminal and an accessor have other
shapes and are not settings. A setting taken by reference (`&mut self`
returning `&mut Self`) would slip past that reading, so one fails the check
outright: the crate's builders take themselves by value.

A flag is checked for the invocation it belongs to as well as for existing.
The flag table records each flag's mode, and a flag a launch refuses -- a
removal's, an export's, `--help` -- cannot be what reaches a launch builder's
setting. A builder of another mode names that mode in the record.

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

KINDS = {"code", "positional", "library"}

# An inherent impl block's header: `impl Type`, `impl<'a> Type<'a>`. A trait
# impl names the trait first and is not matched.
IMPL = re.compile(r"^impl(?:<[^>]*>)? (ferroday_cage::[A-Za-z0-9_:]+)(?:<[^>]*>)?$")

# A method line inside one: its path, its name, and where its parameters open.
METHOD = re.compile(
    r"^pub (?:const )?(?:unsafe )?fn (ferroday_cage::[A-Za-z0-9_:]+)(?:<[^>]*>)?"
    r"::([A-Za-z_][A-Za-z0-9_]*)(?:<.*?>)?\("
)


def signature(line: str, opening: int) -> tuple[str, str]:
    """A method line's parameter list and its return type.

    The parameters are read by matching the parenthesis that opens them, since
    a closure bound such as `impl FnMut(&Entry) -> bool` carries an arrow of its
    own. A `where` clause after the return type is dropped.
    """
    depth = 0
    for at in range(opening, len(line)):
        if line[at] == "(":
            depth += 1
        elif line[at] == ")":
            depth -= 1
            if depth == 0:
                parameters = line[opening + 1 : at]
                rest = line[at + 1 :]
                returned = rest[4:] if rest.startswith(" -> ") else ""
                return parameters, returned.split(" where ")[0]
    return line[opening + 1 :], ""


def returns_itself(returned: str, path: str) -> bool:
    """Whether `returned` names the type at `path` itself."""
    return returned == "Self" or re.fullmatch(re.escape(path) + r"(?:<[^>]*>)?", returned) is not None


def types() -> set[str]:
    """Every type the snapshot has an inherent impl block for."""
    return {
        match.group(1)
        for line in SNAPSHOT.read_text(encoding="utf-8").splitlines()
        if (match := IMPL.match(line))
    }


def methods() -> list[tuple[str, str, str, str]]:
    """Every inherent method in the snapshot: its type, name, parameters, return."""
    found = []
    own = None
    for line in SNAPSHOT.read_text(encoding="utf-8").splitlines():
        if line.startswith("impl"):
            match = IMPL.match(line)
            own = match.group(1) if match else None
            continue
        if own is None:
            continue
        match = METHOD.match(line)
        if not match or match.group(1) != own:
            continue
        parameters, returned = signature(line, match.end() - 1)
        found.append((own, match.group(2), parameters, returned))
    return found


def builders() -> dict[str, list[str]]:
    """Every builder in the snapshot and its settings, in order of appearance.

    Rustdoc lists a method once per impl block, and a generic builder's blocks
    repeat it; each setting is kept once.
    """
    found: dict[str, list[str]] = {}
    for path, name, parameters, returned in methods():
        by_value = re.match(r"(?:mut )?self(?:,|$)", parameters) is not None
        if by_value and returns_itself(returned, path):
            settings = found.setdefault(path, [])
            if name not in settings:
                settings.append(name)
    return found


def by_reference() -> list[str]:
    """Every setting written to take its builder by reference."""
    return [
        f"{path}::{name}"
        for path, name, parameters, returned in methods()
        if re.match(r"&(?:'\w+ )?mut self(?:,|$)", parameters)
        and returned.startswith("&")
        and returns_itself(re.sub(r"^&(?:'\w+ )?mut ", "", returned), path)
    ]


def flags() -> dict[str, str]:
    """Every long flag the CLI's own table declares, with the invocation that
    takes it: `Launch` for one a launch applies, and otherwise its mode.

    An entry states its `mode` and its `take` only where they differ from the
    table's defaults, which are a launch and a refusal: a launch takes a flag
    only when its entry gives it a `take` other than `Refused`.
    """
    source = CLI.read_text(encoding="utf-8")
    table = re.search(r"^const FLAGS: &\[Flag\] = &\[\n(.*?)^\];", source, re.MULTILINE | re.DOTALL)
    if not table:
        raise SystemExit(f"{CLI}: no FLAGS table")
    found = {}
    for entry in re.split(r"^    Flag \{\n", table.group(1), flags=re.MULTILINE)[1:]:
        long = re.search(r'^        long: "(--[a-z0-9-]+)"', entry, re.MULTILINE)
        mode = re.search(r"^        mode: Mode::(\w+)", entry, re.MULTILINE)
        take = re.search(r"^        take: Take::(\w+)", entry, re.MULTILINE)
        if not long:
            raise SystemExit(f"{CLI}: a FLAGS entry names no flag")
        mode = mode.group(1) if mode else "Launch"
        refused = take is None or take.group(1) == "Refused"
        found[long.group(1)] = "Refused" if mode == "Launch" and refused else mode
    return found


def check(builder: dict, present: list[str], offered: dict[str, str]) -> list[str]:
    """How the record for one builder differs from the two surfaces."""
    recorded = {setting["name"]: setting for setting in builder.get("setting", [])}
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
            elif offered[flag] not in ("Launch", builder.get("mode", "Launch")):
                problems.append(
                    f"    elsewhere   {name}: {flag} is not taken by "
                    f"{'a launch' if 'mode' not in builder else 'a launch or ' + builder['mode']}"
                )
    return problems


def main() -> int:
    record = tomllib.loads(RECORD.read_text(encoding="utf-8"))
    offered = flags()
    found = builders()
    failures, total, unflagged = [], 0, 0

    recorded = {builder["path"] for builder in record["builder"]}
    unrecorded = sorted(set(found) - recorded)
    vanished = sorted(recorded - types())
    if vanished:
        failures.append(
            "\n".join(
                ["The record names builders the snapshot no longer holds."]
                + [f"    gone        {path}" for path in vanished]
            )
        )
    if unrecorded:
        failures.append(
            "\n".join(
                ["The snapshot holds builders the record does not name."]
                + [f"    unrecorded  {path}: {', '.join(found[path])}" for path in unrecorded]
            )
        )
    by_ref = by_reference()
    if by_ref:
        failures.append(
            "\n".join(
                ["A setting takes its builder by reference, which this check cannot see."]
                + [f"    by reference  {name}: take self by value" for name in by_ref]
            )
        )

    for builder in record["builder"]:
        total += len(builder.get("setting", []))
        unflagged += sum(1 for s in builder.get("setting", []) if "kind" in s)
        problems = check(builder, found.get(builder["path"], []), offered)
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
