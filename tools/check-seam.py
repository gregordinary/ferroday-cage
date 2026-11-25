#!/usr/bin/env python3
"""Check the boundary between the userland side of `provision` and the rest.

The userland side is the three archive layers (`provision::debian`, `alpine`,
`gentoo`) and the archive machinery only they use: the transport, digests, the
plan-document syntax, OpenPGP, the package cache, mirror coordination, layered
builds and their observers. Its shape is driven by three external archives'
formats, the part of the library most likely to have to move, tied to the
version number of the part least likely to. `docs/src/stability.md` records how
it versions with the library. What this check keeps true is that the userland
side could become a crate of its own cheaply.

A crate of its own could reach the rest of this crate through its public API
and nothing else. Every item it reaches that is not public API is a cost that
would be paid first, and `tools/seam.toml` records each of them with what it
would cost. Three more things are recorded or refused, because each is the same
cost spelled another way:

- **Reverse edges.** Code outside the userland side that names an item inside
  it. A crate of its own could not be named back.
- **Userland feature gates outside it.** Each `feature = "debian"`, `"alpine"`
  or `"gentoo"` in the rest of the crate is code that knows the userlands
  exist.
- **Refused outright:** a layer naming another layer, since the three formats
  are deliberately not shared; and a glob import of anything outside the
  userland side, whose names the code then uses bare, where no count can see
  them.

This compares the record against the tree and fails on any difference, so a new
reach is *chosen*, in a diff a reviewer can see, and a reach that goes away is
recorded as gone in the change that removed it.

How a reach is read. Every path the userland side spells is resolved to the item
it names: a `use` tree, grouped or aliased; a `crate::`, `super::`, `self::` or
`$crate::` path; and a path that starts from a name a `use` bound or from a child
module. Resolution follows `use` bindings, so a reach through a re-export counts
as a reach of the item re-exported; it follows a glob import to the names it
brings in; and it knows a test module's `super::` from its file's. A reach is
public when `crates/ferroday-cage/public-api.txt` lists the item at its own path
or at the path a `pub use` re-exports it to. Public reaches are counted but not
recorded.

What it cannot see. A method called on a value, and a field, are not paths, and
reading text cannot tell whose they are. A reach of that kind is a cost all the
same; the type it belongs to is recorded here, and the compiler is what lists
its members.

Counts are of spellings, as a reviewer reads them: each path is one reach,
whether it names a type, a function or an associated function. A count is kept
for the code and another for its tests, which `tools/rust_source.py` separates.

Usage:

    python3 tools/check-seam.py

Exits non-zero, naming every difference, when the tree and the record disagree.
"""

from __future__ import annotations

import functools
import re
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# The reading `tools/check-idioms.py` takes, and for the same reason: a doc
# link naming another layer is prose about it rather than a use of it. Unlike
# that check, this one reads test code too, in a count of its own. The reader is
# found beside this script, which names its own directory since `python3 -I`
# does not, and a run leaves no bytecode beside it.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rust_source import code, strip_comments  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
RECORD = REPO / "tools" / "seam.toml"
SRC = REPO / "crates" / "ferroday-cage" / "src"
API = REPO / "crates" / "ferroday-cage" / "public-api.txt"

# What a reach would cost, and so the only values `cost` takes in the record.
# `tools/seam.toml` says what each means.
COSTS = ("share", "move", "copy", "reroute", "test")

# A `use` declaration, whatever its visibility, up to the semicolon that ends
# it; a grouped one spans lines. Anchored at the start of a line, where
# `cargo fmt` puts every declaration, so the word in a string is not one. The
# visibility is captured, since a `pub` one is a re-export.
USE = re.compile(r"^[ \t]*(pub(?:\([^)]*\))?[ \t]+)?use[ \t]+([^;]*);", re.S | re.M)

# A path in an expression or a type that starts from the crate root or climbs
# out of the current module. `$crate` in a macro body is the crate root too.
ROOTED = re.compile(r"\b(?:crate|super|self)(?:::[A-Za-z_][A-Za-z0-9_]*)+")

# A path of two or more segments that does not start one of the rooted forms
# above, nor continue another path. Its first segment is resolved against the
# names in scope where it is written.
RELATIVE = re.compile(
    r"(?<![\w:$])([A-Za-z_][A-Za-z0-9_]*)((?:::[A-Za-z_][A-Za-z0-9_]*)+)"
)

# A module declared inline, with a body.
INLINE = re.compile(r"\bmod[ \t]+([A-Za-z_][A-Za-z0-9_]*)[ \t]*\{")

# The tokens a `use` tree is written in.
TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|::|[{},*]")

# A conditional-compilation predicate, as an attribute or the macro.
CFG = re.compile(r"\bcfg(_attr)?\s*!?\s*\(")

# A userland feature, named in a predicate.
GATE = re.compile(r'\bfeature\s*=\s*"(?:debian|alpine|gentoo)"')

Module = tuple[str, ...]


def module_of(path: Path) -> Module:
    """The module a source file defines, as its path from the crate root."""
    parts = list(path.relative_to(SRC).with_suffix("").parts)
    if parts == ["lib"]:
        return ()
    return tuple(parts[:-1] if parts[-1] == "mod" else parts)


def use_tree(tree: str) -> list[tuple[list[str], str]]:
    """Every path a `use` tree names, with the name it binds.

    `crate::{IdentityMap, provision::{self, Fetch as F}}` names three paths,
    binding `IdentityMap`, `provision` and `F`. A glob keeps its prefix and
    binds `*`.
    """
    tokens = TOKEN.findall(tree)

    def subtree(at: int, prefix: list[str]) -> tuple[list[tuple[list[str], str]], int]:
        segments = list(prefix)
        while at < len(tokens):
            token = tokens[at]
            if token == "{":
                at += 1
                paths: list[tuple[list[str], str]] = []
                while at < len(tokens) and tokens[at] != "}":
                    found, at = subtree(at, segments)
                    paths += found
                    if at < len(tokens) and tokens[at] == ",":
                        at += 1
                return paths, at + 1
            if token == "*":
                return [(segments, "*")], at + 1
            if token != "self":
                segments.append(token)
            at += 1
            if at < len(tokens) and tokens[at] == "::":
                at += 1
                continue
            name = segments[-1] if segments else ""
            if at + 1 < len(tokens) and tokens[at] == "as":
                name = tokens[at + 1]
                at += 2
            return [(segments, name)], at
        return [(segments, segments[-1] if segments else "")], at

    return subtree(0, [])[0]


@functools.cache
def read(text: str) -> tuple[str, str]:
    """`text` without comments, and the same with every literal blanked."""
    return strip_comments(text)


@functools.cache
def inline_spans(text: str) -> list[tuple[int, int, str]]:
    """Where each inline module of `text` begins and ends, and its name."""
    shape = read(text)[1]
    spans = []
    for match in INLINE.finditer(shape):
        depth, at = 0, match.end() - 1
        while at < len(shape):
            if shape[at] == "{":
                depth += 1
            elif shape[at] == "}":
                depth -= 1
                if depth == 0:
                    break
            at += 1
        spans.append((match.start(), at, match.group(1)))
    return spans


@dataclass
class Source:
    """One file, read whole and without its tests."""

    path: Path
    module: Module
    whole: str
    built: str

    def texts(self) -> dict[str, str]:
        """The two readings a count is taken over; the tests' count is their
        difference."""
        return {"code": self.built, "all": self.whole}


@dataclass
class Tree:
    """The crate's modules, the names each binds, and its public paths."""

    modules: set[Module] = field(default_factory=set)
    # module -> name -> (absolute target, whether a `pub use` binds it)
    bindings: dict[Module, dict[str, tuple[list[str], bool]]] = field(default_factory=dict)
    # module -> the modules a glob `use` imports every name of
    globs: dict[Module, list[Module]] = field(default_factory=dict)
    public: set[str] = field(default_factory=set)
    # (module, item) -> the paths a `pub use` re-exports it at
    reexports: dict[tuple[Module, str], list[Module]] = field(default_factory=dict)

    def scope(self, source: Source, at: int, spans: list[tuple[int, int, str]]) -> Module:
        """The module the code of `source` at `at` is in, `spans` being its
        inline modules."""
        inner = [name for start, end, name in spans if start <= at <= end]
        return source.module + tuple(inner)

    def absolute(self, segments: list[str], module: Module) -> list[str] | None:
        """`segments`, written in `module`, as a path from the crate root, or
        `None` for one another crate's or a local name starts."""
        if not segments:
            return None
        head = segments[0]
        if head == "crate":
            return segments[1:]
        if head == "self":
            return list(module) + segments[1:]
        if head == "super":
            climbs = 0
            while climbs < len(segments) and segments[climbs] == "super":
                climbs += 1
            if climbs > len(module):
                return None
            return list(module[: len(module) - climbs]) + segments[climbs:]
        named = self.lookup(module, head)
        return None if named is None else named + segments[1:]

    def lookup(self, module: Module, name: str, depth: int = 0) -> list[str] | None:
        """What `name` means where `module`'s code uses it bare: a child
        module, a name a `use` binds, or one a glob import brings in."""
        if module + (name,) in self.modules:
            return list(module) + [name]
        bound = self.bindings.get(module, {}).get(name)
        if bound is not None:
            return bound[0]
        if depth < 4:
            for imported in self.globs.get(module, []):
                if imported != module:
                    found = self.lookup(imported, name, depth + 1)
                    if found is not None:
                        return found
        return None

    def resolve(self, path: list[str], depth: int = 0) -> tuple[Module, str | None, str | None]:
        """The module, item and member `path` names, through any `use` that
        rebinds a name on the way."""
        module: Module = ()
        at = 0
        while at < len(path):
            step = module + (path[at],)
            if step in self.modules:
                module, at = step, at + 1
                continue
            bound = self.bindings.get(module, {}).get(path[at])
            if bound is not None and depth < 16 and bound[0] != list(module) + [path[at]]:
                return self.resolve(bound[0] + path[at + 1 :], depth + 1)
            break
        item = path[at] if at < len(path) else None
        member = path[at + 1] if at + 1 < len(path) else None
        return module, item, member

    def is_public(self, module: Module, item: str, member: str | None) -> bool:
        """Whether the API snapshot lists `item` (or its `member`) at its own
        path or at one a `pub use` re-exports it to."""
        seen, paths = set(), [module + (item,)]
        while paths:
            path = paths.pop()
            if path in seen:
                continue
            seen.add(path)
            spelled = "::".join(path + ((member,) if member else ()))
            if spelled in self.public:
                return True
            paths += self.reexports.get((path[:-1], path[-1]), [])
        return False


def api_paths() -> set[str]:
    """Every path the API snapshot declares an item at, generics removed."""
    text = API.read_text(encoding="utf-8").replace("->", " ")
    while True:
        bare = re.sub(r"<[^<>]*>", "", text)
        if bare == text:
            break
        text = bare
    return set(re.findall(r"\bferroday_cage::([A-Za-z_][\w]*(?:::[A-Za-z_]\w*)*)", text))


def read_tree(sources: list[Source]) -> Tree:
    """Every module, every name a `use` binds, and every public path."""
    tree = Tree(public=api_paths())
    tree.modules.add(())
    for source in sources:
        tree.modules.add(source.module)
        for start, end, name in inline_spans(source.whole):
            spans = [span for span in inline_spans(source.whole) if span[0] < start <= span[1]]
            tree.modules.add(source.module + tuple(n for _, _, n in spans) + (name,))
    # Bindings in two passes, so a `use` can lean on a module another declares.
    for _ in range(2):
        for source in sources:
            spans = inline_spans(source.whole)
            for declaration in USE.finditer(source.whole):
                module = tree.scope(source, declaration.start(), spans)
                exported = (declaration.group(1) or "").strip() == "pub"
                for segments, name in use_tree(declaration.group(2)):
                    target = tree.absolute(segments, module)
                    if not target and not (name == "*" and segments == ["crate"]):
                        continue
                    if name == "*":
                        imported = tree.resolve(target or [])[0]
                        if imported not in tree.globs.setdefault(module, []):
                            tree.globs[module].append(imported)
                        continue
                    tree.bindings.setdefault(module, {})[name] = (target, exported)
    for module, names in tree.bindings.items():
        for name, (target, exported) in names.items():
            if exported:
                defined, item, member = tree.resolve(target)
                if item and not member:
                    tree.reexports.setdefault((defined, item), []).append(module + (name,))
    return tree


@dataclass
class Reach:
    """A path one file spells, resolved."""

    module: Module
    item: str
    member: str | None
    # Spelled by a `use` that re-exports it, which is how a module's public
    # paths are laid out rather than a use of what it names.
    reexport: bool

    def key(self) -> str:
        named = list(self.module) + [self.item]
        if self.member and self.member[:1].islower():
            named.append(self.member)
        return "::".join(named)


def reaches_in(tree: Tree, source: Source, text: str) -> tuple[list[Reach], list[str]]:
    """Every path `text` spells that names an item, resolved; and every glob
    import, by the module it imports from."""
    # Paths are read with every literal blanked, so a doc string's link is not
    # one: `#[cfg_attr(feature = "debian", doc = "[`Debian`](debian::Debian)")]`.
    text = read(text)[1]
    spans = inline_spans(text)
    found, globs, consumed = [], [], []
    for declaration in USE.finditer(text):
        consumed.append((declaration.start(), declaration.end()))
        module = tree.scope(source, declaration.start(), spans)
        exported = declaration.group(1) is not None
        for segments, name in use_tree(declaration.group(2)):
            target = tree.absolute(segments, module)
            if target is None:
                continue
            if name == "*":
                globs.append("::".join(tree.resolve(target)[0]) or "crate")
                continue
            defined, item, member = tree.resolve(target)
            if item:
                found.append(Reach(defined, item, member, exported))

    def inside_use(at: int) -> bool:
        return any(start <= at < end for start, end in consumed)

    for match in ROOTED.finditer(text):
        if inside_use(match.start()):
            continue
        module = tree.scope(source, match.start(), spans)
        target = tree.absolute(match.group(0).split("::"), module)
        if target:
            defined, item, member = tree.resolve(target)
            if item:
                found.append(Reach(defined, item, member, False))
    for match in RELATIVE.finditer(text):
        if inside_use(match.start()) or match.group(1) in ("crate", "super", "self"):
            continue
        module = tree.scope(source, match.start(), spans)
        segments = [match.group(1)] + match.group(2).split("::")[1:]
        target = tree.absolute(segments, module)
        if target:
            defined, item, member = tree.resolve(target)
            if item:
                found.append(Reach(defined, item, member, False))
    return found, globs


def gates_in(text: str) -> int:
    """How many `cfg` predicates in `text` name a userland feature: one for
    `cfg(any(feature = "debian", feature = "alpine"))`, as for each other.

    A `cfg_attr`'s predicate is its first argument; what it applies is not
    read, since a doc string there can spell anything."""
    kept, shape = read(text)
    found = 0
    for match in CFG.finditer(shape):
        opening = match.end() - 1
        depth, at, comma, closing = 0, opening, None, None
        while at < len(shape):
            if shape[at] == "(":
                depth += 1
            elif shape[at] == ")":
                depth -= 1
                if depth == 0:
                    closing = at
                    break
            elif shape[at] == "," and depth == 1 and comma is None:
                comma = at
            at += 1
        end = comma if match.group(1) and comma is not None else closing
        if end is not None and GATE.search(kept[opening:end]):
            found += 1
    return found


@dataclass
class Census:
    """What the tree holds, in the record's terms."""

    reaches: dict[str, Counter] = field(default_factory=dict)
    reverse: dict[str, Counter] = field(default_factory=dict)
    gates: dict[str, Counter] = field(default_factory=dict)
    public: int = 0
    refused: list[str] = field(default_factory=list)


def counted(by_text: dict[str, Counter]) -> Counter:
    """Each key's count in the code, and in the tests: the whole file's count
    less the code's."""
    out: Counter = Counter()
    for key, number in by_text["code"].items():
        out[(key, "code")] = number
    for key, number in (by_text["all"] - by_text["code"]).items():
        out[(key, "tests")] = number
    return out


def take_census(userland: list[str], layers: list[str]) -> Census:
    """Reads every source file of the crate and counts what the record
    holds: `userland` names the modules of `provision` on the userland side,
    and `layers` the ones among them that may not name each other."""
    paths = sorted(SRC.rglob("*.rs"))
    sources = []
    for path in paths:
        whole = strip_comments(path.read_text(encoding="utf-8"))[0]
        sources.append(Source(path, module_of(path), whole, code(path)))
    tree = read_tree(sources)

    def side(module: Module) -> str | None:
        """The userland module `module` belongs to, if it belongs to one."""
        if len(module) >= 2 and module[0] == "provision" and module[1] in userland:
            return module[1]
        return None

    census = Census()
    reaches: Counter = Counter()
    reverse: Counter = Counter()
    for source in sources:
        mine = side(source.module)
        relative = str(source.path.relative_to(REPO))
        by_text: dict[str, Counter] = {}
        reverse_text: dict[str, Counter] = {}
        for kind, text in source.texts().items():
            found, globs = reaches_in(tree, source, text)
            by_text[kind], reverse_text[kind] = Counter(), Counter()
            for reach in found:
                theirs = side(reach.module)
                if mine is not None and theirs is None:
                    member = reach.member if reach.member and reach.member[:1].islower() else None
                    if tree.is_public(reach.module, reach.item, member):
                        if kind == "code":
                            census.public += 1
                    else:
                        by_text[kind][reach.key()] += 1
                elif (
                    kind == "code"
                    and mine in layers
                    and theirs in layers
                    and theirs != mine
                ):
                    census.refused.append(f"{relative} names {theirs}: {reach.key()}")
                elif mine is None and theirs is not None and not reach.reexport:
                    reverse_text[kind][reach.key()] += 1
            if mine is not None:
                for glob in globs:
                    module = tuple(glob.split("::")) if glob != "crate" else ()
                    if side(module) is None:
                        census.refused.append(f"{relative} imports {glob}::*")
            if mine is None:
                census.gates.setdefault(relative, Counter())[kind] = gates_in(text)
        reaches += counted(by_text)
        reverse += counted(reverse_text)
    census.refused = sorted(set(census.refused))
    for (key, kind), number in reaches.items():
        census.reaches.setdefault(key, Counter())[kind] = number
    for (key, kind), number in reverse.items():
        census.reverse.setdefault(key, Counter())[kind] = number
    gates = {}
    for path, by_kind in census.gates.items():
        code_gates = by_kind["code"]
        test_gates = by_kind["all"] - by_kind["code"]
        if code_gates or test_gates:
            gates[path] = Counter({"code": code_gates, "tests": test_gates})
    census.gates = gates
    return census


def differences(
    label: str, recorded: dict[str, Counter], found: dict[str, Counter]
) -> list[str]:
    """How the tree differs from the record, one line each."""
    lines = []

    def spelled(counts: Counter) -> str:
        return f"code {counts['code']}, tests {counts['tests']}"

    for key in sorted(set(recorded) | set(found)):
        was, now = recorded.get(key, Counter()), found.get(key, Counter())
        if (was["code"], was["tests"]) == (now["code"], now["tests"]):
            continue
        if not (was["code"] or was["tests"]):
            lines.append(f"    new      {label} {key}: {spelled(now)}")
        elif not (now["code"] or now["tests"]):
            lines.append(f"    gone     {label} {key}: was {spelled(was)}")
        else:
            lines.append(f"    changed  {label} {key}: {spelled(was)} -> {spelled(now)}")
    return lines


def recorded(entries: list[dict], key: str) -> dict[str, Counter]:
    """The record's entries, keyed by `key`, as counts for code and tests."""
    return {
        entry[key]: Counter({"code": entry.get("code", 0), "tests": entry.get("tests", 0)})
        for entry in entries
    }


def main() -> int:
    record = tomllib.loads(RECORD.read_text(encoding="utf-8"))
    userland, layers = record["userland"], record["layers"]
    failures = []

    malformed = [
        f"    {entry['item']}: cost {entry.get('cost')!r} is none of {', '.join(COSTS)}"
        for entry in record.get("reach", [])
        if entry.get("cost") not in COSTS
    ] + [
        f"    {entry['item']}: no `why`"
        for entry in record.get("reach", []) + record.get("reverse", [])
        if not entry.get("why")
    ]
    if malformed:
        failures.append("\n".join(["The record is malformed."] + malformed))

    census = take_census(userland, layers)
    changes = (
        differences("reach", recorded(record.get("reach", []), "item"), census.reaches)
        + differences("reverse", recorded(record.get("reverse", []), "item"), census.reverse)
        + differences("gate", recorded(record.get("gate", []), "path"), census.gates)
    )
    if changes:
        failures.append("\n".join(["The record and the tree disagree about the seam."] + changes))
    if census.refused:
        failures.append(
            "\n".join(
                [
                    "A layer names another, or the userland side imports a module "
                    "outside it whole; neither is ever right."
                ]
                + [f"    {line}" for line in census.refused]
            )
        )

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(
            "\nReach through the public API, or record the reach in tools/seam.toml "
            "with what it would cost.",
            file=sys.stderr,
        )
        return 1

    def total(entries: list[dict]) -> tuple[int, int]:
        return sum(e.get("code", 0) for e in entries), sum(e.get("tests", 0) for e in entries)

    reach_code, reach_tests = total(record.get("reach", []))
    reverse_code, reverse_tests = total(record.get("reverse", []))
    gate_code, gate_tests = total(record.get("gate", []))
    print(
        f"{len(userland)} userland modules: {len(record.get('reach', []))} items reached "
        f"past the public API ({reach_code} in code, {reach_tests} in tests), "
        f"{census.public} public reaches, "
        f"{len(record.get('reverse', []))} reverse edges ({reverse_code} in code, "
        f"{reverse_tests} in tests), {gate_code + gate_tests} userland gates outside "
        f"({gate_code} in code, {gate_tests} in tests): unchanged."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
