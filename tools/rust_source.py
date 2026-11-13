"""The code of a Rust source file, as the workspace's census tools read it.

`tools/check-idioms.py` and `tools/check-seam.py` both count shapes in the
crates' code, and both mean the same thing by "code": what the crate builds
outside its tests, with no comment in it. A comment naming a shape is prose
about it rather than a use of it, and a test constructs the shape it tests.
This is that one reading, so the two tools cannot come to disagree about it.

Two things are removed:

- Every comment: line comments wherever they start, doc comments, and block
  comments, nested ones included. A `//` inside a string literal is part of the
  string, so the scan tracks string, raw-string, byte-string, C-string and
  character literals to tell the two apart. A removed comment leaves its
  newlines behind, so the lines that follow keep their place.
- Every item gated on a `cfg` that holds only in a test build, wherever it
  sits: the trailing test module, a test-only module or function between
  production items, and a test-only item nested inside one. A gate is
  test-only when its predicate cannot hold without `test` or `doctest`:
  `cfg(test)`, `cfg(all(feature = "x", test))`, `cfg(all(any(test, doctest),
  ...))`. `cfg(any(test, feature = "x"))` is not one, since such an item is
  also built for whatever else the `any` names. A `#[test]` function is
  test-only wherever it sits, since the attribute builds it only for a test.
- The whole of a module file that only a test build reads: one whose `mod`
  declaration is test-only, such as `#[cfg(test)] mod scratch;`, and every file
  beneath such a module.

An item's extent is read by matching its delimiters, over a copy of the file
in which every literal is blanked, so a brace or a bracket inside a string is
not one. An item ends at the `;` that closes it, or at the brace that closes
its body. A field, a variant or a match arm can also end at a comma, which then
ends its line: a comma inside a line can belong to generic arguments, whose
angle brackets are not delimiters a scan can match. An item whose end cannot be
found that way is an error rather than a guess, because a census that silently
counts the wrong lines reports "unchanged" about code it never read.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

# The cfg names that hold only in a build of the crate's tests.
TEST_CFGS = ("test", "doctest")

# Whether this run has read `CASES` as expected yet.
PROVEN = False

OPENERS = "([{"
CLOSERS = ")]}"

# The words an item opens with, after its visibility. An item that opens with
# one ends only at a `;` or at its body's closing brace; one that does not is a
# field, a variant, a match arm or a statement, and may also end at a comma.
ITEM = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:fn|mod|struct|enum|union|impl|trait|const|static|type|use|extern|unsafe|async"
    r"|let|macro_rules)\b"
)


def code(path: Path) -> str:
    """The file's own code: no comments, no test-only items, and nothing at all
    for a file only a test build reads.

    The first call reads the shapes in `CASES` and `MODULE_CASES` first, and
    refuses to read anything when one of them comes out wrong.
    """
    global PROVEN
    if not PROVEN:
        problems = self_test()
        if problems:
            raise ValueError(
                "the reading gets shapes it must read wrong:\n    " + "\n    ".join(problems)
            )
        PROVEN = True
    if test_only_file(path):
        return ""
    return code_of(path.read_text(encoding="utf-8"), path)


# A module declared by name, whose body is the file the declaration names.
DECLARATION = re.compile(
    r"^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M
)


@functools.cache
def test_only_file(path: Path) -> bool:
    """Whether only a test build reads `path`: the module file a test-only
    `mod` declaration names, or one beneath such a module."""
    declared = declaring_file(path)
    if declared is None:
        return False
    parent, name = declared
    if test_only_file(parent):
        return True
    return name in test_only_modules(parent.read_text(encoding="utf-8"), parent)


def declaring_file(path: Path) -> tuple[Path, str] | None:
    """The file that declares the module `path` holds, and the name it declares
    it by, or `None` for a crate root or a file no module file beside it
    declares.

    `a/b.rs` and `a/b/mod.rs` are both the module `b`, declared in `a.rs` or
    `a/mod.rs`, or in `lib.rs` or `main.rs` where `a` is the crate's `src`.
    """
    if path.name == "mod.rs":
        name, directory = path.parent.name, path.parent.parent
    else:
        name, directory = path.stem, path.parent
    candidates = [directory / "mod.rs", directory.with_suffix(".rs")]
    if directory.name == "src":
        candidates += [directory / "lib.rs", directory / "main.rs"]
    for candidate in candidates:
        if candidate != path and candidate.exists():
            return candidate, name
    return None


def test_only_modules(text: str, path: Path) -> set[str]:
    """The modules `text` declares by name that only a test build reads: those
    its comments do not hide and its test-only items do."""
    kept, shape = strip_comments(text)
    declared = set(DECLARATION.findall(kept))
    built = set(DECLARATION.findall(without_tests(kept, shape, path)))
    return declared - built


def code_of(text: str, path: Path) -> str:
    """The code of `text`, which `path` names in an error."""
    kept, shape = strip_comments(text)
    return without_tests(kept, shape, path)


def strip_comments(text: str) -> tuple[str, str]:
    """`text` with every comment removed and every newline kept, and the same
    with every literal blanked as well.

    The two have the same length line for line, so a position in one is the
    same position in the other: the blanked copy is where delimiters are
    matched, and the other is what is kept.
    """
    out: list[str] = []
    shape: list[str] = []
    at, end = 0, len(text)
    while at < end:
        char = text[at]
        ahead = text[at : at + 2]
        if ahead == "//":
            newline = text.find("\n", at)
            at = end if newline < 0 else newline
        elif ahead == "/*":
            at = skip_block_comment(text, at, out, shape)
        elif char == '"':
            at = literal(text, at, string_end(text, at), out, shape)
        elif char in "rbc" and starts_raw_string(text, at):
            at = literal(text, at, raw_string_end(text, at), out, shape)
        elif char == "b" and text[at + 1 : at + 2] in ('"', "'"):
            out.append(char)
            shape.append(char)
            at += 1
        elif char == "'":
            finish = char_end(text, at)
            if finish is None:
                # The quote of a lifetime or a label, which delimits nothing.
                out.append(char)
                shape.append(char)
                at += 1
            else:
                at = literal(text, at, finish, out, shape)
        else:
            if char.isalnum() or char == "_":
                # A whole identifier at once, so an `r` or a `b` ending one is
                # never read as the prefix of a raw or byte string.
                start = at
                while at < end and (text[at].isalnum() or text[at] == "_"):
                    at += 1
                out.append(text[start:at])
                shape.append(text[start:at])
                continue
            out.append(char)
            shape.append(char)
            at += 1
    return "".join(out), "".join(shape)


def literal(text: str, at: int, finish: int, out: list[str], shape: list[str]) -> int:
    """Keeps the literal spanning `at` to `finish`, and blanks it in the shape."""
    out.append(text[at:finish])
    shape.append(re.sub(r"[^\n]", " ", text[at:finish]))
    return finish


def skip_block_comment(text: str, at: int, out: list[str], shape: list[str]) -> int:
    """Past the block comment opening at `at`, keeping its newlines."""
    depth = 0
    while at < len(text):
        if text.startswith("/*", at):
            depth += 1
            at += 2
        elif text.startswith("*/", at):
            depth -= 1
            at += 2
            if depth == 0:
                return at
        else:
            if text[at] == "\n":
                out.append("\n")
                shape.append("\n")
            at += 1
    return at


def string_end(text: str, at: int) -> int:
    """Past the string literal opening at `at`, escapes included."""
    at += 1
    while at < len(text):
        if text[at] == "\\":
            at += 2
            continue
        if text[at] == '"':
            return at + 1
        at += 1
    return len(text)


def starts_raw_string(text: str, at: int) -> bool:
    """Whether a raw string literal (`r"`, `r#"`, `br"`, `cr#"`, ...) opens at
    `at`."""
    return re.match(r'[bc]?r#*"', text[at : at + 260]) is not None


def raw_string_end(text: str, at: int) -> int:
    """Past the raw string literal opening at `at`, which has no escapes."""
    opening = re.match(r'[bc]?r(#*)"', text[at:])
    closing = '"' + opening.group(1)
    finish = text.find(closing, at + opening.end())
    return len(text) if finish < 0 else finish + len(closing)


def char_end(text: str, at: int) -> int | None:
    """Past the character literal opening at `at`, or `None` where the quote
    begins a lifetime or a label instead."""
    if text[at + 1 : at + 2] == "\\":
        finish = text.find("'", at + 2)
        if text[at + 2 : at + 3] == "'":
            # `'\''`: the escaped quote is the character, not the end.
            finish = text.find("'", at + 3)
        return len(text) if finish < 0 else finish + 1
    if text[at + 2 : at + 3] == "'":
        return at + 3
    return None


def without_tests(kept: str, shape: str, path: Path) -> str:
    """`kept` with every test-only item removed, read through `shape`."""
    lines = kept.split("\n")
    shapes = shape.split("\n")
    starts = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1

    out: list[str] = []
    index = 0
    while index < len(lines):
        attribute = shapes[index].lstrip()
        if attribute.startswith(("#[", "#![")):
            at = starts[index] + len(shapes[index]) - len(attribute)
            close = matching(shape, at + attribute.index("["), path)
            if test_only(kept[at : close + 1], path):
                if attribute.startswith("#!["):
                    if depth_at(shape, at, path) != 0:
                        raise ValueError(
                            f"{line_of(starts, at, path)}: a test-only inner attribute "
                            "inside an item is not read"
                        )
                    # The whole file is test-only.
                    return ""
                finish = item_end(shape, close + 1, starts, path)
                index = line_index(starts, finish) + 1
                continue
        out.append(lines[index])
        index += 1
    return "\n".join(out)


def item_end(shape: str, at: int, starts: list[int], path: Path) -> int:
    """The position of the delimiter that ends the item following `at`.

    Further attributes before the item are part of it. The item ends at a `;`
    outside every delimiter, or at the brace that closes its body, together with
    a `;` or a `,` that directly follows that brace: `use a::{b};` and a variant
    `V { .. },` end at their separator rather than at the brace. One that is not
    an item proper, such as a field, also ends at a comma outside every
    delimiter that ends its line.
    """
    at = skip_space(shape, at)
    while shape.startswith("#[", at):
        at = skip_space(shape, matching(shape, at + 1, path) + 1)
    if at >= len(shape):
        raise ValueError(f"{path}: a test-only attribute gates no item")
    begun = at
    commas = ITEM.match(shape, at) is None
    depth = 0
    while at < len(shape):
        char = shape[at]
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
            if depth < 0:
                raise ValueError(
                    f"{line_of(starts, begun, path)}: a test-only item runs past the "
                    "block that holds it"
                )
            if depth == 0 and char == "}":
                after = skip_space(shape, at + 1)
                return after if after < len(shape) and shape[after] in ";," else at
        elif depth == 0 and (char == ";" or (char == "," and commas and ends_line(shape, at))):
            return at
        at += 1
    raise ValueError(
        f"{line_of(starts, begun, path)}: the end of a test-only item cannot be found"
    )


def matching(shape: str, opening: int, path: Path) -> int:
    """The position of the delimiter that closes the one at `opening`."""
    depth = 0
    for at in range(opening, len(shape)):
        if shape[at] in OPENERS:
            depth += 1
        elif shape[at] in CLOSERS:
            depth -= 1
            if depth == 0:
                return at
    raise ValueError(f"{path}: an attribute opened at offset {opening} never closes")


def depth_at(shape: str, at: int, path: Path) -> int:
    """How many delimiters are open at `at`."""
    depth = 0
    for char in shape[:at]:
        if char in OPENERS:
            depth += 1
        elif char in CLOSERS:
            depth -= 1
    if depth < 0:
        raise ValueError(f"{path}: more delimiters close than open")
    return depth


def ends_line(text: str, at: int) -> bool:
    """Whether nothing but whitespace follows `at` on its line."""
    newline = text.find("\n", at)
    return text[at + 1 : len(text) if newline < 0 else newline].strip() == ""


def skip_space(text: str, at: int) -> int:
    """The first position at or after `at` that is not whitespace."""
    while at < len(text) and text[at].isspace():
        at += 1
    return at


def line_index(starts: list[int], at: int) -> int:
    """The index of the line holding position `at`."""
    low, high = 0, len(starts) - 1
    while low < high:
        middle = (low + high + 1) // 2
        if starts[middle] <= at:
            low = middle
        else:
            high = middle - 1
    return low


def line_of(starts: list[int], at: int, path: Path) -> str:
    """`path:line` for position `at`, as an error names it."""
    return f"{path}:{line_index(starts, at) + 1}"


# One token of a `cfg` predicate: a name, a string, or a punctuation mark.
TOKEN = re.compile(r'\s*(?:([A-Za-z_][A-Za-z0-9_]*)|("(?:[^"\\]|\\.)*")|([(),=]))')


def test_only(attribute: str, path: Path) -> bool:
    """Whether `attribute` builds its item only for a test: `#[test]`, or a
    `cfg` whose predicate holds only in a test build."""
    if re.fullmatch(r"#\[\s*test\s*\]", attribute):
        return True
    match = re.fullmatch(r"#!?\[\s*cfg\s*\((.*)\)\s*\]", attribute, re.DOTALL)
    if not match:
        return False
    tokens = tokenize(match.group(1), path)
    predicate, rest = parse_predicate(tokens, path)
    if rest:
        raise ValueError(f"{path}: {attribute!r} holds more than one predicate")
    return implies_test(predicate)


def tokenize(text: str, path: Path) -> list[str]:
    """The tokens of a `cfg` predicate."""
    tokens = []
    at = 0
    while at < len(text):
        if text[at:].strip() == "":
            break
        match = TOKEN.match(text, at)
        if not match:
            raise ValueError(f"{path}: cannot read the cfg predicate {text!r}")
        tokens.append(next(group for group in match.groups() if group is not None))
        at = match.end()
    return tokens


def parse_predicate(tokens: list[str], path: Path) -> tuple[tuple, list[str]]:
    """One predicate off the front of `tokens`: a name, `name = "value"`, or
    `name(predicate, ...)`, with the tokens left over."""
    if not tokens or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]):
        raise ValueError(f"{path}: a cfg predicate expected a name, not {tokens[:1]}")
    name, rest = tokens[0], tokens[1:]
    if rest[:1] == ["="]:
        return (name, "value", None), rest[2:]
    if rest[:1] != ["("]:
        return (name, None, None), rest
    rest = rest[1:]
    arguments = []
    while rest and rest[0] != ")":
        argument, rest = parse_predicate(rest, path)
        arguments.append(argument)
        if rest[:1] == [","]:
            rest = rest[1:]
    if rest[:1] != [")"]:
        raise ValueError(f"{path}: the cfg predicate {name}(...) never closes")
    return (name, "list", arguments), rest[1:]


def implies_test(predicate: tuple) -> bool:
    """Whether `predicate` can hold only where a test cfg does."""
    name, kind, arguments = predicate
    if kind is None:
        return name in TEST_CFGS
    if kind != "list":
        return False
    if name == "all":
        return any(implies_test(argument) for argument in arguments)
    if name == "any":
        return bool(arguments) and all(implies_test(argument) for argument in arguments)
    return False


# Shapes the reading must get right, each a source and the code it holds.
# `code` reads these before any file, so a reading that misplaces an item's end
# fails the census rather than counting lines it should not. Running this file
# reads them on their own.
CASES = [
    (
        "a comment on an item's closing brace",
        """
        pub fn one() {}

        #[cfg(test)]
        fn helper() {
            let x = 1;
        } // a test-only helper

        pub fn two() {}
        """,
        ["pub fn one() {}", "", "", "pub fn two() {}"],
    ),
    (
        "a raw string holding a closing delimiter at the start of a line",
        """
        pub fn production() {}

        #[cfg(test)]
        mod tests {
            const PROFILE: &str = r#"
        mounts = [
          "a",
        ]
        "#;

            fn t() {}
        }
        pub fn after() {}
        """,
        ["pub fn production() {}", "", "pub fn after() {}"],
    ),
    (
        "test among other conditions of an all",
        """
        #[cfg(all(feature = "serde", test))]
        mod serde_tests {
            fn t() {}
        }
        #[cfg(all(
            any(test, doctest),
            feature = "serde",
        ))]
        mod guide;
        pub fn kept() {}
        """,
        ["pub fn kept() {}"],
    ),
    (
        "a condition that also holds outside a test build",
        """
        #[cfg(any(test, feature = "serde"))]
        fn shared() {}
        #[cfg(not(test))]
        fn production() {}
        """,
        [
            '#[cfg(any(test, feature = "serde"))]',
            "fn shared() {}",
            "#[cfg(not(test))]",
            "fn production() {}",
        ],
    ),
    (
        "a comma inside a signature's generic arguments",
        """
        #[cfg(test)]
        pub(crate) unsafe fn send(tid: Pid) -> Result<(), Errno> {
            Ok(())
        }
        pub fn kept() {}
        """,
        ["pub fn kept() {}"],
    ),
    (
        "test-only fields, variants and imports",
        """
        use std::collections::HashMap;
        #[cfg(test)]
        use std::{fs, io};
        struct Held {
            #[cfg(test)]
            seen: HashMap<String, u32>,
            kept: u32,
        }
        enum Shape {
            #[cfg(test)]
            Probe { at: u32 },
            Kept,
        }
        """,
        [
            "use std::collections::HashMap;",
            "struct Held {",
            "    kept: u32,",
            "}",
            "enum Shape {",
            "    Kept,",
            "}",
        ],
    ),
    (
        "a test function outside a test module",
        """
        pub fn kept() {}

        #[test]
        fn checks_kept() {
            kept();
        }
        """,
        ["pub fn kept() {}", ""],
    ),
    (
        "a raw C string holding a quote and a comment's opener",
        """
        const NAME: &CStr = cr#"a"//b"#;
        pub fn kept() {}
        """,
        ['const NAME: &CStr = cr#"a"//b"#;', "pub fn kept() {}"],
    ),
    (
        "comments, and a comment's opener inside a string",
        """
        /// A doc comment.
        fn url() -> &'static str {
            "http://example.org" // the default
        }
        """,
        ["", "fn url() -> &'static str {", '    "http://example.org" ', "}"],
    ),
]


# Module declarations the reading must sort right, each a source and the
# modules it declares that only a test build reads.
MODULE_CASES = [
    (
        "a test-only module declared by name beside production ones",
        """
        mod kept;
        #[cfg(test)]
        mod scratch;
        #[cfg(feature = "x")]
        pub(crate) mod gated;
        // mod commented;
        """,
        {"scratch"},
    ),
]


def self_test() -> list[str]:
    """Every case the reading gets wrong, described."""
    import textwrap

    failures = []
    for name, source, expected in MODULE_CASES:
        text = textwrap.dedent(source).strip("\n") + "\n"
        try:
            got = test_only_modules(text, Path(f"<{name}>"))
        except ValueError as error:
            failures.append(f"{name}: {error}")
            continue
        if got != expected:
            failures.append(f"{name}: read {sorted(got)!r}, expected {sorted(expected)!r}")
    for name, source, expected in CASES:
        text = textwrap.dedent(source).strip("\n") + "\n"
        try:
            got = code_of(text, Path(f"<{name}>")).split("\n")
        except ValueError as error:
            failures.append(f"{name}: {error}")
            continue
        got = got[:-1] if got and got[-1] == "" else got
        if got != expected:
            failures.append(f"{name}: read {got!r}, expected {expected!r}")
    return failures


if __name__ == "__main__":
    import sys

    problems = self_test()
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"{len(CASES) + len(MODULE_CASES)} shapes read as expected.")
    sys.exit(1 if problems else 0)
