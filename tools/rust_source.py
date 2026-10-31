"""The code of a Rust source file, as the workspace's census tools read it.

`tools/check-idioms.py` and `tools/check-seam.py` both count shapes in the
crates' code, and both mean the same thing by "code": what the crate builds
outside its tests, with no comment in it. A comment naming a shape is prose
about it rather than a use of it, and a test constructs the shape it tests.
This is that one reading, so the two tools cannot come to disagree about it.

Two things are removed:

- Every comment: line comments wherever they start, doc comments, and block
  comments, nested ones included. A `//` inside a string literal is part of the
  string, so the scan tracks string, raw-string, byte-string and character
  literals to tell the two apart. A removed comment leaves its newlines behind,
  so the lines that follow keep their place.
- Every item gated on `#[cfg(test)]` or `#[cfg(all(test, ...))]`, wherever it
  sits: the trailing test module, a test-only module or function between
  production items, and a test-only item nested inside one. An item's extent is
  read from its layout, which `cargo fmt --check` holds every file to: a block
  item closes on a line of its own at the indentation its attribute opened at.
  An item whose end cannot be found that way is an error rather than a guess,
  because a census that silently counts the wrong lines reports "unchanged"
  about code it never read.
"""

from __future__ import annotations

import re
from pathlib import Path

# The attribute that makes an item test-only. `cfg(any(test, ...))` is not
# here: such an item is also built for whatever else the `any` names.
TEST_GATE = re.compile(r"#\[cfg\((?:test|all\(test\b[^\]]*\))\)\]$")

# A line that closes a multi-line item at the item's own indentation: one or
# more closing delimiters, then at most the separator that ends the item.
CLOSER = re.compile(r"[}\])]+[;,]?$")


def code(path: Path) -> str:
    """The file's own code: no comments, no test-only items."""
    text = path.read_text(encoding="utf-8")
    return "\n".join(without_tests(strip_comments(text).split("\n"), path))


def strip_comments(text: str) -> str:
    """`text` with every comment removed and every newline kept."""
    out: list[str] = []
    at, end = 0, len(text)
    while at < end:
        char = text[at]
        ahead = text[at : at + 2]
        if ahead == "//":
            newline = text.find("\n", at)
            at = end if newline < 0 else newline
        elif ahead == "/*":
            at = skip_block_comment(text, at, out)
        elif char == '"':
            at = copy_string(text, at, out)
        elif char in "rb" and starts_raw_string(text, at):
            at = copy_raw_string(text, at, out)
        elif char == "b" and text[at + 1 : at + 2] in ('"', "'"):
            out.append(char)
            at += 1
        elif char == "'":
            at = copy_char_or_lifetime(text, at, out)
        else:
            if char.isalnum() or char == "_":
                # A whole identifier at once, so an `r` or a `b` ending one is
                # never read as the prefix of a raw or byte string.
                start = at
                while at < end and (text[at].isalnum() or text[at] == "_"):
                    at += 1
                out.append(text[start:at])
                continue
            out.append(char)
            at += 1
    return "".join(out)


def skip_block_comment(text: str, at: int, out: list[str]) -> int:
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
            at += 1
    return at


def copy_string(text: str, at: int, out: list[str]) -> int:
    """Copies the string literal opening at `at`, escapes included."""
    start = at
    at += 1
    while at < len(text):
        if text[at] == "\\":
            at += 2
            continue
        if text[at] == '"':
            at += 1
            break
        at += 1
    out.append(text[start:at])
    return at


def starts_raw_string(text: str, at: int) -> bool:
    """Whether a raw string literal (`r"`, `r#"`, `br"`, ...) opens at `at`."""
    return re.match(r'b?r#*"', text[at : at + 260]) is not None


def copy_raw_string(text: str, at: int, out: list[str]) -> int:
    """Copies the raw string literal opening at `at`, which has no escapes."""
    opening = re.match(r'b?r(#*)"', text[at:])
    closing = '"' + opening.group(1)
    finish = text.find(closing, at + opening.end())
    finish = len(text) if finish < 0 else finish + len(closing)
    out.append(text[at:finish])
    return finish


def copy_char_or_lifetime(text: str, at: int, out: list[str]) -> int:
    """Copies a character literal, or the quote of a lifetime or a label."""
    if text[at + 1 : at + 2] == "\\":
        finish = text.find("'", at + 2)
        if text[at + 2 : at + 3] == "'":
            # `'\''`: the escaped quote is the character, not the end.
            finish = text.find("'", at + 3)
        finish = len(text) if finish < 0 else finish + 1
        out.append(text[at:finish])
        return finish
    if text[at + 2 : at + 3] == "'":
        out.append(text[at : at + 3])
        return at + 3
    out.append("'")
    return at + 1


def without_tests(lines: list[str], path: Path) -> list[str]:
    """`lines` with every test-only item removed."""
    kept: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not TEST_GATE.match(stripped):
            kept.append(line)
            index += 1
            continue
        indent = line[: len(line) - len(line.lstrip())]
        index = past_item(lines, index + 1, indent, path)
    return kept


def past_item(lines: list[str], index: int, indent: str, path: Path) -> int:
    """The index of the first line after the item whose attributes end at `index`."""
    while index < len(lines) and lines[index].strip().startswith("#["):
        index += 1
    if index >= len(lines):
        raise ValueError(f"{path}: a test-only attribute gates no item")
    first = lines[index].strip()
    if first.endswith((";", ",")) or (first.endswith("}") and balanced(first)):
        return index + 1
    for later in range(index + 1, len(lines)):
        line = lines[later]
        if line.startswith(indent) and not line[len(indent) :].startswith((" ", "\t")):
            if CLOSER.match(line[len(indent) :]):
                return later + 1
    raise ValueError(
        f"{path}:{index + 1}: the end of a test-only item cannot be found; "
        "is the file formatted?"
    )


def balanced(line: str) -> bool:
    """Whether every brace `line` opens it also closes."""
    return line.count("{") == line.count("}")
