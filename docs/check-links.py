#!/usr/bin/env python3
"""Check every link in the guide against something that can prove it.

The guide links into the API documentation with absolute `docs.rs` URLs,
which mdBook cannot check: to mdBook they are external, and nothing notices
when a method is renamed out from under one. This resolves them against the
rustdoc output instead, where the URL path maps one-to-one onto a generated
file and a `#method.x` fragment onto an anchor in it.

Relative links between chapters are checked too, including their heading
anchors, so a section rename does not leave a dangling cross-reference. A
reference-style link whose label no definition in its chapter names is a
failure as well: mdBook renders it as the bracketed text, with no link. So are
the links that point at this repository's own source on GitHub: they are
external URLs and mdBook skips them, but the file they name is right here, and a
rename would otherwise leave the guide pointing at nothing with nothing
noticing.

A heading's anchor is computed here the way mdBook computes it. Given a build
of the guide with `--book`, each chapter's computed anchors are also compared
with the ids that build rendered, so a heading read differently from mdBook
fails the check rather than passing a link the published guide breaks.

Usage:

    cargo doc --workspace --all-features --no-deps
    python3 docs/check-links.py [--book docs/book]

Exits non-zero, listing every bad link, when any link cannot be resolved.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "docs" / "src"
RUSTDOC = REPO / "target" / "doc"
DOCS_RS = "https://docs.rs/ferroday-cage/latest/"
# A link into this repository's own source. The URL is external, so mdBook does
# not check it, but everything after the prefix is a path in this working tree.
SOURCE_BLOB = "https://github.com/gregordinary/ferroday-cage/blob/main/"

# Markdown inline links and reference definitions alike: everything that is a
# destination. Code spans are not excluded, because a link inside one is not a
# link — the pattern only matches the `](...)`/`]: ...` forms.
INLINE = re.compile(r"\]\(\s*<?([^)\s>]+)>?[^)]*\)")
REFERENCE = re.compile(r"^\[[^\]]+\]:\s*(\S+)", re.MULTILINE)

# Fenced code blocks: skipped, so an example that happens to contain `](` is
# not mistaken for a link.
FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)

# A code span, as CommonMark closes one: a backtick run ended by the next run
# of the same length. HTML comments are dropped with them, since neither holds
# a link.
CODE_SPAN_ANYWHERE = re.compile(r"(`+).+?(?<!`)\1(?!`)", re.DOTALL)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)

# A reference-style link: `[text][label]`, `[label][]`, or `[label]` alone. An
# inline link, a definition, an image, and an escaped bracket are not one, and
# neither is the second half of a full reference, which the first half's match
# consumes.
REFERENCE_USE = re.compile(r"(?<![\\!\]])\[([^\[\]]+)\](?:\[([^\[\]]*)\])?(?![(:\[])")


# A code span in a heading: mdBook keeps its text and drops the backticks.
CODE_SPAN = re.compile(r"(`+)(.+?)\1")

# A run of underscores, which may delimit emphasis.
UNDERSCORES = re.compile(r"_+")


def anchors_of_markdown(text: str) -> set[str]:
    """The heading anchors mdBook generates for a chapter."""
    anchors: set[str] = set()
    for line in FENCE.sub("", text).splitlines():
        if not line.startswith("#"):
            continue
        heading = line.lstrip("#").strip()
        if not heading:
            continue
        slug = slug_of(rendered(heading))
        # A repeated heading takes the first free numbered suffix, as mdBook
        # numbers it.
        anchor, repeat = slug, 0
        while anchor in anchors:
            repeat += 1
            anchor = f"{slug}-{repeat}"
        anchors.add(anchor)
    return anchors


def rendered(heading: str) -> str:
    """The text of a heading as mdBook renders it: a code span's contents as
    written, and the rest without the underscores that delimit emphasis.

    An asterisk delimits emphasis too, and needs no rule of its own: the slug
    drops it like any other punctuation.
    """
    parts = []
    at = 0
    for span in CODE_SPAN.finditer(heading):
        parts.append(without_emphasis(heading[at : span.start()]))
        parts.append(span.group(2))
        at = span.end()
    parts.append(without_emphasis(heading[at:]))
    return "".join(parts)


def without_emphasis(text: str) -> str:
    """`text` without the underscore runs that pair up as emphasis.

    A run can open emphasis where it starts a word and close it where it ends
    one; an underscore inside a word, as in `snake_case`, does neither. Each
    closer pairs with the nearest open run before it, and a run left unpaired is
    the literal underscore it looks like, as in `foo_`.
    """
    def word(at: int) -> bool:
        return 0 <= at < len(text) and text[at].isalnum()

    def blank(at: int) -> bool:
        return not 0 <= at < len(text) or text[at].isspace()

    paired: list[tuple[int, int]] = []
    open_runs: list[tuple[int, int]] = []
    for run in UNDERSCORES.finditer(text):
        start, end = run.span()
        closes = not blank(start - 1) and not word(end)
        opens = not blank(end) and not word(start - 1)
        if closes and open_runs:
            paired.extend([open_runs.pop(), (start, end)])
        elif opens:
            open_runs.append((start, end))
    kept = list(text)
    for start, end in paired:
        kept[start:end] = [""] * (end - start)
    return "".join(kept)


def slug_of(heading: str) -> str:
    """mdBook's anchor for a heading's rendered text.

    Character by character: a letter, a digit, `_` and `-` stay, lowercased;
    each whitespace character becomes a `-`, so a run of them is a run of
    hyphens; everything else is dropped. "Read & write" is therefore
    `read--write`, and "a `non_exhaustive` type" keeps its underscore.
    """
    out = []
    for char in heading:
        if char.isalnum() or char in "_-":
            out.append(char.lower())
        elif char.isspace():
            out.append("-")
    return "".join(out)


def check_rustdoc_link(url: str) -> str | None:
    """Resolve a `docs.rs` URL against the rustdoc output; None if it is fine."""
    target = url[len(DOCS_RS) :]
    path, _, fragment = target.partition("#")
    page = RUSTDOC / path
    if not page.is_file():
        return f"no such rustdoc page: {path}"
    if fragment:
        html = page.read_text(encoding="utf-8", errors="replace")
        if f'id="{fragment}"' not in html:
            return f"{path} has no anchor #{fragment}"
    return None


def check_source_link(url: str) -> str | None:
    """Resolve a link into this repository's source; None if it is fine.

    An `#L<n>` fragment names a line, which is checked too: a link to a line
    past the end of the file is as dangling as a link to a missing file.
    """
    target, _, fragment = url[len(SOURCE_BLOB) :].partition("#")
    path = REPO / target
    if not path.is_file():
        return f"no such file in this repository: {target}"
    match = re.fullmatch(r"L(\d+)(?:-L(\d+))?", fragment)
    if fragment and not match:
        return f"unrecognized source fragment: #{fragment}"
    if match:
        last = int(match.group(2) or match.group(1))
        lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        if last > lines:
            return f"{target} has {lines} lines, so #{fragment} names nothing"
    return None


def check_chapter_link(source: Path, url: str) -> str | None:
    """Resolve a relative link between chapters; None if it is fine."""
    path, _, fragment = url.partition("#")
    if not path:
        # A same-page anchor.
        target = source
    else:
        target = (source.parent / path).resolve()
        if not target.is_file():
            return f"no such file: {path}"
    if fragment:
        anchors = anchors_of_markdown(target.read_text(encoding="utf-8"))
        if fragment not in anchors:
            return f"{target.name} has no heading anchor #{fragment}"
    return None


def check_rendered_anchors(chapter: Path, book: Path) -> str | None:
    """Compare a chapter's computed anchors with those a build rendered; None if
    they agree."""
    page = book / f"{chapter.stem}.html"
    if not page.is_file():
        return f"the build at {book} has no page {page.name}"
    rendered_ids = {
        html.unescape(found)
        for found in re.findall(r'<h[1-6] id="([^"]+)"', page.read_text(encoding="utf-8"))
    }
    computed = anchors_of_markdown(chapter.read_text(encoding="utf-8"))
    if computed == rendered_ids:
        return None
    return (
        f"anchors computed here and not rendered: {sorted(computed - rendered_ids)}; "
        f"rendered and not computed: {sorted(rendered_ids - computed)}"
    )


def undefined_references(text: str) -> list[str]:
    """The labels of the reference-style links in a chapter that no definition
    in it names, in the order they appear.

    Code spans are masked rather than removed: a label is often one, as in
    ``[`Network`]``, and a bracket inside one elsewhere, as in `` `[[mount]]` ``,
    is no link. Labels compare as CommonMark compares them, ignoring case and
    collapsing whitespace.
    """
    spans: list[str] = []

    def mask(match: re.Match[str]) -> str:
        spans.append(match.group(0))
        return f"\0{len(spans) - 1}\0"

    masked = CODE_SPAN_ANYWHERE.sub(mask, HTML_COMMENT.sub("", FENCE.sub("", text)))

    def label(raw: str) -> str:
        unmasked = re.sub("\0(\\d+)\0", lambda found: spans[int(found.group(1))], raw)
        return " ".join(unmasked.split())

    definitions = re.finditer(r"^\[([^\]]+)\]:", masked, re.MULTILINE)
    defined = {label(found.group(1)).casefold() for found in definitions}
    missing = []
    for use in REFERENCE_USE.finditer(masked):
        text_part, label_part = use.group(1), use.group(2)
        named = label(label_part) if label_part else label(text_part)
        if named.startswith("^") or named.casefold() in defined:
            continue
        missing.append(named)
    return missing


def links_in(text: str) -> list[str]:
    stripped = FENCE.sub("", text)
    return [
        *(match.group(1) for match in INLINE.finditer(stripped)),
        *(match.group(1) for match in REFERENCE.finditer(stripped)),
    ]


def main() -> int:
    arguments = sys.argv[1:]
    book = None
    if arguments[:1] == ["--book"] and len(arguments) == 2:
        book = Path(arguments[1])
    elif arguments:
        print("usage: python3 docs/check-links.py [--book DIR]", file=sys.stderr)
        return 2
    if not RUSTDOC.is_dir():
        print(
            "docs/check-links.py: no rustdoc output at target/doc; run\n"
            "    cargo doc --workspace --all-features --no-deps\n"
            "first, so the API links have something to resolve against.",
            file=sys.stderr,
        )
        return 2

    failures: list[str] = []
    checked = 0
    for chapter in sorted(SRC.glob("*.md")):
        if book is not None and chapter.name != "SUMMARY.md":
            problem = check_rendered_anchors(chapter, book)
            if problem:
                failures.append(f"{chapter.relative_to(REPO)}: heading anchors\n    {problem}")
        text = chapter.read_text(encoding="utf-8")
        for missing in undefined_references(text):
            checked += 1
            failures.append(
                f"{chapter.relative_to(REPO)}: [{missing}]\n    no reference definition names this label"
            )
        for url in links_in(text):
            if url.startswith(DOCS_RS):
                problem = check_rustdoc_link(url)
            elif url.startswith(SOURCE_BLOB):
                problem = check_source_link(url)
            elif url.startswith(("http://", "https://", "mailto:")):
                # An external link: not this check's business.
                continue
            elif url.endswith(".md") or ".md#" in url or url.startswith("#"):
                problem = check_chapter_link(chapter, url)
            else:
                continue
            checked += 1
            if problem:
                failures.append(f"{chapter.relative_to(REPO)}: {url}\n    {problem}")

    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        print(f"\n{len(failures)} of {checked} guide links are broken.", file=sys.stderr)
        return 1
    print(f"{checked} guide links resolve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
