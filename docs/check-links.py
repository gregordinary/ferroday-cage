#!/usr/bin/env python3
"""Check every link in the guide against something that can prove it.

The guide links into the API documentation with absolute `docs.rs` URLs,
which mdBook cannot check: to mdBook they are external, and nothing notices
when a method is renamed out from under one. This resolves them against the
rustdoc output instead, where the URL path maps one-to-one onto a generated
file and a `#method.x` fragment onto an anchor in it.

Relative links between chapters are checked too, including their heading
anchors, so a section rename does not leave a dangling cross-reference.

Usage:

    cargo doc --workspace --all-features --no-deps
    python3 docs/check-links.py

Exits non-zero, listing every bad link, when any link cannot be resolved.
"""

from __future__ import annotations

import re
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "docs" / "src"
RUSTDOC = REPO / "target" / "doc"
DOCS_RS = "https://docs.rs/ferroday-cage/latest/"

# Markdown inline links and reference definitions alike: everything that is a
# destination. Code spans are not excluded, because a link inside one is not a
# link — the pattern only matches the `](...)`/`]: ...` forms.
INLINE = re.compile(r"\]\(\s*<?([^)\s>]+)>?[^)]*\)")
REFERENCE = re.compile(r"^\[[^\]]+\]:\s*(\S+)", re.MULTILINE)

# Fenced code blocks: skipped, so an example that happens to contain `](` is
# not mistaken for a link.
FENCE = re.compile(r"^```.*?^```", re.MULTILINE | re.DOTALL)


def anchors_of_markdown(text: str) -> set[str]:
    """The heading anchors mdBook generates for a chapter."""
    anchors: set[str] = set()
    for line in FENCE.sub("", text).splitlines():
        if not line.startswith("#"):
            continue
        heading = line.lstrip("#").strip()
        if not heading:
            continue
        # mdBook's slug: lowercase, strip anything that is not alphanumeric,
        # a space, a hyphen, or an underscore, then hyphenate spaces.
        slug = unicodedata.normalize("NFKD", heading).lower()
        slug = re.sub(r"[^\w\s-]", "", slug, flags=re.UNICODE)
        slug = re.sub(r"[\s_]+", "-", slug.strip())
        anchors.add(slug)
    return anchors


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


def links_in(text: str) -> list[str]:
    stripped = FENCE.sub("", text)
    return [
        *(match.group(1) for match in INLINE.finditer(stripped)),
        *(match.group(1) for match in REFERENCE.finditer(stripped)),
    ]


def main() -> int:
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
        text = chapter.read_text(encoding="utf-8")
        for url in links_in(text):
            if url.startswith(DOCS_RS):
                problem = check_rustdoc_link(url)
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
