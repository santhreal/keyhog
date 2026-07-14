#!/usr/bin/env python3
"""Validate local links in the built mdBook site."""

from __future__ import annotations

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[str] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        node_id = values.get("id")
        if node_id:
            self.ids.add(node_id)
        attribute = {
            "a": "href",
            "img": "src",
            "iframe": "src",
            "link": "href",
            "script": "src",
            "source": "src",
        }.get(tag)
        if attribute and values.get(attribute):
            self.references.append(values[attribute] or "")


def parse_page(path: Path) -> PageParser:
    parser = PageParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


def css_urls(text: str) -> list[str]:
    """Return CSS url(...) operands without interpreting their contents."""
    references: list[str] = []
    cursor = 0
    while cursor < len(text):
        if text.startswith("/*", cursor):
            end = text.find("*/", cursor + 2)
            cursor = len(text) if end < 0 else end + 2
            continue
        if text[cursor] in "\"'":
            quote = text[cursor]
            cursor += 1
            while cursor < len(text):
                if text[cursor] == "\\":
                    cursor += 2
                elif text[cursor] == quote:
                    cursor += 1
                    break
                else:
                    cursor += 1
            continue
        if text[cursor : cursor + 4].lower() != "url(":
            cursor += 1
            continue
        cursor += 4
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        quote = text[cursor] if cursor < len(text) and text[cursor] in "\"'" else None
        if quote is not None:
            cursor += 1
        value: list[str] = []
        escaped = False
        while cursor < len(text):
            character = text[cursor]
            cursor += 1
            if escaped:
                value.append(character)
                escaped = False
                continue
            if character == "\\":
                escaped = True
                continue
            if quote is not None and character == quote:
                while cursor < len(text) and text[cursor].isspace():
                    cursor += 1
                if cursor < len(text) and text[cursor] == ")":
                    cursor += 1
                    references.append("".join(value))
                break
            if quote is None and character == ")":
                references.append("".join(value).strip())
                break
            value.append(character)
    return references


def resolve_target(book: Path, source: Path, href_path: str, site_prefix: str) -> Path | None:
    if not href_path:
        return source
    decoded = unquote(href_path)
    if decoded.startswith("/"):
        prefix = site_prefix.rstrip("/") + "/"
        if not decoded.startswith(prefix):
            return None
        target = book / decoded[len(prefix) :]
    else:
        target = source.parent / decoded
    target = target.resolve()
    try:
        target.relative_to(book)
    except ValueError:
        return None
    if target.is_dir():
        target = target / "index.html"
    elif not target.exists() and target.suffix == "":
        html_target = target.with_suffix(".html")
        index_target = target / "index.html"
        target = html_target if html_target.exists() else index_target
    return target


def main() -> int:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("book", type=Path)
    argument_parser.add_argument("--site-prefix", default="/keyhog/")
    args = argument_parser.parse_args()

    book = args.book.resolve()
    if not book.is_dir():
        print(f"Built documentation directory does not exist: {book}")
        return 1
    index = book / "index.html"
    if not index.is_file():
        print(f"Built documentation is missing its entry page: {index}")
        return 1
    pages = {path.resolve(): parse_page(path) for path in book.rglob("*.html")}
    if not pages:
        print(f"Built documentation contains no HTML pages: {book}")
        return 1
    failures: list[str] = []
    references = [
        (source, reference)
        for source, page in pages.items()
        for reference in page.references
    ]
    references.extend(
        (stylesheet.resolve(), reference)
        for stylesheet in book.rglob("*.css")
        for reference in css_urls(stylesheet.read_text(encoding="utf-8"))
    )
    for source, reference in sorted(references):
        parsed = urlsplit(reference)
        if parsed.scheme or parsed.netloc or reference.startswith(("mailto:", "javascript:")):
            continue
        target = resolve_target(book, source, parsed.path, args.site_prefix)
        if target is None or not target.is_file():
            failures.append(
                f"{source.relative_to(book)}: unresolved local resource {reference!r}"
            )
            continue
        if parsed.fragment and target.suffix == ".html":
            target_page = pages.get(target.resolve())
            if target_page is None or unquote(parsed.fragment) not in target_page.ids:
                failures.append(
                    f"{source.relative_to(book)}: missing fragment {parsed.fragment!r} in "
                    f"{target.relative_to(book)}"
                )

    if failures:
        print("Built documentation contains broken local links:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"validated {len(pages)} built documentation pages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
