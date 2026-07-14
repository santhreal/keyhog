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
    pages = {path.resolve(): parse_page(path) for path in book.rglob("*.html")}
    failures: list[str] = []
    for source, page in sorted(pages.items()):
        for reference in page.references:
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
