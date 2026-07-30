#!/usr/bin/env python3
"""Add canonical discovery metadata to the built KeyHog mdBook site."""

from __future__ import annotations

import argparse
import html
import json
import re
from pathlib import Path
from urllib.parse import quote

SITE_ROOT = "https://santhreal.github.io/keyhog/"
DESCRIPTION = (
    "Use KeyHog to scan repositories, Git history, CI, hosted Git collections, "
    "cloud object inventories, archives, and local systems for leaked credentials."
)
_START = "<!-- KEYHOG:SEO:BEGIN -->"
_END = "<!-- KEYHOG:SEO:END -->"


class SiteMetadataError(ValueError):
    """The built book cannot receive unambiguous discovery metadata."""


def canonical_url(relative: Path) -> str:
    """Map one mdBook HTML path to its stable GitHub Pages URL."""
    parts = list(relative.parts)
    if not parts or parts[-1] == "index.html":
        parts = parts[:-1]
        suffix = "/"
    else:
        suffix = ""
    encoded = "/".join(quote(part) for part in parts)
    return SITE_ROOT if not encoded else SITE_ROOT + encoded + suffix


def metadata_block(title: str, canonical: str) -> str:
    """Render canonical, social-card, and structured-data metadata."""
    escaped_title = html.escape(title, quote=True)
    escaped_description = html.escape(DESCRIPTION, quote=True)
    escaped_canonical = html.escape(canonical, quote=True)
    structured = json.dumps(
        {
            "@context": "https://schema.org",
            "@type": "TechArticle",
            "headline": title,
            "description": DESCRIPTION,
            "url": canonical,
            "isPartOf": {
                "@type": "SoftwareSourceCode",
                "name": "KeyHog",
                "codeRepository": "https://github.com/santhreal/keyhog",
                "programmingLanguage": "Rust",
            },
        },
        ensure_ascii=True,
        separators=(",", ":"),
    ).replace("</", "<\\/")
    return "\n".join(
        (
            _START,
            f'<link rel="canonical" href="{escaped_canonical}">',
            '<meta name="robots" content="index,follow,max-image-preview:large">',
            '<meta property="og:type" content="article">',
            '<meta property="og:site_name" content="KeyHog documentation">',
            f'<meta property="og:title" content="{escaped_title}">',
            f'<meta property="og:description" content="{escaped_description}">',
            f'<meta property="og:url" content="{escaped_canonical}">',
            '<meta name="twitter:card" content="summary">',
            f'<meta name="twitter:title" content="{escaped_title}">',
            f'<meta name="twitter:description" content="{escaped_description}">',
            f'<script type="application/ld+json">{structured}</script>',
            _END,
        )
    )


def enhance_html(document: str, relative: Path) -> str:
    """Insert or replace one generated metadata block before ``</head>``."""
    title_match = re.search(r"<title>(.*?)</title>", document, re.DOTALL | re.IGNORECASE)
    if title_match is None:
        raise SiteMetadataError(f"{relative} has no HTML title")
    title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip()
    if not title:
        raise SiteMetadataError(f"{relative} has an empty HTML title")
    block = metadata_block(title, canonical_url(relative))
    existing = re.compile(
        rf"\s*{re.escape(_START)}.*?{re.escape(_END)}\s*", re.DOTALL
    )
    if existing.search(document):
        return existing.sub("\n" + block + "\n", document, count=1)
    if document.lower().count("</head>") != 1:
        raise SiteMetadataError(f"{relative} must contain exactly one closing head tag")
    return re.sub(r"</head>", "\n" + block + "\n</head>", document, count=1, flags=re.IGNORECASE)


def publishable_pages(site: Path) -> list[Path]:
    """Return stable reader pages, excluding mdBook utility documents."""
    excluded = {Path("404.html"), Path("print.html"), Path("toc.html")}
    return [
        path
        for path in sorted(site.rglob("*.html"))
        if path.relative_to(site) not in excluded
    ]

def build_site_metadata(site: Path) -> int:
    """Enhance every page and atomically write sitemap and crawler policy."""
    if not site.is_dir():
        raise SiteMetadataError(f"built mdBook directory does not exist: {site}")
    pages = publishable_pages(site)
    if not pages:
        raise SiteMetadataError(f"built mdBook contains no publishable HTML pages: {site}")
    urls: list[str] = []
    for path in pages:
        relative = path.relative_to(site)
        updated = enhance_html(path.read_text(encoding="utf-8"), relative)
        temporary = path.with_name(path.name + ".seo-tmp")
        temporary.write_text(updated, encoding="utf-8")
        temporary.replace(path)
        urls.append(canonical_url(relative))
    sitemap = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    sitemap.extend(f"  <url><loc>{html.escape(url)}</loc></url>" for url in urls)
    sitemap.extend(("</urlset>", ""))
    (site / "sitemap.xml").write_text("\n".join(sitemap), encoding="utf-8")
    (site / "robots.txt").write_text(
        f"User-agent: *\nAllow: /keyhog/\nSitemap: {SITE_ROOT}sitemap.xml\n",
        encoding="utf-8",
    )
    return len(pages)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate canonical metadata, sitemap.xml, and robots.txt for mdBook."
    )
    parser.add_argument("site", type=Path)
    args = parser.parse_args()
    try:
        count = build_site_metadata(args.site)
    except (OSError, SiteMetadataError) as error:
        parser.error(str(error))
    print(f"Generated discovery metadata for {count} documentation pages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
