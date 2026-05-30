#!/usr/bin/env python3
"""Render every pages/*.html fragment into a full standalone HTML page.

Each fragment starts with a small TOML-style header followed by `---`:

    title = "Installation"
    description = "Install keyhog via cargo, prebuilt binaries, or source."
    ---
    <h1>Installation</h1>
    <p>…</p>

Run from site/ root: `python3 build.py` → writes *.html to site/ root.
"""
from __future__ import annotations
import re, sys
from pathlib import Path

ROOT = Path(__file__).parent
PAGES = ROOT / "pages"

NAV = [
    ("Getting started", [
        ("index.html",       "Introduction"),
        ("install.html",     "Installation"),
        ("quickstart.html",  "Quickstart"),
    ]),
    ("Scanning", [
        ("scan.html",     "Scan command"),
        ("output.html",   "Output formats"),
        ("baseline.html", "Baselines"),
        ("ignore.html",   "Allowlists"),
    ]),
    ("Integrations", [
        ("ci.html",     "CI / SARIF"),
        ("hooks.html",  "Pre-commit hooks"),
        ("daemon.html", "Daemon mode"),
        ("system.html", "System triage"),
    ]),
    ("Reference", [
        ("detectors.html", "Detector catalog"),
        ("config.html",    "Configuration"),
        ("api.html",       "Library API"),
    ]),
    ("Internals", [
        ("architecture.html", "Architecture"),
        ("performance.html",  "Performance"),
        ("lockdown.html",     "Lockdown mode"),
        ("faq.html",          "FAQ"),
    ]),
]

VERSION = "v0.5.37"

def sidebar() -> str:
    out = ['<aside class="sidebar">']
    for section, items in NAV:
        out.append(f'  <h4>{section}</h4>')
        out.append('  <ul>')
        for href, label in items:
            out.append(f'    <li><a href="{href}">{label}</a></li>')
        out.append('  </ul>')
    out.append('</aside>')
    return "\n".join(out)

SHELL = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} · keyhog</title>
  <meta name="description" content="{description}">
  <link rel="stylesheet" href="css/style.css">
{extra_head}</head>
<body>
<header class="site">
  <a href="index.html" class="brand">
    <span class="mark">k</span>
    keyhog
    <span class="v">{version}</span>
  </a>
  <nav class="top">
    <a href="detectors.html">Detectors</a>
    <a href="ci.html">CI</a>
    <a href="api.html">API</a>
    <a href="https://github.com/santhsecurity/keyhog" class="gh">GitHub →</a>
  </nav>
</header>

<div class="layout">
{sidebar}

<main class="content">
<article{article_attrs}>
{content}
</article>
</main>
</div>

<footer class="site">
  <div class="left">
    <strong>keyhog</strong> · secret scanner by
    <a href="https://github.com/santhsecurity">santhsecurity</a>. MIT licensed.
  </div>
  <div class="right">
    <a href="https://github.com/santhsecurity/keyhog">GitHub</a>
    <a href="https://crates.io/crates/keyhog">crates.io</a>
    <a href="https://github.com/santhsecurity/keyhog/issues">Issues</a>
    <a href="https://github.com/santhsecurity/keyhog/blob/main/CHANGELOG.md">Changelog</a>
  </div>
</footer>

<script src="js/nav.js" defer></script>
{extra_scripts}</body>
</html>
"""

HEADER_RE = re.compile(r"^\s*(\w+)\s*=\s*\"(.*?)\"\s*$")

def parse_fragment(path: Path) -> dict:
    text = path.read_text()
    if "---" not in text:
        return {"title": path.stem, "description": "", "content": text, "article_attrs": "", "extra_head": "", "extra_scripts": ""}
    head, _, body = text.partition("---")
    meta = {"title": path.stem, "description": "", "article_attrs": "", "extra_head": "", "extra_scripts": ""}
    for line in head.strip().splitlines():
        m = HEADER_RE.match(line)
        if m:
            meta[m.group(1)] = m.group(2)
    meta["content"] = body.strip()
    return meta

def main() -> int:
    if not PAGES.exists():
        print(f"no pages/ directory at {PAGES}", file=sys.stderr)
        return 1
    rendered = 0
    for frag in sorted(PAGES.glob("*.html")):
        meta = parse_fragment(frag)
        html = SHELL.format(
            title       = meta["title"],
            description = meta["description"],
            sidebar     = sidebar(),
            version     = VERSION,
            content     = meta["content"],
            article_attrs = (" " + meta["article_attrs"]) if meta.get("article_attrs") else "",
            extra_head  = meta.get("extra_head", ""),
            extra_scripts = meta.get("extra_scripts", ""),
        )
        out_path = ROOT / frag.name
        if out_path.name == "index.html":
            # Landing page has bespoke layout — leave the hand-authored one alone.
            if out_path.exists() and "<section class=\"hero\">" in out_path.read_text():
                continue
        out_path.write_text(html)
        rendered += 1
    print(f"rendered {rendered} pages")
    return 0

if __name__ == "__main__":
    sys.exit(main())
