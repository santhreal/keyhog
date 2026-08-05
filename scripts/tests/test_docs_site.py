"""Behavioral regressions for GitHub Pages discovery metadata."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts import docs_site


class DocumentationSiteMetadataTests(unittest.TestCase):
    """Prove every published guide has one stable search and sharing identity."""

    def test_canonical_urls_preserve_book_routes(self) -> None:
        """Search engines must resolve the book root, chapters, and nested indexes exactly."""
        self.assertEqual(docs_site.canonical_url(Path("index.html")), docs_site.SITE_ROOT)
        self.assertEqual(
            docs_site.canonical_url(Path("guides/deep-recovery.html")),
            docs_site.SITE_ROOT + "guides/deep-recovery.html",
        )
        self.assertEqual(
            docs_site.canonical_url(Path("reference/index.html")),
            docs_site.SITE_ROOT + "reference/",
        )

    def test_metadata_contains_exact_canonical_social_and_structured_identity(self) -> None:
        """A shared guide must identify the same URL and title to crawlers and social clients."""
        source = "<html><head><title>Scan CI &amp; Git - KeyHog</title></head><body></body></html>"

        updated = docs_site.enhance_html(source, Path("workflows/ci.html"))

        canonical = docs_site.SITE_ROOT + "workflows/ci.html"
        self.assertEqual(updated.count('rel="canonical"'), 1)
        self.assertIn(f'<link rel="canonical" href="{canonical}">', updated)
        self.assertIn('<meta property="og:title" content="Scan CI &amp; Git - KeyHog">', updated)
        self.assertIn(f'"url":"{canonical}"', updated)
        self.assertIn('"codeRepository":"https://github.com/santhreal/keyhog"', updated)
        self.assertIn('"keywords":["secret scanner","secret scanning"', updated)
        self.assertIn('"runtimePlatform":["Linux","macOS","Windows"]', updated)
        self.assertIn(
            '<meta property="og:image" content="https://santh.dev/og-keyhog-v0-5-34.png">',
            updated,
        )

    def test_metadata_generation_is_idempotent(self) -> None:
        """Repeated docs builds must replace generated metadata instead of duplicating it."""
        source = "<html><head><title>Install - KeyHog</title></head><body></body></html>"
        first = docs_site.enhance_html(source, Path("install.html"))

        second = docs_site.enhance_html(first, Path("install.html"))

        self.assertEqual(first, second)
        self.assertEqual(second.count("KEYHOG:SEO:BEGIN"), 1)
        self.assertEqual(second.count('property="og:url"'), 1)

    def test_missing_or_ambiguous_head_fails_closed(self) -> None:
        """A malformed mdBook template must not publish a partially enhanced site."""
        with self.assertRaisesRegex(docs_site.SiteMetadataError, "no HTML title"):
            docs_site.enhance_html("<html><head></head></html>", Path("broken.html"))
        with self.assertRaisesRegex(docs_site.SiteMetadataError, "exactly one"):
            docs_site.enhance_html("<title>Broken</title>", Path("broken.html"))

    def test_site_build_excludes_utility_pages_and_writes_exact_discovery_files(self) -> None:
        """The sitemap must list reader guides while excluding print and error utility pages."""
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            (site / "guides").mkdir()
            template = "<html><head><title>{}</title></head><body></body></html>"
            (site / "index.html").write_text(template.format("KeyHog"))
            (site / "guides" / "mass.html").write_text(template.format("Mass scanning"))
            (site / "print.html").write_text(template.format("Print"))
            (site / "404.html").write_text(template.format("Missing"))
            (site / "toc.html").write_text("<ol><li>Utility navigation</li></ol>")

            count = docs_site.build_site_metadata(site)

            self.assertEqual(count, 2)
            self.assertEqual(
                (site / "robots.txt").read_text(),
                "User-agent: *\nAllow: /keyhog/\n"
                f"Sitemap: {docs_site.SITE_ROOT}sitemap.xml\n",
            )
            sitemap = (site / "sitemap.xml").read_text()
            self.assertIn(f"<loc>{docs_site.SITE_ROOT}</loc>", sitemap)
            self.assertIn(f"<loc>{docs_site.SITE_ROOT}guides/mass.html</loc>", sitemap)
            self.assertNotIn("print.html", sitemap)
            self.assertNotIn("404.html", sitemap)
            self.assertNotIn("toc.html", sitemap)
            self.assertNotIn("KEYHOG:SEO", (site / "print.html").read_text())
            self.assertNotIn("KEYHOG:SEO", (site / "toc.html").read_text())


if __name__ == "__main__":
    unittest.main()
