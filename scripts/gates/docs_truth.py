#!/usr/bin/env python3
"""Prove that the canonical mdBook documentation is complete and source-true."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.parse

REPO = pathlib.Path(__file__).resolve().parents[2]
DOCS = REPO / "docs" / "src"
LICENSE_DOCS = [REPO / "README.md", DOCS / "introduction.md", DOCS / "contributing.md"]

STALE_PATTERNS = [
    ("unsupported recall claim", re.compile(r"\b96\s*%")),
    ("unsupported recall delta", re.compile(r"\b33\s*%\s+more\b")),
    ("unsupported superlative", re.compile(r"fastest, most accurate", re.I)),
    ("startup hardware guess", re.compile(r"Auto-detects your hardware", re.I)),
    ("fallback-router claim", re.compile(r"(?:picks|routes scans to) the fastest backend", re.I)),
    ("retired benchmark path", re.compile(r"benchmark-harness/")),
    ("retired routing output", re.compile(r"routing matrix:")),
    ("duplicate website path", re.compile(r"(?:^|[(`\s])/?site/")),
]

MARKDOWN_LINK = re.compile(
    r"!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))(?:\s+['\"][^)]*['\"])?\)"
)
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$")
EXPLICIT_ANCHOR = re.compile(
    r"<(?:a\s+(?:[^>]*\s)?(?:id|name)|[^>]+\s+id)=[\"']([^\"']+)[\"']", re.I
)
HOSTED_TOKEN_ARG = re.compile(r"--(?:github|gitlab|bitbucket)-token\b")


def prose_lines(text: str):
    """Yield non-fenced Markdown lines with their one-based line numbers."""
    fence: str | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        marker = stripped[:3]
        if marker in {"```", "~~~"}:
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            continue
        if fence is None:
            yield lineno, line


def fenced_lines(text: str):
    """Yield Markdown code-fence content with one-based line numbers."""
    fence: str | None = None
    for lineno, line in enumerate(text.splitlines(), 1):
        marker = line.lstrip()[:3]
        if marker in {"```", "~~~"}:
            if fence is None:
                fence = marker
            elif marker == fence:
                fence = None
            continue
        if fence is not None:
            yield lineno, line


def heading_slug(heading: str) -> str:
    """Match mdBook's lowercase, punctuation-stripping heading id shape."""
    text = re.sub(r"<[^>]+>", "", heading)
    text = re.sub(r"!?\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = text.replace("`", "").replace("*", "")
    return "".join(
        char.lower() if char.isalnum() or char in "_-" else "-" if char.isspace() else ""
        for char in text
    )


def page_anchors(path: pathlib.Path) -> set[str]:
    anchors: set[str] = set()
    occurrences: dict[str, int] = {}
    for _, line in prose_lines(path.read_text(errors="replace")):
        if match := HEADING.match(line):
            base = heading_slug(match.group(1))
            occurrence = occurrences.get(base, 0)
            occurrences[base] = occurrence + 1
            anchors.add(base if occurrence == 0 else f"{base}-{occurrence}")
        anchors.update(EXPLICIT_ANCHOR.findall(line))
    return anchors


def navigation_issues(paths: list[pathlib.Path]) -> list[str]:
    """Validate local Markdown targets and mdBook heading fragments."""
    issues: list[str] = []
    anchor_cache: dict[pathlib.Path, set[str]] = {}
    for source in paths:
        if source.suffix.lower() != ".md":
            continue
        for lineno, line in prose_lines(source.read_text(errors="replace")):
            for match in MARKDOWN_LINK.finditer(line):
                raw = match.group(1) or match.group(2)
                if not raw or raw.startswith(("http://", "https://", "mailto:", "data:")):
                    continue
                parsed = urllib.parse.urlsplit(raw)
                if parsed.scheme or parsed.netloc:
                    continue
                target = source if not parsed.path else (
                    source.parent / urllib.parse.unquote(parsed.path)
                ).resolve()
                rel = source.relative_to(REPO).as_posix()
                if not target.exists():
                    issues.append(f"{rel}:{lineno}: broken local link target {raw}")
                    continue
                fragment = urllib.parse.unquote(parsed.fragment)
                if fragment and target.suffix.lower() == ".md":
                    anchors = anchor_cache.setdefault(target, page_anchors(target))
                    if fragment not in anchors:
                        issues.append(
                            f"{rel}:{lineno}: missing anchor #{fragment} in "
                            f"{target.relative_to(REPO).as_posix()}"
                        )
    return issues


def workspace_version() -> str:
    cargo = tomllib.loads((REPO / "Cargo.toml").read_text())
    return f"v{cargo['workspace']['package']['version']}"


def workspace_license() -> str:
    cargo = tomllib.loads((REPO / "Cargo.toml").read_text())
    return cargo["workspace"]["package"]["license"]


def detector_count() -> int:
    return sum(1 for path in (REPO / "detectors").glob("*.toml") if path.is_file())


def canonical_paths() -> list[pathlib.Path]:
    paths = [REPO / "README.md", REPO / ".github" / "actions" / "keyhog" / "README.md"]
    paths.extend(sorted(DOCS.rglob("*.md")))
    paths.extend(sorted((REPO / "docs" / "assets").glob("*.svg")))
    return paths


def summary_targets() -> set[pathlib.Path]:
    summary = (DOCS / "SUMMARY.md").read_text()
    targets: set[pathlib.Path] = set()
    for target in re.findall(r"\]\(([^)#]+\.md)(?:#[^)]+)?\)", summary):
        targets.add((DOCS / target).resolve())
    return targets


def security_reporting_issues() -> list[str]:
    """Keep one visible security policy with private-first reporting."""
    issues: list[str] = []
    policy = (REPO / "SECURITY.md").read_text(errors="replace")
    page = (DOCS / "security.md").read_text(errors="replace")
    summary = (DOCS / "SUMMARY.md").read_text(errors="replace")
    workflow = (REPO / ".github" / "workflows" / "docs.yml").read_text(errors="replace")

    if page.strip() != "{{#include ../../SECURITY.md}}":
        issues.append("docs/src/security.md: must include the canonical root SECURITY.md verbatim")
    if "[Security](./security.md)" not in summary:
        issues.append("docs/src/SUMMARY.md: missing visible Security navigation entry")

    private_url = "https://github.com/santhreal/keyhog/security/advisories/new"
    email = "security@santh.dev"
    private_at = policy.find(private_url)
    email_at = policy.find(email)
    if private_at < 0 or email_at < 0 or private_at >= email_at:
        issues.append(
            "SECURITY.md: reporting must list GitHub private vulnerability reporting before the email fallback"
        )
    if "PGP encryption is not required" not in policy:
        issues.append("SECURITY.md: email fallback must state that PGP is not required")
    if "Do not open a public issue" not in policy:
        issues.append("SECURITY.md: must prohibit public vulnerability issues")
    if workflow.count("- 'SECURITY.md'") != 2:
        issues.append(
            ".github/workflows/docs.yml: SECURITY.md must rebuild docs on pushes and pull requests"
        )
    return issues


def truth_issues() -> list[str]:
    issues: list[str] = []
    expected_version = workspace_version()
    keyhog_series = ".".join(expected_version.split(".")[:2]) + "."
    expected_count = detector_count()
    expected_license = workspace_license()
    for path in canonical_paths():
        text = path.read_text(errors="replace")
        rel = path.relative_to(REPO).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            for version in re.findall(r"\bv\d+\.\d+\.\d+\b", line):
                if not version.startswith(keyhog_series):
                    continue
                if version != expected_version:
                    issues.append(f"{rel}:{lineno}: stale version {version}; expected {expected_version}")
            for count in re.findall(r"\b(\d+)\s+detectors\b", line, re.I):
                if int(count) != expected_count:
                    issues.append(
                        f"{rel}:{lineno}: stale detector count {count}; expected {expected_count}"
                    )
            for label, pattern in STALE_PATTERNS:
                if pattern.search(line):
                    issues.append(f"{rel}:{lineno}: {label}: {line.strip()}")
        for lineno, line in fenced_lines(text):
            if HOSTED_TOKEN_ARG.search(line):
                issues.append(
                    f"{rel}:{lineno}: hosted-source token must use its dedicated environment variable"
                )

    for path in LICENSE_DOCS:
        text = path.read_text(errors="replace")
        rel = path.relative_to(REPO).as_posix()
        canonical = f"License: {expected_license}."
        if canonical not in text.splitlines():
            issues.append(f"{rel}: missing canonical license sentence {canonical}")
    for name in ("LICENSE-MIT", "LICENSE-APACHE"):
        if not (REPO / name).is_file():
            issues.append(f"{name}: license file required by {expected_license} is missing")

    summary = summary_targets()
    for page in sorted(DOCS.rglob("*.md")):
        if page.name == "SUMMARY.md":
            continue
        if page.resolve() not in summary:
            issues.append(f"{page.relative_to(REPO)}: orphaned from docs/src/SUMMARY.md")

    tracked = subprocess.run(
        ["git", "ls-files", "site", "docs/book"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    for path in tracked:
        issues.append(f"{path}: duplicate/generated documentation must not be tracked")
    issues.extend(security_reporting_issues())
    issues.extend(navigation_issues(canonical_paths()))
    return issues


def self_test() -> int:
    expected = workspace_version()
    count = detector_count()
    bad = f"site/config.html keyhog v0.0.0 with {count + 1} detectors picks the fastest backend"
    stale_detected = (
        bool(STALE_PATTERNS[-1][1].search(bad))
        and bool(STALE_PATTERNS[4][1].search(bad))
        and "v0.0.0" != expected
        and count + 1 != count
    )
    slug_detected = all(
        (
            heading_slug("The pipeline: bytes → finding")
            == "the-pipeline-bytes--finding",
            heading_slug("Stage 4 - post-process") == "stage-4---post-process",
            heading_slug("Combining with `--verify`") == "combining-with---verify",
        )
    )
    with tempfile.TemporaryDirectory(prefix=".docs-truth-selftest-", dir=REPO) as raw:
        root = pathlib.Path(raw)
        source = root / "index.md"
        target = root / "target.md"
        source.write_text(
            "[valid](target.md#present) [missing](absent.md) "
            "[bad anchor](target.md#absent)\n"
        )
        target.write_text("# Present\n")
        navigation = navigation_issues([source, target])
    navigation_detected = (
        len(navigation) == 2
        and any("broken local link target absent.md" in issue for issue in navigation)
        and any("missing anchor #absent" in issue for issue in navigation)
    )
    canonical_license = f"License: {workspace_license()}."
    license_detected = canonical_license == "License: MIT OR Apache-2.0." and (
        canonical_license in "License: MIT OR Apache-2.0.".splitlines()
        and canonical_license not in "License: MIT.".splitlines()
    )
    token_arg_detected = any(
        HOSTED_TOKEN_ARG.search(line)
        for _, line in fenced_lines("```bash\nkeyhog scan --github-token secret\n```\n")
    )
    detected = (
        stale_detected
        and slug_detected
        and navigation_detected
        and license_detected
        and token_arg_detected
    )
    print("self-test PASS" if detected else "self-test FAIL", file=sys.stderr)
    return 0 if detected else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    issues = truth_issues()
    if issues:
        print(f"FAIL - {len(issues)} documentation truth issue(s):", file=sys.stderr)
        for issue in issues:
            print(f"  {issue}", file=sys.stderr)
        return 1
    print("OK - canonical mdBook documentation is complete and source-true.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
