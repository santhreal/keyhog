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
DETECTOR_CORPUS_MANIFEST_FILE = "corpus.toml"
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
BENCH_MARKER = re.compile(r"^<!-- BENCH:[^:]+:(start|end) -->$")


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


def detector_count(detectors_dir: pathlib.Path | None = None) -> int:
    """Count detector definitions, excluding the directory-level corpus manifest."""
    root = detectors_dir or REPO / "detectors"
    return sum(
        1
        for path in root.glob("*.toml")
        if path.is_file() and path.name != DETECTOR_CORPUS_MANIFEST_FILE
    )


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


def version_truth_issues(text: str, rel: str, expected_version: str) -> list[str]:
    """Reject stale operator claims while preserving measured benchmark identity."""
    issues: list[str] = []
    keyhog_series = ".".join(expected_version.split(".")[:2]) + "."
    inside_benchmark = False
    for lineno, line in enumerate(text.splitlines(), 1):
        marker = BENCH_MARKER.match(line)
        if marker:
            boundary = marker.group(1)
            if boundary == "start":
                if inside_benchmark:
                    issues.append(f"{rel}:{lineno}: nested benchmark start marker")
                inside_benchmark = True
            elif not inside_benchmark:
                issues.append(f"{rel}:{lineno}: benchmark end marker without start")
            else:
                inside_benchmark = False
            continue
        if inside_benchmark:
            continue
        for version in re.findall(r"\bv\d+\.\d+\.\d+\b", line):
            if version.startswith(keyhog_series) and version != expected_version:
                issues.append(
                    f"{rel}:{lineno}: stale version {version}; expected {expected_version}"
                )
    if inside_benchmark:
        issues.append(f"{rel}: benchmark start marker without end")
    return issues


def truth_issues() -> list[str]:
    issues: list[str] = []
    expected_version = workspace_version()
    issues.extend(corpus_claim_issues())
    expected_license = workspace_license()
    for path in canonical_paths():
        text = path.read_text(errors="replace")
        rel = path.relative_to(REPO).as_posix()
        issues.extend(version_truth_issues(text, rel, expected_version))
        for lineno, line in enumerate(text.splitlines(), 1):
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


def entropy_mode_counts(detectors_dir: pathlib.Path | None = None) -> dict[str, int]:
    """Count `entropy_mode` values, excluding the directory-level corpus manifest.

    Takes a directory so `--self-test` can prove the read against a synthetic
    corpus. Without that, the gate check and `--sync-counts` share one
    derivation, and a green gate would only mean the two agree with each other.
    """
    modes: dict[str, int] = {}
    pattern = re.compile(r'entropy_mode\s*=\s*"([a-z]+)"')
    root = detectors_dir or REPO / "detectors"
    for path in root.glob("*.toml"):
        if not path.is_file() or path.name == DETECTOR_CORPUS_MANIFEST_FILE:
            continue
        for mode in pattern.findall(path.read_text(errors="replace")):
            modes[mode] = modes.get(mode, 0) + 1
    return modes


def corpus_claims() -> list[tuple[str, re.Pattern[str], int, bool]]:
    """Every numeric docs claim the detector corpus owns.

    Each entry is a label, a pattern whose group 1 is the number, the value that
    number must equal, and whether the claim applies inside a code fence.
    `--sync-counts` rewrites group 1; the gate reports a mismatch. Adding a claim
    here makes it both checked and repairable, so a corpus change never leaves a
    stale number behind in prose, a sample envelope, or the banner art.

    Prose claims are exempt inside fences because a fence can hold real program
    output for a smaller corpus, such as `Loaded 1 detectors` from a
    single-detector custom directory. Sample-envelope field claims are the
    opposite: they only ever appear inside a fence, so they are checked there.
    """
    total = detector_count()
    entropy = entropy_mode_counts()
    return [
        (
            "detector count",
            # Explicit noun phrases only. A loose "N <word> detectors" match
            # rewrites unrelated prose such as "Phase-2 generic detectors".
            re.compile(
                r"\b(\d+)(?=\s+(?:service-specific\s+|embedded\s+|shipped\s+|"
                r"built-in\s+|loaded\s+|secret\s+)?detectors\b)",
                re.I,
            ),
            total,
            False,
        ),
        ("sample detector_count", re.compile(r'(?<="detector_count":\s)(\d+)'), total, True),
        (
            "sample detector_digest",
            re.compile(r'(?<="detector_digest":\s")(\d+)(?=-)'),
            total,
            True,
        ),
        (
            "entropy channels disabling ML",
            re.compile(r"\b(\d+)(?= of \d+ entropy channels disable ML)"),
            entropy.get("disabled", 0),
            False,
        ),
        (
            "entropy channel total",
            re.compile(r"(?<= of )(\d+)(?= entropy channels disable ML)"),
            total,
            False,
        ),
    ]


def claim_lines(text: str):
    """Yield `(lineno, line, rewritable, fenced)` for corpus-claim scanning.

    A benchmark panel records a measurement pinned to the binary and detector
    set it was taken with. Rewriting a count in there would falsify recorded
    evidence, so corpus claims never look inside one. `fenced` lets a claim opt
    out of code blocks, which hold sample output rather than live claims.
    """
    inside_bench = False
    inside_fence = False
    for lineno, line in enumerate(text.splitlines(), 1):
        marker = BENCH_MARKER.match(line)
        if marker:
            inside_bench = marker.group(1) == "start"
            yield lineno, line, False, inside_fence
            continue
        if line.lstrip().startswith("```"):
            inside_fence = not inside_fence
            yield lineno, line, False, True
            continue
        yield lineno, line, not inside_bench, inside_fence


def corpus_claim_issues() -> list[str]:
    issues: list[str] = []
    claims = corpus_claims()
    for path in canonical_paths():
        rel = path.relative_to(REPO).as_posix()
        for lineno, line, checked, fenced in claim_lines(
            path.read_text(errors="replace")
        ):
            if not checked:
                continue
            for label, pattern, expected, in_fence in claims:
                if fenced and not in_fence:
                    continue
                for found in pattern.findall(line):
                    if int(found) != expected:
                        issues.append(
                            f"{rel}:{lineno}: stale {label} {found}; expected {expected}"
                        )
    return issues


def sync_detector_counts() -> int:
    """Rewrite every corpus-owned number in canonical docs to the live value.

    A detector add or removal otherwise breaks this gate for every canonical
    page, the Action README, the sample envelopes, and the banner art at once,
    and each site has to be edited by hand. The corpus is the single source of
    truth, so make one command carry it everywhere the gate already checks.
    """
    claims = corpus_claims()
    superseded: set[str] = set()
    changed: dict[str, list[str]] = {}
    for path in canonical_paths():
        text = path.read_text(errors="replace")
        touched: list[str] = []
        lines: list[str] = []
        for _, line, rewritable, fenced in claim_lines(text):
            if rewritable:
                for label, pattern, expected, in_fence in claims:
                    if fenced and not in_fence:
                        continue
                    def replace(match: re.Match[str], expected: int = expected) -> str:
                        if match.group(1) != str(expected):
                            superseded.add(match.group(1))
                        return str(expected)

                    after = pattern.sub(replace, line)
                    if after != line:
                        touched.append(label)
                    line = after
            lines.append(line)
        updated = "\n".join(lines) + ("\n" if text.endswith("\n") else "")
        if updated != text:
            path.write_text(updated)
            changed[path.relative_to(REPO).as_posix()] = touched
    if changed:
        print(f"synced {len(changed)} file(s):")
        for rel, labels in changed.items():
            print(f"  {rel}: {', '.join(sorted(set(labels)))}")
    else:
        print("every corpus-owned number in canonical docs is already current.")
    if superseded:
        review = review_occurrences(superseded)
        print(
            f"\nreview: the superseded value(s) {', '.join(sorted(superseded))} "
            "still appear where no rule owns them."
        )
        for line in review:
            print(f"  {line}")
        if not review:
            print("  none")
    return 0


def review_occurrences(values: set[str]) -> list[str]:
    """Report standalone occurrences of a superseded count no rule rewrote."""
    hits: list[str] = []
    patterns = [(value, re.compile(rf"\b{re.escape(value)}\b")) for value in values]
    for path in canonical_paths():
        rel = path.relative_to(REPO).as_posix()
        for lineno, line in enumerate(
            path.read_text(errors="replace").splitlines(), 1
        ):
            for value, pattern in patterns:
                if pattern.search(line):
                    hits.append(f"{rel}:{lineno}: {value}: {line.strip()[:120]}")
    return hits


def self_test() -> int:
    """Prove this gate's own derivations, not just its agreement with itself.

    Do not delete these fixtures as redundant with a normal gate run. The gate
    check and `--sync-counts` call the SAME derivation functions, so a green
    gate proves the two agree, not that the number is right. And `--sync-counts`
    does not merely report: it WRITES corpus-derived numbers into README, every
    `docs/src` page, the Action README, and the banner art in one command. These
    fixtures are the only independent evidence standing between a bad derivation
    and a repository full of confidently wrong numbers that the check then
    confirms as correct.

    Every assertion here has been shown to fail under a deliberate defect, so
    none of it is untested ceremony. Removing the corpus-manifest exclusion from
    `entropy_mode_counts`, loosening the detector-count phrase back to
    `N <word> detectors` (which once rewrote "Phase-2 generic detectors" to
    "Phase-925"), dropping the `<!-- BENCH: -->` guard, and dropping code-fence
    tracking each turn this function red. If you change a derivation, re-run
    that mutation check rather than trusting a green.

    The claims most likely to be wrong are the inherited ones. A sentence that
    has been nearly right for a long time is more dangerous than a new mistake,
    because nobody feels responsible for re-checking it.
    """
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
    with tempfile.TemporaryDirectory(prefix=".docs-truth-detectors-", dir=REPO) as raw:
        detectors = pathlib.Path(raw)
        (detectors / "detector.toml").write_text(
            '[detector]\nml = { entropy_mode = "disabled" }\n'
        )
        (detectors / "owner.toml").write_text(
            '[detector]\nml = { entropy_mode = "authoritative" }\n'
        )
        # The manifest and non-TOML files must not contribute to either count.
        (detectors / DETECTOR_CORPUS_MANIFEST_FILE).write_text(
            '[corpus]\nentropy_mode = "disabled"\n'
        )
        (detectors / "ignored.txt").write_text('entropy_mode = "disabled"\n')
        detector_manifest_excluded = detector_count(detectors) == 2
        entropy_counts_derived = entropy_mode_counts(detectors) == {
            "disabled": 1,
            "authoritative": 1,
        }
    canonical_license = f"License: {workspace_license()}."
    license_detected = canonical_license == "License: MIT OR Apache-2.0." and (
        canonical_license in "License: MIT OR Apache-2.0.".splitlines()
        and canonical_license not in "License: MIT.".splitlines()
    )
    token_arg_detected = any(
        HOSTED_TOKEN_ARG.search(line)
        for _, line in fenced_lines("```bash\nkeyhog scan --github-token secret\n```\n")
    )
    count_pattern = next(
        pattern for label, pattern, *_ in corpus_claims() if label == "detector count"
    )
    count_phrases_detected = (
        count_pattern.findall("KeyHog compiles 923 detectors") == ["923"]
        and count_pattern.findall("**923 service-specific detectors**") == ["923"]
        and count_pattern.findall("923 embedded detectors") == ["923"]
        # Unrelated prose must never be rewritten as a corpus claim.
        and count_pattern.findall("Phase-2 generic detectors participate") == []
    )
    scanned = [
        (line, rewritable, fenced)
        for _, line, rewritable, fenced in claim_lines(
            "923 detectors\n"
            "<!-- BENCH:mirror:start -->\n"
            "923 detectors\n"
            "<!-- BENCH:mirror:end -->\n"
            "```text\n"
            "Loaded 1 detectors\n"
            "```\n"
            "923 detectors\n"
        )
    ]
    # A benchmark panel is never rewritable. Sample output inside a fence is
    # rewritable but marked fenced, so a prose-only claim skips it.
    bench_guarded = [
        line for line, rewritable, fenced in scanned if rewritable and not fenced
    ] == ["923 detectors", "923 detectors"]
    fence_marked = any(
        line == "Loaded 1 detectors" and fenced for line, _, fenced in scanned
    )

    detected = (
        stale_detected
        and slug_detected
        and navigation_detected
        and license_detected
        and token_arg_detected
        and detector_manifest_excluded
        and entropy_counts_derived
        and count_phrases_detected
        and bench_guarded
        and fence_marked
    )
    print("self-test PASS" if detected else "self-test FAIL", file=sys.stderr)
    return 0 if detected else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if "--sync-counts" in argv:
        return sync_detector_counts()
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
