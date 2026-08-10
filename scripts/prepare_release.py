#!/usr/bin/env python3
"""Prepare one KeyHog release from validated change fragments."""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts.bump_doc_versions import VersionBumpError, bump_markdown
except ModuleNotFoundError:
    from bump_doc_versions import VersionBumpError, bump_markdown


CATEGORIES = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security")
# Keep a Changelog has no Performance heading. Accept it in fragments and publish
# under Changed so the 58+ already-committed notes can release without a rewrite.
CATEGORY_ALIASES = {
    "Performance": "Changed",
    "Documentation": "Changed",
}
CRATE_CHANGELOGS = {
    "cli": Path("crates/cli/CHANGELOG.md"),
    "core": Path("crates/core/CHANGELOG.md"),
    "scanner": Path("crates/scanner/CHANGELOG.md"),
    "profile": Path("crates/profile/CHANGELOG.md"),
    "sources": Path("crates/sources/CHANGELOG.md"),
    "verifier": Path("crates/verifier/CHANGELOG.md"),
}
VERSIONED_TEXT_PATHS = (
    Path("README.md"),
    Path("PUBLISHING.md"),
    Path(".github/actions/keyhog/README.md"),
    Path(".github/workflows/action-e2e.yml"),
    # Both published Action entrypoints state the minimum version they install,
    # and a contract test requires them to stay byte-identical. Neither was in
    # this list, so both sat on v0.5.50 through two releases and
    # `action_examples_and_hosted_release_default_follow_workspace_version`
    # failed as soon as that suite ran.
    Path("action.yml"),
    Path(".github/actions/keyhog/action.yml"),
)
_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
_FRAGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]*\.toml$")


class PrepareError(ValueError):
    """The working tree cannot be transformed into a coherent release."""


@dataclass(frozen=True)
class Fragment:
    """One operator-visible change and the crates that own it."""

    path: Path
    category: str
    summary: str
    crates: tuple[str, ...]
    synthetic: bool = False


def parse_version(value: str) -> tuple[int, int, int]:
    """Parse canonical stable SemVer used by the release workflow."""
    match = _VERSION_RE.fullmatch(value)
    if match is None:
        raise PrepareError(f"invalid version {value!r}; expected canonical X.Y.Z")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def load_fragments(directory: Path) -> list[Fragment]:
    """Load deterministic, strictly shaped release change fragments.

    An empty ``crates`` list means repository scope: the note belongs in the
    root changelog and in no crate changelog. README evidence, the benchmark
    harness and CI are real user-visible changes with no crate behind them, and
    requiring at least one crate forced them to be filed against a crate they
    never touched, which is worse than not listing them.
    """
    if not directory.is_dir():
        raise PrepareError(f"change fragment directory does not exist: {directory}")
    fragments: list[Fragment] = []
    summaries: set[str] = set()
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.name == ".gitkeep":
            continue
        if not path.is_file() or not _FRAGMENT_RE.fullmatch(path.name):
            raise PrepareError(f"unexpected change fragment path: {path}")
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise PrepareError(f"cannot parse {path}: {error}") from error
        if set(data) != {"category", "summary", "crates"}:
            raise PrepareError(
                f"{path} must contain exactly category, summary, and crates"
            )
        category = data["category"]
        summary = data["summary"]
        crates = data["crates"]
        if not isinstance(category, str):
            raise PrepareError(f"{path} category must be a string")
        category = CATEGORY_ALIASES.get(category, category)
        if category not in CATEGORIES:
            raise PrepareError(f"{path} has unsupported category {category!r}")
        if not isinstance(summary, str) or not summary.strip() or "\n" in summary:
            raise PrepareError(f"{path} summary must be one non-empty line")
        summary = summary.strip()
        if summary.startswith("-") or summary.casefold() in summaries:
            raise PrepareError(f"{path} summary is a duplicate or Markdown bullet")
        summaries.add(summary.casefold())
        if (
            not isinstance(crates, list)
            or any(not isinstance(crate, str) or crate not in CRATE_CHANGELOGS for crate in crates)
            or len(set(crates)) != len(crates)
        ):
            raise PrepareError(
                f"{path} crates must be a unique subset of {sorted(CRATE_CHANGELOGS)}, "
                "or empty for a repository-scope change"
            )
        fragments.append(Fragment(path, category, summary, tuple(sorted(crates))))
    return fragments


def complete_fragment_coverage(
    fragments: list[Fragment], fallback_summary: str | None
) -> list[Fragment]:
    """Add one automatic note for crates not covered by authored fragments."""
    covered = {crate for fragment in fragments for crate in fragment.crates}
    missing = tuple(sorted(set(CRATE_CHANGELOGS) - covered))
    if not missing:
        return fragments
    summary = (fallback_summary or "").strip()
    if not summary or "\n" in summary:
        raise PrepareError(
            "automatic release summary must be one non-empty line when fragments "
            f"do not cover {list(missing)}"
        )
    if summary.startswith("-"):
        summary = summary.lstrip("-").strip()
    if not summary:
        raise PrepareError("automatic release summary must contain text")
    if any(fragment.summary.casefold() == summary.casefold() for fragment in fragments):
        summary = f"{summary} (workspace release)"
    return [
        *fragments,
        Fragment(
            Path("changes/.automatic.toml"),
            "Changed",
            summary,
            missing,
            synthetic=True,
        ),
    ]


def render_section(
    version: str, release_date: str, fragments: list[Fragment], crate: str | None = None
) -> str:
    """Render one root or crate changelog section in canonical order."""
    selected = [item for item in fragments if crate is None or crate in item.crates]
    heading = f"## [{version}] - {release_date}" if crate is None else f"## {version} - {release_date}"
    lines = [heading, ""]
    for category in CATEGORIES:
        entries = [item.summary for item in selected if item.category == category]
        if not entries:
            continue
        if crate is None:
            lines.extend((f"### {category}", ""))
        lines.extend(f"- {entry}" for entry in entries)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n\n"


def insert_release(changelog: str, section: str) -> str:
    """Insert a release after the changelog preamble and reject stale drafts."""
    if re.search(r"^## \[?Unreleased\]?\s*$", changelog, re.MULTILINE):
        raise PrepareError("changelog contains a hand-maintained Unreleased section")
    first_release = re.search(r"^## ", changelog, re.MULTILINE)
    if first_release is None:
        raise PrepareError("changelog has no existing release heading")
    return changelog[: first_release.start()] + section + changelog[first_release.start() :]


def bump_manifest(text: str, current: str, next_version: str) -> str:
    """Update the workspace version and every exact internal dependency pin."""
    workspace, workspace_count = re.subn(
        rf'^version = "{re.escape(current)}"$',
        f'version = "{next_version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    updated, pin_count = re.subn(
        rf'={re.escape(current)}"', f'={next_version}"', workspace
    )
    if workspace_count != 1 or pin_count != 5:
        raise PrepareError(
            "Cargo.toml must contain one workspace version and five exact internal pins"
        )
    return updated


def bump_lockfile(text: str, current: str, next_version: str) -> str:
    """Update exactly the six KeyHog workspace packages in Cargo.lock."""
    workspace = {
        "keyhog",
        "keyhog-core",
        "keyhog-profile",
        "keyhog-scanner",
        "keyhog-sources",
        "keyhog-verifier",
    }
    lines = text.splitlines(keepends=True)
    package: str | None = None
    updated: set[str] = set()
    for index, line in enumerate(lines):
        if line == "[[package]]\n":
            package = None
        elif line.startswith('name = "') and line.endswith('"\n'):
            package = line[len('name = "') : -2]
        elif package in workspace and line == f'version = "{current}"\n':
            lines[index] = f'version = "{next_version}"\n'
            updated.add(package)
    if updated != workspace:
        raise PrepareError(
            f"Cargo.lock workspace versions do not match {current}: {sorted(workspace - updated)}"
        )
    return "".join(lines)

def bump_versioned_texts(root: Path, current: str, next_version: str) -> dict[Path, str]:
    """Update operator-facing version pins while preserving benchmark evidence."""
    candidates = [root / relative for relative in VERSIONED_TEXT_PATHS]
    docs = root / "docs" / "src"
    if docs.is_dir():
        candidates.extend(sorted(docs.rglob("*.md")))
    replacements: dict[Path, str] = {}
    for path in candidates:
        if not path.is_file():
            continue
        try:
            replacements[path] = bump_markdown(
                path.read_text(encoding="utf-8"), current, next_version
            )
        except VersionBumpError as error:
            if str(error) == f"document does not contain canonical pin {current}":
                continue
            raise PrepareError(f"{path.relative_to(root)}: {error}") from error
    return replacements


def prepare(
    root: Path,
    version: str,
    release_date: str,
    apply: bool,
    fallback_summary: str | None = None,
) -> list[Path]:
    """Validate and optionally apply the complete release preparation transaction."""
    parse_version(version)
    try:
        dt.date.fromisoformat(release_date)
    except ValueError as error:
        raise PrepareError(f"invalid release date {release_date!r}; expected YYYY-MM-DD") from error
    manifest = root / "Cargo.toml"
    current_match = re.search(
        r'^version = "([^"]+)"$', manifest.read_text(encoding="utf-8"), re.MULTILINE
    )
    if current_match is None:
        raise PrepareError("Cargo.toml has no workspace version")
    current = current_match.group(1)
    if parse_version(version) <= parse_version(current):
        raise PrepareError(f"release version {version} must be newer than {current}")
    fragments = complete_fragment_coverage(
        load_fragments(root / "changes"), fallback_summary
    )

    replacements: dict[Path, str] = {}
    manifest_text = manifest.read_text(encoding="utf-8")
    replacements[manifest] = bump_manifest(manifest_text, current, version)
    lockfile = root / "Cargo.lock"
    replacements[lockfile] = bump_lockfile(
        lockfile.read_text(encoding="utf-8"), current, version
    )
    root_changelog = root / "CHANGELOG.md"
    replacements[root_changelog] = insert_release(
        root_changelog.read_text(encoding="utf-8"),
        render_section(version, release_date, fragments),
    )
    for crate, relative in CRATE_CHANGELOGS.items():
        path = root / relative
        replacements[path] = insert_release(
            path.read_text(encoding="utf-8"),
            render_section(version, release_date, fragments, crate),
        )
    replacements.update(bump_versioned_texts(root, current, version))

    changed = sorted(replacements, key=lambda path: str(path.relative_to(root)))
    if apply:
        temporary: list[tuple[Path, Path]] = []
        try:
            for path in changed:
                tmp = path.with_name(path.name + ".release-prepare-tmp")
                tmp.write_text(replacements[path], encoding="utf-8")
                os.chmod(tmp, path.stat().st_mode)
                temporary.append((path, tmp))
            for path, tmp in temporary:
                os.replace(tmp, path)
            for fragment in fragments:
                if not fragment.synthetic:
                    fragment.path.unlink()
        finally:
            for _path, tmp in temporary:
                tmp.unlink(missing_ok=True)
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate or apply one deterministic KeyHog release preparation."
    )
    parser.add_argument("--version", required=True, help="next stable version, without v")
    parser.add_argument("--date", default=dt.datetime.now(dt.UTC).date().isoformat())
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--fallback-summary",
        help="one-line automatic note for crates not covered by change fragments",
    )
    parser.add_argument(
        "--apply", action="store_true", help="write validated updates and consume fragments"
    )
    args = parser.parse_args()
    try:
        changed = prepare(
            args.root.resolve(),
            args.version,
            args.date,
            args.apply,
            args.fallback_summary,
        )
    except (OSError, PrepareError) as error:
        parser.error(str(error))
    mode = "prepared" if args.apply else "validated"
    print(f"{mode} v{args.version}: {len(changed)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
