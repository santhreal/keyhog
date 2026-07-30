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
CRATE_CHANGELOGS = {
    "cli": Path("crates/cli/CHANGELOG.md"),
    "core": Path("crates/core/CHANGELOG.md"),
    "scanner": Path("crates/scanner/CHANGELOG.md"),
    "sources": Path("crates/sources/CHANGELOG.md"),
    "verifier": Path("crates/verifier/CHANGELOG.md"),
}
VERSIONED_FILES = (
    Path("README.md"),
    Path("action.yml"),
    Path(".github/actions/keyhog/action.yml"),
    Path(".github/workflows/action-e2e.yml"),
    Path(".github/actions/keyhog/README.md"),
    Path("docs/src/install.md"),
    Path("docs/src/introduction.md"),
    Path("docs/src/first-scan.md"),
    Path("docs/src/reference/exit-codes.md"),
    Path("docs/assets/keyhog-banner.svg"),
    Path("docs/src/reference/oob-verification.md"),
    Path("docs/src/verification.md"),
    Path("docs/src/workflows/ci.md"),
    Path("docs/src/workflows/precommit.md"),
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


def parse_version(value: str) -> tuple[int, int, int]:
    """Parse canonical stable SemVer used by the release workflow."""
    match = _VERSION_RE.fullmatch(value)
    if match is None:
        raise PrepareError(f"invalid version {value!r}; expected canonical X.Y.Z")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def load_fragments(directory: Path) -> list[Fragment]:
    """Load deterministic, strictly shaped release change fragments."""
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
            or not crates
            or any(not isinstance(crate, str) or crate not in CRATE_CHANGELOGS for crate in crates)
            or len(set(crates)) != len(crates)
        ):
            raise PrepareError(
                f"{path} crates must be a unique non-empty subset of {sorted(CRATE_CHANGELOGS)}"
            )
        fragments.append(Fragment(path, category, summary, tuple(sorted(crates))))
    if not fragments:
        raise PrepareError(f"no release change fragments found in {directory}")
    return fragments


def validate_crate_coverage(fragments: list[Fragment]) -> None:
    """Require a substantive owned note for every crate in the release chain."""
    covered = {crate for fragment in fragments for crate in fragment.crates}
    missing = sorted(set(CRATE_CHANGELOGS) - covered)
    if missing:
        raise PrepareError(
            f"release fragments must cover every published crate; missing {missing}"
        )


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
    if workspace_count != 1 or pin_count != 4:
        raise PrepareError(
            "Cargo.toml must contain one workspace version and four exact internal pins"
        )
    return updated


def bump_lockfile(text: str, current: str, next_version: str) -> str:
    """Update exactly the five KeyHog workspace packages in Cargo.lock."""
    workspace = {"keyhog", "keyhog-core", "keyhog-scanner", "keyhog-sources", "keyhog-verifier"}
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


def prepare(root: Path, version: str, release_date: str, apply: bool) -> list[Path]:
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
    fragments = load_fragments(root / "changes")
    validate_crate_coverage(fragments)

    replacements: dict[Path, str] = {}
    manifest_text = manifest.read_text(encoding="utf-8")
    replacements[manifest] = bump_manifest(manifest_text, current, version)
    lockfile = root / "Cargo.lock"
    replacements[lockfile] = bump_lockfile(
        lockfile.read_text(encoding="utf-8"), current, version
    )
    for relative in VERSIONED_FILES:
        path = root / relative
        try:
            replacements[path] = bump_markdown(
                path.read_text(encoding="utf-8"), current, version
            )
        except VersionBumpError as error:
            raise PrepareError(f"{relative}: {error}") from error
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
        "--apply", action="store_true", help="write validated updates and consume fragments"
    )
    args = parser.parse_args()
    try:
        changed = prepare(args.root.resolve(), args.version, args.date, args.apply)
    except (OSError, PrepareError) as error:
        parser.error(str(error))
    mode = "prepared" if args.apply else "validated"
    print(f"{mode} v{args.version}: {len(changed)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
