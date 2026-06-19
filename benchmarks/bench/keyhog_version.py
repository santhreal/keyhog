"""Keyhog benchmark version freshness checks.

Benchmark gates may consume existing result JSONs or resolve a release binary
from the cargo target directory. Both are useful only when they match the
workspace version being gated; otherwise a stale binary/result can turn a
regression into a false green.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import tomllib

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SEMVER_RE = re.compile(
    r"(?<![0-9A-Za-z])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)"
)


class KeyhogVersionError(Exception):
    """A benchmark input cannot prove it belongs to this workspace version."""


def workspace_keyhog_version(repo_root: pathlib.Path = _REPO_ROOT) -> str:
    cargo = repo_root / "Cargo.toml"
    try:
        data = tomllib.loads(cargo.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise KeyhogVersionError(
            f"cannot read current workspace version from {cargo}: {exc}"
        ) from exc
    version = data.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not version.strip():
        raise KeyhogVersionError(f"{cargo} has no [workspace.package] version")
    return version.strip()


def scanner_semver(raw: str) -> str | None:
    match = _SEMVER_RE.search(raw)
    return match.group(1) if match else None


def assert_version_matches_workspace(raw_version: str, *, what: str) -> None:
    expected = workspace_keyhog_version()
    observed = scanner_semver(raw_version)
    if observed is None:
        raise KeyhogVersionError(
            f"{what} does not record a parseable semver "
            f"(version={raw_version!r}); rebuild or rerun the benchmark"
        )
    if observed != expected:
        raise KeyhogVersionError(
            f"stale {what}: version={raw_version!r} parsed as {observed}, "
            f"but workspace version is {expected}; rebuild keyhog and rerun the benchmark"
        )


def assert_keyhog_binary_current(binary: str) -> None:
    proc = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        raise KeyhogVersionError(
            f"keyhog binary {binary!r} --version failed with exit {proc.returncode}: "
            f"{output}"
        )
    assert_version_matches_workspace(output, what=f"keyhog binary {binary!r}")
