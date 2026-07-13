"""KeyHog benchmark version freshness checks.

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
_COMMIT_RE = re.compile(r"(?m)^Commit:\s+([0-9a-f]{40}|unknown)\s*$")
_DETECTOR_SET_RE = re.compile(
    r"(?m)^Detector Set:\s+\d+\s+\((\d+-[0-9a-f]{16})\)\s*$"
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


def workspace_git_hash(repo_root: pathlib.Path = _REPO_ROOT) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    value = proc.stdout.strip()
    if proc.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise KeyhogVersionError(
            f"cannot resolve the workspace git commit for benchmark freshness: "
            f"exit={proc.returncode}, output={(proc.stdout + proc.stderr).strip()!r}"
        )
    return value


def workspace_detector_digest(repo_root: pathlib.Path = _REPO_ROOT) -> str:
    detector_dir = repo_root / "detectors"
    try:
        paths = sorted(detector_dir.glob("*.toml"), key=lambda path: path.name)
        if not paths:
            raise KeyhogVersionError(
                f"{detector_dir} contains no detector TOMLs; cannot validate benchmark binary"
            )
        value = 0xCBF29CE484222325
        for path in paths:
            for payload in (path.name.encode(), b"\0", path.read_bytes(), b"\0"):
                for byte in payload:
                    value ^= byte
                    value = (value * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
    except OSError as exc:
        raise KeyhogVersionError(
            f"cannot compute the detector digest from {detector_dir}: {exc}"
        ) from exc
    return f"{len(paths)}-{value:016x}"


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
    commit_match = _COMMIT_RE.search(output)
    if commit_match is None:
        raise KeyhogVersionError(
            f"keyhog binary {binary!r} does not report a Commit line; rebuild it"
        )
    expected_commit = workspace_git_hash()
    if commit_match.group(1) != expected_commit:
        raise KeyhogVersionError(
            f"stale keyhog binary {binary!r}: commit={commit_match.group(1)}, "
            f"workspace={expected_commit}; rebuild the candidate before benchmarking"
        )
    detector_match = _DETECTOR_SET_RE.search(output)
    if detector_match is None:
        raise KeyhogVersionError(
            f"keyhog binary {binary!r} does not report a parseable Detector Set digest; rebuild it"
        )
    expected_detectors = workspace_detector_digest()
    if detector_match.group(1) != expected_detectors:
        raise KeyhogVersionError(
            f"stale keyhog binary {binary!r}: detector_set={detector_match.group(1)}, "
            f"workspace={expected_detectors}; rebuild after detector TOML changes"
        )
