"""KeyHog benchmark version freshness checks.

Benchmark gates may consume existing result JSONs or resolve a release binary
from the cargo target directory. Both are useful only when they match the
workspace version being gated; otherwise a stale binary/result can turn a
regression into a false green.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import subprocess
import tomllib

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SEMVER_RE = re.compile(
    r"(?<![0-9A-Za-z])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)"
)
_COMMIT_RE = re.compile(r"(?m)^Commit:\s+([0-9a-f]{40}(?:[0-9a-f]{24})?|unknown)\s*$")
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
    if proc.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", value):
        raise KeyhogVersionError(
            f"cannot resolve the workspace git commit for benchmark freshness: "
            f"exit={proc.returncode}, output={(proc.stdout + proc.stderr).strip()!r}"
        )
    return value


def assert_workspace_tracked_tree_clean(repo_root: pathlib.Path = _REPO_ROOT) -> None:
    """Require every tracked workspace byte to match HEAD for release evidence."""
    try:
        proc = subprocess.run(
            [
                "git", "-C", str(repo_root), "status", "--porcelain=v1", "-z",
                "--untracked-files=no", "--ignore-submodules=none",
            ],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeyhogVersionError(
            f"cannot inspect tracked workspace state for benchmark freshness: {exc}"
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stdout + proc.stderr)[:500]
        raise KeyhogVersionError(
            "cannot inspect tracked workspace state for benchmark freshness: "
            f"git exited {proc.returncode}, output={detail!r}"
        )
    if proc.stdout:
        raise KeyhogVersionError(
            "the tracked KeyHog workspace has uncommitted changes, so the candidate "
            "binary cannot prove it represents the current source. Commit the changes, "
            "rebuild the release candidate, and rerun the benchmark"
        )
    try:
        flags = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "-v", "-z"],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeyhogVersionError(
            f"cannot inspect tracked workspace index flags for benchmark freshness: {exc}"
        ) from exc
    if flags.returncode != 0:
        detail = (flags.stdout + flags.stderr)[:500]
        raise KeyhogVersionError(
            "cannot inspect tracked workspace index flags for benchmark freshness: "
            f"git exited {flags.returncode}, output={detail!r}"
        )
    hidden = [
        entry for entry in flags.stdout.split(b"\0")
        if entry and (entry[:1] == b"S" or entry[:1].islower())
    ]
    if hidden:
        raise KeyhogVersionError(
            "the tracked KeyHog workspace uses assume-unchanged or skip-worktree "
            "index flags, so source freshness cannot be proven. Clear those flags, "
            "rebuild the release candidate, and rerun the benchmark"
        )


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


def detector_corpus_sha256(detector_dir: pathlib.Path) -> str:
    """Digest the exact detector filenames and bytes consumed by a run."""
    try:
        paths = sorted(detector_dir.glob("*.toml"), key=lambda path: os.fsencode(path.name))
        if not paths:
            raise KeyhogVersionError(
                f"{detector_dir} contains no detector TOMLs; cannot bind benchmark provenance"
            )
        digest = hashlib.sha256()
        for path in paths:
            name = os.fsencode(path.name)
            payload = path.read_bytes()
            digest.update(len(name).to_bytes(8, "big"))
            digest.update(name)
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
    except OSError as exc:
        raise KeyhogVersionError(
            f"cannot compute the detector corpus SHA-256 from {detector_dir}: {exc}"
        ) from exc
    return digest.hexdigest()


def workspace_detector_corpus_sha256(repo_root: pathlib.Path = _REPO_ROOT) -> str:
    return detector_corpus_sha256(repo_root / "detectors")


def assert_reported_identity_matches_workspace(raw: str, *, what: str) -> None:
    assert_version_matches_workspace(raw, what=what)
    commit_match = _COMMIT_RE.search(raw)
    if commit_match is None:
        raise KeyhogVersionError(f"{what} does not report a Commit line; rebuild or rerun it")
    expected_commit = workspace_git_hash()
    if commit_match.group(1) != expected_commit:
        raise KeyhogVersionError(
            f"stale {what}: commit={commit_match.group(1)}, workspace={expected_commit}; "
            "rebuild or rerun the benchmark"
        )
    detector_match = _DETECTOR_SET_RE.search(raw)
    if detector_match is None:
        raise KeyhogVersionError(
            f"{what} does not report a parseable Detector Set digest; rebuild or rerun it"
        )
    expected_detectors = workspace_detector_digest()
    if detector_match.group(1) != expected_detectors:
        raise KeyhogVersionError(
            f"stale {what}: detector_set={detector_match.group(1)}, "
            f"workspace={expected_detectors}; rebuild after detector TOML changes"
        )


def assert_keyhog_binary_current(binary: str, *, pass_fds: tuple[int, ...] = ()) -> str:
    popen_kwargs = {"pass_fds": pass_fds} if pass_fds else {}
    proc = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        timeout=30,
        **popen_kwargs,
    )
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        raise KeyhogVersionError(
            f"keyhog binary {binary!r} --version failed with exit {proc.returncode}: "
            f"{output}"
        )
    assert_reported_identity_matches_workspace(output, what=f"keyhog binary {binary!r}")
    assert_workspace_tracked_tree_clean()
    return output
