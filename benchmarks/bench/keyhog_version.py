"""KeyHog benchmark version freshness checks.

Benchmark gates may consume existing result JSONs or resolve a release binary
from the cargo target directory. Both are useful only when they match the
workspace version being gated; otherwise a stale binary/result can turn a
regression into a false green.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tomllib

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_ALLOW_GENERATED_EVIDENCE_DIRTY_ENV = (
    "KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY"
)
_GENERATED_EVIDENCE_EXACT_PATHS = frozenset(
    {
        pathlib.PurePosixPath("README.md"),
        pathlib.PurePosixPath("metrics/stars.svg"),
        pathlib.PurePosixPath("benchmarks/run-sets/canonical.toml"),
    }
)
_GENERATED_EVIDENCE_DIRECTORY = pathlib.PurePosixPath("benchmarks/reports")
_DETECTOR_CORPUS_MANIFEST_FILE = "corpus.toml"
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
    """Read and return the workspace package version from root Cargo.toml."""
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
    """Extract semver string from scanner version or output string."""
    match = _SEMVER_RE.search(raw)
    return match.group(1) if match else None


def assert_version_matches_workspace(
    raw_version: str,
    *,
    what: str,
    repo_root: pathlib.Path = _REPO_ROOT,
) -> None:
    """Assert that raw_version matches the current workspace Cargo.toml version."""
    expected = workspace_keyhog_version() if repo_root == _REPO_ROOT else workspace_keyhog_version(repo_root)
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
    """Resolve and return the current workspace git commit SHA."""
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


def _tracked_status_paths(raw: bytes) -> set[pathlib.PurePosixPath]:
    """Decode exact tracked paths from NUL-delimited porcelain status."""
    paths: set[pathlib.PurePosixPath] = set()
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        if len(entry) < 4 or entry[2:3] != b" ":
            raise KeyhogVersionError(
                f"malformed tracked workspace status entry: {entry[:100]!r}"
            )
        status = entry[:2]
        if b"R" in status or b"C" in status:
            raise KeyhogVersionError(
                "generated-evidence freshness does not accept renamed or copied paths"
            )
        paths.add(pathlib.PurePosixPath(os.fsdecode(entry[3:])))
    return paths


def _is_generated_evidence_path(path: pathlib.PurePosixPath) -> bool:
    """Return whether path matches a release-generated report or matrix output location."""
    return path in _GENERATED_EVIDENCE_EXACT_PATHS or (
        _GENERATED_EVIDENCE_DIRECTORY in path.parents
    )



def _generated_evidence_only_since(
    observed_commit: str,
    current_commit: str,
    repo_root: pathlib.Path = _REPO_ROOT,
) -> bool:
    """Return whether one ancestor differs from HEAD only by generated evidence."""
    try:
        ancestor = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "merge-base",
                "--is-ancestor",
                observed_commit,
                current_commit,
            ],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeyhogVersionError(
            f"cannot validate benchmark commit ancestry: {exc}"
        ) from exc
    if ancestor.returncode != 0:
        return False
    try:
        changed = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                observed_commit,
                current_commit,
                "--",
            ],
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KeyhogVersionError(
            f"cannot inspect post-benchmark commit paths: {exc}"
        ) from exc
    if changed.returncode != 0:
        detail = (changed.stdout + changed.stderr)[:500]
        raise KeyhogVersionError(
            "cannot inspect post-benchmark commit paths: "
            f"git exited {changed.returncode}, output={detail!r}"
        )
    paths = {
        pathlib.PurePosixPath(os.fsdecode(raw_path))
        for raw_path in changed.stdout.split(b"\0")
        if raw_path
    }
    return bool(paths) and all(_is_generated_evidence_path(path) for path in paths)

def assert_workspace_tracked_tree_clean(repo_root: pathlib.Path = _REPO_ROOT) -> None:
    """Require source and build inputs to match HEAD for release evidence.

    ``KEYHOG_BENCH_ALLOW_DIRTY=1`` remains a developer-only full bypass.
    The release orchestrator may set the narrower generated-evidence switch,
    which still rejects every dirty source, manifest, fixture, or executable input.
    """
    if os.environ.get("KEYHOG_BENCH_ALLOW_DIRTY") == "1":
        return
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
        paths = _tracked_status_paths(proc.stdout)
        allow_generated = (
            os.environ.get(_ALLOW_GENERATED_EVIDENCE_DIRTY_ENV) == "1"
        )
        unexpected = sorted(
            str(path) for path in paths if not _is_generated_evidence_path(path)
        )
        if not allow_generated or unexpected:
            detail = (
                f" Unexpected non-evidence paths: {', '.join(unexpected)}."
                if unexpected
                else ""
            )
            raise KeyhogVersionError(
                "the tracked KeyHog workspace has uncommitted changes, so the candidate "
                "binary cannot prove it represents the current source. Commit the changes, "
                f"rebuild the release candidate, and rerun the benchmark.{detail}"
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
    """Match the effective detector-set identity stamped by ``core/build.rs``."""
    detector_dir = repo_root / "detectors"
    try:
        paths = sorted(
            (
                path
                for path in detector_dir.iterdir()
                if path.suffix == ".toml"
                and path.name != _DETECTOR_CORPUS_MANIFEST_FILE
            ),
            key=lambda path: path.name,
        )
    except OSError as exc:
        raise KeyhogVersionError(
            f"cannot enumerate detector TOMLs in {detector_dir}: {exc}"
        ) from exc
    if not paths:
        raise KeyhogVersionError(
            f"{detector_dir} contains no detector TOMLs; cannot validate benchmark binary"
        )

    manifest_path = detector_dir / _DETECTOR_CORPUS_MANIFEST_FILE
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest_bytes.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise KeyhogVersionError(
            "cannot read detector corpus manifest "
            f"{manifest_path}; restore a readable UTF-8 "
            f"{_DETECTOR_CORPUS_MANIFEST_FILE}: {exc}"
        ) from exc

    value = 0xCBF29CE484222325
    try:
        # build.rs hashes sorted detector (name, UTF-8 content) pairs first,
        # then the canonical manifest pair. Its count excludes the manifest.
        for path in (*paths, manifest_path):
            content = path.read_bytes() if path != manifest_path else manifest_bytes
            content.decode("utf-8")
            for payload in (path.name.encode("utf-8"), b"\0", content, b"\0"):
                for byte in payload:
                    value ^= byte
                    value = (value * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
    except (OSError, UnicodeError) as exc:
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
    """Return the SHA-256 digest of the workspace detectors directory."""
    return detector_corpus_sha256(repo_root / "detectors")


def assert_reported_identity_matches_workspace(
    raw: str,
    *,
    what: str,
    allow_generated_evidence_ancestor: bool = False,
    repo_root: pathlib.Path = _REPO_ROOT,
) -> bool:
    """Validate a reported identity and return whether its commit equals HEAD."""
    if repo_root == _REPO_ROOT:
        assert_version_matches_workspace(raw, what=what)
        expected_commit = workspace_git_hash()
        expected_detectors = workspace_detector_digest()
    else:
        assert_version_matches_workspace(raw, what=what, repo_root=repo_root)
        expected_commit = workspace_git_hash(repo_root)
        expected_detectors = workspace_detector_digest(repo_root)

    commit_match = _COMMIT_RE.search(raw)
    if commit_match is None:
        raise KeyhogVersionError(f"{what} does not report a Commit line; rebuild or rerun it")
    observed_commit = commit_match.group(1)
    exact_commit = observed_commit == expected_commit
    generated_evidence_ancestor = (
        allow_generated_evidence_ancestor
        and observed_commit != "unknown"
        and (
            _generated_evidence_only_since(observed_commit, expected_commit)
            if repo_root == _REPO_ROOT
            else _generated_evidence_only_since(observed_commit, expected_commit, repo_root=repo_root)
        )
    )
    if not exact_commit and not generated_evidence_ancestor:
        raise KeyhogVersionError(
            f"stale {what}: commit={observed_commit}, workspace={expected_commit}; "
            "rebuild or rerun the benchmark"
        )
    detector_match = _DETECTOR_SET_RE.search(raw)
    if detector_match is None:
        raise KeyhogVersionError(
            f"{what} does not report a parseable Detector Set digest; rebuild or rerun it"
        )
    if detector_match.group(1) != expected_detectors:
        raise KeyhogVersionError(
            f"stale {what}: detector_set={detector_match.group(1)}, "
            f"workspace={expected_detectors}; rebuild after detector TOML or corpus.toml changes"
        )
    return exact_commit


def assert_keyhog_binary_current(
    binary: str,
    *,
    pass_fds: tuple[int, ...] = (),
    repo_root: pathlib.Path = _REPO_ROOT,
) -> str:
    """Verify that candidate binary --version matches current workspace version and commit."""
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
    if repo_root == _REPO_ROOT:
        assert_reported_identity_matches_workspace(
            output,
            what=f"keyhog binary {binary!r}",
        )
        assert_workspace_tracked_tree_clean()
    else:
        assert_reported_identity_matches_workspace(
            output,
            what=f"keyhog binary {binary!r}",
            repo_root=repo_root,
        )
        assert_workspace_tracked_tree_clean(repo_root=repo_root)
    return output
def build_evidence_inventory(
    *,
    catalog_path: str | pathlib.Path | None = None,
    fixture_lock_path: str | pathlib.Path | None = None,
    target_matrix_path: str | pathlib.Path | None = None,
    binary: str | pathlib.Path | None = None,
    repo_root: pathlib.Path = _REPO_ROOT,
    execution_pack_manifest_path: str | pathlib.Path | None = None,
) -> dict[str, object]:
    """Prove catalog, fixture lock, target, binary, detector corpus, pack manifest, and route identities agree.

    Emits one authoritative evidence inventory with exactly 59 workloads and no stale or ambiguous artifact references.
    """
    c_path = pathlib.Path(catalog_path) if catalog_path else repo_root / "benchmarks" / "workload-catalog.toml"
    l_path = pathlib.Path(fixture_lock_path) if fixture_lock_path else repo_root / "benchmarks" / "workload-fixtures.lock.json"
    t_path = pathlib.Path(target_matrix_path) if target_matrix_path else repo_root / "benchmarks" / "target-matrix.toml"

    from .workload_catalog import load_workload_catalog
    from .target_matrix import load_target_matrix, target_matrix_sha256
    from .workload_fixtures import validate_fixture_lock

    catalog = load_workload_catalog(c_path)
    expected_workload_count = len(catalog.workloads)

    lock = validate_fixture_lock(c_path, l_path)
    lock_workloads = lock.get("workloads", [])
    if len(lock_workloads) != expected_workload_count:
        raise KeyhogVersionError(
            f"fixture lock workload count ({len(lock_workloads)}) differs from catalog workload count ({expected_workload_count})"
        )
    cat_ids = [w.workload_id for w in catalog.workloads]
    lock_ids = [row["workload_id"] for row in lock_workloads]
    if set(cat_ids) != set(lock_ids):
        raise KeyhogVersionError(
            "workload catalog and fixture lock workload IDs differ"
        )

    matrix = load_target_matrix(t_path)
    workspace_ver = workspace_keyhog_version(repo_root)
    if matrix.software.workspace_version != workspace_ver:
        raise KeyhogVersionError(
            f"target matrix software version {matrix.software.workspace_version!r} "
            f"does not match workspace version {workspace_ver!r}"
        )

    detector_sha256 = workspace_detector_corpus_sha256(repo_root)
    detector_digest = workspace_detector_digest(repo_root)

    binary_info = None
    if binary is not None:
        try:
            bin_path = pathlib.Path(binary).resolve(strict=True)
            assert_keyhog_binary_current(str(bin_path), repo_root=repo_root)
            with bin_path.open("rb") as handle:
                bin_sha256 = hashlib.sha256(handle.read()).hexdigest()
        except (OSError, KeyhogVersionError) as exc:
            if isinstance(exc, KeyhogVersionError):
                raise
            raise KeyhogVersionError(f"cannot inspect keyhog binary {binary!r}: {exc}") from exc
        binary_info = {
            "path": str(bin_path),
            "sha256": bin_sha256,
            "version": workspace_ver,
        }

    pack_info = None
    if execution_pack_manifest_path is not None:
        try:
            p_path = pathlib.Path(execution_pack_manifest_path).resolve(strict=True)
            pack_data = json.loads(p_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyhogVersionError(f"cannot load execution pack manifest {execution_pack_manifest_path}: {exc}") from exc
        if not isinstance(pack_data, dict):
            raise KeyhogVersionError("execution pack manifest must be a JSON object")
        
        pack_ver = pack_data.get("version")
        if not isinstance(pack_ver, int) or isinstance(pack_ver, bool) or pack_ver != 1:
            raise KeyhogVersionError(
                f"execution pack manifest schema version must be integer 1, got {pack_ver!r}"
            )

        digest_fields = {
            "detector_digest": pack_data.get("detector_digest"),
            "target_digest": pack_data.get("target_digest"),
            "binary_digest": pack_data.get("binary_digest"),
            "feature_digest": pack_data.get("feature_digest"),
            "fixture_digest": pack_data.get("fixture_digest"),
        }
        for field_name, field_value in digest_fields.items():
            if (
                not isinstance(field_value, str)
                or len(field_value) != 64
                or any(char not in "0123456789abcdef" for char in field_value)
            ):
                raise KeyhogVersionError(
                    f"execution pack manifest field {field_name!r} must be a 64-character lowercase hexadecimal digest"
                )

        packs = pack_data.get("packs")
        if not isinstance(packs, list):
            raise KeyhogVersionError(
                "execution pack manifest field 'packs' must be a JSON array"
            )

        ws_ver = pack_data.get("workspace_version")
        if ws_ver is not None and ws_ver != workspace_ver:
            raise KeyhogVersionError(
                f"execution pack manifest workspace_version {ws_ver!r} does not match workspace version {workspace_ver!r}"
            )

        pack_info = {
            "path": str(p_path),
            "version": pack_ver,
            **digest_fields,
            "pack_count": len(packs),
        }
        if ws_ver is not None:
            pack_info["workspace_version"] = ws_ver
    lock_by_id = {row["workload_id"]: row for row in lock_workloads}
    workload_entries = []
    for wl in catalog.workloads:
        receipt = lock_by_id[wl.workload_id]
        workload_entries.append(
            {
                "workload_id": wl.workload_id,
                "family": wl.family,
                "surface": wl.surface,
                "owner": wl.owner,
                "fixture": wl.fixture,
                "execution_routes": list(wl.execution_routes),
                "betterleaks_comparable": wl.betterleaks_comparable,
                "gpu_eligible": wl.gpu_eligible,
                "fixture_input_sha256": receipt["input_sha256"],
                "fixture_answer_sha256": receipt["answer_sha256"],
                "expected_findings": receipt["expected_findings"],
                "expected_coverage_gap": receipt["expected_coverage_gap"],
            }
        )

    try:
        with c_path.open("rb") as f:
            c_sha256 = hashlib.sha256(f.read()).hexdigest()
        with l_path.open("rb") as f:
            l_sha256 = hashlib.sha256(f.read()).hexdigest()
    except OSError as exc:
        raise KeyhogVersionError(f"cannot compute evidence inventory file digests: {exc}") from exc

    return {
        "schema_version": 1,
        "workload_count": expected_workload_count,
        "workspace_version": workspace_ver,
        "git_commit": workspace_git_hash(repo_root),
        "catalog_sha256": c_sha256,
        "fixture_lock_sha256": l_sha256,
        "target_matrix_sha256": target_matrix_sha256(t_path),
        "detector_corpus_sha256": detector_sha256,
        "detector_set_digest": detector_digest,
        "binary": binary_info,
        "execution_pack_manifest": pack_info,
        "workloads": workload_entries,
    }
