"""Gate #2: BACKEND DIFFERENTIAL PARITY (the one gate that catches the most).

keyhog runs `walk -> match -> emit` through several divergent backends. SimdCpu,
the platform CPU fallback, plus exact CUDA and WGPU region-presence peers. A silent fallback in any one of them drops
findings only on THAT path, invisibly. The "validator bypass on the fast path"
bug class is exactly this: the fast path skips a per-match policy the slow path
applies, so the two disagree and nobody notices.

This gate packs CredData into stable source-bounded partitions, runs SIMD and
each acquired GPU peer over those exact process boundaries, and requires CUDA
and WGPU to return the exact same finding identity set.
Autoroute is cache-keyed by calibrated workload buckets, so the product-path
autoroute proof is a separate bounded calibration/replay test in this module;
the CredData fixture must not live-calibrate an unbounded set of per-batch keys
and pretend that proves every future scan bucket.

`cpu` is a platform fallback for no-SIMD builds and an explicit diagnostic
override on SIMD builds; it must not be selected by autoroute on a SIMD-capable
binary until it has its own parity proof.
Each GPU driver is tested for exact detector/value/location parity when that
peer is acquired. An unacquired peer is skipped loudly, never substituted.

Speed: one stable set of bounded corpus shards per tested backend. Belongs in
the bench/nightly lane, not the fast unit lane.

Requires: the CredData corpus, a current full release binary (`KEYHOG_BIN` or a
release build), and, for timing-fixture tests, a current ci-lean binary in
`KEYHOG_AUTOROUTE_FIXTURE_BIN`. Missing assets skip loudly instead of changing
the product binary's feature set.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess

import pytest

from bench.corpora.creddata import CredDataCorpus
from bench.keyhog_version import KeyhogVersionError, assert_keyhog_binary_current
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import ScannerConfig

_CORPUS = CredDataCorpus()
_AVAILABLE = _CORPUS.is_downloaded()

# Deterministic CredData reference. Auto is proven by the bounded persisted-cache
# replay test below because full-corpus live calibration is an unbounded bucket
# generator, not a stable parity proof.
_DETERMINISTIC = ["simd"]
# Accelerated backends checked for exact finding parity IF available.
_ACCELERATED = ["gpu-cuda", "gpu-wgpu"]
# CredData is a 1 GiB, 11k-file end-to-end corpus. Each accelerated subprocess
# receives at most 256 MiB. A broken driver must fail inside the surrounding
# project-gate deadline instead of consuming its former 20-minute watchdog.
_ACCELERATED_TIMEOUT_SECONDS = 300
_ACCELERATED_SHARD_SOURCE_BYTES = 256 * 1024 * 1024


def _pack_accelerated_scan_roots(
    entries: list[tuple[pathlib.Path, int]],
    byte_limit: int = _ACCELERATED_SHARD_SOURCE_BYTES,
) -> list[tuple[pathlib.Path, ...]]:
    """Pack disjoint roots into stable source-bounded scan processes."""
    if byte_limit <= 0:
        raise ValueError("accelerated scan shard byte limit must be positive")
    shards: list[tuple[pathlib.Path, ...]] = []
    current: list[pathlib.Path] = []
    current_bytes = 0
    for path, size in entries:
        if size < 0:
            raise ValueError(f"accelerated scan root size must be non-negative: {path}")
        if current and current_bytes + size > byte_limit:
            shards.append(tuple(current))
            current = []
            current_bytes = 0
        current.append(path)
        current_bytes += size
    if current:
        shards.append(tuple(current))
    return shards


def _tree_bytes(path: pathlib.Path) -> int:
    if path.is_file():
        return path.stat().st_size
    return sum(candidate.stat().st_size for candidate in path.rglob("*") if candidate.is_file())


def _accelerated_scan_roots(root: pathlib.Path) -> list[tuple[pathlib.Path, ...]]:
    entries = sorted(root.iterdir(), key=lambda path: path.name)
    measured = [(path, _tree_bytes(path)) for path in entries]
    return _pack_accelerated_scan_roots(measured)


def _finding_keys(findings) -> set[tuple]:
    """Exact backend-comparable identity, including location and confidence."""
    return {
        (
            f.get("file", ""),
            f.get("line", 0),
            f.get("offset", 0),
            f.get("value", ""),
            f.get("detector", ""),
            f.get("confidence"),
        )
        for f in findings
    }


def test_finding_identity_includes_detector_offset_and_confidence():
    base = {
        "file": "fixture.env",
        "line": 7,
        "offset": 41,
        "value": "credential",
        "detector": "generic-secret",
        "confidence": 0.73,
    }
    variants = [
        base,
        {**base, "detector": "generic-password"},
        {**base, "offset": 42},
        {**base, "confidence": 0.74},
    ]
    assert len(_finding_keys(variants)) == 4


def test_accelerated_scan_root_packing_is_stable_and_source_bounded():
    roots = [
        (pathlib.Path("/corpus/a"), 100),
        (pathlib.Path("/corpus/b"), 156),
        (pathlib.Path("/corpus/c"), 1),
        (pathlib.Path("/corpus/d"), 300),
    ]
    assert _pack_accelerated_scan_roots(roots, 256) == [
        (pathlib.Path("/corpus/a"), pathlib.Path("/corpus/b")),
        (pathlib.Path("/corpus/c"),),
        (pathlib.Path("/corpus/d"),),
    ]
    with pytest.raises(ValueError, match="positive"):
        _pack_accelerated_scan_roots(roots, 0)


def test_accelerated_scan_stops_after_first_shard_watchdog_expiry(monkeypatch):
    """A hung driver must fail one bounded shard without starting more 20-minute waits."""
    shards = [
        (pathlib.Path("/corpus/a"),),
        (pathlib.Path("/corpus/b"),),
    ]
    observed_timeouts: list[int] = []
    monkeypatch.setitem(
        globals(),
        "_accelerated_scan_roots",
        lambda _root: shards,
    )

    def time_out(_binary, _backend, _root, *, extra_args, timeout):
        observed_timeouts.append(timeout)
        raise TimeoutError("driver dispatch stalled")

    monkeypatch.setitem(globals(), "_scan", time_out)

    with pytest.raises(TimeoutError, match="driver dispatch stalled"):
        _scan_accelerated("/unused/keyhog", "gpu-cuda")
    assert observed_timeouts == [300]


def _current_keyhog_binary() -> str:
    binary = resolve_keyhog_binary()
    if binary is None:
        pytest.fail("no keyhog binary (set KEYHOG_BIN or build a release binary); "
                    "refusing to declare backend parity off a binary that never ran")
    try:
        assert_keyhog_binary_current(binary)
    except KeyhogVersionError as exc:
        pytest.fail(f"{exc}; refusing to score backend parity with a stale binary")
    return binary


def _gpu_preflight(binary: str) -> dict:
    """Run the production self-test once and validate its global GPU state."""
    try:
        completed = subprocess.run(
            [binary, "backend", "--self-test", "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.fail(f"GPU parity preflight could not run: {exc}")
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            "GPU parity preflight returned invalid JSON: "
            f"{exc}; stdout={completed.stdout[-600:]!r}; "
            f"stderr={completed.stderr[-600:]!r}"
        )
    if not isinstance(report, dict):
        pytest.fail(
            "GPU parity preflight JSON must be an object; "
            f"got {type(report).__name__}"
        )
    if not report.get("gpu_available", False):
        if report.get("status") != "skip" or not report.get("ok", False):
            pytest.fail(
                f"GPU preflight reported an inconsistent unavailable state: {report}"
            )
        return report
    if (
        completed.returncode != 0
        or not report.get("ok", False)
        or report.get("status") != "pass"
    ):
        pytest.fail(
            "GPU adapter exists but its production self-test failed; refusing to "
            f"mislabel a broken accelerator as unavailable: {report}"
        )
    return report


def _gpu_peer_available(report: dict, backend: str) -> bool:
    """Return False only when the validated report lacks the exact GPU peer."""
    if backend not in _ACCELERATED:
        pytest.fail(f"GPU preflight requires an exact peer, got {backend!r}")
    if not report.get("gpu_available", False):
        return False
    peer_probes = [
        probe
        for probe in report.get("probes", [])
        if isinstance(probe, dict)
        and probe.get("name") == "gpu_region_presence"
        and probe.get("backend_route") == backend
    ]
    if len(peer_probes) > 1:
        pytest.fail(f"GPU preflight reported duplicate {backend} probes: {report}")
    if not peer_probes:
        return False
    if peer_probes[0].get("status") != "pass":
        pytest.fail(f"GPU preflight reported a broken {backend} peer: {report}")
    return True


def test_gpu_preflight_skips_only_absent_hardware(monkeypatch):
    """A validated unavailable report may skip peers without hiding a broken adapter."""
    report = {"ok": True, "status": "skip", "gpu_available": False}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, json.dumps(report), ""
        ),
    )
    validated = _gpu_preflight("/unused/keyhog")
    assert _gpu_peer_available(validated, "gpu-cuda") is False


def test_gpu_preflight_distinguishes_exact_acquired_peer(monkeypatch):
    """One self-test must identify both exact peers without rerunning GPU diagnostics."""
    report = {
        "ok": True,
        "status": "pass",
        "gpu_available": True,
        "probes": [
            {
                "name": "gpu_region_presence",
                "status": "pass",
                "backend_route": "gpu-wgpu",
                "backend_id": "wgpu:adapter",
            }
        ],
    }
    calls = 0

    def run_once(*args, **kwargs):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(args[0], 0, json.dumps(report), "")

    monkeypatch.setattr(subprocess, "run", run_once)
    validated = _gpu_preflight("/unused/keyhog")
    assert _gpu_peer_available(validated, "gpu-wgpu") is True
    assert _gpu_peer_available(validated, "gpu-cuda") is False
    assert calls == 1


def test_gpu_preflight_rejects_broken_present_adapter(monkeypatch):
    """A present adapter that fails production diagnostics must stop parity scoring."""
    report = {"ok": False, "status": "fail", "gpu_available": True}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 4, json.dumps(report), "kernel parity failed"
        ),
    )
    with pytest.raises(pytest.fail.Exception, match="production self-test failed"):
        _gpu_preflight("/unused/keyhog")


def _scan(
    binary: str,
    backend: str,
    root: pathlib.Path,
    extra_env: dict[str, str] | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 3600,
) -> set[tuple]:
    cfg = ScannerConfig(backend=backend, cache="off", daemon="off", mode="full")
    findings, stats = KeyhogScanner(binary=binary).run(
        root,
        cfg,
        extra_env=extra_env,
        extra_args=extra_args,
        timeout=timeout,
    )
    print(
        f"\n[parity] backend={backend} wall_ms={stats.wall_ms:.0f} "
        f"peak_rss_kb={stats.peak_rss_kb}"
    )
    return _finding_keys(findings)


def _scan_accelerated(binary: str, backend: str) -> set[tuple]:
    roots = _accelerated_scan_roots(_CORPUS.scan_root)
    if not roots:
        pytest.fail("CredData accelerated parity root contains no scan entries")

    findings: set[tuple] = set()
    for index, shard in enumerate(roots):
        shard_findings = _scan(
            binary,
            backend,
            shard[0],
            extra_args=[str(path) for path in shard[1:]],
            timeout=_ACCELERATED_TIMEOUT_SECONDS,
        )
        duplicates = findings & shard_findings
        if duplicates:
            pytest.fail(
                f"accelerated parity shards overlap at shard {index}: "
                f"{sorted(duplicates, key=repr)[:3]}"
            )
        findings.update(shard_findings)
    return findings


def _collect_backend_findings(
    binary: str,
    reference_keys: set[tuple],
    gpu_report: dict,
) -> dict[str, set | None]:
    """Compare each acquired GPU peer with the supplied partition-matched SIMD scan."""
    out: dict[str, set | None] = {
        _DETERMINISTIC[0]: set(reference_keys)
    }
    for backend in _ACCELERATED:
        if not _gpu_peer_available(gpu_report, backend):
            print(f"\n[parity] backend {backend!r} was not acquired; SKIPPED (loud).")
            out[backend] = None
            continue
        try:
            got = _scan_accelerated(binary, backend)
        except TimeoutError as exc:
            pytest.fail(
                f"accelerated backend {backend!r} timed out; this is an execution "
                f"failure, not hardware unavailability: {exc}"
            )
        except RuntimeError as exc:
            pytest.fail(
                f"accelerated backend {backend!r} failed during the parity scan; "
                f"the preflight passed, so this is an execution defect: {exc}"
            )
        # Preflight proved the backend exists and --require-gpu forbids CPU
        # fallback. Even an empty successful result is therefore a real parity
        # result; the differential assertion below must score it, not skip it.
        out[backend] = got
    return out


def test_backend_collection_uses_supplied_partition_matched_reference(monkeypatch):
    """Collection must not rescan a supplied reference before comparing GPU peers."""
    reference = [
        {
            "file": "fixture.env",
            "line": 1,
            "offset": 0,
            "value": "credential",
            "detector": "generic-secret",
            "confidence": 0.9,
        }
    ]
    unavailable = {"ok": True, "status": "skip", "gpu_available": False}
    monkeypatch.setitem(
        globals(),
        "_scan_accelerated",
        lambda *_args, **_kwargs: pytest.fail("supplied SIMD reference was rescanned"),
    )

    findings = _collect_backend_findings(
        "/unused/keyhog", _finding_keys(reference), unavailable
    )

    assert findings["simd"] == _finding_keys(reference)
    assert findings["gpu-cuda"] is None
    assert findings["gpu-wgpu"] is None


@pytest.fixture(scope="session")
def partitioned_simd_reference():
    """Run SIMD across the same process partitions used by each GPU peer."""
    binary = _current_keyhog_binary()
    return binary, _scan_accelerated(binary, _DETERMINISTIC[0])


@pytest.fixture(scope="session")
def backend_findings(partitioned_simd_reference):
    """Compare GPU peers with SIMD under identical source-process boundaries."""
    binary, reference_keys = partitioned_simd_reference
    return _collect_backend_findings(
        binary,
        reference_keys,
        _gpu_preflight(binary),
    )


_AUTOROUTE_TIMING_FIXTURE_ENV = "KEYHOG_CI_AUTOROUTE_TIMING_FIXTURE"
_AUTOROUTE_TIMING_FIXTURE_AUTH_ENV = "KEYHOG_CI_AUTOROUTE_FIXTURE_AUTH"
_AUTOROUTE_TIMING_FIXTURE_AUTH = "bench-backend-parity-v1"
_AUTOROUTE_FIXTURE_BIN_ENV = "KEYHOG_AUTOROUTE_FIXTURE_BIN"


def _autoroute_fixture_binary() -> str:
    """Return the explicit ci-lean binary that owns the test-only timing seam."""
    binary = os.environ.get(_AUTOROUTE_FIXTURE_BIN_ENV)
    if not binary:
        pytest.skip(
            f"{_AUTOROUTE_FIXTURE_BIN_ENV} is unset; build a current ci-lean binary "
            "before running deterministic autoroute timing-fixture tests"
        )
    try:
        assert_keyhog_binary_current(binary)
    except KeyhogVersionError as exc:
        pytest.fail(
            f"{exc}; refusing to exercise test-only autoroute timing fixtures "
            "with a stale ci-lean binary"
        )
    return binary


def _autoroute_timing_fixture_env(fixture: str) -> dict[str, str]:
    return {
        _AUTOROUTE_TIMING_FIXTURE_ENV: fixture,
        _AUTOROUTE_TIMING_FIXTURE_AUTH_ENV: _AUTOROUTE_TIMING_FIXTURE_AUTH,
    }


def _write_fused_autoroute_fixture(root: pathlib.Path) -> None:
    root.mkdir()
    secret = "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n"
    for index in range(40):
        body = secret if index in {0, 33} else f"clean_{index}=not_a_secret\n"
        (root / f"fixture-{index:02}.env").write_text(body)


def test_fused_autoroute_calibration_cache_replay_matches_simd(tmp_path):
    binary = _autoroute_fixture_binary()
    root = tmp_path / "fused-fixture"
    _write_fused_autoroute_fixture(root)

    cache = tmp_path / "autoroute.json"
    autoroute_args = ["--autoroute-cache", str(cache)]
    calibration_args = [*autoroute_args, "--autoroute-calibrate"]

    simd = _scan(binary, "simd", root)
    assert simd, "bounded fused fixture must produce real findings on the simd reference path"

    # Regression: real host timings can overlap legitimately, so success/replay
    # cannot depend on scheduler luck. The explicit test-only fixture replaces
    # timing evidence after every real candidate scan and parity receipt with
    # confidence-separated trials; route confidence selection still runs.
    calibrated = _scan(
        binary,
        "auto",
        root,
        extra_args=calibration_args,
        extra_env=_autoroute_timing_fixture_env("confidence-separated-v1"),
    )
    assert calibrated == simd, (
        "fused autoroute calibration must scan the same production batch shape "
        "and preserve the simd finding set"
    )
    assert cache.exists(), "confidence-supported calibration must persist a cache file"

    replayed = _scan(binary, "auto", root, extra_args=autoroute_args)
    assert replayed == simd, (
        "default fused auto replay must consume the persisted calibration cache "
        "and preserve the simd finding set"
    )


def test_fused_autoroute_inconclusive_timing_fails_closed(tmp_path):
    binary = _autoroute_fixture_binary()
    root = tmp_path / "noisy-fused-fixture"
    _write_fused_autoroute_fixture(root)
    cache = tmp_path / "autoroute.json"

    # Negative twin: candidate execution and parity remain real, while injected
    # distinct-median, overlapping-interval trials model a noisy host. No route
    # may be forced or published from that evidence.
    completed = subprocess.run(
        [
            binary,
            "scan",
            "--backend",
            "auto",
            "--daemon=off",
            "--no-config",
            "--format",
            "json",
            "--autoroute-cache",
            str(cache),
            "--autoroute-calibrate",
            str(root),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, **_autoroute_timing_fixture_env("overlapping-v1")},
    )

    detail = completed.stderr
    assert completed.returncode == 2, detail
    assert completed.stdout == ""
    assert "autoroute calibration did not persist a routing decision" in detail
    assert (
        "calibration timing is inconclusive: neither one exact route nor one backend "
        "with its compiled default plan is confidence-supported at 95%"
    ) in detail
    assert "rerun `keyhog calibrate-autoroute`" in detail
    assert "explicit `--backend` only for a diagnostic scan" in detail
    assert not cache.exists(), "inconclusive calibration must publish no routing cache"


def test_fused_autoroute_timing_fixture_requires_authorization(tmp_path):
    binary = _autoroute_fixture_binary()
    root = tmp_path / "unauthorized-fused-fixture"
    _write_fused_autoroute_fixture(root)
    cache = tmp_path / "autoroute.json"

    # The ci-lean seam is inert unless the benchmark contract supplies its
    # independent authorization value; an ambient fixture name cannot alter
    # routing evidence or create a cache.
    with pytest.raises(RuntimeError) as raised:
        _scan(
            binary,
            "auto",
            root,
            extra_args=[
                "--autoroute-cache",
                str(cache),
                "--autoroute-calibrate",
            ],
            extra_env={
                _AUTOROUTE_TIMING_FIXTURE_ENV: "confidence-separated-v1",
            },
        )

    detail = str(raised.value)
    assert "timed scan exited 2" in detail
    assert "test-only autoroute timing fixture authorization failed" in detail
    assert _AUTOROUTE_TIMING_FIXTURE_AUTH_ENV in detail
    assert not cache.exists(), "unauthorized fixture input must publish no routing cache"


@pytest.mark.skipif(not _AVAILABLE, reason="CredData corpus not on disk, backend parity cannot run")
def test_deterministic_reference_backend_produces_findings(backend_findings):
    assert backend_findings[_DETERMINISTIC[0]], (
        "CredData deterministic reference backend produced no findings; backend parity "
        "cannot be scored against an empty reference")


@pytest.mark.skipif(not _AVAILABLE, reason="CredData corpus not on disk, backend parity cannot run")
@pytest.mark.parametrize("backend", _ACCELERATED)
def test_accelerated_backend_drops_nothing(backend, backend_findings):
    got = backend_findings[backend]
    if got is None:
        pytest.skip(f"{backend} unavailable on this host (reported loudly in fixture)")
    ref = backend_findings[_DETERMINISTIC[0]]
    dropped = ref - got
    added = got - ref
    ref_structural = {finding[:-1] for finding in ref}
    got_structural = {finding[:-1] for finding in got}
    structurally_dropped = ref_structural - got_structural
    structurally_added = got_structural - ref_structural
    assert not dropped and not added, (
        f"accelerated backend {backend!r} diverged from the deterministic path: "
        f"structurally_dropped={len(structurally_dropped)}, "
        f"structurally_added={len(structurally_added)}, "
        f"exact_dropped={len(dropped)}, exact_added={len(added)}\n"
        f"  structurally dropped: {sorted(structurally_dropped, key=repr)[:12]}\n"
        f"  structurally added:   {sorted(structurally_added, key=repr)[:12]}\n"
        f"  dropped: {sorted(dropped, key=repr)[:12]}\n"
        f"  added:   {sorted(added, key=repr)[:12]}\n"
        "Detector, value, file, line, offset, and confidence must be backend-invariant."
    )
