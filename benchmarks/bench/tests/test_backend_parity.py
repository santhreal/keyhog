"""Gate #2 — BACKEND DIFFERENTIAL PARITY (the one gate that catches the most).

keyhog runs `walk -> match -> emit` through several divergent backends — SimdCpu,
the platform CPU fallback, plus GPU region presence — and a silent fallback in any one of them drops
findings only on THAT path, invisibly. The "validator bypass on the fast path"
bug class is exactly this: the fast path skips a per-match policy the slow path
applies, so the two disagree and nobody notices.

This gate scans the real CredData corpus through the deterministic SIMD
reference, then requires accelerated backends to return the exact same finding
identity set.
Autoroute is cache-keyed by calibrated workload buckets, so the product-path
autoroute proof is a separate bounded calibration/replay test in this module;
the CredData fixture must not live-calibrate an unbounded set of per-batch keys
and pretend that proves every future scan bucket.

`cpu` is a platform fallback for no-SIMD builds and an explicit diagnostic
override on SIMD builds; it must not be selected by autoroute on a SIMD-capable
binary until it has its own parity proof.
GPU is tested for exact detector/value/location parity when a GPU-capable
binary is present; if it is
not, that backend is skipped LOUDLY (printed), never silently passed.

Speed: one scan per checked backend over CredData. Belongs in the bench/nightly
lane, not the fast unit lane.

Requires: the CredData corpus on disk + a keyhog binary (KEYHOG_BIN or a release
build). Both checked; absence skips the module with the reason.
"""

from __future__ import annotations

import json
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
_ACCELERATED = ["gpu"]
# CredData is a 1 GiB, 11k-file end-to-end corpus.  This is a recall gate, not
# a microbenchmark: give slow/cold hosts enough time to produce a real result,
# while retaining a finite watchdog for hangs.
_ACCELERATED_TIMEOUT_SECONDS = 600


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


def _gpu_preflight(binary: str) -> bool:
    """Return False only for an honestly absent adapter; fail on broken GPU paths."""
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
        return False
    if (
        completed.returncode != 0
        or not report.get("ok", False)
        or report.get("status") != "pass"
    ):
        pytest.fail(
            "GPU adapter exists but its production self-test failed; refusing to "
            f"mislabel a broken accelerator as unavailable: {report}"
        )
    return True


def test_gpu_preflight_skips_only_absent_hardware(monkeypatch):
    report = {"ok": True, "status": "skip", "gpu_available": False}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, json.dumps(report), ""
        ),
    )
    assert _gpu_preflight("/unused/keyhog") is False


def test_gpu_preflight_rejects_broken_present_adapter(monkeypatch):
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
    findings, _stats = KeyhogScanner(binary=binary).run(
        root,
        cfg,
        extra_env=extra_env,
        extra_args=extra_args,
        timeout=timeout,
    )
    return _finding_keys(findings)


@pytest.fixture(scope="session")
def backend_findings(creddata_simd_findings):
    """Scan the corpus once per backend. Deterministic backends are required;
    an accelerated backend is recorded as None only when preflight proves the
    hardware adapter is absent (printed loudly, never silently dropped)."""
    binary = _current_keyhog_binary()

    out: dict[str, set | None] = {
        _DETERMINISTIC[0]: _finding_keys(creddata_simd_findings)
    }

    ref = out[_DETERMINISTIC[0]]
    for b in _ACCELERATED:
        if b == "gpu" and not _gpu_preflight(binary):
            print("\n[parity] backend 'gpu' has no hardware adapter; SKIPPED (loud).")
            out[b] = None
            continue
        try:
            got = _scan(
                binary,
                b,
                _CORPUS.scan_root,
                timeout=_ACCELERATED_TIMEOUT_SECONDS,
            )
        except TimeoutError as exc:
            pytest.fail(
                f"accelerated backend {b!r} timed out; this is an execution "
                f"failure, not hardware unavailability: {exc}"
            )
        except RuntimeError as exc:
            pytest.fail(
                f"accelerated backend {b!r} failed during the parity scan; "
                f"the preflight passed, so this is an execution defect: {exc}"
            )
        # Preflight proved the backend exists and --require-gpu forbids CPU
        # fallback.  Even an empty successful result is therefore a real parity
        # result; the differential assertion below must score it, not skip it.
        out[b] = got
    return out


def test_fused_autoroute_calibration_cache_replay_matches_simd(tmp_path):
    binary = _current_keyhog_binary()
    root = tmp_path / "fused-fixture"
    root.mkdir()
    secret = "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n"
    for index in range(40):
        body = secret if index in {0, 33} else f"clean_{index}=not_a_secret\n"
        (root / f"fixture-{index:02}.env").write_text(body)

    cache = tmp_path / "autoroute.json"
    autoroute_args = ["--autoroute-cache", str(cache)]
    calibration_args = [*autoroute_args, "--autoroute-calibrate"]

    simd = _scan(binary, "simd", root)
    assert simd, "bounded fused fixture must produce real findings on the simd reference path"

    calibrated = _scan(binary, "auto", root, extra_args=calibration_args)
    assert calibrated == simd, (
        "fused autoroute calibration must scan the same production batch shape "
        "and preserve the simd finding set")
    assert cache.exists(), "fused autoroute calibration must persist a cache file"

    replayed = _scan(binary, "auto", root, extra_args=autoroute_args)
    assert replayed == simd, (
        "default fused auto replay must consume the persisted calibration cache "
        "and preserve the simd finding set")


@pytest.mark.skipif(not _AVAILABLE, reason="CredData corpus not on disk — backend parity cannot run")
def test_deterministic_reference_backend_produces_findings(backend_findings):
    assert backend_findings[_DETERMINISTIC[0]], (
        "CredData deterministic reference backend produced no findings; backend parity "
        "cannot be scored against an empty reference")


@pytest.mark.skipif(not _AVAILABLE, reason="CredData corpus not on disk — backend parity cannot run")
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
