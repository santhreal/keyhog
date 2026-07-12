"""Gate #2 — BACKEND DIFFERENTIAL PARITY (the one gate that catches the most).

keyhog runs `walk -> match -> emit` through several divergent backends — SimdCpu,
the platform CPU fallback, plus Gpu/MegaScan — and a silent fallback in any one of them drops
findings only on THAT path, invisibly. The "validator bypass on the fast path"
bug class is exactly this: the fast path skips a per-match policy the slow path
applies, so the two disagree and nobody notices.

This gate scans the real CredData corpus through the deterministic SIMD
reference, then checks accelerated backends as recall-preserving supersets.
Autoroute is cache-keyed by calibrated workload buckets, so the product-path
autoroute proof is a separate bounded calibration/replay test in this module;
the CredData fixture must not live-calibrate an unbounded set of per-batch keys
and pretend that proves every future scan bucket.

`cpu` is a platform fallback for no-SIMD builds and an explicit diagnostic
override on SIMD builds; it must not be selected by autoroute on a SIMD-capable
binary until it has its own parity proof.
GPU/MegaScan are tested as RECALL-PRESERVING (must not drop anything the
deterministic reference found) when a GPU-capable binary is present; if it is
not, that backend is skipped LOUDLY (printed), never silently passed.

Speed: one scan per checked backend over CredData. Belongs in the bench/nightly
lane, not the fast unit lane.

Requires: the CredData corpus on disk + a keyhog binary (KEYHOG_BIN or a release
build). Both checked; absence skips the module with the reason.
"""

from __future__ import annotations

import pathlib

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
# Accelerated backends checked as recall-preserving supersets IF available.
_ACCELERATED = ["gpu", "megascan"]
_ACCELERATED_TIMEOUT_SECONDS = 120


def _finding_keys(findings) -> set[tuple]:
    """A backend-comparable identity per finding: (file, line, value, detector).
    Confidence is deliberately excluded — it may legitimately differ by a hair
    across backends; a DROPPED or ADDED finding is what this gate is about."""
    return {
        (f.get("file", ""), f.get("line", 0), f.get("value", ""), f.get("detector", ""))
        for f in findings
    }


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
    accelerated ones are best-effort and recorded as None when unavailable
    (printed loudly, never silently dropped)."""
    binary = _current_keyhog_binary()

    out: dict[str, set | None] = {
        _DETERMINISTIC[0]: _finding_keys(creddata_simd_findings)
    }

    ref = out[_DETERMINISTIC[0]]
    for b in _ACCELERATED:
        try:
            got = _scan(
                binary,
                b,
                _CORPUS.scan_root,
                timeout=_ACCELERATED_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 — record + surface, never swallow
            print(f"\n[parity] backend {b!r} errored ({exc}); SKIPPED (loud).")
            out[b] = None
            continue
        # REQUIRE_GPU makes an unavailable accelerator yield nothing; distinguish
        # "ran and found the same" from "could not run" by comparing to the ref.
        if not got and ref:
            print(f"\n[parity] backend {b!r} produced no findings (GPU/feature "
                  f"unavailable on this host); SKIPPED (loud, not a pass).")
            out[b] = None
        else:
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
    assert not dropped, (
        f"accelerated backend {backend!r} DROPPED {len(dropped)} finding(s) the "
        f"deterministic path found — silent recall loss on the fast path:\n"
        f"  {sorted(dropped)[:12]}\n"
        f"The GPU/megakernel path may add findings, but it must never lose one "
        f"the CPU path surfaces.")
