from __future__ import annotations

import pytest

from bench.corpora.creddata import CredDataCorpus
from bench.keyhog_version import KeyhogVersionError, assert_keyhog_binary_current
from bench.scanners.keyhog import KeyhogScanner, resolve_keyhog_binary
from bench.schema import ScannerConfig


@pytest.fixture(scope="session")
def creddata_simd_findings():
    """One exact-candidate SIMD scan shared by every CredData release gate."""
    corpus = CredDataCorpus()
    binary = resolve_keyhog_binary()
    if binary is None:
        pytest.fail(
            "no keyhog binary found; build the candidate or set KEYHOG_BIN before "
            "running CredData release gates"
        )
    try:
        assert_keyhog_binary_current(binary)
    except KeyhogVersionError as exc:
        pytest.fail(f"{exc}; refusing to score CredData with a stale binary")

    cfg = ScannerConfig(backend="simd", cache="off", daemon="off", mode="full")
    findings, _stats = KeyhogScanner(binary=binary).run(corpus.scan_root, cfg)
    if not findings:
        pytest.fail(
            f"keyhog ({binary}) produced zero findings over CredData; this is a "
            "candidate/harness failure, not a recall result"
        )
    return findings
