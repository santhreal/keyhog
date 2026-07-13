from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from bench import keyhog_version


def _version_output(*, commit: str, detector_digest: str) -> str:
    return (
        f"KeyHog v{keyhog_version.workspace_keyhog_version()}\n"
        f"Commit: {commit}\n"
        f"Detector Set: 1 ({detector_digest})\n"
        "Build Target: test-test\n"
    )


def test_detector_corpus_sha256_binds_filenames_and_bytes(tmp_path):
    first = tmp_path / "a.toml"
    second = tmp_path / "b.toml"
    first.write_text("[detector]\nid = 'a'\n", encoding="utf-8")
    second.write_text("[detector]\nid = 'b'\n", encoding="utf-8")

    initial = keyhog_version.detector_corpus_sha256(tmp_path)
    assert len(initial) == 64

    second.write_text("[detector]\nid = 'changed'\n", encoding="utf-8")
    changed_bytes = keyhog_version.detector_corpus_sha256(tmp_path)
    assert changed_bytes != initial

    second.rename(tmp_path / "renamed.toml")
    assert keyhog_version.detector_corpus_sha256(tmp_path) != changed_bytes


@pytest.mark.skipif(os.name != "posix", reason="POSIX permits non-UTF-8 filenames")
def test_detector_corpus_sha256_accepts_non_utf8_filenames(tmp_path):
    name = os.fsdecode(b"detector-\xff.toml")
    (tmp_path / name).write_bytes(b"[detector]\nid = 'raw-name'\n")

    digest = keyhog_version.detector_corpus_sha256(tmp_path)

    assert len(digest) == 64


def test_binary_freshness_rejects_same_version_from_an_older_commit(monkeypatch):
    current = "a" * 40
    output = _version_output(commit="b" * 40, detector_digest="1-0000000000000001")
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(
        keyhog_version, "workspace_detector_digest", lambda: "1-0000000000000001"
    )

    with pytest.raises(keyhog_version.KeyhogVersionError, match="older commit|stale"):
        keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")


def test_binary_freshness_rejects_stale_embedded_detector_set(monkeypatch):
    current = "a" * 40
    output = _version_output(commit=current, detector_digest="1-0000000000000001")
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(
        keyhog_version, "workspace_detector_digest", lambda: "1-0000000000000002"
    )

    with pytest.raises(keyhog_version.KeyhogVersionError, match="detector_set"):
        keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")


def test_binary_freshness_accepts_exact_commit_and_detector_set(monkeypatch):
    current = "a" * 40
    digest = "1-0000000000000001"
    output = _version_output(commit=current, detector_digest=digest)
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(keyhog_version, "workspace_detector_digest", lambda: digest)

    keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")
