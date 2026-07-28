"""Behavioral tests for exact benchmark workload hashing."""

from __future__ import annotations

import pathlib
import os

import pytest


from bench.corpora.base import Corpus, LabeledRecord
from bench.schema import is_sha256


class _FixtureCorpus(Corpus):
    name = "fixture"

    def __init__(
        self, root: pathlib.Path, secret: str = "secret", label: bool = True
    ):
        self._root = root
        self._secret = secret
        self._label = label

    @property
    def root(self) -> pathlib.Path:
        return self._root

    def _load_records(self) -> list[LabeledRecord]:
        return [
            LabeledRecord(
                id="row-1",
                secret=self._secret,
                label=self._label,
                category="token",
                file_path="input.txt",
            )
        ]


def test_workload_hash_binds_scanned_bytes_and_answer_key(tmp_path):
    """Guards workload hash binds scanned bytes and answer key; prevents this evidence regression from false-passing or crashing."""
    path = tmp_path / "input.txt"
    path.write_text("secret\n")
    original = _FixtureCorpus(tmp_path).info()
    assert is_sha256(original.workload_sha256)
    assert original.bytes == len(b"secret\n")

    path.write_text("changed\n")
    changed_bytes = _FixtureCorpus(tmp_path).info()
    assert changed_bytes.workload_sha256 != original.workload_sha256

    changed_labels = _FixtureCorpus(tmp_path, secret="different").info()
    assert changed_labels.workload_sha256 != changed_bytes.workload_sha256


def test_workload_hash_is_stable_for_identical_paths_labels_and_bytes(tmp_path):
    """Guards workload hash is stable for identical paths labels and bytes; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    first = _FixtureCorpus(tmp_path).info()
    second = _FixtureCorpus(tmp_path).info()
    assert first == second


def test_workload_info_does_not_reuse_cached_byte_or_label_identity(tmp_path):
    """Guards workload info does not reuse cached byte or label identity; prevents this evidence regression from false-passing or crashing."""
    path = tmp_path / "input.txt"
    path.write_text("first", encoding="utf-8")
    corpus = _FixtureCorpus(tmp_path)
    first = corpus.info()

    path.write_text("other", encoding="utf-8")
    changed_bytes = corpus.info()
    assert changed_bytes.workload_sha256 != first.workload_sha256

    corpus.records()[0] = LabeledRecord(
        id="row-1",
        secret="secret",
        label=False,
        category="token",
        file_path="input.txt",
    )
    changed_label = corpus.info()
    assert changed_label.workload_sha256 != changed_bytes.workload_sha256
    assert changed_label.labeled_positives == 0


def test_workload_hash_rejects_mutation_during_snapshot(tmp_path, monkeypatch):
    """Guards workload hash rejects mutation during snapshot; prevents this evidence regression from false-passing or crashing."""
    path = tmp_path / "input.txt"
    path.write_text("first", encoding="utf-8")
    corpus = _FixtureCorpus(tmp_path)
    scan = corpus._scan_workload_files
    first_scan = True

    def mutate_after_scan(root):
        nonlocal first_scan
        files = scan(root)
        if first_scan:
            first_scan = False
            path.write_text("changed while hashing", encoding="utf-8")
        return files

    monkeypatch.setattr(corpus, "_scan_workload_files", mutate_after_scan)
    with pytest.raises(RuntimeError, match="changed while being snapshotted"):
        corpus.workload_snapshot()


def test_workload_hash_rejects_absent_root(tmp_path):
    """Guards workload hash rejects absent root; prevents this evidence regression from false-passing or crashing."""
    with pytest.raises(FileNotFoundError, match="scan root does not exist"):
        _FixtureCorpus(tmp_path / "absent").info()


def test_workload_hash_rejects_symlink(tmp_path):
    """Guards workload hash rejects symlink; prevents this evidence regression from false-passing or crashing."""
    target = tmp_path / "target.txt"
    target.write_text("secret", encoding="utf-8")
    try:
        (tmp_path / "input.txt").symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="must not contain symlinks"):
        _FixtureCorpus(tmp_path).info()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_workload_hash_rejects_special_file(tmp_path):
    """Guards workload hash rejects special file; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "input.txt").write_text("secret", encoding="utf-8")
    os.mkfifo(tmp_path / "pipe")

    with pytest.raises(ValueError, match="only regular files"):
        _FixtureCorpus(tmp_path).info()


def test_workload_hash_rejects_duplicate_unicode_normalized_paths(tmp_path):
    """Guards workload hash rejects duplicate unicode normalized paths; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "input.txt").write_text("secret", encoding="utf-8")
    (tmp_path / "\N{LATIN SMALL LETTER E WITH ACUTE}").write_text(
        "one", encoding="utf-8"
    )
    (tmp_path / "e\N{COMBINING ACUTE ACCENT}").write_text(
        "two", encoding="utf-8"
    )

    with pytest.raises(ValueError, match="duplicate normalized path"):
        _FixtureCorpus(tmp_path).info()
