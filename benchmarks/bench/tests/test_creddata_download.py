"""Regression coverage for CredData downloader scratch cleanup."""

from __future__ import annotations

import pathlib
import subprocess
import sys
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from bench.corpora import creddata


def _install_fake_downloader(
    monkeypatch: pytest.MonkeyPatch,
    clone: pathlib.Path,
    populate: Callable[[pathlib.Path], None],
) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(args, *, check, cwd=None):
        command = [str(value) for value in args]
        calls.append(command)
        if command[:2] == ["git", "clone"]:
            clone.mkdir(parents=True)
            (clone / ".git").mkdir()
            (clone / "download_data.py").write_text("# fixture\n", encoding="utf-8")
        elif command[0] == sys.executable:
            assert cwd == str(clone)
            populate(clone)
        return subprocess.CompletedProcess(command, 0)

    def info(_self):
        assert (clone / "data").is_dir()
        return SimpleNamespace(fixture_count=1, labeled_positives=0)

    monkeypatch.setattr(creddata.CredDataCorpus, "info", info)
    monkeypatch.setattr(creddata.subprocess, "run", run)
    return calls


def test_successful_download_removes_unscored_repository_scratch(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """CredData leaves broken and recursive links under tmp; snapshots must retain only canonical data."""
    clone = tmp_path / "CredData"
    outside = tmp_path / "outside.txt"
    outside.write_text("must survive\n", encoding="utf-8")
    readiness_during_repair: list[tuple[bool, str | None]] = []

    def populate(root: pathlib.Path) -> None:
        corpus = creddata.CredDataCorpus(root=root)
        assert corpus.is_downloaded(require_complete=False) is False
        readiness_during_repair.append(
            (corpus.is_downloaded(), corpus.availability_error)
        )
        (root / "data").mkdir()
        (root / "data" / "fixture.txt").write_text("scanned bytes\n", encoding="utf-8")
        scratch = root / "tmp"
        scratch.mkdir()
        (scratch / "dangling").symlink_to("missing")
        (scratch / "cycle-a").symlink_to("cycle-b")
        (scratch / "cycle-b").symlink_to("cycle-a")
        (scratch / "outside").symlink_to(outside)

    calls = _install_fake_downloader(monkeypatch, clone, populate)
    creddata.CredDataCorpus(root=clone).download()

    assert not (clone / "tmp").exists()
    assert (clone / "data" / "fixture.txt").read_bytes() == b"scanned bytes\n"
    assert outside.read_bytes() == b"must survive\n"
    assert readiness_during_repair == [
        (False, f"CredData repair is incomplete: {clone / '.keyhog-repairing'}")
    ]
    assert not (clone / ".keyhog-repairing").exists()
    assert calls[-1] == [
        sys.executable,
        str(clone / "download_data.py"),
        "--data_dir",
        "data",
        "--clean_data",
        "--jobs",
        "1",
    ]
    assert not any("fetch" in command for command in calls)


def test_successful_download_without_scratch_is_valid(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """An upstream downloader that already cleans tmp must remain a successful, idempotent boundary case."""
    clone = tmp_path / "CredData"

    def populate(root: pathlib.Path) -> None:
        (root / "data").mkdir()
        (root / "data" / "fixture.txt").write_text("canonical\n", encoding="utf-8")

    _install_fake_downloader(monkeypatch, clone, populate)
    creddata.CredDataCorpus(root=clone).download()

    assert (clone / "data" / "fixture.txt").read_bytes() == b"canonical\n"
    assert not (clone / "tmp").exists()


def test_scratch_symlink_fails_closed_without_deleting_target(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """A replaced tmp path must never redirect cleanup into data outside the pinned checkout."""
    clone = tmp_path / "CredData"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep\n", encoding="utf-8")

    def populate(root: pathlib.Path) -> None:
        (root / "data").mkdir()
        (root / "tmp").symlink_to(outside, target_is_directory=True)

    _install_fake_downloader(monkeypatch, clone, populate)

    with pytest.raises(RuntimeError, match="temporary path is not a real directory"):
        creddata.CredDataCorpus(root=clone).download()

    assert (outside / "keep.txt").read_bytes() == b"keep\n"
    assert (clone / "tmp").is_symlink()


def test_failed_downloader_preserves_scratch_for_diagnosis(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """Cleanup must run only after a successful acquisition, so a failed upstream clone remains inspectable."""
    clone = tmp_path / "CredData"

    def run(args, *, check, cwd=None):
        command = [str(value) for value in args]
        if command[:2] == ["git", "clone"]:
            clone.mkdir(parents=True)
            (clone / ".git").mkdir()
            (clone / "download_data.py").write_text("# fixture\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        if command[0] == sys.executable:
            scratch = clone / "tmp"
            scratch.mkdir()
            (scratch / "partial.txt").write_text("partial\n", encoding="utf-8")
            raise subprocess.CalledProcessError(9, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(creddata.subprocess, "run", run)

    with pytest.raises(subprocess.CalledProcessError) as failure:
        creddata.CredDataCorpus(root=clone).download()

    assert failure.value.returncode == 9
    assert (clone / "tmp" / "partial.txt").read_bytes() == b"partial\n"
    corpus = creddata.CredDataCorpus(root=clone)
    assert corpus.is_downloaded() is False
    assert corpus.availability_error == (
        f"CredData repair is incomplete: {clone / '.keyhog-repairing'}"
    )



def test_repair_marker_symlink_fails_closed_without_touching_target(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hostile marker must not redirect repair status writes outside the dataset checkout."""
    clone = tmp_path / "CredData"
    (clone / ".git").mkdir(parents=True)
    (clone / "download_data.py").write_text("# fixture\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep\n", encoding="utf-8")
    (clone / ".keyhog-repairing").symlink_to(outside)

    def populate(_root: pathlib.Path) -> None:
        raise AssertionError("downloader must not run through an unsafe marker")

    _install_fake_downloader(monkeypatch, clone, populate)

    with pytest.raises(RuntimeError, match="marker is not a regular file"):
        creddata.CredDataCorpus(root=clone).download()

    assert outside.read_bytes() == b"keep\n"
    corpus = creddata.CredDataCorpus(root=clone)
    assert corpus.is_downloaded() is False
    assert corpus.availability_error == (
        f"unsafe CredData repair marker: {clone / '.keyhog-repairing'}"
    )


def test_failed_post_download_validation_preserves_repair_checkouts(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """A byte-incomplete rebuilt corpus must keep pinned source clones for diagnosis and retry."""
    clone = tmp_path / "CredData"

    def populate(root: pathlib.Path) -> None:
        (root / "data").mkdir()
        (root / "data" / "fixture.txt").write_text("incomplete\n", encoding="utf-8")
        scratch = root / "tmp"
        scratch.mkdir()
        (scratch / "checkout").mkdir()

    _install_fake_downloader(monkeypatch, clone, populate)

    def fail_validation(_self):
        raise ValueError("manifest fixture missing for record '3756'")

    monkeypatch.setattr(creddata.CredDataCorpus, "info", fail_validation)

    with pytest.raises(ValueError, match="fixture missing"):
        creddata.CredDataCorpus(root=clone).download()

    assert (clone / "tmp" / "checkout").is_dir()
    assert (clone / "data" / "fixture.txt").read_bytes() == b"incomplete\n"

def test_missing_downloader_dependency_fails_without_mutating_python(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """Repair must request a virtual-environment dependency instead of writing into system Python."""
    clone = tmp_path / "CredData"

    def populate(_root: pathlib.Path) -> None:
        raise AssertionError("downloader must not run without pybase62")

    calls = _install_fake_downloader(monkeypatch, clone, populate)
    monkeypatch.setattr(creddata.importlib.util, "find_spec", lambda _name: None)

    with pytest.raises(RuntimeError, match="pybase62==1.0.0.*virtual environment"):
        creddata.CredDataCorpus(root=clone).download()

    assert not any(command[0] == sys.executable for command in calls)


def test_repair_worker_count_must_be_positive(tmp_path: pathlib.Path) -> None:
    """A zero-worker repair must fail before cloning or deleting an existing corpus."""
    root = tmp_path / "CredData"

    with pytest.raises(ValueError, match="at least 1"):
        creddata.CredDataCorpus(root=root).download(jobs=0)

    assert not root.exists()


def test_partial_corpus_is_not_reported_as_downloaded(tmp_path: pathlib.Path) -> None:
    """A nonempty data directory must not make missing manifest fixtures fail during test collection."""
    root = tmp_path / "CredData"
    (root / "data").mkdir(parents=True)
    (root / "data" / "present.txt").write_text("partial\n", encoding="utf-8")
    (root / "meta").mkdir()
    (root / "meta" / "repo.csv").write_text(
        "Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,"
        "ValueStart,ValueEnd,CryptographyKey,PredefinedPattern,Category\n"
        "3756,0fadd2c6,GitHub,repo,data/repo/missing.md,1,1,F,,,,,Key\n",
        encoding="utf-8",
    )

    corpus = creddata.CredDataCorpus(root=root)

    assert corpus.is_downloaded() is False
    assert "manifest fixture missing for record '3756'" in (corpus.availability_error or "")
    assert corpus.is_downloaded(require_complete=False) is True
    assert corpus.availability_error is None

def test_repair_start_during_validation_is_not_reported_ready(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repair that starts during manifest validation must not expose a mixed old/new corpus."""
    root = tmp_path / "CredData"
    (root / "data").mkdir(parents=True)
    (root / "data" / "present.txt").write_text("old\n", encoding="utf-8")
    (root / "meta").mkdir()
    corpus = creddata.CredDataCorpus(root=root)

    def start_repair(_self: creddata.CredDataCorpus) -> list:
        (root / ".keyhog-repairing").write_text("repairing\n", encoding="utf-8")
        return []

    monkeypatch.setattr(creddata.CredDataCorpus, "records", start_repair)

    assert corpus.is_downloaded() is False
    assert corpus.availability_error == (
        f"CredData repair is incomplete: {root / '.keyhog-repairing'}"
    )
