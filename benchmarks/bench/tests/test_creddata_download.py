"""Regression coverage for CredData downloader scratch cleanup."""

from __future__ import annotations

import pathlib
import subprocess
import sys
from collections.abc import Callable

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

    monkeypatch.setattr(creddata.subprocess, "run", run)
    return calls


def test_successful_download_removes_unscored_repository_scratch(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
):
    """CredData leaves broken and recursive links under tmp; snapshots must retain only canonical data."""
    clone = tmp_path / "CredData"
    outside = tmp_path / "outside.txt"
    outside.write_text("must survive\n", encoding="utf-8")

    def populate(root: pathlib.Path) -> None:
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
    assert calls[-1] == [
        sys.executable,
        str(clone / "download_data.py"),
        "--data_dir",
        "data",
    ]


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
