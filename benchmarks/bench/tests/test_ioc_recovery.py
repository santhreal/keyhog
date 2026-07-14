import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from bench.corpora.ioc_recovery import IocRecoveryCorpus
from bench.corpus_integrity import tree_sha256
from bench.generator_checksums import (
    base62_encode_u32,
    crc32_base62,
    crc32_iso_hdlc,
)
from generators.ioc_recovery import generate as ioc_generator

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[2]
_GENERATOR = _BENCH_ROOT / "generators" / "ioc_recovery" / "generate.py"


def test_generator_checksum_primitives_match_independent_oracles():
    assert crc32_iso_hdlc(b"abc") == 891_568_578
    assert base62_encode_u32(891_568_578, 6) == "0yKviM"
    assert crc32_base62("A" * 30) == "0uCPlr"


@pytest.mark.skipif(
    shutil.which("node") is None,
    reason="recovery corpus AES generation requires Node",
)
def test_ioc_recovery_generator_is_deterministic_and_executable(tmp_path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    for output in (left, right):
        subprocess.run(
            [
                sys.executable,
                str(_GENERATOR),
                "--out",
                str(output),
                "--samples",
                "2",
                "--seed",
                "17",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    assert tree_sha256(left) == tree_sha256(right)
    assert not (left / "corpus" / "manifest.jsonl").exists()

    records = [json.loads(line) for line in (left / "manifest.jsonl").read_text().splitlines()]
    assert len(records) == 26
    assert {record["phase"] for record in records} == set(range(13))
    assert {record["match_mode"] for record in records} == {"exact"}
    first_secret = next(
        record["secret"]
        for record in records
        if record["source_id"] == "synthetic-js-0000"
    )
    assert first_secret == "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"
    assert {record["secret"] for record in records} == {
        "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",
        "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",
    }

    metadata = json.loads((left / "corpus.json").read_text())
    assert metadata["schema_version"] == 2
    assert metadata["methodology_url"] == "https://arxiv.org/abs/2605.06910"
    assert metadata["upstream_repository_url"] == (
        "https://github.com/jaimemorales52/llm-ioc-detection"
    )
    assert metadata["upstream_repository_commit"] == (
        "91d45377cf482c1de6c36a0d33744665976a19b6"
    )
    assert metadata["upstream_public_example_count"] == 13
    assert metadata["upstream_evaluation_corpus_published"] is False
    assert metadata["artifact_relationship"] == "methodology-adaptation"
    assert metadata["match_mode"] == "exact"
    assert metadata["credential_shape"] == (
        "checksum-valid synthetic GitHub classic PAT"
    )

    # Execute every phase for one source sample. This proves that Base64, XOR,
    # AES, and combined structural variants recover the exact expected value,
    # not merely that the generator wrote files with plausible names.
    sample_records = [
        record
        for record in records
        if record["source_id"] == "synthetic-js-0000"
    ]
    for record in sample_records:
        source = left / "corpus" / record["on_disk_path"]
        completed = subprocess.run(
            [shutil.which("node"), str(source)],
            check=True,
            capture_output=True,
            text=True,
        )
        assert completed.stdout == record["secret"]


@pytest.mark.skipif(
    shutil.which("node") is None,
    reason="recovery corpus AES generation requires Node",
)
def test_ioc_recovery_adapter_excludes_answer_key_and_loads_exact_records(tmp_path):
    home = tmp_path / "recovery"
    corpus = IocRecoveryCorpus(corpus_dir=home)
    corpus.ensure(samples=1, seed=23)

    records = corpus.records()
    info = corpus.info()

    assert len(records) == 13
    assert info.fixture_count == 13
    assert info.labeled_positives == 13
    assert corpus.scan_root == home / "corpus"
    assert corpus.file_root == corpus.scan_root
    assert corpus.manifest == home / "manifest.jsonl"
    assert all(record.match_mode == "exact" for record in records)
    assert not (corpus.scan_root / "manifest.jsonl").exists()

    with pytest.raises(SystemExit, match="requested 2"):
        corpus.ensure(samples=2, seed=23)

    fixture = corpus.scan_root / records[0].file_path
    fixture.write_text(fixture.read_text() + "\n// modified\n")
    reloaded = IocRecoveryCorpus(corpus_dir=home)
    with pytest.raises(SystemExit, match="scan-tree digest mismatch"):
        reloaded.records()


@pytest.mark.skipif(os.name != "posix", reason="fake sleeping Node uses a POSIX shell")
def test_ioc_recovery_generator_times_out_node_and_removes_staging(
    monkeypatch, tmp_path
):
    fake_node = tmp_path / "node"
    fake_node.write_text("#!/bin/sh\nsleep 30\n")
    fake_node.chmod(0o755)
    output = tmp_path / "recovery"

    monkeypatch.setattr(ioc_generator.shutil, "which", lambda _name: str(fake_node))
    monkeypatch.setattr(ioc_generator, "NODE_AES_TIMEOUT_SECONDS", 0.05)
    with pytest.raises(SystemExit, match=r"exceeded 0.05s and was terminated"):
        ioc_generator.generate(output, samples=1, seed=17)

    assert not output.exists()
    assert list(tmp_path.glob(".recovery-*")) == []


def test_ioc_recovery_timeout_termination_covers_posix_and_windows_branches(
    monkeypatch,
):
    class Stream:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class Process:
        def __init__(self):
            self.pid = 123
            self.stdin = Stream()
            self.stdout = Stream()
            self.stderr = Stream()
            self.killed = False
            self.waited = False

        def kill(self):
            self.killed = True

        def wait(self, timeout):
            assert timeout == ioc_generator.NODE_AES_REAP_SECONDS
            self.waited = True

    killed_groups = []
    monkeypatch.setattr(
        ioc_generator.os,
        "killpg",
        lambda pid, sig: killed_groups.append((pid, sig)),
    )

    posix_process = Process()
    ioc_generator._terminate_process(posix_process, posix=True)
    assert killed_groups == [(123, ioc_generator.signal.SIGKILL)]
    assert not posix_process.killed
    assert posix_process.waited
    assert all(
        stream.closed
        for stream in (
            posix_process.stdin,
            posix_process.stdout,
            posix_process.stderr,
        )
    )

    windows_process = Process()
    ioc_generator._terminate_process(windows_process, posix=False)
    assert windows_process.killed
    assert windows_process.waited
