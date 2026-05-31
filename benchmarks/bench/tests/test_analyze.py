import pathlib

from bench import __main__ as bench_main
from bench import analyze as analyze_mod
from bench.corpora.base import LabeledRecord
from bench.schema import ScannerConfig


class FakeCorpus:
    name = "fake"

    def __init__(self, root: pathlib.Path, records: list[LabeledRecord]):
        self.root = root
        self.scan_root = root
        self.file_root = root
        self._records = records

    def records(self) -> list[LabeledRecord]:
        return self._records


class FakeScanner:
    binary = "fake-scanner"

    def __init__(self, findings: list[dict]):
        self._findings = findings

    def available(self) -> bool:
        return True

    def default_config(self) -> ScannerConfig:
        return ScannerConfig()

    def run(self, root: pathlib.Path, cfg: ScannerConfig):
        return self._findings, None


def test_analyze_groups_false_negatives_and_false_positives(monkeypatch, tmp_path):
    records = [
        LabeledRecord("hit", "real-secret", True, "api-key", "hit.env"),
        LabeledRecord("miss", "missed-secret", True, "api-key", "miss.env"),
        LabeledRecord("neg", "not-a-secret", False, "negative", "neg.env"),
        LabeledRecord("ignore", "template-secret", True, "template", "ignore.env", ignore=True),
    ]
    corpus = FakeCorpus(tmp_path, records)
    findings = [
        {"file": str(tmp_path / "hit.env"), "value": "real-secret", "detector": "api"},
        {"file": str(tmp_path / "neg.env"), "value": "wrong-value", "detector": "generic"},
        {"file": str(tmp_path / "ignore.env"), "value": "template-secret", "detector": "api"},
        {"file": str(tmp_path / "unknown.env"), "value": "orphan", "detector": "generic"},
    ]

    monkeypatch.setattr(analyze_mod, "resolve_corpus_with_root", lambda *args, **kwargs: corpus)
    monkeypatch.setattr(
        analyze_mod,
        "resolve_scanner",
        lambda *args, **kwargs: FakeScanner(findings),
    )

    report = analyze_mod.analyze("keyhog", "fake")

    assert [r.id for r in report["fn"]["api-key"]] == ["miss"]
    assert report["fp"]["negative"] == [findings[1]]
    assert report["fp"]["unknown"] == [findings[3]]
    assert "template" not in report["fp"]


def test_main_wires_analyze_command(monkeypatch, capsys):
    seen = {}

    def fake_analyze(scanner, corpus, *, corpus_root=None, scanner_binary=None):
        seen.update(
            {
                "scanner": scanner,
                "corpus": corpus,
                "corpus_root": corpus_root,
                "scanner_binary": scanner_binary,
            }
        )
        return {"fn": {"api-key": [object()]}, "fp": {"unknown": [object(), object()]}}

    monkeypatch.setattr(bench_main, "analyze_examples", fake_analyze)
    monkeypatch.setattr(bench_main, "print_report", lambda report, top: seen.update({"top": top}))

    code = bench_main.main(
        [
            "analyze",
            "--scanner",
            "keyhog",
            "--corpus",
            "mirror",
            "--scanner-bin",
            "/tmp/keyhog",
            "--corpus-root",
            "/tmp/corpus",
            "--top",
            "3",
        ]
    )

    assert code == 0
    assert seen == {
        "scanner": "keyhog",
        "corpus": "mirror",
        "corpus_root": "/tmp/corpus",
        "scanner_binary": "/tmp/keyhog",
        "top": 3,
    }
    assert "1 missed positives, 2 false fires" in capsys.readouterr().err
