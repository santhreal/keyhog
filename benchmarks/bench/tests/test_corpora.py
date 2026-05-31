import csv
import json

from bench import hardware
from bench.corpora import resolve_corpus
from bench.corpora.creddata import CredDataCorpus
from bench.corpora.mirror import MirrorCorpus


def test_mirror_corpus_loads_manifest_jsonl(tmp_path):
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "id": "one",
                "secret": "secret-one",
                "label": True,
                "category": "api",
                "on_disk_path": "one.txt",
                "start_line": 2,
                "end_line": 2,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "one.txt").write_text("secret-one\n", encoding="utf-8")

    corpus = MirrorCorpus(corpus_dir=tmp_path)
    records = corpus.records()

    assert records[0].id == "one"
    assert records[0].label is True
    assert corpus.info().labeled_positives == 1


def test_creddata_corpus_loads_csv_and_ignores_templates(tmp_path):
    manifest = tmp_path / "manifest.csv"
    with open(manifest, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["id", "Secret", "Label", "Category", "Path", "line"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "id": "positive",
                "Secret": "live-secret",
                "Label": "positive",
                "Category": "token",
                "Path": "positive.txt",
                "line": "7",
            }
        )
        writer.writerow(
            {
                "id": "template",
                "Secret": "PLACEHOLDER",
                "Label": "Template",
                "Category": "fixture",
                "Path": "template.txt",
                "line": "9",
            }
        )

    corpus = CredDataCorpus(root=tmp_path)
    records = corpus.records()

    assert records[0].label is True
    assert records[0].line_start == 7
    assert records[1].ignore is True
    assert corpus.info().labeled_positives == 1


def test_resolve_corpus_known_adapters(tmp_path):
    assert resolve_corpus("mirror", corpus_dir=tmp_path).name == "mirror"
    assert resolve_corpus("creddata", root=tmp_path).name == "creddata"
    assert resolve_corpus("kernel", root=tmp_path).name == "kernel"


def test_hardware_capture_is_json_serializable():
    payload = hardware.capture().to_json()
    assert "hostname_hash" in payload
    assert "cores" in payload
