import builtins
import csv
import json
import pathlib

from bench import hardware
from bench.corpora import resolve_corpus
from bench.corpora.creddata import CredDataCorpus
from bench.corpora.homefield import HomefieldCorpus
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


def test_mirror_corpus_scans_neutral_tree_without_manifest(tmp_path):
    # Split layout: the answer key (manifest.jsonl) sits at the home root,
    # while the scan tree is a NEUTRALLY-NAMED subdir ("corpus", never
    # "fixtures"/"test"). Two regressions are pinned here:
    #   1. scan_root excludes the manifest (no scanner sees the answer key).
    #   2. the scan dir name does not trip keyhog's path-based test-fixture
    #      confidence penalty (same 15k files: 1880 findings under
    #      "fixtures/" vs 2484 under a neutral name; --no-suppress-test-
    #      fixtures does NOT override that penalty).
    scan = tmp_path / "corpus"
    shard = scan / "aa"
    shard.mkdir(parents=True)
    (shard / "one.txt").write_text("secret-one\n", encoding="utf-8")
    manifest = tmp_path / "manifest.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "id": "one",
                "secret": "secret-one",
                "label": True,
                "category": "api",
                "on_disk_path": "aa/one.txt",
                "start_line": 2,
                "end_line": 2,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    corpus = MirrorCorpus(corpus_dir=tmp_path)

    assert corpus.scan_root == scan
    assert corpus.file_root == scan
    assert "fixtures" not in corpus.scan_root.name  # no test-context penalty
    assert not (corpus.scan_root / "manifest.jsonl").exists()  # answer key excluded
    assert corpus.info().fixture_count == 1


def test_mirror_ensure_lifts_existing_manifest_out_of_scan_tree(tmp_path):
    scan = tmp_path / "corpus"
    scan.mkdir()
    (scan / "manifest.jsonl").write_text("", encoding="utf-8")
    (scan / "manifest.sha256").write_text("hash\n", encoding="utf-8")

    corpus = MirrorCorpus(corpus_dir=tmp_path)
    corpus.ensure()

    assert (tmp_path / "manifest.jsonl").exists()
    assert (tmp_path / "manifest.sha256").exists()
    assert not (scan / "manifest.jsonl").exists()
    assert not (scan / "manifest.sha256").exists()


def test_homefield_corpus_scans_neutral_tree_without_manifest(tmp_path):
    scan = tmp_path / "corpus"
    shard = scan / "aa"
    shard.mkdir(parents=True)
    (shard / "one.txt").write_text("secret-one\n", encoding="utf-8")
    (tmp_path / "manifest.jsonl").write_text(
        json.dumps(
            {
                "id": "one",
                "secret": "secret-one",
                "label": True,
                "category": "api",
                "on_disk_path": "aa/one.txt",
                "start_line": 1,
                "end_line": 1,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    corpus = HomefieldCorpus(turf="betterleaks", corpus_dir=tmp_path)

    assert corpus.scan_root == scan
    assert corpus.file_root == scan
    assert not (corpus.scan_root / "manifest.jsonl").exists()
    assert corpus.info().fixture_count == 1


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


def test_creddata_native_meta_reuses_file_reads(tmp_path, monkeypatch):
    meta = tmp_path / "meta"
    data_dir = tmp_path / "data" / "repo-one"
    meta.mkdir()
    data_dir.mkdir(parents=True)
    source = data_dir / "settings.txt"
    source.write_text(
        "alpha SECRET_ONE tail\n"
        "beta SECRET_TWO tail\n",
        encoding="latin-1",
    )
    with open(meta / "repo-one.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "Id",
                "FileID",
                "Domain",
                "RepoName",
                "FilePath",
                "LineStart",
                "LineEnd",
                "GroundTruth",
                "ValueStart",
                "ValueEnd",
                "CryptographyKey",
                "PredefinedPattern",
                "Category",
            ],
        )
        writer.writeheader()
        writer.writerow(
            {
                "Id": "1",
                "FileID": "settings",
                "FilePath": "data/repo-one/settings.txt",
                "LineStart": "1",
                "LineEnd": "1",
                "GroundTruth": "T",
                "ValueStart": "6",
                "ValueEnd": "16",
                "Category": "Auth:Token",
            }
        )
        writer.writerow(
            {
                "Id": "2",
                "FileID": "settings",
                "FilePath": "data/repo-one/settings.txt",
                "LineStart": "2",
                "LineEnd": "2",
                "GroundTruth": "T",
                "ValueStart": "5",
                "ValueEnd": "15",
                "Category": "Auth:Token",
            }
        )

    real_open = builtins.open
    source_opens = []

    def counting_open(path, *args, **kwargs):
        if pathlib.Path(path) == source:
            source_opens.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    records = CredDataCorpus(root=tmp_path).records()

    assert [record.secret for record in records] == ["SECRET_ONE", "SECRET_TWO"]
    assert len(source_opens) == 1


def test_creddata_recovers_multiline_and_split_drift_positives(tmp_path):
    """Two slicer bugs each silently dropped real positives from the ground
    truth (undercounting recall + starving the MoE retrain):

    * ValueStart == -1 marks a WHOLE-LINE multi-line span (PEM/RSA private keys,
      1003 CredData positives) — the old `value_start < 0 -> return ""` guard
      dropped every one.
    * `str.splitlines()` breaks on \\v \\f \\x1c-\\x1e \\x85 U+2028 U+2029, which
      CredData's `\\n`-based LineStart does not, drifting the line index so the
      labeled line no longer held the secret (181 CredData positives).

    Both are asserted with EXACT recovered values, not just a non-empty count.
    """
    data_dir = tmp_path / "data" / "repo"
    (tmp_path / "meta").mkdir()
    data_dir.mkdir(parents=True)

    # (1) multi-line PEM key, ValueStart/ValueEnd = -1 (whole-line span).
    pem_body = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIFakeKeyMaterialLine0000\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    (data_dir / "id.pem").write_text(pem_body, encoding="latin-1")
    # (2) a NEL (U+0085) before the labeled line: splitlines() would make the
    #     secret land on line 3, '\n'-counting keeps it on line 2.
    (data_dir / "drift.env").write_text(
        "pre\x85post\nkey = DRIFTSECRET tail\n", encoding="latin-1"
    )

    fields = [
        "Id", "FilePath", "LineStart", "LineEnd",
        "GroundTruth", "ValueStart", "ValueEnd", "Category",
    ]
    with open(tmp_path / "meta" / "repo.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerow({
            "Id": "pem", "FilePath": "data/repo/id.pem",
            "LineStart": "1", "LineEnd": "3", "GroundTruth": "T",
            "ValueStart": "-1", "ValueEnd": "-1", "Category": "PEM Private Key",
        })
        writer.writerow({
            "Id": "drift", "FilePath": "data/repo/drift.env",
            "LineStart": "2", "LineEnd": "2", "GroundTruth": "T",
            "ValueStart": "6", "ValueEnd": "17", "Category": "Password",
        })

    records = CredDataCorpus(root=tmp_path).records()
    by_id = {r.id: r for r in records}
    # both survive (neither dropped as "unextractable")
    assert len(records) == 2, [r.secret for r in records]

    pem = next(r for r in records if r.category == "PEM Private Key")
    assert pem.secret == (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIFakeKeyMaterialLine0000\n"
        "-----END RSA PRIVATE KEY-----"
    )

    drift = next(r for r in records if r.category == "Password")
    assert drift.secret == "DRIFTSECRET"


def test_resolve_corpus_known_adapters(tmp_path):
    assert resolve_corpus("mirror", corpus_dir=tmp_path).name == "mirror"
    assert resolve_corpus("creddata", root=tmp_path).name == "creddata"
    assert resolve_corpus("kernel", root=tmp_path).name == "kernel"


def test_hardware_capture_is_json_serializable():
    payload = hardware.capture().to_json()
    assert "hostname_hash" in payload
    assert "cores" in payload
