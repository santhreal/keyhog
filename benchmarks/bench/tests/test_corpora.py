import builtins
import csv
import json
import pathlib
import os

import pytest


from bench import hardware
from bench.corpora import resolve_corpus
from bench.corpora.creddata import CredDataCorpus
from bench.corpora.homefield import HomefieldCorpus
from bench.corpora.mirror import MirrorCorpus
from bench.corpora.perf_corpus import DaemonFileCorpus


def test_daemon_file_corpus_measures_exact_input_file(tmp_path):
    """Guards daemon file corpus measures exact input file; prevents this evidence regression from false-passing or crashing."""
    input_file = tmp_path / "workload.bin"
    input_file.write_bytes(b"benchmark bytes")

    corpus = DaemonFileCorpus(input_file)
    info = corpus.info()

    assert corpus.scan_root == input_file
    assert corpus.records() == []
    assert info.fixture_count == 1
    assert info.bytes == len(b"benchmark bytes")


def test_mirror_corpus_loads_manifest_jsonl(tmp_path):
    """Guards mirror corpus loads manifest jsonl; prevents this evidence regression from false-passing or crashing."""
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
    """Guards mirror corpus scans neutral tree without manifest; prevents this evidence regression from false-passing or crashing."""
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
    """Guards mirror ensure lifts existing manifest out of scan tree; prevents this evidence regression from false-passing or crashing."""
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
    """Guards homefield corpus scans neutral tree without manifest; prevents this evidence regression from false-passing or crashing."""
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
                "source_tool": "betterleaks",
                "source_version": "v1.6.1",
                "source_commit": "a" * 40,
                "source_rules_sha256": "b" * 64,
                "file_type": "txt",
                "on_disk_path": "aa/one.txt",
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


def _mirror_row(**changes):
    row = {
        "id": "one",
        "secret": "secret-one",
        "label": True,
        "category": "api",
        "on_disk_path": "one.txt",
        "start_line": 1,
        "end_line": 1,
    }
    row.update(changes)
    return row


def _write_mirror_manifest(root, *rows):
    (root / "manifest.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_mirror_manifest_rejects_string_label_false_positive(tmp_path):
    """Guards mirror manifest rejects string label false positive; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "one.txt").write_text("secret-one", encoding="utf-8")
    _write_mirror_manifest(tmp_path, _mirror_row(label="false"))

    with pytest.raises(ValueError, match="field 'label'.*expected"):
        MirrorCorpus(corpus_dir=tmp_path).records()


@pytest.mark.parametrize(
    "missing",
    ["secret", "label", "category", "on_disk_path", "start_line", "end_line"],
)
def test_mirror_manifest_rejects_missing_scoring_fields(tmp_path, missing):
    """Guards mirror manifest rejects missing scoring fields; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "one.txt").write_text("secret-one", encoding="utf-8")
    row = _mirror_row()
    del row[missing]
    _write_mirror_manifest(tmp_path, row)

    with pytest.raises(ValueError, match="missing required fields"):
        MirrorCorpus(corpus_dir=tmp_path).records()


@pytest.mark.parametrize(
    ("field", "value"),
    [("id", 1), ("secret", False), ("category", 7), ("start_line", "1")],
)
def test_mirror_manifest_rejects_non_exact_string_and_int_types(
    tmp_path, field, value
):
    """Guards mirror manifest rejects non exact string and int types; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "one.txt").write_text("secret-one", encoding="utf-8")
    _write_mirror_manifest(tmp_path, _mirror_row(**{field: value}))

    with pytest.raises(ValueError, match=f"field '{field}'.*expected"):
        MirrorCorpus(corpus_dir=tmp_path).records()


def test_mirror_manifest_rejects_unknown_fields_and_unsafe_paths(tmp_path):
    """Guards mirror manifest rejects unknown fields and unsafe paths; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "one.txt").write_text("secret-one", encoding="utf-8")
    _write_mirror_manifest(tmp_path, _mirror_row(unexpected="silent-default"))
    with pytest.raises(ValueError, match="unknown fields"):
        MirrorCorpus(corpus_dir=tmp_path).records()

    outside = tmp_path.parent / "outside.txt"
    outside.write_text("secret-one", encoding="utf-8")
    _write_mirror_manifest(tmp_path, _mirror_row(on_disk_path="../outside.txt"))
    with pytest.raises(ValueError, match="unsafe path"):
        MirrorCorpus(corpus_dir=tmp_path).records()


def test_mirror_manifest_rejects_duplicate_ids_and_paths(tmp_path):
    """Guards mirror manifest rejects duplicate ids and paths; prevents this evidence regression from false-passing or crashing."""
    (tmp_path / "one.txt").write_text("secret-one", encoding="utf-8")
    (tmp_path / "two.txt").write_text("secret-two", encoding="utf-8")
    _write_mirror_manifest(
        tmp_path,
        _mirror_row(),
        _mirror_row(id="one", on_disk_path="two.txt"),
    )
    with pytest.raises(ValueError, match="duplicate record id"):
        MirrorCorpus(corpus_dir=tmp_path).records()

    _write_mirror_manifest(
        tmp_path,
        _mirror_row(),
        _mirror_row(id="two", secret="secret-two"),
    )
    with pytest.raises(ValueError, match="duplicate fixture path"):
        MirrorCorpus(corpus_dir=tmp_path).records()


def test_mirror_manifest_requires_regular_non_symlink_fixture(tmp_path):
    """Guards mirror manifest requires regular non symlink fixture; prevents this evidence regression from false-passing or crashing."""
    target = tmp_path / "target.txt"
    target.write_text("secret-one", encoding="utf-8")
    link = tmp_path / "one.txt"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")
    _write_mirror_manifest(tmp_path, _mirror_row())

    with pytest.raises(ValueError, match="must not traverse a symlink"):
        MirrorCorpus(corpus_dir=tmp_path).records()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_mirror_manifest_rejects_special_fixture(tmp_path):
    """Guards mirror manifest rejects special fixture; prevents this evidence regression from false-passing or crashing."""
    os.mkfifo(tmp_path / "one.txt")
    _write_mirror_manifest(tmp_path, _mirror_row())

    with pytest.raises(ValueError, match="must be a regular file"):
        MirrorCorpus(corpus_dir=tmp_path).records()


def _creddata_manifest_row(**changes):
    row = {
        "id": "one",
        "secret": "live-secret",
        "label": True,
        "category": "token",
        "on_disk_path": "one.txt",
        "start_line": 1,
        "end_line": 1,
    }
    row.update(changes)
    return row


def _write_creddata_jsonl(root, *rows):
    (root / "manifest.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def _native_creddata_row(**changes):
    row = {
        "Id": "1",
        "FileID": "one",
        "Domain": "GitHub",
        "RepoName": "repo",
        "FilePath": "data/repo/one.txt",
        "LineStart": "1",
        "LineEnd": "1",
        "GroundTruth": "T",
        "ValueStart": "0",
        "ValueEnd": "11",
        "CryptographyKey": "",
        "PredefinedPattern": "",
        "Category": "Token",
    }
    row.update(changes)
    return row


def _write_native_creddata(root, *rows, fieldnames=None):
    meta = root / "meta"
    meta.mkdir(exist_ok=True)
    selected_fields = fieldnames or list(_native_creddata_row())
    with (meta / "repo.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=selected_fields, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)


def test_creddata_corpus_loads_canonical_typed_csv(tmp_path):
    """Canonical CSV booleans and integers decode without legacy aliases."""
    (tmp_path / "positive.txt").write_text("live-secret", encoding="utf-8")
    (tmp_path / "template.txt").write_text("PLACEHOLDER", encoding="utf-8")
    manifest = tmp_path / "manifest.csv"
    fields = list(_creddata_manifest_row(ignore=False))
    with manifest.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                **_creddata_manifest_row(on_disk_path="positive.txt"),
                "label": "true",
                "ignore": "false",
                "start_line": "7",
                "end_line": "7",
            }
        )
        writer.writerow(
            {
                **_creddata_manifest_row(
                    id="template",
                    secret="PLACEHOLDER",
                    category="fixture",
                    on_disk_path="template.txt",
                ),
                "label": "false",
                "ignore": "true",
                "start_line": "9",
                "end_line": "9",
            }
        )

    corpus = CredDataCorpus(root=tmp_path)
    records = corpus.records()

    assert records[0].label is True
    assert records[0].line_start == 7
    assert records[1].ignore is True
    assert corpus.info().labeled_positives == 1


def test_creddata_jsonl_rejects_string_label_false(tmp_path):
    """A JSON string ``"false"`` cannot silently become a negative label."""
    (tmp_path / "one.txt").write_text("live-secret", encoding="utf-8")
    _write_creddata_jsonl(tmp_path, _creddata_manifest_row(label="false"))

    with pytest.raises(ValueError, match="field 'label'.*expected"):
        CredDataCorpus(root=tmp_path).records()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 1),
        ("secret", False),
        ("start_line", "1"),
        ("end_line", True),
        ("ignore", "false"),
    ],
)
def test_creddata_jsonl_rejects_coerced_manifest_types(tmp_path, field, value):
    """JSON values must have the exact canonical type for every known field."""
    (tmp_path / "one.txt").write_text("live-secret", encoding="utf-8")
    row = _creddata_manifest_row(ignore=False)
    row[field] = value
    _write_creddata_jsonl(tmp_path, row)

    with pytest.raises(ValueError, match=f"field '{field}'.*expected"):
        CredDataCorpus(root=tmp_path).records()


@pytest.mark.parametrize(
    "missing",
    ["id", "secret", "label", "category", "on_disk_path", "start_line", "end_line"],
)
def test_creddata_jsonl_rejects_missing_manifest_fields(tmp_path, missing):
    """Every scoring and fixture-identity field is mandatory in JSONL."""
    (tmp_path / "one.txt").write_text("live-secret", encoding="utf-8")
    row = _creddata_manifest_row()
    del row[missing]
    _write_creddata_jsonl(tmp_path, row)

    with pytest.raises(ValueError, match="missing required fields"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_manifests_reject_unknown_fields_and_noncanonical_csv(tmp_path):
    """Unknown JSONL keys and loosely spelled CSV scalars fail closed."""
    (tmp_path / "one.txt").write_text("live-secret", encoding="utf-8")
    _write_creddata_jsonl(
        tmp_path, _creddata_manifest_row(unexpected="silent-default")
    )
    with pytest.raises(ValueError, match="unknown fields"):
        CredDataCorpus(root=tmp_path).records()

    (tmp_path / "manifest.jsonl").unlink()
    row = _creddata_manifest_row()
    with (tmp_path / "manifest.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow({**row, "label": "False", "start_line": "1", "end_line": "1"})
    with pytest.raises(ValueError, match="field 'label'.*invalid bool"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_parquet_requires_native_typed_columns(tmp_path):
    """Parquet string labels are rejected instead of truthiness-coerced."""
    parquet = pytest.importorskip("pyarrow.parquet")
    pyarrow = pytest.importorskip("pyarrow")
    (tmp_path / "one.txt").write_text("live-secret", encoding="utf-8")
    table = pyarrow.Table.from_pylist([_creddata_manifest_row(label="false")])
    parquet.write_table(table, tmp_path / "manifest.parquet")

    with pytest.raises(ValueError, match="field 'label'.*expected"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_manifest_rejects_unsafe_and_duplicate_identities(tmp_path):
    """Escaping fixture paths and duplicate record identities are rejected."""
    (tmp_path / "one.txt").write_text("live-secret", encoding="utf-8")
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("live-secret", encoding="utf-8")
    _write_creddata_jsonl(
        tmp_path, _creddata_manifest_row(on_disk_path="../outside.txt")
    )
    with pytest.raises(ValueError, match="unsafe path"):
        CredDataCorpus(root=tmp_path).records()

    _write_creddata_jsonl(
        tmp_path,
        _creddata_manifest_row(),
        _creddata_manifest_row(id="one"),
    )
    with pytest.raises(ValueError, match="duplicate record id"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_manifest_requires_regular_non_symlink_fixture(tmp_path):
    """Manifest fixture resolution rejects symlinks before scanner evidence."""
    target = tmp_path / "target.txt"
    target.write_text("live-secret", encoding="utf-8")
    try:
        (tmp_path / "one.txt").symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")
    _write_creddata_jsonl(tmp_path, _creddata_manifest_row())

    with pytest.raises(ValueError, match="must not traverse a symlink"):
        CredDataCorpus(root=tmp_path).records()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_creddata_manifest_rejects_special_fixture(tmp_path):
    """Manifest fixture paths must terminate at regular files, not FIFOs."""
    os.mkfifo(tmp_path / "one.txt")
    _write_creddata_jsonl(tmp_path, _creddata_manifest_row())

    with pytest.raises(ValueError, match="must be a regular file"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_native_meta_reuses_file_reads(tmp_path, monkeypatch):
    """Guards creddata native meta reuses file reads; prevents this evidence regression from false-passing or crashing."""
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
                **_native_creddata_row(
                    FilePath="data/repo-one/settings.txt",
                    FileID="settings",
                    RepoName="repo-one",
                    Category="Auth:Token",
                    ValueStart="6",
                    ValueEnd="16",
                ),
            }
        )
        writer.writerow(
            {
                **_native_creddata_row(
                    Id="2",
                    FilePath="data/repo-one/settings.txt",
                    FileID="settings",
                    RepoName="repo-one",
                    LineStart="2",
                    LineEnd="2",
                    Category="Auth:Token",
                    ValueStart="5",
                    ValueEnd="15",
                ),
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
      1003 CredData positives): the old `value_start < 0 -> return ""` guard
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

    _write_native_creddata(
        tmp_path,
        _native_creddata_row(
            Id="pem",
            FileID="id.pem",
            FilePath="data/repo/id.pem",
            LineStart="1",
            LineEnd="3",
            ValueStart="-1",
            ValueEnd="-1",
            Category="PEM Private Key",
        ),
        _native_creddata_row(
            Id="drift",
            FileID="drift.env",
            FilePath="data/repo/drift.env",
            LineStart="2",
            LineEnd="2",
            ValueStart="6",
            ValueEnd="17",
            Category="Password",
        ),
    )

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


def test_creddata_native_ground_truth_domain_and_x_policy(tmp_path):
    """Only T/F/X are valid, and configured X handling controls ignore state."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    (data_dir / "one.txt").write_text("live-secret", encoding="latin-1")
    _write_native_creddata(
        tmp_path,
        _native_creddata_row(GroundTruth="X", ValueStart="", ValueEnd=""),
    )

    assert CredDataCorpus(root=tmp_path).records()[0].ignore is False
    assert (
        CredDataCorpus(root=tmp_path, treat_x="ignore").records()[0].ignore is True
    )

    _write_native_creddata(
        tmp_path,
        _native_creddata_row(GroundTruth="unknown"),
    )
    with pytest.raises(ValueError, match="must be exactly T, F, or X"):
        CredDataCorpus(root=tmp_path).records()


@pytest.mark.parametrize("ground_truth", ["t", "false", "Y"])
def test_creddata_native_rejects_coerced_truth_labels(tmp_path, ground_truth):
    """Case folding and truthy spellings cannot relabel native metadata."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    (data_dir / "one.txt").write_text("live-secret", encoding="latin-1")
    _write_native_creddata(
        tmp_path,
        _native_creddata_row(GroundTruth=ground_truth),
    )

    with pytest.raises(ValueError, match="must be exactly T, F, or X"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_native_requires_exact_columns_and_integer_types(tmp_path):
    """Native headers and coordinate text must match CredData's exact schema."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    (data_dir / "one.txt").write_text("live-secret", encoding="latin-1")
    missing_column = [
        field for field in _native_creddata_row() if field != "Category"
    ]
    _write_native_creddata(
        tmp_path, _native_creddata_row(), fieldnames=missing_column
    )
    with pytest.raises(ValueError, match="exactly the native CredData columns"):
        CredDataCorpus(root=tmp_path).records()

    _write_native_creddata(
        tmp_path,
        _native_creddata_row(LineStart=" 1"),
    )
    with pytest.raises(ValueError, match="invalid integer value"):
        CredDataCorpus(root=tmp_path).records()


@pytest.mark.parametrize("empty_field", ["Id", "FileID", "Domain", "FilePath"])
def test_creddata_native_rejects_empty_required_values(tmp_path, empty_field):
    """Identity and fixture fields cannot silently default or disappear."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    (data_dir / "one.txt").write_text("live-secret", encoding="latin-1")
    _write_native_creddata(
        tmp_path,
        _native_creddata_row(**{empty_field: ""}),
    )

    with pytest.raises(ValueError, match="empty required fields"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_native_rejects_unsafe_paths_and_duplicate_ids(tmp_path):
    """Native fixture paths stay contained and annotation IDs stay unique."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    (data_dir / "one.txt").write_text("live-secret", encoding="latin-1")
    _write_native_creddata(
        tmp_path,
        _native_creddata_row(FilePath="../outside.txt"),
    )
    with pytest.raises(ValueError, match="unsafe path"):
        CredDataCorpus(root=tmp_path).records()

    _write_native_creddata(
        tmp_path,
        _native_creddata_row(GroundTruth="F"),
        _native_creddata_row(GroundTruth="F"),
    )
    with pytest.raises(ValueError, match="duplicate record id"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_native_requires_regular_non_symlink_fixture(tmp_path):
    """Native metadata cannot traverse a symlink to source outside its tree."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    target = tmp_path / "target.txt"
    target.write_text("live-secret", encoding="latin-1")
    try:
        (data_dir / "one.txt").symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")
    _write_native_creddata(tmp_path, _native_creddata_row())

    with pytest.raises(ValueError, match="must not traverse a symlink"):
        CredDataCorpus(root=tmp_path).records()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_creddata_native_rejects_special_fixture(tmp_path):
    """Native metadata cannot label a FIFO as scanner input."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    os.mkfifo(data_dir / "one.txt")
    _write_native_creddata(tmp_path, _native_creddata_row(GroundTruth="F"))

    with pytest.raises(ValueError, match="must be a regular file"):
        CredDataCorpus(root=tmp_path).records()


def test_creddata_native_rejects_unextractable_positive(tmp_path):
    """A positive with an out-of-range span fails instead of being dropped."""
    data_dir = tmp_path / "data" / "repo"
    data_dir.mkdir(parents=True)
    (data_dir / "one.txt").write_text("live-secret", encoding="latin-1")
    _write_native_creddata(
        tmp_path,
        _native_creddata_row(LineStart="2", LineEnd="2"),
    )

    with pytest.raises(ValueError, match="positive has an empty or out-of-range"):
        CredDataCorpus(root=tmp_path).records()


def test_resolve_corpus_known_adapters(tmp_path):
    """Guards resolve corpus known adapters; prevents this evidence regression from false-passing or crashing."""
    assert resolve_corpus("mirror", corpus_dir=tmp_path).name == "mirror"
    assert resolve_corpus("creddata", root=tmp_path).name == "creddata"
    assert resolve_corpus("kernel", root=tmp_path).name == "kernel"


def test_hardware_capture_is_json_serializable():
    """Guards hardware capture is json serializable; prevents this evidence regression from false-passing or crashing."""
    payload = hardware.capture().to_json()
    assert "hostname_hash" in payload
    assert "cores" in payload
