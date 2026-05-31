import json
import sqlite3

from bench import scanners


def test_keyhog_normalizer_reads_json_array_shape():
    data = [
        {
            "detector_id": "github-classic-pat",
            "credential_redacted": "ghp_secret",
            "location": {"file_path": "secret.env", "line": 4},
        }
    ]

    assert scanners._normalize_keyhog(data) == [
        {
            "file": "secret.env",
            "line": 4,
            "value": "ghp_secret",
            "detector": "github-classic-pat",
        }
    ]


def test_betterleaks_normalizer_reads_gitleaks_json_shape():
    data = [{"File": "a.env", "StartLine": 2, "Secret": "sekret", "RuleID": "aws"}]

    assert scanners._normalize_betterleaks(data) == [
        {"file": "a.env", "line": 2, "value": "sekret", "detector": "aws"}
    ]


def test_kingfisher_normalizer_skips_summary_lines():
    text = "\n".join(
        [
            json.dumps(
                {
                    "rule": {"id": "np.github.1"},
                    "finding": {"path": "a.env", "line": 3, "snippet": "ghp_secret"},
                }
            ),
            json.dumps({"findings": 1, "blobs_scanned": 1}),
        ]
    )

    assert scanners._normalize_kingfisher_jsonl(text) == [
        {"file": "a.env", "line": 3, "value": "ghp_secret", "detector": "np.github.1"}
    ]


def test_noseyparker_normalizer_reads_report_json_shape():
    data = [
        {
            "rule_text_id": "np.github.1",
            "matches": [
                {
                    "provenance": [{"kind": "file", "path": "/tmp/a.env"}],
                    "location": {"source_span": {"start": {"line": 5}}},
                    "snippet": {"matching": "ghp_secret"},
                }
            ],
        }
    ]

    assert scanners._normalize_nosey_report(data) == [
        {"file": "/tmp/a.env", "line": 5, "value": "ghp_secret", "detector": "np.github.1"}
    ]


def test_titus_normalizer_reads_datastore_sqlite(tmp_path):
    db = tmp_path / "datastore.db"
    with sqlite3.connect(db) as con:
        con.executescript(
            """
            create table matches (
              id integer primary key,
              blob_id text not null,
              rule_id text not null,
              start_line integer,
              snippet_matching blob
            );
            create table provenance (
              id integer primary key,
              blob_id text not null,
              path text
            );
            insert into matches(blob_id, rule_id, start_line, snippet_matching)
              values ('blob-1', 'np.github.1', 7, X'6768705F736563726574');
            insert into provenance(blob_id, path) values ('blob-1', '/tmp/a.env');
            """
        )

    assert scanners._normalize_titus_datastore(db) == [
        {"file": "/tmp/a.env", "line": 7, "value": "ghp_secret", "detector": "np.github.1"}
    ]


def test_requested_competitor_adapters_are_registered():
    assert {"betterleaks", "kingfisher", "noseyparker", "titus"}.issubset(scanners.SCANNERS)


def test_requested_competitor_adapters_resolve_to_measured_scanners():
    for name in ["betterleaks", "kingfisher", "noseyparker", "titus"]:
        scanner = scanners.resolve_scanner(name)
        cfg = scanner.default_config()

        assert scanner.name == name
        assert cfg.backend == "default"
        assert cfg.cache == "off"
        assert cfg.daemon == "off"
