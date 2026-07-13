import importlib.util
import json
import pathlib

import pytest

from bench.corpora.homefield import HomefieldCorpus

_GEN_DIR = (
    pathlib.Path(__file__).resolve().parents[2] / "generators" / "homefield"
)


def _load_generator(name: str):
    path = _GEN_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_betterleaks_generator():
    return _load_generator("harvest_betterleaks")


def _make_rules_dir(root: pathlib.Path) -> None:
    (root / "cmd" / "generate" / "config" / "rules").mkdir(parents=True)


def test_betterleaks_generator_uses_explicit_root(tmp_path, monkeypatch):
    gen = _load_betterleaks_generator()
    root = tmp_path / "betterleaks"
    _make_rules_dir(root)
    monkeypatch.delenv("BETTERLEAKS_ROOT", raising=False)
    monkeypatch.delenv("GOMODCACHE", raising=False)
    monkeypatch.delenv("GOPATH", raising=False)

    assert gen.resolve_betterleaks_root(str(root)) == root


def test_betterleaks_generator_uses_gomodcache_without_user_path(tmp_path, monkeypatch):
    gen = _load_betterleaks_generator()
    module_root = tmp_path / "modcache" / gen.BETTERLEAKS_MODULE
    _make_rules_dir(module_root)
    monkeypatch.delenv("BETTERLEAKS_ROOT", raising=False)
    monkeypatch.setenv("GOMODCACHE", str(tmp_path / "modcache"))
    monkeypatch.delenv("GOPATH", raising=False)

    assert gen.resolve_betterleaks_root() == module_root


def test_betterleaks_generator_failure_names_overrides(tmp_path, monkeypatch):
    gen = _load_betterleaks_generator()
    monkeypatch.delenv("BETTERLEAKS_ROOT", raising=False)
    monkeypatch.delenv("GOMODCACHE", raising=False)
    monkeypatch.setenv("GOPATH", str(tmp_path / "go"))

    try:
        gen.resolve_betterleaks_root(str(tmp_path / "missing"))
    except FileNotFoundError as exc:
        message = str(exc)
    else:
        raise AssertionError("missing betterleaks root must fail closed")

    assert "--betterleaks-root" in message
    assert "BETTERLEAKS_ROOT" in message
    assert str(tmp_path / "missing") in message
    assert str(tmp_path / "go" / "pkg" / "mod" / gen.BETTERLEAKS_MODULE) in message


# ── manifest placement: answer key beside, never inside, the scan tree ──

_SAMPLE_RECORDS = [
    {"id": "xx-00001", "secret": "AKIAIOSFODNN7EXAMPLE", "label": True,
     "category": "aws", "source_tool": "t", "value": "AKIAIOSFODNN7EXAMPLE",
     "file_type": "txt"},
    {"id": "xx-00002", "secret": "", "label": False, "category": "aws",
     "source_tool": "t", "value": "not-a-secret", "file_type": "txt"},
]


def _assert_split_layout(home: pathlib.Path, turf: str) -> None:
    manifest = home / "manifest.jsonl"
    assert manifest.exists(), "manifest must sit at <home>/manifest.jsonl"
    # The scan tree must NOT contain the answer key, a scanner pointed at
    # <home>/corpus would otherwise 'find' every labeled secret in plaintext.
    scan_root = home / "corpus"
    assert scan_root.is_dir()
    assert not (scan_root / "manifest.jsonl").exists()
    assert list(scan_root.rglob("manifest.jsonl")) == []

    rows = [json.loads(line) for line in manifest.read_text().splitlines() if line.strip()]
    assert len(rows) == 2
    assert rows[0]["on_disk_path"] == "01/xx-00001.txt"
    assert (scan_root / "01" / "xx-00001.txt").read_text() == "AKIAIOSFODNN7EXAMPLE"

    # The loader resolves the manifest at <home>/ and the scan tree at <home>/corpus.
    corpus = HomefieldCorpus(turf=turf, corpus_dir=home)
    assert corpus.scan_root == scan_root
    recs = corpus.records()
    assert len(recs) == 2
    positive = next(r for r in recs if r.label)
    assert positive.secret == "AKIAIOSFODNN7EXAMPLE"
    assert positive.file_path == "01/xx-00001.txt"


def test_betterleaks_write_corpus_places_manifest_beside_scan_tree(tmp_path):
    gen = _load_betterleaks_generator()
    gen.write_corpus([dict(r) for r in _SAMPLE_RECORDS], tmp_path)
    _assert_split_layout(tmp_path, "betterleaks")


def test_kingfisher_write_corpus_places_manifest_beside_scan_tree(tmp_path):
    pytest.importorskip("yaml")
    gen = _load_generator("harvest_kingfisher")
    gen.write_corpus([dict(r) for r in _SAMPLE_RECORDS], tmp_path)
    _assert_split_layout(tmp_path, "kingfisher")


def test_kingfisher_root_resolution_prefers_explicit(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    gen = _load_generator("harvest_kingfisher")
    root = tmp_path / "kf"
    (root / "crates" / "kingfisher-rules" / "data" / "rules").mkdir(parents=True)
    monkeypatch.delenv("KINGFISHER_ROOT", raising=False)
    assert gen.resolve_kingfisher_root(str(root)) == root


def test_kingfisher_root_resolution_fails_closed(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    gen = _load_generator("harvest_kingfisher")
    monkeypatch.delenv("KINGFISHER_ROOT", raising=False)
    with pytest.raises(FileNotFoundError) as exc:
        gen.resolve_kingfisher_root(str(tmp_path / "missing"))
    assert "--kingfisher-root" in str(exc.value)
    assert "KINGFISHER_ROOT" in str(exc.value)
