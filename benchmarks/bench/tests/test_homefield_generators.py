import importlib.util
import pathlib


def _load_betterleaks_generator():
    path = (
        pathlib.Path(__file__).resolve().parents[2]
        / "generators"
        / "homefield"
        / "harvest_betterleaks.py"
    )
    spec = importlib.util.spec_from_file_location("harvest_betterleaks", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


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
