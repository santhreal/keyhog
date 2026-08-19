from __future__ import annotations

import pathlib
import pytest

from bench.scanners import keyhog as keyhog_adapter
from bench.scanners.keyhog import _cargo_target_dir, _freshly_built_keyhog, resolve_keyhog_binary


def test_cargo_target_dir_from_env(monkeypatch, tmp_path):
    target = tmp_path / "env-target"
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target))
    assert _cargo_target_dir() == target


def test_cargo_target_dir_from_cargo_config_toml(monkeypatch, tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "config-toml-target"
    cargo_dir = home / ".cargo"
    cargo_dir.mkdir(parents=True)
    (cargo_dir / "config.toml").write_text(f'[build]\ntarget-dir = "{target}"\n')

    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)

    assert _cargo_target_dir() == target


def test_cargo_target_dir_from_cargo_config_legacy(monkeypatch, tmp_path):
    home = tmp_path / "home"
    target = tmp_path / "config-legacy-target"
    cargo_dir = home / ".cargo"
    cargo_dir.mkdir(parents=True)
    (cargo_dir / "config").write_text(f'[build]\ntarget-dir = "{target}"\n')

    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)

    assert _cargo_target_dir() == target


def test_cargo_target_dir_fallback_to_repo_target_when_exists(monkeypatch, tmp_path):
    home = tmp_path / "empty-home"
    home.mkdir(parents=True)
    repo_target = tmp_path / "repo-root" / "target"
    repo_target.mkdir(parents=True)

    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)
    monkeypatch.setattr(keyhog_adapter, "_REPO_ROOT", tmp_path / "repo-root")

    assert _cargo_target_dir() == repo_target


def test_cargo_target_dir_returns_none_when_no_config_or_target_exists(monkeypatch, tmp_path):
    home = tmp_path / "empty-home"
    home.mkdir(parents=True)
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir(parents=True)

    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)
    monkeypatch.setattr(keyhog_adapter, "_REPO_ROOT", repo_root)

    assert _cargo_target_dir() is None


def test_resolve_keyhog_binary_prefers_explicit_argument(monkeypatch):
    monkeypatch.setenv("KEYHOG_BIN", "/env/keyhog")
    assert resolve_keyhog_binary("/explicit/keyhog") == "/explicit/keyhog"


def test_resolve_keyhog_binary_prefers_keyhog_bin_env(monkeypatch):
    monkeypatch.setenv("KEYHOG_BIN", "/env/keyhog")
    assert resolve_keyhog_binary() == "/env/keyhog"


def test_resolve_keyhog_binary_resolves_release_binary(monkeypatch, tmp_path):
    target = tmp_path / "target"
    release_dir = target / "release"
    release_dir.mkdir(parents=True)
    binary = release_dir / "keyhog"
    binary.write_text("#!/bin/sh\n")

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target))

    assert resolve_keyhog_binary() == str(binary)


def test_resolve_keyhog_binary_resolves_release_fast_binary(monkeypatch, tmp_path):
    target = tmp_path / "target"
    release_fast_dir = target / "release-fast"
    release_fast_dir.mkdir(parents=True)
    binary = release_fast_dir / "keyhog"
    binary.write_text("#!/bin/sh\n")

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target))

    assert resolve_keyhog_binary() == str(binary)


def test_resolve_keyhog_binary_prefers_release_over_release_fast(monkeypatch, tmp_path):
    target = tmp_path / "target"
    (target / "release").mkdir(parents=True)
    (target / "release-fast").mkdir(parents=True)
    release_binary = target / "release" / "keyhog"
    release_fast_binary = target / "release-fast" / "keyhog"
    release_binary.write_text("#!/bin/sh\n")
    release_fast_binary.write_text("#!/bin/sh\n")

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(target))

    assert resolve_keyhog_binary() == str(release_binary)


def test_resolve_keyhog_binary_returns_none_when_no_binary_exists(monkeypatch, tmp_path):
    home = tmp_path / "empty-home"
    home.mkdir(parents=True)
    repo_root = tmp_path / "repo-root"
    repo_root.mkdir(parents=True)

    monkeypatch.delenv("KEYHOG_BIN", raising=False)
    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.setattr(pathlib.Path, "home", lambda: home)
    monkeypatch.setattr(keyhog_adapter, "_REPO_ROOT", repo_root)

    assert resolve_keyhog_binary() is None
