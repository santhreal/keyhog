import hashlib
import os
import pathlib

import pytest

import bench.corpora.agentre_recovery as agentre_recovery
from bench.agentre_provenance import OFFICIAL_LINUX_SLICE, PinnedArtifact
from bench.corpora.agentre_recovery import (
    AgentREMaterializationError,
    AgentRERecoveryMaterializer,
)


def artifact(path: str, payload: bytes) -> PinnedArtifact:
    return PinnedArtifact(path, hashlib.sha256(payload).hexdigest())


@pytest.fixture
def fixture_artifacts():
    payloads = {
        "LICENSE": b"license bytes\n",
        "samples/level1.c": b"int main(void) { return 0; }\n",
        "ground_truths/level1.json": b'{"decoded_c2": null}\n',
    }
    artifacts = tuple(artifact(path, payload) for path, payload in payloads.items())
    return artifacts, payloads


def staging_paths(home: pathlib.Path) -> list[pathlib.Path]:
    return list(home.parent.glob(f".{home.name}-*.staging"))


def test_default_materializer_owns_the_official_repository_location():
    materializer = AgentRERecoveryMaterializer()

    assert materializer.root.name == "agentre-recovery"
    assert materializer.root.parent.name == "corpora"
    assert materializer._artifacts == OFFICIAL_LINUX_SLICE


def test_materialize_publishes_exact_read_only_non_executable_inventory(
    tmp_path, fixture_artifacts
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)

    published = materializer.materialize(lambda item: payloads[item.path])

    assert published == home
    materializer.validate()
    assert {
        path.relative_to(home).as_posix() for path in home.rglob("*") if path.is_file()
    } == set(payloads)
    for path in home.rglob("*"):
        mode = path.stat().st_mode
        if path.is_file():
            assert mode & 0o333 == 0
        elif os.name == "posix":
            assert mode & 0o222 == 0
    assert not staging_paths(home)


def test_digest_failure_leaves_no_partial_destination(tmp_path, fixture_artifacts):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)

    with pytest.raises(AgentREMaterializationError, match="digest mismatch"):
        materializer.materialize(
            lambda item: b"corrupt" if item.path == "LICENSE" else payloads[item.path]
        )

    assert not home.exists()
    assert not staging_paths(home)


def test_interrupted_fetch_cleans_staging_and_retry_publishes_atomically(
    tmp_path, fixture_artifacts
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    calls = 0

    def interrupted(item):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ConnectionError("connection lost")
        return payloads[item.path]

    with pytest.raises(ConnectionError, match="connection lost"):
        materializer.materialize(interrupted)

    assert not home.exists()
    assert not staging_paths(home)
    materializer.materialize(lambda item: payloads[item.path])
    materializer.validate()


def test_valid_existing_corpus_never_refetches(tmp_path, fixture_artifacts):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])

    def forbidden_fetch(_item):
        raise AssertionError("valid corpus must not be fetched again")

    assert materializer.materialize(forbidden_fetch) == home


@pytest.mark.parametrize("mutation", ["partial", "unexpected"])
def test_existing_invalid_inventory_is_rejected_without_override(
    tmp_path, fixture_artifacts, mutation
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    home.chmod(0o700)
    if mutation == "partial":
        target = home / "LICENSE"
        target.chmod(0o600)
        target.unlink()
    else:
        unexpected = home / "unexpected.txt"
        unexpected.write_bytes(b"extra")
        unexpected.chmod(0o400)
    home.chmod(0o500)

    with pytest.raises(AgentREMaterializationError, match="inventory mismatch"):
        materializer.materialize(lambda _item: b"must not fetch")


def test_symlinked_material_is_rejected(tmp_path, fixture_artifacts):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    external = tmp_path / "external"
    external.write_bytes(payloads["LICENSE"])
    home.chmod(0o700)
    license_path = home / "LICENSE"
    license_path.unlink()
    license_path.symlink_to(external)
    home.chmod(0o500)

    with pytest.raises(AgentREMaterializationError, match="symlink"):
        materializer.validate()


def test_symlinked_directory_is_rejected_without_traversal(tmp_path, fixture_artifacts):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    external = tmp_path / "external-directory"
    external.mkdir()
    home.chmod(0o700)
    (home / "linked-directory").symlink_to(external, target_is_directory=True)
    home.chmod(0o500)

    with pytest.raises(AgentREMaterializationError, match="directory symlink"):
        materializer.validate()


def test_symlinked_corpus_root_is_rejected(tmp_path, fixture_artifacts):
    artifacts, _payloads = fixture_artifacts
    external = tmp_path / "external-corpus"
    external.mkdir()
    home = tmp_path / "agentre-recovery"
    home.symlink_to(external, target_is_directory=True)
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)

    with pytest.raises(AgentREMaterializationError, match="real directory"):
        materializer.materialize(lambda _item: b"must not fetch")


def test_corrupt_existing_bytes_are_rejected(tmp_path, fixture_artifacts):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    home.chmod(0o700)
    license_path = home / "LICENSE"
    license_path.chmod(0o600)
    license_path.write_bytes(b"corrupt")
    license_path.chmod(0o400)
    home.chmod(0o500)

    with pytest.raises(AgentREMaterializationError, match="digest mismatch"):
        materializer.validate()


def test_read_pinned_text_validates_and_decodes_the_pinned_artifact(
    tmp_path, fixture_artifacts
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])

    path, text = materializer.read_pinned_text("ground_truths/level1.json")

    assert path == home / "ground_truths/level1.json"
    assert text == payloads["ground_truths/level1.json"].decode()


def test_read_pinned_texts_validates_once_and_preserves_request_order(
    tmp_path, fixture_artifacts, monkeypatch
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    original_validate = materializer.validate
    validation_count = 0

    def counted_validate():
        nonlocal validation_count
        validation_count += 1
        original_validate()

    monkeypatch.setattr(materializer, "validate", counted_validate)
    rows = materializer.read_pinned_texts(
        ["ground_truths/level1.json", "samples/level1.c"]
    )

    assert validation_count == 1
    assert [path.relative_to(home).as_posix() for path, _text in rows] == [
        "ground_truths/level1.json",
        "samples/level1.c",
    ]
    assert [text.encode() for _path, text in rows] == [
        payloads["ground_truths/level1.json"],
        payloads["samples/level1.c"],
    ]


def test_read_pinned_text_rejects_unpinned_and_non_utf8_artifacts(tmp_path):
    payloads = {"ground_truths/level1.json": b"\xff"}
    artifacts = tuple(artifact(path, payload) for path, payload in payloads.items())
    materializer = AgentRERecoveryMaterializer(
        tmp_path / "agentre-recovery", _artifacts=artifacts
    )
    materializer.materialize(lambda item: payloads[item.path])

    with pytest.raises(AgentREMaterializationError, match="does not pin"):
        materializer.read_pinned_text("ground_truths/missing.json")
    with pytest.raises(AgentREMaterializationError, match="not valid UTF-8"):
        materializer.read_pinned_text("ground_truths/level1.json")


@pytest.mark.skipif(os.name != "posix", reason="POSIX no-follow descriptor traversal")
def test_read_pinned_text_rejects_symlink_replacement_after_validation(
    tmp_path, fixture_artifacts, monkeypatch
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    target = home / "ground_truths/level1.json"
    external = tmp_path / "external.json"
    external.write_bytes(payloads["ground_truths/level1.json"])
    original_validate = materializer.validate

    def validate_then_replace():
        original_validate()
        home.chmod(0o700)
        target.parent.chmod(0o700)
        target.unlink()
        target.symlink_to(external)
        target.parent.chmod(0o500)
        home.chmod(0o500)

    monkeypatch.setattr(materializer, "validate", validate_then_replace)

    with pytest.raises(AgentREMaterializationError, match="safely open"):
        materializer.read_pinned_text("ground_truths/level1.json")


@pytest.mark.skipif(os.name != "posix", reason="POSIX open-file replacement semantics")
def test_read_pinned_text_detects_regular_file_replacement_during_read(
    tmp_path, fixture_artifacts, monkeypatch
):
    artifacts, payloads = fixture_artifacts
    home = tmp_path / "agentre-recovery"
    materializer = AgentRERecoveryMaterializer(home, _artifacts=artifacts)
    materializer.materialize(lambda item: payloads[item.path])
    target = home / "ground_truths/level1.json"
    displaced = tmp_path / "displaced.json"
    original_validate = materializer.validate
    original_read = os.read
    replaced = False

    def replace_then_read(descriptor, count):
        nonlocal replaced
        if not replaced:
            replaced = True
            home.chmod(0o700)
            target.parent.chmod(0o700)
            target.rename(displaced)
            target.write_bytes(payloads["ground_truths/level1.json"])
            target.chmod(0o400)
            target.parent.chmod(0o500)
            home.chmod(0o500)
        return original_read(descriptor, count)

    def validate_then_arm_read_race():
        original_validate()
        monkeypatch.setattr(agentre_recovery.os, "read", replace_then_read)

    monkeypatch.setattr(materializer, "validate", validate_then_arm_read_race)

    with pytest.raises(AgentREMaterializationError, match="replaced while"):
        materializer.read_pinned_text("ground_truths/level1.json")


def test_traversal_is_rejected_before_any_fetch(tmp_path):
    unsafe = object.__new__(PinnedArtifact)
    object.__setattr__(unsafe, "path", "../escape")
    object.__setattr__(unsafe, "sha256", "a" * 64)

    with pytest.raises(AgentREMaterializationError, match="escapes"):
        AgentRERecoveryMaterializer(tmp_path / "agentre-recovery", _artifacts=(unsafe,))
