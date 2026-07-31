from __future__ import annotations

import os
import pathlib
import subprocess
from types import SimpleNamespace

import pytest

from bench import keyhog_version


@pytest.fixture(autouse=True)
def _isolate_dirty_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ambient developer overrides must not disable dirty-tree regression tests."""
    monkeypatch.delenv("KEYHOG_BENCH_ALLOW_DIRTY", raising=False)
    monkeypatch.delenv(
        "KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY",
        raising=False,
    )


def _version_output(*, commit: str, detector_digest: str) -> str:
    return (
        f"KeyHog v{keyhog_version.workspace_keyhog_version()}\n"
        f"Commit: {commit}\n"
        f"Detector Set: 1 ({detector_digest})\n"
        "Build Target: test-test\n"
    )

def _build_rs_detector_digest(detector_dir: pathlib.Path) -> str:
    """Independent translation of crates/core/build.rs detector_set_digest."""
    manifest_name = "corpus.toml"
    detector_paths = sorted(
        path
        for path in detector_dir.iterdir()
        if path.suffix == ".toml" and path.name != manifest_name
    )
    entries = [
        (path.name, path.read_bytes().decode("utf-8")) for path in detector_paths
    ]
    manifest = (detector_dir / manifest_name).read_bytes().decode("utf-8")

    value = 0xCBF29CE484222325
    for name, content in (*entries, (manifest_name, manifest)):
        for payload in (
            name.encode("utf-8"),
            b"\0",
            content.encode("utf-8"),
            b"\0",
        ):
            for byte in payload:
                value ^= byte
                value = (value * 0x00000100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"{len(entries)}-{value:016x}"


def _git_commit_all(repo: pathlib.Path, message: str) -> str:
    """Commit the complete temporary tree and return its exact object identity."""
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Santh",
            "-c",
            "user.email=santh@example.invalid",
            "commit",
            "-q",
            "-m",
            message,
        ],
        check=True,
    )
    return subprocess.check_output(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def test_generated_evidence_commit_preserves_measured_binary_identity(tmp_path):
    """Committing a report must not create an impossible self-referential hash gate."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    source = tmp_path / "crates/scanner/src/lib.rs"
    report = tmp_path / "benchmarks/reports/leaderboard.md"
    source.parent.mkdir(parents=True)
    report.parent.mkdir(parents=True)
    source.write_text("pub fn version() -> u8 { 1 }\n", encoding="utf-8")
    report.write_text("old evidence\n", encoding="utf-8")
    measured_commit = _git_commit_all(tmp_path, "source")

    report.write_text("current evidence\n", encoding="utf-8")
    current_commit = _git_commit_all(tmp_path, "evidence")

    assert keyhog_version._generated_evidence_only_since(
        measured_commit, current_commit, tmp_path
    )


def test_source_commit_invalidates_ancestor_benchmark_identity(tmp_path):
    """A source change after measurement must still fail even beside generated reports."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    source = tmp_path / "crates/scanner/src/lib.rs"
    report = tmp_path / "benchmarks/reports/leaderboard.md"
    source.parent.mkdir(parents=True)
    report.parent.mkdir(parents=True)
    source.write_text("pub fn version() -> u8 { 1 }\n", encoding="utf-8")
    report.write_text("old evidence\n", encoding="utf-8")
    measured_commit = _git_commit_all(tmp_path, "source")

    source.write_text("pub fn version() -> u8 { 2 }\n", encoding="utf-8")
    report.write_text("current evidence\n", encoding="utf-8")
    current_commit = _git_commit_all(tmp_path, "source and evidence")

    assert not keyhog_version._generated_evidence_only_since(
        measured_commit, current_commit, tmp_path
    )


def test_source_rename_into_report_directory_cannot_evade_freshness_gate(tmp_path):
    """Rename detection must expose the deleted source path, not only its safe destination."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    source = tmp_path / "crates/scanner/src/lib.rs"
    destination = tmp_path / "benchmarks/reports/disguised.md"
    source.parent.mkdir(parents=True)
    destination.parent.mkdir(parents=True)
    source.write_text("pub fn version() -> u8 { 1 }\n", encoding="utf-8")
    measured_commit = _git_commit_all(tmp_path, "source")

    source.rename(destination)
    current_commit = _git_commit_all(tmp_path, "disguised source")

    assert not keyhog_version._generated_evidence_only_since(
        measured_commit, current_commit, tmp_path
    )


def test_workspace_detector_digest_matches_build_rs_on_current_tree():
    repo_root = pathlib.Path(__file__).resolve().parents[3]
    detector_dir = repo_root / "detectors"

    # Regression: treating corpus.toml as detector 924 and hashing it in sorted
    # order produced 924-c403f3d2507f00dc instead of the audit tree's
    # build-stamped 923-8ff9138381e6a120. The explicit final-tree lock also
    # forces intentional manifest/schema changes to regenerate this assertion.
    authoritative = _build_rs_detector_digest(detector_dir)
    assert authoritative == "923-8785f8837d2cd505"
    assert keyhog_version.workspace_detector_digest(repo_root) == authoritative

    correct_output = _version_output(
        commit=keyhog_version.workspace_git_hash(), detector_digest=authoritative
    )
    keyhog_version.assert_reported_identity_matches_workspace(
        correct_output, what="keyhog benchmark result"
    )


def test_report_identity_rejects_pre_manifest_fix_digest():
    commit = keyhog_version.workspace_git_hash()
    stale_output = _version_output(
        commit=commit, detector_digest="924-c403f3d2507f00dc"
    )

    # The old benchmark digest must fail closed rather than rejecting the
    # correctly built binary and accepting stale pre-manifest result metadata.
    with pytest.raises(
        keyhog_version.KeyhogVersionError,
        match=(
            "detector_set=924-c403f3d2507f00dc, "
            "workspace=923-8785f8837d2cd505"
        ),
    ):
        keyhog_version.assert_reported_identity_matches_workspace(
            stale_output, what="keyhog benchmark result"
        )


def test_workspace_detector_digest_requires_corpus_manifest(tmp_path):
    detector_dir = tmp_path / "detectors"
    detector_dir.mkdir()
    (detector_dir / "a.toml").write_text("id = 'a'\n", encoding="utf-8")

    # build.rs fails when corpus.toml is missing; the benchmark must not invent
    # a detector-only identity that no authoritative build can stamp.
    with pytest.raises(
        keyhog_version.KeyhogVersionError,
        match=r"corpus\.toml.*restore a readable UTF-8",
    ):
        keyhog_version.workspace_detector_digest(tmp_path)


def test_workspace_detector_digest_binds_manifest_content_after_detectors(tmp_path):
    detector_dir = tmp_path / "detectors"
    detector_dir.mkdir()
    (detector_dir / "z.toml").write_text(
        "[detector]\nid = 'z'\n", encoding="utf-8"
    )
    (detector_dir / "a.toml").write_text(
        "[detector]\nid = 'a'\n", encoding="utf-8"
    )
    manifest = detector_dir / "corpus.toml"
    manifest.write_text("schema_version = 1\n", encoding="utf-8")

    # Regression: the manifest is schema metadata, so it changes the hash but
    # remains outside the detector count and follows every sorted detector.
    initial = keyhog_version.workspace_detector_digest(tmp_path)
    assert initial == "2-86d220cb297a8ec5"
    assert initial == _build_rs_detector_digest(detector_dir)

    manifest.write_text("schema_version = 2\n", encoding="utf-8")
    changed = keyhog_version.workspace_detector_digest(tmp_path)
    assert changed == "2-8f453bcb2e345ae0"
    assert changed == _build_rs_detector_digest(detector_dir)
    assert changed != initial


def test_detector_corpus_sha256_binds_filenames_and_bytes(tmp_path):
    first = tmp_path / "a.toml"
    second = tmp_path / "b.toml"
    first.write_text("[detector]\nid = 'a'\n", encoding="utf-8")
    second.write_text("[detector]\nid = 'b'\n", encoding="utf-8")

    initial = keyhog_version.detector_corpus_sha256(tmp_path)
    assert len(initial) == 64

    second.write_text("[detector]\nid = 'changed'\n", encoding="utf-8")
    changed_bytes = keyhog_version.detector_corpus_sha256(tmp_path)
    assert changed_bytes != initial

    second.rename(tmp_path / "renamed.toml")
    assert keyhog_version.detector_corpus_sha256(tmp_path) != changed_bytes


@pytest.mark.skipif(os.name != "posix", reason="POSIX permits non-UTF-8 filenames")
def test_detector_corpus_sha256_accepts_non_utf8_filenames(tmp_path):
    name = os.fsdecode(b"detector-\xff.toml")
    (tmp_path / name).write_bytes(b"[detector]\nid = 'raw-name'\n")

    digest = keyhog_version.detector_corpus_sha256(tmp_path)

    assert len(digest) == 64


def test_binary_freshness_rejects_same_version_from_an_older_commit(monkeypatch):
    current = "a" * 40
    output = _version_output(commit="b" * 40, detector_digest="1-0000000000000001")
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(
        keyhog_version, "workspace_detector_digest", lambda: "1-0000000000000001"
    )

    with pytest.raises(keyhog_version.KeyhogVersionError, match="older commit|stale"):
        keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")


def test_binary_freshness_rejects_stale_embedded_detector_set(monkeypatch):
    current = "a" * 40
    output = _version_output(commit=current, detector_digest="1-0000000000000001")
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(
        keyhog_version, "workspace_detector_digest", lambda: "1-0000000000000002"
    )

    with pytest.raises(keyhog_version.KeyhogVersionError, match="detector_set"):
        keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")


def test_binary_freshness_accepts_exact_commit_and_detector_set(monkeypatch):
    current = "a" * 40
    digest = "1-0000000000000001"
    output = _version_output(commit=current, detector_digest=digest)
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(keyhog_version, "workspace_detector_digest", lambda: digest)
    monkeypatch.setattr(keyhog_version, "assert_workspace_tracked_tree_clean", lambda: None)

    keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")


def test_workspace_cleanliness_rejects_unstaged_and_staged_tracked_edits(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    scanner = tmp_path / "crates/scanner/src/lib.rs"
    scanner.parent.mkdir(parents=True)
    scanner.write_text("pub fn version() -> u8 { 1 }\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "crates/scanner/src/lib.rs"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )
    keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)

    renamed = scanner.with_name("renamed lib.rs")
    scanner.rename(renamed)
    with pytest.raises(keyhog_version.KeyhogVersionError, match="uncommitted changes"):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)

    renamed.rename(scanner)
    scanner.unlink()
    with pytest.raises(keyhog_version.KeyhogVersionError, match="uncommitted changes"):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)

    scanner.write_text("pub fn version() -> u8 { 2 }\n")
    with pytest.raises(keyhog_version.KeyhogVersionError, match="uncommitted changes"):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)

    subprocess.run(["git", "-C", str(tmp_path), "add", "crates/scanner/src/lib.rs"], check=True)
    with pytest.raises(keyhog_version.KeyhogVersionError, match="uncommitted changes"):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)

    (tmp_path / "untracked.txt").write_text("does not affect a tracked build graph\n")
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "scanner edit",
        ],
        check=True,
    )
    keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)


def test_generated_evidence_scope_accepts_only_release_owned_outputs(
    tmp_path, monkeypatch
):
    """Release measurements may continue after their own reports dirty the tree."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    paths = [
        tmp_path / "README.md",
        tmp_path / "metrics/stars.svg",
        tmp_path / "benchmarks/reports/leaderboard.md",
        tmp_path / "benchmarks/run-sets/canonical.toml",
    ]
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("old\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )
    for path in paths:
        path.write_text("new\n")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "benchmarks/run-sets/canonical.toml"],
        check=True,
    )
    monkeypatch.setenv("KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY", "1")

    keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)


@pytest.mark.parametrize(
    "relative",
    [
        "Cargo.toml",
        "benchmarks/bench/report.py",
        "benchmarks/run-sets/lookalike.toml",
        "benchmarks/results/result.json",
        "metrics/stars.json",
    ],
)
def test_generated_evidence_scope_rejects_source_and_lookalike_paths(
    tmp_path, monkeypatch, relative
):
    """The release-only scope must not become a broad dirty-worktree bypass."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("old\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", relative], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )
    path.write_text("new\n")
    monkeypatch.setenv("KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY", "1")

    with pytest.raises(
        keyhog_version.KeyhogVersionError,
        match="Unexpected non-evidence paths",
    ):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)


def test_generated_evidence_scope_rejects_renamed_report(
    tmp_path, monkeypatch
):
    """A rename must not hide deleted evidence or an unexpected destination path."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    report = tmp_path / "benchmarks/reports/leaderboard.md"
    report.parent.mkdir(parents=True)
    report.write_text("old\n")
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "benchmarks/reports/leaderboard.md"],
        check=True,
    )
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )
    report.rename(report.with_name("renamed.md"))
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    monkeypatch.setenv("KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY", "1")

    with pytest.raises(
        keyhog_version.KeyhogVersionError,
        match="does not accept renamed or copied paths",
    ):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_workspace_cleanliness_rejects_hidden_index_flags(tmp_path, flag):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    scanner = tmp_path / "crates/scanner/src/lib.rs"
    scanner.parent.mkdir(parents=True)
    scanner.write_text("pub fn version() -> u8 { 1 }\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "crates/scanner/src/lib.rs"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "update-index", flag, "crates/scanner/src/lib.rs"],
        check=True,
    )
    scanner.write_text("pub fn version() -> u8 { 2 }\n")

    with pytest.raises(keyhog_version.KeyhogVersionError, match="index flags"):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)


def test_binary_freshness_rejects_dirty_tracked_workspace(monkeypatch):
    current = "a" * 40
    digest = "1-0000000000000001"
    output = _version_output(commit=current, detector_digest=digest)
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(keyhog_version, "workspace_detector_digest", lambda: digest)
    monkeypatch.setattr(
        keyhog_version,
        "assert_workspace_tracked_tree_clean",
        lambda: (_ for _ in ()).throw(
            keyhog_version.KeyhogVersionError("tracked workspace has uncommitted changes")
        ),
    )

    with pytest.raises(keyhog_version.KeyhogVersionError, match="uncommitted changes"):
        keyhog_version.assert_keyhog_binary_current("/candidate/keyhog")


def test_binary_freshness_accepts_matching_sha256_commit_identity(monkeypatch):
    current = "a" * 64
    digest = "1-0000000000000001"
    output = _version_output(commit=current, detector_digest=digest)
    monkeypatch.setattr(
        keyhog_version.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output, stderr=""),
    )
    monkeypatch.setattr(keyhog_version, "workspace_git_hash", lambda: current)
    monkeypatch.setattr(keyhog_version, "workspace_detector_digest", lambda: digest)
    monkeypatch.setattr(keyhog_version, "assert_workspace_tracked_tree_clean", lambda: None)

    assert keyhog_version.assert_keyhog_binary_current("/candidate/keyhog") == output.strip()


def test_workspace_git_hash_accepts_sha256_repository(tmp_path):
    initialized = subprocess.run(
        ["git", "init", "-q", "--object-format=sha256", str(tmp_path)],
        capture_output=True,
    )
    if initialized.returncode != 0:
        pytest.skip("installed Git does not support SHA-256 repositories")
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("content\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "tracked.txt"], check=True)
    subprocess.run(
        [
            "git", "-C", str(tmp_path), "-c", "user.name=Santh",
            "-c", "user.email=64453045+santhreal@users.noreply.github.com",
            "commit", "-qm", "fixture",
        ],
        check=True,
    )

    assert len(keyhog_version.workspace_git_hash(tmp_path)) == 64


def test_workspace_cleanliness_honors_allow_dirty_env(tmp_path, monkeypatch):
    """KEYHOG_BENCH_ALLOW_DIRTY=1 lets a developer benchmark an uncommitted tree."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    scanner = tmp_path / "crates" / "scanner" / "src" / "lib.rs"
    scanner.parent.mkdir(parents=True)
    scanner.write_text("pub fn version() -> u8 { 1 }\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", str(scanner)], check=True)
    # Without the env, the same tree is rejected.
    with pytest.raises(keyhog_version.KeyhogVersionError, match="uncommitted changes"):
        keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)

    monkeypatch.setenv("KEYHOG_BENCH_ALLOW_DIRTY", "1")
    # With the env, the check passes despite the uncommitted edit.
    keyhog_version.assert_workspace_tracked_tree_clean(tmp_path)
