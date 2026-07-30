"""Behavioral regressions for the local and SSH release orchestrator."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import release


class FakeRunner:
    """Record orchestration commands without touching Git, GitHub, or crates.io."""

    def __init__(self, status: str = "") -> None:
        self.status = status
        self.commands: list[list[str]] = []

    def output(self, args: list[str]) -> str:
        self.commands.append(args)
        if args[:3] == ["git", "status", "--porcelain=v1"]:
            return self.status
        raise AssertionError(f"unexpected output command: {args}")

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")



class TagRunner:
    """Serve exact local and remote tag states to the resume verifier."""

    def __init__(self, local: str | None, remote: str) -> None:
        self.local = local
        self.remote = remote
        self.commands: list[list[str]] = []

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(args)
        if args[:4] == ["git", "rev-parse", "-q", "--verify"]:
            return subprocess.CompletedProcess(
                args, 0 if self.local else 1, f"{self.local}\n" if self.local else "", ""
            )
        if args[:3] == ["git", "ls-remote", "--exit-code"]:
            return subprocess.CompletedProcess(
                args, 0 if self.remote else 2, self.remote, ""
            )
        if args[:2] == ["git", "fetch"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected run command: {args}")

    def output(self, args: list[str]) -> str:
        self.commands.append(args)
        if args[:3] == ["git", "rev-parse", "--verify"]:
            for line in self.remote.splitlines():
                commit, ref = line.split(maxsplit=1)
                if ref.endswith("^{}"):
                    return commit
        raise AssertionError(f"unexpected output command: {args}")


class MetricsAheadRunner:
    """Model origin/main containing the release commit plus one metrics commit."""

    head = "a" * 40
    upstream = "b" * 40
    metric_commit = "c" * 40

    def __init__(self, changed_path: str = "metrics/stars.json") -> None:
        self.changed_path = changed_path
        self.commands: list[list[str]] = []

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(args)
        if args[:3] == ["git", "fetch", "origin"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] in (["git", "push"], ["git", "rebase"]):
            raise AssertionError(f"release commit must not be rewritten or pushed: {args}")
        raise AssertionError(f"unexpected run command: {args}")

    def output(self, args: list[str]) -> str:
        self.commands.append(args)
        if args == ["git", "rev-parse", "origin/main"]:
            return self.upstream
        if args == ["git", "rev-parse", "HEAD"]:
            return self.head
        if args == ["git", "merge-base", "HEAD", "origin/main"]:
            return self.head
        if args == ["git", "rev-list", "HEAD..origin/main"]:
            return self.metric_commit
        if args[:4] == ["git", "diff-tree", "--no-commit-id", "--name-only"]:
            return self.changed_path
        raise AssertionError(f"unexpected output command: {args}")


class IdentityRunner:
    """Model the exact GitHub actor and OpenPGP key checks before publication."""

    def __init__(self, actor_id: str = release.GITHUB_ACTOR_ID) -> None:
        self.actor_id = actor_id
        self.commands: list[list[str]] = []

    def run(
        self,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
        check: bool = True,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(args)
        if args[:3] == ["git", "config", "--get"]:
            return subprocess.CompletedProcess(args, 1, "", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def output(self, args: list[str]) -> str:
        self.commands.append(args)
        if args[:3] == ["gh", "api", "user"]:
            return self.actor_id
        if args == ["git", "config", "--get", "user.signingkey"]:
            return "ABCDEF1234567890"
        raise AssertionError(f"unexpected output command: {args}")

class RemoteReleaseCommandTests(unittest.TestCase):
    """Protect the SSH boundary from injection and option drift."""

    def test_remote_command_quotes_directory_and_forwards_release_once(self) -> None:
        """One SSH call must enter the requested tree and execute the same non-recursive script."""
        command = release.remote_command(
            ["0.5.49", "--date", "2026-07-30", "--publish"],
            "builder@example.com",
            "/srv/KeyHog release",
            2222,
            "/keys/release key",
        )

        self.assertEqual(
            command,
            [
                "ssh",
                "-p",
                "2222",
                "-i",
                "/keys/release key",
                "builder@example.com",
                "cd -- '/srv/KeyHog release' && exec python3 -B scripts/release.py "
                "0.5.49 --date 2026-07-30 --publish",
            ],
        )
        self.assertNotIn("--ssh", command[-1])

    def test_ssh_target_rejects_shell_syntax(self) -> None:
        """A caller-supplied SSH target must not become an arbitrary local or remote command."""
        for target in ("host;touch /tmp/pwn", "host $(id)", "host\nwhoami"):
            with self.subTest(target=target), self.assertRaisesRegex(
                release.ReleaseError, "without shell syntax"
            ):
                release.remote_command(["0.5.49"], target, "/srv/keyhog", None, None)

    def test_remote_directory_must_be_absolute(self) -> None:
        """Remote execution must not depend on an unknown SSH login working directory."""
        with self.assertRaisesRegex(release.ReleaseError, "absolute"):
            release.remote_command(["0.5.49"], "host", "repo/keyhog", None, None)

    def test_invalid_ssh_port_fails_before_execution(self) -> None:
        """Malformed ports must fail locally instead of changing SSH argument meaning."""
        with self.assertRaisesRegex(release.ReleaseError, "between 1 and 65535"):
            release.remote_command(["0.5.49"], "host", "/repo", 70000, None)


class ReleasePlanContractTests(unittest.TestCase):
    """Protect release identity and phase-owned file boundaries."""

    def test_release_options_require_stable_semver_and_iso_date(self) -> None:
        """Published tags must have the exact stable identity consumed by release.yml."""
        release.validate_options(
            release.Options("0.5.49", "2026-07-30", False, False, False, True)
        )
        with self.assertRaises(ValueError):
            release.validate_options(
                release.Options("v0.5.49", "2026-07-30", False, False, False, True)
            )
        with self.assertRaisesRegex(release.ReleaseError, "invalid release date"):
            release.validate_options(
                release.Options("0.5.49", "30-07-2026", False, False, False, True)
            )

    def test_publication_identity_uses_supported_gh_status_and_stable_actor_id(self) -> None:
        """The release must prove the authorized account without relying on an unavailable gh flag."""
        runner = IdentityRunner()

        release.require_publication_identity(runner)

        self.assertEqual(
            runner.commands[0],
            ["gh", "auth", "status", "--hostname", "github.com"],
        )
        self.assertIn(
            ["gh", "api", "user", "--jq", ".id | tostring"],
            runner.commands,
        )
        self.assertIn(
            ["gpg", "--list-secret-keys", "ABCDEF1234567890"],
            runner.commands,
        )

    def test_wrong_github_actor_fails_before_signing(self) -> None:
        """A valid token for another account must not publish under the wrong identity."""
        runner = IdentityRunner("1")
        with self.assertRaisesRegex(release.ReleaseError, "not authorized"):
            release.require_publication_identity(runner)
        self.assertFalse(any(command[0] == "gpg" for command in runner.commands))

    def test_benchmark_phase_accepts_only_generated_evidence(self) -> None:
        """Benchmark commits must never absorb source, changelog, or unrelated user edits."""
        accepted = (
            Path("README.md"),
            Path("metrics/stars.svg"),
            Path("benchmarks/reports/readme-matrix.json"),
        )
        rejected = (
            Path("Cargo.toml"),
            Path("metrics/stars.json"),
            Path("crates/scanner/src/lib.rs"),
        )
        self.assertTrue(all(release.benchmark_path(path) for path in accepted))
        self.assertFalse(any(release.benchmark_path(path) for path in rejected))

    def test_release_phase_accepts_exact_version_and_changelog_surfaces(self) -> None:
        """Release preparation must consume fragments without staging arbitrary repository files."""
        accepted = (
            Path("Cargo.toml"),
            Path("Cargo.lock"),
            Path("CHANGELOG.md"),
            Path("README.md"),
            Path("crates/scanner/CHANGELOG.md"),
            Path("changes/scanner-fix.toml"),
        )
        rejected = (
            Path("changes/README.md"),
            Path("metrics/stars.svg"),
            Path("crates/scanner/src/lib.rs"),
        )
        self.assertTrue(all(release.release_path(path) for path in accepted))
        self.assertFalse(any(release.release_path(path) for path in rejected))

    def test_commit_expected_stages_only_validated_paths(self) -> None:
        """A generated phase must commit its complete owned diff with no broad git add."""
        runner = FakeRunner(" M README.md\n?? benchmarks/reports/new.json")

        committed = release.commit_expected(
            runner, "bench: refresh evidence", release.benchmark_path
        )

        self.assertTrue(committed)
        self.assertEqual(
            runner.commands[-2],
            ["git", "add", "--", "README.md", "benchmarks/reports/new.json"],
        )
        self.assertEqual(
            runner.commands[-1], ["git", "commit", "-m", "bench: refresh evidence"]
        )

    def test_commit_expected_rejects_unowned_path_before_staging(self) -> None:
        """An unrelated source edit must stop publication before any index mutation."""
        runner = FakeRunner(" M README.md\n M crates/scanner/src/lib.rs")

        with self.assertRaisesRegex(release.ReleaseError, "unexpected paths"):
            release.commit_expected(
                runner, "bench: refresh evidence", release.benchmark_path
            )

        self.assertEqual(len(runner.commands), 1)

    def test_no_generated_change_produces_no_empty_commit(self) -> None:
        """Stable benchmark bytes must not create an empty release-history commit."""
        runner = FakeRunner("")
        self.assertFalse(
            release.commit_expected(runner, "bench: refresh evidence", release.benchmark_path)
        )
        self.assertEqual(len(runner.commands), 1)

    def test_git_status_rejects_rename_shape(self) -> None:
        """A rename must not hide its source path from phase ownership validation."""
        runner = FakeRunner("R  old.txt -> README.md")
        with self.assertRaisesRegex(release.ReleaseError, "renamed"):
            release.git_status_paths(runner)

    def test_pre_tag_gate_runs_product_docs_and_source_proofs(self) -> None:
        """The signed tag must not be created after only a narrowed release check."""
        runner = FakeRunner("")
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, True
        )

        release.run_pre_tag_gates(runner, options)

        self.assertEqual(
            runner.commands,
            [
                ["scripts/prerelease.sh", "--pre-tag"],
                ["make", "docs-build"],
                ["bash", "scripts/gates/run_all.sh"],
                ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            ],
        )

    def test_skip_rust_is_forwarded_only_as_explicit_diagnostic_override(self) -> None:
        """Recovery may skip duplicate Rust gates only when the caller names that choice."""
        runner = FakeRunner("")
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, True, True
        )

        release.run_pre_tag_gates(runner, options)

        self.assertEqual(
            runner.commands[0],
            ["scripts/prerelease.sh", "--pre-tag", "--skip-rust"],
        )


class ReleaseResumeContractTests(unittest.TestCase):
    """Protect immutable tag recovery and already-prepared workspace detection."""

    def test_absent_local_and_remote_tag_starts_new_release(self) -> None:
        """A new version must proceed only when neither namespace already owns its tag."""
        runner = TagRunner(None, "")
        self.assertEqual(release.release_tag_state(runner, "v0.5.49"), (None, False))

    def test_remote_lightweight_tag_is_rejected(self) -> None:
        """Resume must not accept a movable lightweight tag as immutable release proof."""
        runner = TagRunner(
            None,
            "a" * 40 + "\trefs/tags/v0.5.49\n",
        )
        with self.assertRaisesRegex(release.ReleaseError, "not an annotated tag"):
            release.release_tag_state(runner, "v0.5.49")

    def test_remote_annotated_tag_is_fetched_and_peeled_exactly(self) -> None:
        """A disconnected watcher may resume only from the remote tag's peeled commit."""
        tag_object = "a" * 40
        commit = "b" * 40
        runner = TagRunner(
            None,
            f"{tag_object}\trefs/tags/v0.5.49\n"
            f"{commit}\trefs/tags/v0.5.49^{{}}\n",
        )

        state = release.release_tag_state(runner, "v0.5.49")

        self.assertEqual(state, (commit, True))
        self.assertIn(
            ["git", "fetch", "origin", "refs/tags/v0.5.49:refs/tags/v0.5.49"],
            runner.commands,
        )

    def test_local_and_remote_tag_mismatch_fails_closed(self) -> None:
        """A local tag must never overwrite or reinterpret an existing remote release tag."""
        runner = TagRunner(
            "c" * 40,
            f"{'a' * 40}\trefs/tags/v0.5.49\n"
            f"{'b' * 40}\trefs/tags/v0.5.49^{{}}\n",
        )
        with self.assertRaisesRegex(release.ReleaseError, "different commits"):
            release.release_tag_state(runner, "v0.5.49")

    def test_workspace_version_reads_exact_release_owner(self) -> None:
        """Resume decisions must use workspace.package.version instead of a crate lookalike."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text(
                '[workspace.package]\nversion = "0.5.49"\n'
                '[package]\nname = "lookalike"\nversion = "9.9.9"\n'
            )
            runner = type("RootOnlyRunner", (), {"root": root})()
            self.assertEqual(release.workspace_version(runner), "0.5.49")

    def test_remote_metrics_commit_does_not_rewrite_release_commit(self) -> None:
        """A post-release star snapshot must leave the already-tested tag commit unchanged."""
        runner = MetricsAheadRunner()

        release.push_main(runner)

        self.assertNotIn(["git", "rebase", "origin/main"], runner.commands)
        self.assertFalse(any(command[:2] == ["git", "push"] for command in runner.commands))

    def test_remote_nonmetrics_commit_blocks_resume(self) -> None:
        """Any product change beyond the release commit must return to review and testing."""
        runner = MetricsAheadRunner("crates/scanner/src/lib.rs")
        with self.assertRaisesRegex(release.ReleaseError, "non-metrics work"):
            release.push_main(runner)


if __name__ == "__main__":
    unittest.main()
