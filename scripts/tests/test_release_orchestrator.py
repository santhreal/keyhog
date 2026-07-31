"""Behavioral regressions for the local and SSH release orchestrator."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts import release


class FakeRunner:
    """Record orchestration commands without touching Git, GitHub, or crates.io."""

    def __init__(self, status: str = "") -> None:
        self.status = status
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str] | None] = []

    def output(self, args: list[str]) -> str:
        self.commands.append(args)
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
        self.environments.append(env)
        if args[:3] == ["git", "status", "--porcelain=v1"]:
            return subprocess.CompletedProcess(args, 0, self.status, "")
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
        if args and args[0] == "gpg":
            return (
                "sec:u:4096:1:ABCDEF1234567890:0:0::::::scESC:::+:::23::0:\n"
                "fpr:::::::::0123456789ABCDEF0123456789ABCDEF01234567:\n"
            )
        raise AssertionError(f"unexpected output command: {args}")

class SignatureRunner:
    """Model valid, invalid, and wrong-key OpenPGP tag signatures."""

    def __init__(
        self,
        fingerprint: str,
        *,
        returncode: int = 0,
        include_status: bool = True,
    ) -> None:
        self.fingerprint = fingerprint
        self.returncode = returncode
        self.include_status = include_status
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
        status = ""
        if self.include_status:
            status = (
                f"[GNUPG:] VALIDSIG {self.fingerprint} 2026-07-30 0 4 0 1 10 00 "
                f"{self.fingerprint}\n"
            )
        return subprocess.CompletedProcess(args, self.returncode, "", status)


class PublicationRunner:
    """Serve one final GitHub release record after successful workflow watches."""

    def __init__(self, record: dict[str, object]) -> None:
        self.record = record
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
        return subprocess.CompletedProcess(args, 0, "", "")

    def output(self, args: list[str]) -> str:
        self.commands.append(args)
        if args[:3] == ["gh", "release", "view"]:
            return json.dumps(self.record)
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
        """A caller-supplied SSH target must not become an option or arbitrary command."""
        for target in (
            "host;touch /tmp/pwn",
            "host $(id)",
            "host\nwhoami",
            "-oProxyCommand=id",
            "user@@host",
            "host-",
        ):
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

    def test_help_explains_local_remote_resume_and_diagnostic_modes(self) -> None:
        """The one-command interface must make every safe operator path discoverable."""
        help_text = " ".join(release.parser().format_help().split())

        for expected in (
            "next stable SemVer without a v prefix",
            "release date in UTC",
            "omit the duplicate local Rust gate",
            "watching exact publication workflows",
            "execute the same release command on one prepared SSH host",
            "absolute KeyHog checkout path on the SSH host",
            "scripts/release.py X.Y.Z --publish --resume",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, help_text)

    def test_publication_identity_uses_supported_gh_status_and_stable_actor_id(self) -> None:
        """The release must bind GitHub identity to one usable OpenPGP primary fingerprint."""
        runner = IdentityRunner()

        fingerprint = release.require_publication_identity(runner)

        self.assertEqual(fingerprint, "0123456789ABCDEF0123456789ABCDEF01234567")
        self.assertEqual(
            runner.commands[0],
            ["gh", "auth", "status", "--hostname", "github.com"],
        )
        self.assertIn(
            ["gh", "api", "user", "--jq", ".id | tostring"],
            runner.commands,
        )
        self.assertIn(
            [
                "gpg",
                "--batch",
                "--with-colons",
                "--fingerprint",
                "--fingerprint",
                "--list-secret-keys",
                "ABCDEF1234567890",
            ],
            runner.commands,
        )

    def test_wrong_github_actor_fails_before_signing(self) -> None:
        """A valid token for another account must not publish under the wrong identity."""
        runner = IdentityRunner("1")
        with self.assertRaisesRegex(release.ReleaseError, "not authorized"):
            release.require_publication_identity(runner)
        self.assertFalse(any(command[0] == "gpg" for command in runner.commands))

    def test_missing_primary_fingerprint_fails_before_tag_operations(self) -> None:
        """A secret-key listing without a primary fingerprint must not authorize signing."""
        runner = IdentityRunner()
        original_output = runner.output

        def output(args: list[str]) -> str:
            if args and args[0] == "gpg":
                return "sec:u:4096:1:ABCDEF1234567890:0:0::::::scESC:::+:::23::0:\n"
            return original_output(args)

        runner.output = output  # type: ignore[method-assign]
        with self.assertRaisesRegex(release.ReleaseError, "no usable OpenPGP"):
            release.require_publication_identity(runner)

    def test_valid_tag_signature_must_match_configured_primary_key(self) -> None:
        """A cryptographically valid signature from the configured key permits resume."""
        fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
        runner = SignatureRunner(fingerprint)

        release.verify_tag_signature(runner, "v0.5.49", fingerprint.lower())

        self.assertEqual(
            runner.commands,
            [["git", "verify-tag", "--raw", "v0.5.49"]],
        )

    def test_unsigned_or_invalid_tag_fails_closed(self) -> None:
        """An annotated tag without a valid signature must never become release identity."""
        runner = SignatureRunner("A" * 40, returncode=1, include_status=False)
        with self.assertRaisesRegex(release.ReleaseError, "valid OpenPGP signature"):
            release.verify_tag_signature(runner, "v0.5.49", "A" * 40)

    def test_valid_signature_from_another_key_fails_closed(self) -> None:
        """Any known valid key other than the configured release key must be rejected."""
        runner = SignatureRunner("B" * 40)
        with self.assertRaisesRegex(release.ReleaseError, "was not signed by configured"):
            release.verify_tag_signature(runner, "v0.5.49", "A" * 40)

    def test_benchmark_phase_accepts_only_generated_evidence(self) -> None:
        """Benchmark commits must never absorb source, changelog, or unrelated user edits."""
        accepted = (
            Path("README.md"),
            Path("metrics/stars.svg"),
            Path("benchmarks/reports/readme-matrix.json"),
            Path("benchmarks/run-sets/canonical.toml"),
        )
        rejected = (
            Path("Cargo.toml"),
            Path("metrics/stars.json"),
            Path("crates/scanner/src/lib.rs"),
        )
        self.assertTrue(all(release.benchmark_path(path) for path in accepted))
        self.assertFalse(any(release.benchmark_path(path) for path in rejected))

    def test_benchmark_refresh_runs_every_evidence_owner_in_order(self) -> None:
        """A release refresh must not omit competitor, matrix, scaling, star, or freshness work."""
        runner = FakeRunner("")
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, True
        )
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "keyhog"
            candidate.write_bytes(b"candidate")
            with mock.patch.object(release, "candidate_binary", return_value=candidate):
                release.refresh_benchmarks(runner, options)

        self.assertEqual(
            runner.commands,
            [
                [
                    "cargo",
                    "build",
                    "-p",
                    "keyhog",
                    "--bin",
                    "keyhog",
                    "--profile",
                    "release-fast",
                ],
                ["make", "-C", "benchmarks", "mirror"],
                ["make", "-C", "benchmarks", "canonical"],
                ["make", "-C", "benchmarks", "report"],
                [
                    "make",
                    "-C",
                    "benchmarks",
                    "readme-matrix",
                    "README_MATRIX_SOURCE_STATE=developer-dirty",
                    "README_SCALING_SOURCE_STATE=developer-dirty",
                ],
                ["python3", "-B", "scripts/star_history.py"],
                ["make", "-C", "benchmarks", "report-check"],
                [
                    "git",
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                ],
            ],
        )
        make_environments = [
            environment
            for command, environment in zip(runner.commands, runner.environments)
            if command[:2] == ["make", "-C"]
        ]
        self.assertEqual(
            make_environments,
            [
                {
                    "KEYHOG_BIN": str(candidate),
                    "KEYHOG_BENCH_ALLOW_GENERATED_EVIDENCE_DIRTY": "1",
                }
            ]
            * 5,
        )

    def test_canonical_bloom_report_is_published_after_freshness_scoring(self) -> None:
        """Generated Bloom Markdown must not dirty the tree before candidate scoring."""
        makefile = Path("benchmarks/Makefile").resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            results = root / "results"
            reports.mkdir()
            results.mkdir()
            tracked = reports / "bloom-creddata-fx-record-spans-v1.md"
            tracked.write_text("committed receipt\n", encoding="utf-8")
            candidate = root / "keyhog"
            candidate.write_bytes(b"candidate")
            fake_python = root / "fake-python"
            fake_python.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "from pathlib import Path\n"
                "args = sys.argv[1:]\n"
                "module = args[1] if len(args) > 1 and args[0] == '-m' else ''\n"
                "tracked = Path('reports/bloom-creddata-fx-record-spans-v1.md')\n"
                "staged = Path('results/.bloom-creddata-fx-record-spans-v1.md')\n"
                "if module == 'bench.corpora.mirror':\n"
                "    raise SystemExit(0)\n"
                "if module == 'bench.bloom':\n"
                "    target = Path(args[args.index('--report') + 1]) "
                "if '--report' in args else tracked\n"
                "    target.write_text('fresh receipt\\n', encoding='utf-8')\n"
                "    raise SystemExit(0)\n"
                "if module == 'bench':\n"
                "    if tracked.read_text(encoding='utf-8') != 'committed receipt\\n':\n"
                "        raise SystemExit('tracked report changed before freshness scoring')\n"
                "    if staged.read_text(encoding='utf-8') != 'fresh receipt\\n':\n"
                "        raise SystemExit('staged report is missing current evidence')\n"
                "    raise SystemExit(0)\n"
                "if module == 'bench.report':\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(f'unexpected command: {args!r}')\n",
                encoding="utf-8",
            )
            fake_python.chmod(0o755)

            completed = subprocess.run(
                [
                    "make",
                    "-f",
                    str(makefile),
                    "canonical",
                    f"BENCH_DIR={root}/",
                    f"PY={fake_python}",
                    f"KEYHOG_BIN={candidate}",
                    "CANONICAL_SCANNERS=keyhog",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(tracked.read_text(encoding="utf-8"), "fresh receipt\n")

    def test_missing_benchmark_candidate_stops_before_measurement(self) -> None:
        """A successful cargo exit without the expected binary must never measure a stale executable."""
        runner = FakeRunner("")
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, True
        )
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing-keyhog"
            with mock.patch.object(release, "candidate_binary", return_value=missing):
                with self.assertRaisesRegex(release.ReleaseError, "was not built"):
                    release.refresh_benchmarks(runner, options)

        self.assertEqual(
            runner.commands,
            [
                [
                    "cargo",
                    "build",
                    "-p",
                    "keyhog",
                    "--bin",
                    "keyhog",
                    "--profile",
                    "release-fast",
                ]
            ],
        )

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
        runner = FakeRunner(" M README.md\0?? benchmarks/reports/new.json\0")

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
        runner = FakeRunner(" M README.md\0 M crates/scanner/src/lib.rs\0")

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
        runner = FakeRunner("R  README-renamed.md\0README.md\0")
        with self.assertRaisesRegex(release.ReleaseError, "renamed"):
            release.git_status_paths(runner)

    def test_git_status_preserves_whitespace_newlines_and_unicode(self) -> None:
        """Phase ownership must inspect exact Git path bytes instead of display quoting."""
        runner = FakeRunner(
            " M docs/ leading.md\0"
            "?? docs/line\nbreak.md\0"
            "?? benchmarks/reports/résumé.json\0"
        )

        self.assertEqual(
            release.git_status_paths(runner),
            {
                Path("docs/ leading.md"),
                Path("docs/line\nbreak.md"),
                Path("benchmarks/reports/résumé.json"),
            },
        )

    def test_malformed_nul_status_fails_before_staging(self) -> None:
        """Truncated porcelain output must not be interpreted as an owned release path."""
        runner = FakeRunner("M README.md\0")
        with self.assertRaisesRegex(release.ReleaseError, "cannot parse"):
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
                [
                    "git",
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                ],
            ],
        )

    def test_pre_tag_aggregate_gate_ignores_an_ambient_stale_binary(self) -> None:
        """Aggregate parity proofs must consume the immutable current candidate explicitly."""
        runner = FakeRunner("")
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, True
        )

        with mock.patch.dict("os.environ", {"KEYHOG_BIN": "/tmp/stale-keyhog"}):
            release.run_pre_tag_gates(runner, options)

        self.assertEqual(
            runner.environments,
            [
                None,
                None,
                {"KEYHOG_BIN": str(release.release_proof_binary())},
                None,
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


class PublicationContractTests(unittest.TestCase):
    """Protect final workflow and public GitHub release identity checks."""

    def _record(self, **overrides: object) -> dict[str, object]:
        record: dict[str, object] = {
            "tagName": "v0.5.49",
            "isDraft": False,
            "isPrerelease": False,
            "publishedAt": "2026-07-30T12:00:00Z",
            "url": "https://github.com/santhreal/keyhog/releases/tag/v0.5.49",
        }
        record.update(overrides)
        return record

    def test_exact_public_release_survives_both_workflow_watches(self) -> None:
        """Success requires the exact tag URL after release and Pages workflows pass."""
        runner = PublicationRunner(self._record())
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, True
        )

        with mock.patch.object(release, "find_workflow_run", side_effect=[101, 202]):
            release.watch_publication(runner, options, "a" * 40)

        self.assertEqual(
            runner.commands[:2],
            [
                ["gh", "run", "watch", "101", "--exit-status"],
                ["gh", "run", "watch", "202", "--exit-status"],
            ],
        )

    def test_draft_prerelease_unpublished_or_wrong_url_fails(self) -> None:
        """No nearby release record may masquerade as the final stable publication."""
        cases = (
            {"isDraft": True},
            {"isPrerelease": True},
            {"publishedAt": None},
            {"url": "https://github.com/santhreal/keyhog/releases/tag/v0.5.48"},
        )
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, True
        )
        for override in cases:
            with self.subTest(override=override):
                runner = PublicationRunner(self._record(**override))
                with mock.patch.object(
                    release, "find_workflow_run", side_effect=[101, 202]
                ), self.assertRaisesRegex(release.ReleaseError, "identity is incomplete"):
                    release.watch_publication(runner, options, "a" * 40)

    def test_preview_names_diagnostic_scope_without_publishing(self) -> None:
        """Preview output must disclose retained evidence and omitted duplicate Rust gates."""
        runner = FakeRunner()
        options = release.Options(
            "0.5.49", "2026-07-30", False, True, True, True
        )
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            release.preview(runner, options)

        rendered = output.getvalue()
        self.assertIn("Retain previously checked benchmark evidence", rendered)
        self.assertIn("excluding the diagnostic Rust rerun", rendered)
        self.assertNotIn("git push", rendered)


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

    def test_new_release_prepares_version_before_measuring_candidate(self) -> None:
        """Benchmark evidence must bind the final versioned executable, not the prior release."""
        events: list[str] = []
        runner = mock.Mock()
        runner.output.return_value = "a" * 40
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, False
        )

        with mock.patch.object(
            release, "require_publication_identity", return_value="A" * 40
        ), mock.patch.object(
            release, "workspace_version", return_value="0.5.48"
        ), mock.patch.object(
            release, "release_tag_state", return_value=(None, False)
        ), mock.patch.object(
            release,
            "prepare_release",
            side_effect=lambda *_: events.append("prepare"),
        ), mock.patch.object(
            release,
            "refresh_benchmarks",
            side_effect=lambda *_: events.append("benchmarks"),
        ), mock.patch.object(
            release,
            "run_pre_tag_gates",
            side_effect=lambda *_: events.append("gates"),
        ), mock.patch.object(
            release, "push_main", side_effect=lambda *_: events.append("push")
        ), mock.patch.object(release, "verify_tag_signature"):
            release.publish(runner, options)

        self.assertEqual(events, ["prepare", "benchmarks", "gates", "push"])

    def test_prepared_resume_refreshes_version_bound_evidence(self) -> None:
        """An interrupted pre-tag release must repair evidence made before its version bump."""
        events: list[str] = []
        runner = mock.Mock()
        runner.output.return_value = "a" * 40
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, False, True
        )

        with mock.patch.object(
            release, "require_publication_identity", return_value="A" * 40
        ), mock.patch.object(
            release, "workspace_version", return_value="0.5.49"
        ), mock.patch.object(
            release, "release_tag_state", return_value=(None, False)
        ), mock.patch.object(
            release,
            "prepare_release",
            side_effect=lambda *_: events.append("prepare"),
        ), mock.patch.object(
            release,
            "refresh_benchmarks",
            side_effect=lambda *_: events.append("benchmarks"),
        ), mock.patch.object(
            release,
            "run_pre_tag_gates",
            side_effect=lambda *_: events.append("gates"),
        ), mock.patch.object(
            release, "push_main", side_effect=lambda *_: events.append("push")
        ), mock.patch.object(release, "verify_tag_signature"):
            release.publish(runner, options)

        self.assertEqual(events, ["benchmarks", "gates", "push"])

    def test_signed_tag_resume_never_remeasures_immutable_evidence(self) -> None:
        """A published tag may be verified and watched, but its commit must not be rewritten."""
        commit = "a" * 40
        events: list[str] = []
        runner = mock.Mock()
        runner.output.return_value = commit
        options = release.Options(
            "0.5.49", "2026-07-30", True, False, False, False, True
        )

        with mock.patch.object(
            release, "require_publication_identity", return_value="A" * 40
        ), mock.patch.object(
            release, "workspace_version", return_value="0.5.49"
        ), mock.patch.object(
            release, "release_tag_state", return_value=(commit, True)
        ), mock.patch.object(
            release, "verify_tag_signature"
        ), mock.patch.object(
            release, "refresh_benchmarks"
        ) as refresh, mock.patch.object(
            release,
            "run_pre_tag_gates",
            side_effect=lambda *_: events.append("gates"),
        ), mock.patch.object(
            release, "push_main", side_effect=lambda *_: events.append("push")
        ):
            release.publish(runner, options)

        refresh.assert_not_called()
        runner.run.assert_not_called()
        self.assertEqual(events, ["gates", "push"])

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
