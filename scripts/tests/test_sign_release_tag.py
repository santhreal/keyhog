"""Behavioral coverage for protected noninteractive release-tag signing."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGNER = ROOT / "scripts" / "sign_release_tag.py"
TAG = "v0.5.49"
WORKFLOW = (ROOT / ".github" / "workflows" / "release-tag.yml").read_text(
    encoding="utf-8"
)
READINESS = (ROOT / ".github" / "workflows" / "release-ready.yml").read_text(
    encoding="utf-8"
)
PREVENTION_GATES = (ROOT / "scripts" / "gates" / "run_all.sh").read_text(
    encoding="utf-8"
)


class SignedReleaseTagBehaviorTests(unittest.TestCase):
    """Exercise real Git and GnuPG boundaries in isolated repositories."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.key_store = tempfile.TemporaryDirectory(prefix="keyhog-signing-key-")
        cls.key_root = Path(cls.key_store.name)
        cls.gnupg_home = cls.key_root / "gnupg"
        cls.gnupg_home.mkdir(mode=0o700)
        cls.passphrase_file = cls.key_root / "passphrase"
        cls.passphrase_file.write_text("correct horse battery staple", encoding="utf-8")
        cls.passphrase_file.chmod(0o600)
        cls.gpg_env = os.environ.copy()
        cls.gpg_env["GNUPGHOME"] = str(cls.gnupg_home)
        generated = subprocess.run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase-file",
                str(cls.passphrase_file),
                "--quick-generate-key",
                "KeyHog test signer <keyhog-signing-test@example.invalid>",
                "ed25519",
                "sign",
                "1d",
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=cls.gpg_env,
        )
        if generated.returncode != 0:
            raise RuntimeError(generated.stderr)
        listing = subprocess.run(
            [
                "gpg",
                "--batch",
                "--with-colons",
                "--fingerprint",
                "--list-secret-keys",
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            env=cls.gpg_env,
        ).stdout
        cls.fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.key_store.cleanup()

    def setUp(self) -> None:
        self.repository_store = tempfile.TemporaryDirectory(prefix="keyhog-signing-repo-")
        self.repository = Path(self.repository_store.name)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "KeyHog test")
        self.git("config", "user.email", "keyhog-signing-test@example.invalid")
        (self.repository / "payload.txt").write_text("signed release payload\n", encoding="utf-8")
        self.git("add", "payload.txt")
        self.git("commit", "-m", "release candidate")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        self.repository_store.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.repository,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.gpg_env,
        )

    def sign(
        self,
        *,
        tag: str = TAG,
        commit: str | None = None,
        fingerprint: str | None = None,
        passphrase_file: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                str(SIGNER),
                "--tag",
                tag,
                "--commit",
                commit or self.commit,
                "--fingerprint",
                fingerprint or self.fingerprint,
                "--passphrase-file",
                str(passphrase_file or self.passphrase_file),
            ],
            cwd=self.repository,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.gpg_env,
        )

    def assert_tag_absent(self, tag: str = TAG) -> None:
        result = subprocess.run(
            ["git", "show-ref", "--verify", "--quiet", f"refs/tags/{tag}"],
            cwd=self.repository,
            check=False,
            env=self.gpg_env,
        )
        self.assertEqual(result.returncode, 1)

    def test_correct_passphrase_creates_exact_verified_annotated_tag(self) -> None:
        """Locks out success that does not bind one signed tag object to the requested commit."""
        result = self.sign()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("cat-file", "-t", TAG).stdout.strip(), "tag")
        self.assertEqual(self.git("rev-parse", f"{TAG}^{{commit}}").stdout.strip(), self.commit)
        verification = subprocess.run(
            ["git", "verify-tag", "--raw", TAG],
            cwd=self.repository,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.gpg_env,
        )
        self.assertEqual(verification.returncode, 0, verification.stderr)
        self.assertIn(self.fingerprint, verification.stderr)
        self.assertEqual(
            self.git("for-each-ref", "--format=%(contents:subject)", f"refs/tags/{TAG}").stdout.strip(),
            f"KeyHog {TAG}",
        )

    def test_wrong_passphrase_fails_without_leaving_a_tag(self) -> None:
        """Prevents a failed automated unlock from leaving an unsigned or partial release ref."""
        wrong = self.repository / "wrong-passphrase"
        wrong.write_text("not the release passphrase", encoding="utf-8")
        wrong.chmod(0o600)

        result = self.sign(passphrase_file=wrong)

        self.assertEqual(result.returncode, 2)
        self.assertIn("signing failed", result.stderr.lower())
        self.assert_tag_absent()

    def test_foreign_fingerprint_fails_before_tag_creation(self) -> None:
        """Prevents any locally present or attacker-selected key from replacing the enrolled signer."""
        result = self.sign(fingerprint="A" * 40)

        self.assertEqual(result.returncode, 2)
        self.assertIn("no OpenPGP secret key", result.stderr)
        self.assert_tag_absent()

    def test_group_readable_passphrase_file_is_rejected(self) -> None:
        """Prevents release automation from consuming a passphrase exposed to another local user."""
        exposed = self.repository / "exposed-passphrase"
        exposed.write_text("correct horse battery staple", encoding="utf-8")
        exposed.chmod(0o640)

        result = self.sign(passphrase_file=exposed)

        self.assertEqual(result.returncode, 2)
        self.assertIn("deny group and other access", result.stderr)
        self.assert_tag_absent()

    def test_symlink_passphrase_file_is_rejected(self) -> None:
        """Prevents a path-swap attack from redirecting the signer to attacker-controlled bytes."""
        link = self.repository / "passphrase-link"
        link.symlink_to(self.passphrase_file)

        result = self.sign(passphrase_file=link)

        self.assertEqual(result.returncode, 2)
        self.assertIn("not a symlink", result.stderr)
        self.assert_tag_absent()

    def test_existing_tag_is_never_replaced(self) -> None:
        """Preserves release-tag immutability even when an existing ref is lightweight or unsigned."""
        self.git("tag", TAG)
        original = self.git("rev-parse", TAG).stdout.strip()

        result = self.sign()

        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(self.git("rev-parse", TAG).stdout.strip(), original)
        self.assertEqual(self.git("cat-file", "-t", TAG).stdout.strip(), "commit")

    def test_noncanonical_version_tag_is_rejected(self) -> None:
        """Prevents aliases such as leading-zero or prerelease tags from entering stable publication."""
        for tag in ("v00.5.49", "v0.05.49", "v0.5.049", "v0.5.49-rc.1", "0.5.49"):
            with self.subTest(tag=tag):
                result = self.sign(tag=tag)
                self.assertEqual(result.returncode, 2)
                self.assertIn("canonical stable", result.stderr)
                self.assert_tag_absent(tag)

    def test_abbreviated_or_foreign_commit_is_rejected(self) -> None:
        """Prevents signing an ambiguous abbreviation or a commit not present in the exact checkout."""
        for commit in (self.commit[:12], "f" * 40, self.commit.upper()):
            with self.subTest(commit=commit):
                result = self.sign(commit=commit)
                self.assertEqual(result.returncode, 2)
                self.assert_tag_absent()



class SigningWorkflowBoundaryTests(unittest.TestCase):
    """Lock the hosted signer to the same identity and immutability contracts."""

    def test_manual_owner_main_environment_is_the_only_entry_boundary(self) -> None:
        """Prevents schedules, pushes, or non-owner refs from gaining release-key access."""
        trigger = WORKFLOW.split("jobs:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("pull_request:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertNotIn("\n  push:", trigger)
        signing_job = WORKFLOW.split("  sign:\n", 1)[1]
        for contract in (
            "environment: release-signing",
            "contents: write",
            '\"$KEYHOG_RELEASE_ACTOR_ID\" != \"64453045\"',
            '\"$GITHUB_REF\" != \"refs/heads/main\"',
            'test \"$head\" = \"$KEYHOG_RELEASE_COMMIT\"',
            'test \"$head\" = \"$(git rev-parse origin/main)\"',
        ):
            self.assertIn(contract, signing_job)

    def test_enrolled_key_and_exact_tag_are_verified_before_push(self) -> None:
        """Prevents a secret swap, passphrase leak, or unverified tag from reaching origin."""
        for contract in (
            "KEYHOG_RELEASE_GPG_PRIVATE_KEY",
            "KEYHOG_RELEASE_GPG_PASSPHRASE",
            "KEYHOG_RELEASE_SIGNING_FINGERPRINT",
            "cmp -s .github/release-signing-key.asc",
            "gh api users/santhreal/gpg_keys",
            "scripts/sign_release_tag.py",
            '--passphrase-file \"$KEYHOG_RELEASE_PASSPHRASE_FILE\"',
            'git push origin \"refs/tags/v$KEYHOG_RELEASE_VERSION\"',
            "Remove imported release secrets",
        ):
            self.assertIn(contract, WORKFLOW)
        signer = WORKFLOW.index("scripts/sign_release_tag.py")
        push = WORKFLOW.index('git push origin \"refs/tags/v$KEYHOG_RELEASE_VERSION\"')
        self.assertLess(signer, push)
        self.assertNotIn("--passphrase $KEYHOG_RELEASE_GPG_PASSPHRASE", WORKFLOW)

    def test_signer_suite_runs_in_readiness_and_full_prevention_gates(self) -> None:
        """Prevents the hosted signing boundary from changing without its real-GPG suite."""
        command = "scripts.tests.test_sign_release_tag"
        self.assertEqual(READINESS.count(command), 1)
        self.assertEqual(PREVENTION_GATES.count(command), 1)

if __name__ == "__main__":
    unittest.main()
