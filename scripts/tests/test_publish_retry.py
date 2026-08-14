"""Behavioral regressions for idempotent crates.io publication recovery."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PUBLISH = ROOT / "scripts" / "publish.sh"
CRATES = [
    "keyhog-profile",
    "keyhog-core",
    "keyhog-verifier",
    "keyhog-sources",
    "keyhog-scanner",
    "keyhog",
]


class PublishRecoveryTests(unittest.TestCase):
    """Exercise the real release shell flow with deterministic local process peers."""

    def run_publish(
        self,
        directory: str,
        *,
        failures: int = 0,
        lose_success_response: bool = False,
        initially_visible: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        root = Path(directory)
        commands = root / "bin"
        state = root / "state"
        commands.mkdir()
        state.mkdir()
        for crate in initially_visible:
            (state / f"{crate}.visible").touch()

        python = commands / "python3"
        python.write_text(
            """#!/usr/bin/python3
import os
import pathlib
import sys

program = sys.stdin.read()
state = pathlib.Path(os.environ["FAKE_PUBLISH_STATE"])
if "tomllib" in program:
    print("9.9.9")
    raise SystemExit(0)
if "urllib.request" in program:
    crate = sys.argv[-2]
    raise SystemExit(0 if (state / f"{crate}.visible").exists() else 1)
print("unexpected embedded Python program", file=sys.stderr)
raise SystemExit(2)
""",
            encoding="utf-8",
        )
        python.chmod(0o755)

        cargo = commands / "cargo"
        cargo.write_text(
            """#!/usr/bin/python3
import os
import pathlib
import sys

state = pathlib.Path(os.environ["FAKE_PUBLISH_STATE"])
crate = sys.argv[-1]
with (state / "cargo.log").open("a", encoding="utf-8") as log:
    log.write(crate + "\\n")
count_path = state / f"{crate}.attempts"
count = int(count_path.read_text() if count_path.exists() else "0") + 1
count_path.write_text(str(count))
if os.environ.get("FAKE_LOST_SUCCESS_RESPONSE") == "1" and count == 1:
    (state / f"{crate}.visible").touch()
    print("simulated lost successful response", file=sys.stderr)
    raise SystemExit(101)
if count <= int(os.environ.get("FAKE_CARGO_FAILURES", "0")):
    print("simulated transient upload failure", file=sys.stderr)
    raise SystemExit(101)
(state / f"{crate}.visible").touch()
raise SystemExit(0)
""",
            encoding="utf-8",
        )
        cargo.chmod(0o755)

        sleep = commands / "sleep"
        sleep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        sleep.chmod(0o755)

        environment = {
            **os.environ,
            "PATH": f"{commands}:{os.environ['PATH']}",
            "CARGO_REGISTRY_TOKEN": "test-token",
            "FAKE_PUBLISH_STATE": str(state),
            "KEYHOG_SKIP_REGISTRY_PREFLIGHT": "1",
            "FAKE_CARGO_FAILURES": str(failures),
            "FAKE_LOST_SUCCESS_RESPONSE": "1" if lose_success_response else "0",
        }
        return subprocess.run(
            ["bash", str(PUBLISH)],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    @staticmethod
    def cargo_log(directory: str) -> list[str]:
        """Return the exact fake Cargo invocation order, or no calls when all were visible."""
        path = Path(directory) / "state" / "cargo.log"
        return path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def test_transient_uploads_retry_in_dependency_order(self) -> None:
        """One transport failure per crate must recover without reordering dependencies."""
        with tempfile.TemporaryDirectory() as directory:
            completed = self.run_publish(directory, failures=1)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                self.cargo_log(directory),
                [crate for crate in CRATES for _attempt in range(2)],
            )
            self.assertIn("Published KeyHog 9.9.9 to crates.io.", completed.stdout)

    def test_lost_success_response_uses_visibility_without_duplicate_upload(self) -> None:
        """A server-accepted upload with a lost response must advance after one Cargo call."""
        with tempfile.TemporaryDirectory() as directory:
            completed = self.run_publish(directory, lose_success_response=True)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(self.cargo_log(directory), CRATES)
            self.assertEqual(
                completed.stdout.count("became visible after the failed upload response"),
                len(CRATES),
            )

    def test_permanent_failure_stops_before_dependent_crates_and_explains_rerun(self) -> None:
        """Three failed uploads must stop at the dependency root and preserve safe recovery."""
        with tempfile.TemporaryDirectory() as directory:
            completed = self.run_publish(directory, failures=99)

            self.assertEqual(self.cargo_log(directory), ["keyhog-profile"] * 3)
            self.assertIn("failed to publish keyhog-profile 9.9.9 after 3 attempts", completed.stderr)
            self.assertIn("already-visible crates will be skipped", completed.stderr)

    def test_visible_crates_are_skipped_without_uploading_again(self) -> None:
        """A workflow rerun must make no Cargo calls for an already complete release."""
        with tempfile.TemporaryDirectory() as directory:
            completed = self.run_publish(directory, initially_visible=tuple(CRATES))

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(self.cargo_log(directory), [])
            self.assertEqual(completed.stdout.count("already published"), len(CRATES))


if __name__ == "__main__":
    unittest.main()
