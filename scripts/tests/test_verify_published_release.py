"""Behavioral contract for the crates.io public-release verdict gate."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

TAG = "v0.5.45"
COMMIT = "a" * 40
REPOSITORY = "santhreal/keyhog"
TOKEN = "github-read-token"
PAYLOAD = b"keyhog-signature-test-v1\n"
SIGNATURE = b"""untrusted comment: signature from rsign secret key
RUTPnJ/p6xVJ3REkJ9dhxwKQpEisq7Y2A4uIZlUzPRM0zDjWidV3sIXjHB8d558++9M0KpCpz6T8efYlVFl/RZhrKIznrUZSGww=
trusted comment: timestamp:1780025193\tfile:/tmp/claude-1000/tmp.JTQWgRt5FO/fixture.bin\tprehashed
L/wvGiwIhpaBlkEUaQ364Q8ph9ksqIxJyIMy1RQbs/QS4+q8biUaJGt+0weV4E0IV/pPHywDFtZhvUD03un2CA==
"""


def payload_names() -> list[str]:
    names = ["install.sh", "install.ps1"]
    for base in (
        "keyhog-linux-x86_64",
        "keyhog-macos-aarch64",
        "keyhog-macos-x86_64",
        "keyhog-windows-x86_64.exe",
    ):
        names.extend((base, f"{base}.gpu-literals.tar.gz"))
    return names


@dataclass
class ReleaseState:
    release: dict[str, Any] | None = None
    commit: str = COMMIT
    asset_bytes: dict[int, bytes] = field(default_factory=dict)
    requests: list[tuple[str, str | None]] = field(default_factory=list)


class ReleaseHandler(BaseHTTPRequestHandler):
    server: "ReleaseServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def reply(self, status: int, value: Any = None, *, raw: bytes | None = None) -> None:
        body = raw if raw is not None else json.dumps(value or {}).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/octet-stream" if raw is not None else "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self.server.state.requests.append((path, self.headers.get("Authorization")))
        release = self.server.state.release
        if path == f"/repos/{REPOSITORY}/releases/tags/{TAG}":
            if release is None:
                self.reply(404, {"message": "Not Found"})
            else:
                self.reply(200, release)
            return
        if path == "/repos/santhreal/keyhog/releases/572":
            if release is None:
                self.reply(404, {"message": "Not Found"})
            else:
                self.reply(200, release)
            return
        if path == f"/repos/{REPOSITORY}/commits/{TAG}":
            self.reply(200, {"sha": self.server.state.commit})
            return
        prefix = "/repos/santhreal/keyhog/releases/assets/"
        if path.startswith(prefix):
            try:
                asset_id = int(unquote(path.removeprefix(prefix)))
                content = self.server.state.asset_bytes[asset_id]
            except (ValueError, KeyError):
                self.reply(404, {"message": "Not Found"})
                return
            self.reply(200, raw=content)
            return
        self.reply(404, {"message": "Not Found"})


class ReleaseServer(ThreadingHTTPServer):
    def __init__(self, state: ReleaseState) -> None:
        super().__init__(("127.0.0.1", 0), ReleaseHandler)
        self.state = state


class PublishedReleaseVerdictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = ReleaseState()
        self.server = ReleaseServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.rsign = shutil.which("rsign")
        if self.rsign is None:
            fake_rsign = self.root / "rsign"
            fake_rsign.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib\n"
                "import sys\n"
                f"expected_payload = {PAYLOAD!r}\n"
                f"expected_signature = {SIGNATURE!r}\n"
                "arguments = sys.argv[1:]\n"
                "signature = pathlib.Path(arguments[arguments.index('-x') + 1]).read_bytes()\n"
                "payload = pathlib.Path(arguments[-1]).read_bytes()\n"
                "raise SystemExit(0 if payload == expected_payload and signature == expected_signature else 1)\n",
                encoding="utf-8",
            )
            fake_rsign.chmod(0o755)
            self.rsign = str(fake_rsign)
        self._install_complete_release_fixture()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tempdir.cleanup()

    def _install_complete_release_fixture(self) -> None:
        contents: dict[str, bytes] = {}
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        for payload in payload_names():
            contents[payload] = PAYLOAD
            contents[f"{payload}.sha256"] = f"{digest}  {payload}\n".encode()
            contents[f"{payload}.minisig"] = SIGNATURE
        assets = []
        for asset_id, name in enumerate(sorted(contents), start=1000):
            content = contents[name]
            self.state.asset_bytes[asset_id] = content
            assets.append(
                {
                    "id": asset_id,
                    "name": name,
                    "size": len(content),
                    "state": "uploaded",
                    "url": (
                        f"http://127.0.0.1:{self.server.server_port}"
                        f"/repos/{REPOSITORY}/releases/assets/{asset_id}"
                    ),
                }
            )
        self.state.release = {
            "id": 572,
            "tag_name": TAG,
            "draft": False,
            "prerelease": False,
            "published_at": "2026-07-25T12:00:00Z",
            "assets": assets,
        }

    def run_verifier(
        self, *, expected_release_id: int | None = 572
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.pop("CARGO_REGISTRY_TOKEN", None)
        environment.update(
            {
                "GH_TOKEN": TOKEN,
                "GITHUB_API_URL": f"http://127.0.0.1:{self.server.server_port}",
                "RSIGN_BIN": self.rsign or "rsign",
            }
        )
        script = Path(__file__).parents[1] / "verify_published_release.py"
        command = [
            "python3",
            "-B",
            str(script),
            "--repository",
            REPOSITORY,
            "--tag",
            TAG,
            "--expected-commit",
            COMMIT,
        ]
        if expected_release_id is not None:
            command.extend(("--expected-release-id", str(expected_release_id)))
        command.extend(("--download-dir", str(self.root / "release-assets")))
        return subprocess.run(
            command,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def assert_failed_before_download(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.state.requests), 1)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_v0_5_45_published_release_shape_is_verified_by_id(self) -> None:
        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"verified immutable published release 572 for {TAG}", result.stdout)
        self.assertEqual(len(self.state.requests), 34)
        self.assertEqual(
            [path for path, _auth in self.state.requests].count(
                "/repos/santhreal/keyhog/releases/572"
            ),
            2,
        )
        self.assertTrue(
            all(auth == f"Bearer {TOKEN}" for _path, auth in self.state.requests)
        )
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_manual_recovery_resolves_and_verifies_release_id(self) -> None:
        result = self.run_verifier(expected_release_id=None)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.state.requests), 34)
        self.assertIn(f"verified immutable published release 572 for {TAG}", result.stdout)

    def test_release_event_id_mismatch_is_rejected(self) -> None:
        result = self.run_verifier(expected_release_id=573)

        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.state.requests), 1)
        self.assertIn("release event ID 573 does not match", result.stderr)

    def test_missing_release_is_rejected(self) -> None:
        self.state.release = None

        result = self.run_verifier()

        self.assert_failed_before_download(result)
        self.assertIn("returned HTTP 404", result.stderr)

    def test_draft_release_is_rejected(self) -> None:
        assert self.state.release is not None
        self.state.release["draft"] = True

        result = self.run_verifier()

        self.assert_failed_before_download(result)
        self.assertIn("is still draft", result.stderr)

    def test_release_without_published_at_is_rejected(self) -> None:
        assert self.state.release is not None
        self.state.release["published_at"] = None

        result = self.run_verifier()

        self.assert_failed_before_download(result)
        self.assertIn("no published_at verdict", result.stderr)

    def test_release_tag_commit_mismatch_is_rejected(self) -> None:
        self.state.commit = "b" * 40

        result = self.run_verifier()

        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.state.requests), 3)
        self.assertIn("resolves to commit", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_incomplete_asset_manifest_is_rejected(self) -> None:
        assert self.state.release is not None
        self.state.release["assets"].pop()

        result = self.run_verifier()

        self.assert_failed_before_download(result)
        self.assertIn("exact signed asset manifest is incomplete", result.stderr)

    def test_windows_binary_checksum_marker_is_verified(self) -> None:
        """Locks out rejecting the valid binary-mode marker emitted by Windows sha256sum."""
        assert self.state.release is not None
        asset = next(
            item
            for item in self.state.release["assets"]
            if item["name"] == "keyhog-windows-x86_64.exe.sha256"
        )
        original = self.state.asset_bytes[asset["id"]]
        binary_mode = original.replace(
            b"  keyhog-windows-x86_64.exe\n",
            b" *keyhog-windows-x86_64.exe\n",
        )
        self.state.asset_bytes[asset["id"]] = binary_mode
        asset["size"] = len(binary_mode)

        result = self.run_verifier()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.state.requests), 34)

    def test_checksum_manifest_mismatch_is_rejected(self) -> None:
        assert self.state.release is not None
        asset = next(
            item for item in self.state.release["assets"] if item["name"] == "install.ps1.sha256"
        )
        forged = f"{'0' * 64}  install.ps1\n".encode()
        self.state.asset_bytes[asset["id"]] = forged
        asset["size"] = len(forged)

        result = self.run_verifier()

        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.state.requests), 34)
        self.assertIn("does not authenticate install.ps1", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_signature_manifest_mismatch_is_rejected(self) -> None:
        assert self.state.release is not None
        asset = next(
            item for item in self.state.release["assets"] if item["name"] == "install.ps1.minisig"
        )
        forged = b"not a minisign signature\n"
        self.state.asset_bytes[asset["id"]] = forged
        asset["size"] = len(forged)

        result = self.run_verifier()

        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(self.state.requests), 34)
        self.assertIn("does not authenticate install.ps1", result.stderr)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
