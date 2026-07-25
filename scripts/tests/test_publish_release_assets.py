"""Behavioral regressions for private, exact GitHub release publication."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from scripts.publish_release_assets import (
    GitHubClient,
    PublicationError,
    publish_release,
)


@dataclass
class ReleaseServerState:
    """Mutable fake GitHub state observed through real HTTP requests."""

    releases: list[dict[str, Any]] = field(default_factory=list)
    requests: list[tuple[str, str, Any]] = field(default_factory=list)
    draft_at_upload: list[bool] = field(default_factory=list)
    next_release_id: int = 100
    next_asset_id: int = 1000
    upload_count: int = 0
    fail_upload_at: int | None = None
    inject_unexpected_asset: bool = False


class ReleaseHandler(BaseHTTPRequestHandler):
    """Minimal release API that preserves mutation ordering for assertions."""

    server: "ReleaseServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _json_body(self) -> dict[str, Any]:
        raw = self._body()
        return json.loads(raw) if raw else {}

    def _reply(self, status: int, value: Any = None) -> None:
        body = b"" if value is None else json.dumps(value).encode("utf-8")
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _release(self, release_id: int) -> dict[str, Any] | None:
        return next(
            (
                release
                for release in self.server.state.releases
                if release["id"] == release_id
            ),
            None,
        )

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        parts = parsed.path.strip("/").split("/")
        self.server.state.requests.append(("GET", self.path, None))
        if (
            len(parts) == 4
            and parts[:3] == ["repos", "owner", "keyhog"]
            and parts[3] == "releases"
        ):
            releases = [
                {key: value for key, value in release.items() if key != "assets"}
                for release in self.server.state.releases
            ]
            self._reply(200, releases)
            return
        if (
            len(parts) == 6
            and parts[:4] == ["repos", "owner", "keyhog", "releases"]
            and parts[5] == "assets"
        ):
            release = self._release(int(parts[4]))
            if release is None:
                self._reply(404, {"message": "release not found"})
                return
            assets = [
                {key: value for key, value in asset.items() if key != "content"}
                for asset in release["assets"]
            ]
            if (
                self.server.state.inject_unexpected_asset
                and self.server.state.upload_count
            ):
                assets.append({"id": 999_999, "name": "unexpected.bin"})
            self._reply(200, assets)
            return
        self._reply(404, {"message": f"unhandled GET {self.path}"})

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 4 and parts == ["repos", "owner", "keyhog", "releases"]:
            payload = self._json_body()
            self.server.state.requests.append(("POST", self.path, payload))
            release = {
                "id": self.server.state.next_release_id,
                "tag_name": payload["tag_name"],
                "draft": payload["draft"],
                "prerelease": payload["prerelease"],
                "assets": [],
            }
            self.server.state.next_release_id += 1
            self.server.state.releases.append(release)
            self._reply(
                201, {key: value for key, value in release.items() if key != "assets"}
            )
            return
        if (
            len(parts) == 6
            and parts[:4] == ["repos", "owner", "keyhog", "releases"]
            and parts[5] == "assets"
        ):
            release = self._release(int(parts[4]))
            content = self._body()
            self.server.state.upload_count += 1
            self.server.state.requests.append(("POST", self.path, content))
            if release is None:
                self._reply(404, {"message": "release not found"})
                return
            self.server.state.draft_at_upload.append(release["draft"])
            if self.server.state.fail_upload_at == self.server.state.upload_count:
                self._reply(500, {"message": "injected upload failure"})
                return
            name = parse_qs(parsed.query)["name"][0]
            asset = {
                "id": self.server.state.next_asset_id,
                "name": name,
                "content": content,
            }
            self.server.state.next_asset_id += 1
            release["assets"].append(asset)
            self._reply(
                201, {key: value for key, value in asset.items() if key != "content"}
            )
            return
        self._reply(404, {"message": f"unhandled POST {self.path}"})

    def do_PATCH(self) -> None:
        parts = urlsplit(self.path).path.strip("/").split("/")
        payload = self._json_body()
        self.server.state.requests.append(("PATCH", self.path, payload))
        if len(parts) == 5 and parts[:4] == ["repos", "owner", "keyhog", "releases"]:
            release = self._release(int(parts[4]))
            if release is None:
                self._reply(404, {"message": "release not found"})
                return
            release.update(payload)
            self._reply(
                200, {key: value for key, value in release.items() if key != "assets"}
            )
            return
        self._reply(404, {"message": f"unhandled PATCH {self.path}"})

    def do_DELETE(self) -> None:
        parts = urlsplit(self.path).path.strip("/").split("/")
        self.server.state.requests.append(("DELETE", self.path, None))
        if len(parts) == 6 and parts[:5] == [
            "repos",
            "owner",
            "keyhog",
            "releases",
            "assets",
        ]:
            asset_id = int(parts[5])
            for release in self.server.state.releases:
                before = len(release["assets"])
                release["assets"] = [
                    asset for asset in release["assets"] if asset["id"] != asset_id
                ]
                if len(release["assets"]) != before:
                    self._reply(204)
                    return
            self._reply(404, {"message": "asset not found"})
            return
        self._reply(404, {"message": f"unhandled DELETE {self.path}"})


class ReleaseServer(ThreadingHTTPServer):
    """HTTP server carrying fake GitHub release state."""

    def __init__(self, state: ReleaseServerState) -> None:
        super().__init__(("127.0.0.1", 0), ReleaseHandler)
        self.state = state


class PublishReleaseAssetsTests(unittest.TestCase):
    """Prove release publication remains private until its manifest is exact."""

    def setUp(self) -> None:
        self.state = ReleaseServerState()
        self.server = ReleaseServer(self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        base = f"http://127.0.0.1:{self.server.server_port}"
        self.client = GitHubClient("test-token", base, base)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tempdir.cleanup()

    def asset(self, name: str, content: bytes) -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def existing_release(
        self,
        release_id: int,
        tag: str,
        *,
        draft: bool = True,
        assets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        release = {
            "id": release_id,
            "tag_name": tag,
            "draft": draft,
            "prerelease": False,
            "assets": assets or [],
        }
        self.state.releases.append(release)
        return release

    def test_first_run_uploads_exact_bytes_while_draft_then_publishes(self) -> None:
        """Locks out first-run exposure of a release before every signed byte is present."""
        first = self.asset("keyhog-linux", b"binary")
        second = self.asset("keyhog-linux.minisig", b"signature")

        release_id = publish_release(
            self.client, "owner/keyhog", "v0.5.45", [second, first]
        )

        self.assertEqual(release_id, 100)
        release = self.state.releases[0]
        self.assertFalse(release["draft"])
        self.assertEqual(
            [(asset["name"], asset["content"]) for asset in release["assets"]],
            [("keyhog-linux", b"binary"), ("keyhog-linux.minisig", b"signature")],
        )
        self.assertEqual(self.state.draft_at_upload, [True, True])
        self.assertEqual(
            [request for request in self.state.requests if request[0] == "PATCH"][-1],
            ("PATCH", "/repos/owner/keyhog/releases/100", {"draft": False}),
        )

    def test_interrupted_draft_reuses_id_and_replaces_stale_assets(self) -> None:
        """Locks out tag-endpoint retries that cannot discover an interrupted draft."""
        release = self.existing_release(
            41,
            "v0.5.45",
            assets=[{"id": 7, "name": "stale.bin", "content": b"stale"}],
        )
        asset = self.asset("keyhog-windows.exe", b"replacement")

        release_id = publish_release(self.client, "owner/keyhog", "v0.5.45", [asset])

        self.assertEqual(release_id, 41)
        self.assertFalse(release["draft"])
        self.assertEqual(
            [(entry["name"], entry["content"]) for entry in release["assets"]],
            [("keyhog-windows.exe", b"replacement")],
        )
        self.assertIn(
            ("DELETE", "/repos/owner/keyhog/releases/assets/7", None),
            self.state.requests,
        )
        self.assertFalse(
            any(
                method == "POST" and path == "/repos/owner/keyhog/releases"
                for method, path, _payload in self.state.requests
            )
        )

    def test_manifest_mismatch_keeps_release_private(self) -> None:
        """Locks out publishing when GitHub's observed asset set differs by one name."""
        release = self.existing_release(42, "v0.5.45", draft=False)
        self.state.inject_unexpected_asset = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "does not equal"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset])

        self.assertTrue(release["draft"])
        self.assertNotIn(
            ("PATCH", "/repos/owner/keyhog/releases/42", {"draft": False}),
            self.state.requests,
        )

    def test_upload_failure_keeps_release_private(self) -> None:
        """Locks out partial publication when a later signed asset upload fails."""
        release = self.existing_release(43, "v0.5.45", draft=False)
        self.state.fail_upload_at = 2
        first = self.asset("a.bin", b"a")
        second = self.asset("b.bin", b"b")

        with self.assertRaisesRegex(PublicationError, "HTTP 500"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [first, second])

        self.assertTrue(release["draft"])
        self.assertEqual(
            [(asset["name"], asset["content"]) for asset in release["assets"]],
            [("a.bin", b"a")],
        )

    def test_duplicate_tag_claims_fail_before_mutation(self) -> None:
        """Locks out mutating an arbitrary release when duplicate tag ownership is ambiguous."""
        self.existing_release(44, "v0.5.45")
        self.existing_release(45, "v0.5.45")
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "multiple GitHub releases"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset])

        self.assertEqual(
            [(method, path) for method, path, _payload in self.state.requests],
            [("GET", "/repos/owner/keyhog/releases?per_page=100")],
        )

    def test_prerelease_tag_and_encoded_asset_name_round_trip(self) -> None:
        """Locks out losing prerelease state or corrupting reserved filename characters."""
        asset = self.asset("keyhog gpu+#1.bin", b"gpu")

        publish_release(self.client, "owner/keyhog", "v0.6.0-rc.1", [asset])

        release = self.state.releases[0]
        self.assertTrue(release["prerelease"])
        self.assertEqual(release["assets"][0]["name"], "keyhog gpu+#1.bin")
        upload_paths = [
            path
            for method, path, _payload in self.state.requests
            if method == "POST" and "/assets?name=" in path
        ]
        self.assertEqual(
            upload_paths,
            ["/repos/owner/keyhog/releases/100/assets?name=keyhog%20gpu%2B%231.bin"],
        )

    def test_duplicate_basenames_fail_without_contacting_github(self) -> None:
        """Locks out an unverifiable manifest when two local paths map to one asset name."""
        left = self.root / "left"
        right = self.root / "right"
        left.mkdir()
        right.mkdir()
        first = left / "keyhog.bin"
        second = right / "keyhog.bin"
        first.write_bytes(b"left")
        second.write_bytes(b"right")

        with self.assertRaisesRegex(PublicationError, "basenames must be unique"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [first, second])

        self.assertEqual(self.state.requests, [])


if __name__ == "__main__":
    unittest.main()
