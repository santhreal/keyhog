"""Behavioral regressions for private, exact GitHub release publication."""

from __future__ import annotations

import hashlib
import json
import os
import tarfile
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
    PublicationReceipt,
    create_deterministic_archive,
    prepare_release,
    publish_prepared_release,
)

RELEASE_NOTES = "### Fixed\n\n- Publish the exact signed manifest.\n"
EXPECTED_COMMIT = "a" * 40

def publish_release(
    client: GitHubClient,
    repository: str,
    tag: str,
    asset_paths: list[Path],
    release_notes: str,
    expected_commit: str,
) -> int:
    receipt = prepare_release(
        client,
        repository,
        tag,
        asset_paths,
        release_notes,
        expected_commit,
    )
    return publish_prepared_release(client, receipt)


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
    detach_tag_on_publish: bool = False
    drift_body_on_publish: bool = False
    invert_prerelease_on_publish: bool = False
    tag_commit: str = EXPECTED_COMMIT
    annotated_tag_sha: str | None = None
    move_tag_after_publish: bool = False
    move_tag_on_manifest_check: bool = False
    wrong_upload_size: bool = False
    wrong_draft_response_id_once: bool = False
    ignore_rollback_after_publish: bool = False
    published_once: bool = False


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

    def _reply_bytes(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
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
            len(parts) == 7
            and parts[:6] == ["repos", "owner", "keyhog", "git", "ref", "tags"]
        ):
            if self.server.state.annotated_tag_sha is None:
                target = {"type": "commit", "sha": self.server.state.tag_commit}
            else:
                target = {
                    "type": "tag",
                    "sha": self.server.state.annotated_tag_sha,
                }
            self._reply(
                200,
                {
                    "ref": f"refs/tags/{parts[6]}",
                    "object": target,
                },
            )
            return
        if (
            len(parts) == 6
            and parts[:5] == ["repos", "owner", "keyhog", "git", "tags"]
            and parts[5] == self.server.state.annotated_tag_sha
        ):
            self._reply(
                200,
                {"object": {"type": "commit", "sha": self.server.state.tag_commit}},
            )
            return
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
        if len(parts) == 5 and parts[:4] == ["repos", "owner", "keyhog", "releases"]:
            release = self._release(int(parts[4]))
            if release is None:
                self._reply(404, {"message": "release not found"})
                return
            self._reply(
                200, {key: value for key, value in release.items() if key != "assets"}
            )
            return
        if (
            len(parts) == 6
            and parts[:5] == ["repos", "owner", "keyhog", "releases", "assets"]
        ):
            asset_id = int(parts[5])
            if asset_id == 999_999 and self.server.state.inject_unexpected_asset:
                self._reply_bytes(200, b"x")
                return
            asset = next(
                (
                    asset
                    for release in self.server.state.releases
                    for asset in release["assets"]
                    if asset["id"] == asset_id
                ),
                None,
            )
            if asset is None:
                self._reply(404, {"message": "asset not found"})
                return
            self._reply_bytes(200, asset["content"])
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
                assets.append({"id": 999_999, "name": "unexpected.bin", "size": 1})
            if (
                self.server.state.move_tag_on_manifest_check
                and self.server.state.upload_count
            ):
                self.server.state.tag_commit = "b" * 40
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
                "published_at": None,
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
                "size": len(content),
                "content": content,
            }
            self.server.state.next_asset_id += 1
            release["assets"].append(asset)
            response = {key: value for key, value in asset.items() if key != "content"}
            if self.server.state.wrong_upload_size:
                response["size"] += 1
            self._reply(201, response)
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
            if not (
                payload.get("draft") is True
                and self.server.state.ignore_rollback_after_publish
                and self.server.state.published_once
            ):
                release.update(payload)
            if payload.get("draft") is False:
                release["published_at"] = "2026-07-25T12:00:00Z"
                self.server.state.published_once = True
                if self.server.state.detach_tag_on_publish:
                    release["tag_name"] = "untagged-injected"
                if self.server.state.drift_body_on_publish:
                    release["body"] = "stale release body"
                if self.server.state.invert_prerelease_on_publish:
                    release["prerelease"] = not release["prerelease"]
                if self.server.state.move_tag_after_publish:
                    self.server.state.tag_commit = "b" * 40
            response = {
                key: value for key, value in release.items() if key != "assets"
            }
            if (
                payload.get("draft") is True
                and self.server.state.wrong_draft_response_id_once
            ):
                self.server.state.wrong_draft_response_id_once = False
                response["id"] = 999_999
            self._reply(200, response)
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
    def test_deterministic_archive_is_byte_identical_across_metadata_changes(self) -> None:
        """Locks out gzip timestamps, host ownership, modes, and walk-order drift."""
        source = self.root / "keyhog-linux.gpu-literals"
        nested = source / "nested"
        nested.mkdir(parents=True)
        (source / "z.bin").write_bytes(b"z")
        (nested / "a.bin").write_bytes(b"a")
        first = self.root / "first.tar.gz"
        second = self.root / "second.tar.gz"

        create_deterministic_archive(source, first)
        for path in (source, nested, source / "z.bin", nested / "a.bin"):
            os.utime(path, (1_800_000_000, 1_800_000_000))
        os.chmod(source / "z.bin", 0o777)
        create_deterministic_archive(source, second)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first.read_bytes()[4:8], b"\0\0\0\0")
        with tarfile.open(first, mode="r:gz") as archive:
            members = archive.getmembers()
        self.assertEqual(
            [member.name for member in members],
            [
                "keyhog-linux.gpu-literals",
                "keyhog-linux.gpu-literals/nested",
                "keyhog-linux.gpu-literals/nested/a.bin",
                "keyhog-linux.gpu-literals/z.bin",
            ],
        )
        self.assertTrue(
            all(
                member.mtime == 0
                and member.uid == 0
                and member.gid == 0
                and member.uname == ""
                and member.gname == ""
                for member in members
            )
        )

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
            "name": tag,
            "body": RELEASE_NOTES.strip(),
            "draft": draft,
            "prerelease": False,
            "published_at": None if draft else "2026-07-25T12:00:00Z",
            "assets": assets or [],
        }
        self.state.releases.append(release)
        return release

    def test_first_run_uploads_exact_bytes_while_draft_then_publishes(self) -> None:
        """Locks out first-run exposure of a release before every signed byte is present."""
        first = self.asset("keyhog-linux", b"binary")
        second = self.asset("keyhog-linux.minisig", b"signature")

        release_id = publish_release(self.client, "owner/keyhog", "v0.5.45", [second, first], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertEqual(release_id, 100)
        release = self.state.releases[0]
        self.assertFalse(release["draft"])
        self.assertEqual(
            [(asset["name"], asset["content"]) for asset in release["assets"]],
            [("keyhog-linux", b"binary"), ("keyhog-linux.minisig", b"signature")],
        )
        self.assertEqual(release["body"], RELEASE_NOTES.strip())
        self.assertEqual(self.state.draft_at_upload, [True, True])
        self.assertEqual(
            [request for request in self.state.requests if request[0] == "PATCH"][-1],
            (
                "PATCH",
                "/repos/owner/keyhog/releases/100",
                {"draft": False},
            ),
        )

    def test_prepare_emits_round_trip_receipt_without_publishing(self) -> None:
        """Locks out exposing the release before downstream container and smoke gates."""
        asset = self.asset("keyhog-linux", b"binary")
        receipt = prepare_release(
            self.client,
            "owner/keyhog",
            "v0.5.45",
            [asset],
            RELEASE_NOTES,
            EXPECTED_COMMIT,
        )
        receipt_path = self.root / "release-publication.json"
        receipt.write(receipt_path)

        self.assertEqual(PublicationReceipt.read(receipt_path), receipt)
        self.assertTrue(self.state.releases[0]["draft"])
        self.assertFalse(
            any(
                method == "PATCH" and payload.get("draft") is False
                for method, _path, payload in self.state.requests
                if isinstance(payload, dict)
            )
        )

    def test_successful_rerun_is_idempotent_without_public_mutation(self) -> None:
        """Locks out re-drafting or replacing exact assets on a serialized rerun."""
        asset = self.asset("keyhog-linux", b"binary")
        first_id = publish_release(
            self.client,
            "owner/keyhog",
            "v0.5.45",
            [asset],
            RELEASE_NOTES,
            EXPECTED_COMMIT,
        )
        mutations_before = [
            request
            for request in self.state.requests
            if request[0] in {"POST", "PATCH", "DELETE"}
        ]

        receipt = prepare_release(
            self.client,
            "owner/keyhog",
            "v0.5.45",
            [asset],
            RELEASE_NOTES,
            EXPECTED_COMMIT,
        )
        second_id = publish_prepared_release(self.client, receipt)
        mutations_after = [
            request
            for request in self.state.requests
            if request[0] in {"POST", "PATCH", "DELETE"}
        ]

        self.assertEqual((first_id, second_id), (100, 100))
        self.assertEqual(mutations_after, mutations_before)
        self.assertFalse(self.state.releases[0]["draft"])

    def test_annotated_tag_chain_resolves_to_built_commit(self) -> None:
        """Locks out rejecting signed annotated release tags or trusting their object SHA."""
        self.state.annotated_tag_sha = "c" * 40
        asset = self.asset("keyhog-linux", b"binary")

        release_id = publish_release(
            self.client,
            "owner/keyhog",
            "v0.5.45",
            [asset],
            RELEASE_NOTES,
            EXPECTED_COMMIT,
        )

        self.assertEqual(release_id, 100)
        tag_requests = [
            path
            for method, path, _payload in self.state.requests
            if method == "GET" and "/git/" in path
        ]
        expected_pair = [
            "/repos/owner/keyhog/git/ref/tags/v0.5.45",
            f"/repos/owner/keyhog/git/tags/{'c' * 40}",
        ]
        self.assertEqual(tag_requests, expected_pair * 5)

    def test_detached_tag_response_reprivatizes_and_fails(self) -> None:
        """Locks out a green workflow that publishes assets under an untagged URL."""
        release = self.existing_release(46, "v0.5.45")
        release["name"] = "v0.5.45"
        self.state.detach_tag_on_publish = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "release identity"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertTrue(release["draft"])
        public_patch = next(
            payload
            for method, _path, payload in self.state.requests
            if method == "PATCH" and payload.get("draft") is False
        )
        self.assertEqual(public_patch, {"draft": False})

    def test_published_body_drift_reprivatizes_and_fails(self) -> None:
        """Locks out a public release whose body differs from the tagged changelog."""
        release = self.existing_release(47, "v0.5.45")
        self.state.drift_body_on_publish = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "identity and body"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertTrue(release["draft"])

    def test_published_prerelease_drift_reprivatizes_and_fails(self) -> None:
        """Locks out an rc tag published with stable-release metadata."""
        release = self.existing_release(48, "v0.6.0-rc.1")
        self.state.invert_prerelease_on_publish = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "prerelease"):
            publish_release(self.client, "owner/keyhog", "v0.6.0-rc.1", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertTrue(release["draft"])

    def test_interrupted_draft_reuses_id_and_replaces_stale_assets(self) -> None:
        """Locks out tag-endpoint retries that cannot discover an interrupted draft."""
        release = self.existing_release(
            41,
            "v0.5.45",
            assets=[{"id": 7, "name": "stale.bin", "content": b"stale"}],
        )
        asset = self.asset("keyhog-windows.exe", b"replacement")

        release_id = publish_release(self.client, "owner/keyhog", "v0.5.45", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

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
        release = self.existing_release(42, "v0.5.45")
        self.state.inject_unexpected_asset = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "does not equal"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertTrue(release["draft"])
        self.assertNotIn(
            ("PATCH", "/repos/owner/keyhog/releases/42", {"draft": False}),
            self.state.requests,
        )
    def test_upload_size_mismatch_keeps_release_private(self) -> None:
        """Locks out publishing a truncated asset that retained the expected name."""
        release = self.existing_release(52, "v0.5.45")
        self.state.wrong_upload_size = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "upload identity"):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertTrue(release["draft"])
        self.assertFalse(
            any(
                method == "PATCH" and payload.get("draft") is False
                for method, _path, payload in self.state.requests
            )
        )

    def test_upload_failure_keeps_release_private(self) -> None:
        """Locks out partial publication when a later signed asset upload fails."""
        release = self.existing_release(43, "v0.5.45")
        self.state.fail_upload_at = 2
        first = self.asset("a.bin", b"a")
        second = self.asset("b.bin", b"b")

        with self.assertRaisesRegex(PublicationError, "HTTP 500"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [first, second], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertTrue(release["draft"])
        self.assertEqual(
            [(asset["name"], asset["content"]) for asset in release["assets"]],
            [("a.bin", b"a")],
        )

    def test_tag_mismatch_fails_before_release_discovery_or_mutation(self) -> None:
        """Locks out publishing assets after the exact built tag has been moved."""
        self.state.tag_commit = "b" * 40
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "does not resolve to built commit"):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertEqual(
            [(method, path) for method, path, _payload in self.state.requests],
            [("GET", "/repos/owner/keyhog/git/ref/tags/v0.5.45")],
        )

    def test_tag_move_during_publication_reprivatizes_and_fails(self) -> None:
        """Locks out leaving a release public when its tag moves during mutation."""
        release = self.existing_release(49, "v0.5.45")
        self.state.move_tag_after_publish = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "does not resolve to built commit"):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertTrue(release["draft"])
    def test_tag_move_before_publish_never_exposes_release(self) -> None:
        """Locks out publishing after the tag moves during private asset mutation."""
        release = self.existing_release(53, "v0.5.45")
        self.state.move_tag_on_manifest_check = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "does not resolve to built commit"):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertTrue(release["draft"])
        self.assertFalse(
            any(
                method == "PATCH" and payload.get("draft") is False
                for method, _path, payload in self.state.requests
            )
        )

    def test_draft_mutation_response_must_name_the_exact_release_id(self) -> None:
        """Locks out deleting assets after GitHub acknowledges a different release."""
        release = self.existing_release(
            50,
            "v0.5.45",
            draft=True,
            assets=[{"id": 70, "name": "existing.bin", "content": b"existing"}],
        )
        self.state.wrong_draft_response_id_once = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "expected id=50"):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertTrue(release["draft"])
        self.assertEqual(self.state.upload_count, 0)
        self.assertFalse(
            any(method == "DELETE" for method, _path, _payload in self.state.requests)
        )

    def test_unconfirmed_rollback_reports_public_release_honestly(self) -> None:
        """Locks out reporting only the trigger error when draft rollback did not stick."""
        release = self.existing_release(51, "v0.5.45")
        self.state.drift_body_on_publish = True
        self.state.ignore_rollback_after_publish = True
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(
            PublicationError, "additionally failed to return release 51 to draft"
        ):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertFalse(release["draft"])

    def test_duplicate_tag_claims_fail_before_mutation(self) -> None:
        """Locks out mutating an arbitrary release when duplicate tag ownership is ambiguous."""
        self.existing_release(44, "v0.5.45")
        self.existing_release(45, "v0.5.45")
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "multiple GitHub releases"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertEqual(
            [(method, path) for method, path, _payload in self.state.requests],
            [
                ("GET", "/repos/owner/keyhog/git/ref/tags/v0.5.45"),
                ("GET", "/repos/owner/keyhog/releases?per_page=100"),
            ],
        )

    def test_prerelease_tag_and_encoded_asset_name_round_trip(self) -> None:
        """Locks out losing prerelease state or corrupting reserved filename characters."""
        asset = self.asset("keyhog gpu+#1.bin", b"gpu")

        publish_release(self.client, "owner/keyhog", "v0.6.0-rc.1", [asset], RELEASE_NOTES, EXPECTED_COMMIT)

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

    def test_placeholder_release_notes_fail_without_contacting_github(self) -> None:
        """Locks out publishing the old changelog-pointer body through direct API use."""
        asset = self.asset("keyhog-linux", b"binary")

        with self.assertRaisesRegex(PublicationError, "changelog pointer"):
            publish_release(self.client, "owner/keyhog", "v0.5.45", [asset], "Prebuilt binaries. See CHANGELOG.md.", EXPECTED_COMMIT)

        self.assertEqual(self.state.requests, [])
    def test_checksum_mismatch_fails_without_contacting_github(self) -> None:
        """Locks out signing and publishing a checksum that names stale payload bytes."""
        asset = self.asset("keyhog-linux", b"binary")
        checksum = self.asset("keyhog-linux.sha256", f"{'0' * 64}  keyhog-linux\n".encode())

        with self.assertRaisesRegex(PublicationError, "checksum manifest"):
            publish_release(
                self.client,
                "owner/keyhog",
                "v0.5.45",
                [asset, checksum],
                RELEASE_NOTES,
                EXPECTED_COMMIT,
            )

        self.assertEqual(self.state.requests, [])

    def test_windows_binary_checksum_marker_round_trips(self) -> None:
        """Locks out rejecting the valid binary-mode marker emitted by Windows sha256sum."""
        payload = b"binary"
        asset = self.asset("keyhog-windows.exe", payload)
        digest = hashlib.sha256(payload).hexdigest()
        checksum = self.asset(
            "keyhog-windows.exe.sha256",
            f"{digest} *keyhog-windows.exe\n".encode(),
        )

        publish_release(
            self.client,
            "owner/keyhog",
            "v0.5.45",
            [asset, checksum],
            RELEASE_NOTES,
            EXPECTED_COMMIT,
        )

        self.assertFalse(self.state.releases[0]["draft"])

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
            publish_release(self.client, "owner/keyhog", "v0.5.45", [first, second], RELEASE_NOTES, EXPECTED_COMMIT)

        self.assertEqual(self.state.requests, [])


if __name__ == "__main__":
    unittest.main()
