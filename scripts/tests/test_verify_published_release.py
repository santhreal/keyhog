"""Behavioral contract for the crates.io public-release verdict gate."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from unittest import mock

from scripts import verify_published_release as verifier

TAG = "v0.5.45"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
SWAPPED_TAG_OBJECT = "c" * 40
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
class AssetResponse:
    status: int = 200
    body: bytes | None = None
    content_type: str = "application/octet-stream"
    content_length: int | None = None
    redirect: str | None = None
    delay_after_first_byte: float = 0.0


@dataclass
class ReleaseState:
    release: dict[str, Any] | None = None
    release_after_marker: dict[str, Any] | None = None
    ref_object: str = TAG_OBJECT
    ref_object_after_marker: str | None = None
    asset_bytes: dict[int, bytes] = field(default_factory=dict)
    asset_responses: dict[int, AssetResponse] = field(default_factory=dict)
    raw_api_responses: dict[str, tuple[int, bytes, str]] = field(default_factory=dict)
    requests: list[tuple[str, str | None]] = field(default_factory=list)
    marker: Path | None = None

    def marker_exists(self) -> bool:
        return self.marker is not None and self.marker.exists()

    def current_release(self) -> dict[str, Any] | None:
        if self.marker_exists() and self.release_after_marker is not None:
            return self.release_after_marker
        return self.release

    def current_ref_object(self) -> str:
        if self.marker_exists() and self.ref_object_after_marker is not None:
            return self.ref_object_after_marker
        return self.ref_object


class ReleaseHandler(BaseHTTPRequestHandler):
    server: "ReleaseServer"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def reply(
        self,
        status: int,
        value: Any = None,
        *,
        raw: bytes | None = None,
        content_type: str | None = None,
        content_length: int | None = None,
        redirect: str | None = None,
        delay_after_first_byte: float = 0.0,
    ) -> None:
        body = raw if raw is not None else json.dumps(value or {}).encode()
        self.send_response(status)
        if redirect is not None:
            self.send_header("Location", redirect)
        self.send_header("Content-Length", str(len(body) if content_length is None else content_length))
        self.send_header(
            "Content-Type",
            content_type
            or ("application/octet-stream" if raw is not None else "application/json"),
        )
        self.end_headers()
        try:
            if delay_after_first_byte and body:
                self.wfile.write(body[:1])
                self.wfile.flush()
                time.sleep(delay_after_first_byte)
                self.wfile.write(body[1:])
            else:
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        self.server.state.requests.append((path, self.headers.get("Authorization")))
        override = self.server.state.raw_api_responses.get(path)
        if override is not None:
            status, body, content_type = override
            self.reply(status, raw=body, content_type=content_type)
            return
        release = self.server.state.current_release()
        if path == f"/repos/{REPOSITORY}/releases/tags/{TAG}":
            if release is None:
                self.reply(404, {"message": "Not Found"})
            else:
                self.reply(200, release)
            return
        if path == f"/repos/{REPOSITORY}/releases/572":
            if release is None:
                self.reply(404, {"message": "Not Found"})
            else:
                self.reply(200, release)
            return
        if path == f"/repos/{REPOSITORY}/git/ref/tags/{TAG}":
            self.reply(
                200,
                {
                    "ref": f"refs/tags/{TAG}",
                    "object": {
                        "type": "tag",
                        "sha": self.server.state.current_ref_object(),
                        "url": (
                            f"https://api.github.com/repos/{REPOSITORY}/git/tags/"
                            f"{self.server.state.current_ref_object()}"
                        ),
                    },
                },
            )
            return
        tag_prefix = f"/repos/{REPOSITORY}/git/tags/"
        if path.startswith(tag_prefix):
            requested_object = unquote(path.removeprefix(tag_prefix))
            if requested_object not in {TAG_OBJECT, SWAPPED_TAG_OBJECT}:
                self.reply(404, {"message": "Not Found"})
            else:
                self.reply(
                    200,
                    {
                        "sha": requested_object,
                        "tag": TAG,
                        "object": {
                            "type": "commit",
                            "sha": COMMIT,
                            "url": (
                                f"https://api.github.com/repos/{REPOSITORY}/git/commits/"
                                f"{COMMIT}"
                            ),
                        },
                    },
                )
            return
        asset_prefix = f"/repos/{REPOSITORY}/releases/assets/"
        if path.startswith(asset_prefix):
            try:
                asset_id = int(unquote(path.removeprefix(asset_prefix)))
                content = self.server.state.asset_bytes[asset_id]
            except (ValueError, KeyError):
                self.reply(404, {"message": "Not Found"})
                return
            response = self.server.state.asset_responses.get(asset_id, AssetResponse())
            body = content if response.body is None else response.body
            if response.redirect is not None:
                self.reply(
                    response.status if response.status != 200 else 302,
                    raw=b"",
                    content_type=response.content_type,
                    redirect=response.redirect,
                )
                return
            self.reply(
                response.status,
                raw=body,
                content_type=response.content_type,
                content_length=response.content_length,
                delay_after_first_byte=response.delay_after_first_byte,
            )
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
        self.rsign_log = self.root / "rsign-invocations"
        self.rsign = self._write_rsign()
        self._install_complete_release_fixture()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tempdir.cleanup()

    def _write_rsign(self, marker: Path | None = None) -> str:
        script = self.root / f"rsign-{len(list(self.root.glob('rsign-*')))}"
        marker_line = f"pathlib.Path({str(marker)!r}).touch()\n" if marker is not None else ""
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            f"expected_payload = {PAYLOAD!r}\n"
            f"expected_signature = {SIGNATURE!r}\n"
            f"log = pathlib.Path({str(self.rsign_log)!r})\n"
            "arguments = sys.argv[1:]\n"
            "signature = pathlib.Path(arguments[arguments.index('-x') + 1]).read_bytes()\n"
            "payload_path = pathlib.Path(arguments[-1])\n"
            "payload = payload_path.read_bytes()\n"
            "with log.open('a', encoding='utf-8') as stream:\n"
            "    stream.write(payload_path.name + '\\n')\n"
            + marker_line
            + "raise SystemExit(0 if payload == expected_payload and signature == expected_signature else 1)\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return str(script)

    def _install_complete_release_fixture(self) -> None:
        contents: dict[str, bytes] = {}
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        for payload in payload_names():
            for signed_asset in (payload, f"{payload}.spdx.json"):
                contents[signed_asset] = PAYLOAD
                contents[f"{signed_asset}.sha256"] = (
                    f"{digest}  {signed_asset}\n".encode()
                )
                contents[f"{signed_asset}.minisig"] = SIGNATURE
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
                        f"https://api.github.com/repos/{REPOSITORY}"
                        f"/releases/assets/{asset_id}"
                    ),
                }
            )
        self.state.release = {
            "id": 572,
            "tag_name": TAG,
            "immutable": True,
            "draft": False,
            "prerelease": False,
            "published_at": "2026-07-25T12:00:00Z",
            "assets": assets,
        }

    def client(
        self,
        *,
        json_deadline: float = 2.0,
        download_deadline: float = 2.0,
        json_limit: int = verifier.MAX_JSON_BYTES,
    ) -> verifier.GitHubClient:
        return verifier.GitHubClient(
            f"http://127.0.0.1:{self.server.server_port}",
            TOKEN,
            json_deadline=json_deadline,
            download_deadline=download_deadline,
            json_limit=json_limit,
        )

    def verify(
        self,
        *,
        destination: Path | None = None,
        expected_release_id: int | None = 572,
        expected_commit: str = COMMIT,
        expected_tag_object: str = TAG_OBJECT,
        client: verifier.GitHubClient | None = None,
        rsign: str | None = None,
    ) -> int:
        return verifier.verify_release(
            tag=TAG,
            expected_commit=expected_commit,
            expected_tag_object=expected_tag_object,
            expected_release_id=expected_release_id,
            destination=destination or self.root / "release-assets",
            client=client or self.client(),
            rsign=rsign or self.rsign,
        )

    def first_asset(self) -> dict[str, Any]:
        assert self.state.release is not None
        return self.state.release["assets"][0]

    def test_complete_release_is_verified_by_exact_id_ref_and_tag_object(self) -> None:
        """Regresses accepting a release without exact immutable ID, ref, tag-object, and peel checks."""
        release_id = self.verify()

        self.assertEqual(release_id, 572)
        paths = [path for path, _auth in self.state.requests]
        self.assertEqual(paths.count(f"/repos/{REPOSITORY}/releases/572"), 2)
        self.assertEqual(paths.count(f"/repos/{REPOSITORY}/git/ref/tags/{TAG}"), 2)
        self.assertEqual(paths.count(f"/repos/{REPOSITORY}/git/tags/{TAG_OBJECT}"), 2)
        self.assertTrue(all(auth == f"Bearer {TOKEN}" for _path, auth in self.state.requests))

    def test_old_48_asset_inventory_without_gpu_sboms_is_rejected(self) -> None:
        """Regresses accepting the former 48-asset inventory that omitted four GPU sidecar SBOM triplets."""
        assert self.state.release is not None
        self.state.release["assets"] = [
            asset
            for asset in self.state.release["assets"]
            if ".gpu-literals.tar.gz.spdx.json" not in asset["name"]
        ]
        self.assertEqual(len(self.state.release["assets"]), 48)

        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact signed asset manifest is incomplete",
        ):
            self.verify()

    def test_all_gpu_sidecar_sbom_signatures_are_verified(self) -> None:
        """Regresses downloading GPU sidecar SBOM triplets without minisign-verifying all four documents."""
        self.assertEqual(self.verify(), 572)

        verified = set(self.rsign_log.read_text(encoding="utf-8").splitlines())
        expected_gpu_sboms = {
            f"{payload}.spdx.json"
            for payload in payload_names()
            if payload.endswith(".gpu-literals.tar.gz")
        }
        self.assertEqual(len(expected_gpu_sboms), 4)
        self.assertLessEqual(expected_gpu_sboms, verified)

    def test_public_client_ignores_github_api_url_environment_override(self) -> None:
        """Regresses production CLI trust in an attacker-controlled GITHUB_API_URL environment value."""
        with mock.patch.dict(os.environ, {"GITHUB_API_URL": "http://127.0.0.1:1"}):
            client = verifier.GitHubClient.public(TOKEN)

        self.assertEqual(client.api_base, "https://api.github.com")
        self.assertTrue(client.is_public)

    def test_non_loopback_api_override_is_rejected(self) -> None:
        """Regresses constructing a production-capable client pointed at an arbitrary API origin."""
        with self.assertRaisesRegex(verifier.VerificationError, "restricted to.*loopback"):
            verifier.GitHubClient("https://evil.example", TOKEN)

    def test_manual_recovery_may_resolve_release_id(self) -> None:
        """Regresses breaking recovery runs that securely discover the immutable release ID by tag."""
        self.assertEqual(self.verify(expected_release_id=None), 572)

    def test_release_event_id_mismatch_is_rejected(self) -> None:
        """Regresses accepting a release whose webhook ID differs from the public tag lookup."""
        with self.assertRaisesRegex(verifier.VerificationError, "release event ID 573 does not match"):
            self.verify(expected_release_id=573)

    def test_boolean_ids_and_sizes_are_rejected_as_non_integer_contract_values(self) -> None:
        """Regresses Python bool values passing integer checks for release IDs, asset IDs, or sizes."""
        assert self.state.release is not None
        original = copy.deepcopy(self.state.release)
        cases = (
            ("release ID", lambda release: release.__setitem__("id", True)),
            (
                "asset ID",
                lambda release: release["assets"][0].__setitem__("id", True),
            ),
            (
                "asset size",
                lambda release: release["assets"][0].__setitem__("size", True),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                self.state.release = copy.deepcopy(original)
                mutate(self.state.release)
                with self.assertRaises(verifier.VerificationError):
                    self.verify()
        self.state.release = original
        with self.assertRaisesRegex(verifier.VerificationError, "not a positive integer"):
            self.verify(expected_release_id=True)

    def test_duplicate_json_object_keys_are_rejected_globally(self) -> None:
        """Regresses ambiguous GitHub JSON whose duplicate security field would otherwise win silently."""
        path = f"/repos/{REPOSITORY}/releases/tags/{TAG}"
        self.state.raw_api_responses[path] = (
            200,
            b'{"id":572,"id":573}',
            "application/json",
        )

        with self.assertRaisesRegex(verifier.VerificationError, "duplicate key 'id'"):
            self.verify()

    def test_release_without_immutable_true_is_rejected(self) -> None:
        """Regresses claiming immutability when GitHub omits the immutable=true verdict."""
        assert self.state.release is not None
        self.state.release.pop("immutable")

        with self.assertRaisesRegex(verifier.VerificationError, "is not immutable"):
            self.verify()

    def test_draft_release_is_rejected(self) -> None:
        """Regresses publishing crates from a GitHub release that is still a mutable draft."""
        assert self.state.release is not None
        self.state.release["draft"] = True

        with self.assertRaisesRegex(verifier.VerificationError, "is still draft"):
            self.verify()

    def test_expected_tag_object_must_be_lowercase_sha(self) -> None:
        """Regresses accepting an ambiguous or noncanonical expected top-level tag-object identifier."""
        with self.assertRaisesRegex(verifier.VerificationError, "not a lowercase 40-hex SHA"):
            self.verify(expected_tag_object=TAG_OBJECT.upper())

    def test_ref_must_point_to_expected_annotated_tag_object(self) -> None:
        """Regresses accepting a ref that names an unapproved annotated tag object for the same tag."""
        self.state.ref_object = SWAPPED_TAG_OBJECT

        with self.assertRaisesRegex(verifier.VerificationError, "exact annotated tag object"):
            self.verify()

    def test_annotated_tag_must_peel_directly_to_commit(self) -> None:
        """Regresses accepting a nested tag peel instead of the expected tag-object-to-commit edge."""
        original_do_get = ReleaseHandler.do_GET

        def nested_tag(handler: ReleaseHandler) -> None:
            path = urlsplit(handler.path).path
            if path == f"/repos/{REPOSITORY}/git/tags/{TAG_OBJECT}":
                handler.server.state.requests.append((path, handler.headers.get("Authorization")))
                handler.reply(
                    200,
                    {
                        "sha": TAG_OBJECT,
                        "tag": TAG,
                        "object": {
                            "type": "tag",
                            "sha": COMMIT,
                            "url": (
                                f"https://api.github.com/repos/{REPOSITORY}/git/tags/"
                                f"{COMMIT}"
                            ),
                        },
                    },
                )
                return
            original_do_get(handler)

        with mock.patch.object(ReleaseHandler, "do_GET", nested_tag):
            with self.assertRaisesRegex(verifier.VerificationError, "does not peel directly"):
                self.verify()

    def test_wrong_asset_url_is_rejected_before_asset_request(self) -> None:
        """Regresses attaching the GitHub token to an API-supplied asset URL outside the exact endpoint."""
        self.first_asset()["url"] = "https://evil.example/steal"

        with self.assertRaisesRegex(verifier.VerificationError, "unsafe asset record"):
            self.verify()
        self.assertFalse(any("/releases/assets/" in path for path, _auth in self.state.requests))


    def test_unknown_nested_ref_identity_key_is_rejected(self) -> None:
        """Regresses accepting an unprojected field in the exact annotated-ref identity record."""
        original_do_get = ReleaseHandler.do_GET

        def extra_ref_identity(handler: ReleaseHandler) -> None:
            path = urlsplit(handler.path).path
            if path == f"/repos/{REPOSITORY}/git/ref/tags/{TAG}":
                handler.server.state.requests.append((path, handler.headers.get("Authorization")))
                handler.reply(
                    200,
                    {
                        "ref": f"refs/tags/{TAG}",
                        "object": {
                            "type": "tag",
                            "sha": TAG_OBJECT,
                            "url": (
                                f"https://api.github.com/repos/{REPOSITORY}/git/tags/"
                                f"{TAG_OBJECT}"
                            ),
                            "unexpected": "ambiguous",
                        },
                    },
                )
                return
            original_do_get(handler)

        with mock.patch.object(ReleaseHandler, "do_GET", extra_ref_identity):
            with self.assertRaisesRegex(verifier.VerificationError, "exact annotated tag object"):
                self.verify()

    def test_same_host_http_asset_url_is_rejected(self) -> None:
        """Regresses permitting a canonical-looking api.github.com asset URL over plaintext HTTP."""
        asset = self.first_asset()
        asset["url"] = asset["url"].replace("https://", "http://")

        with self.assertRaisesRegex(verifier.VerificationError, "unsafe asset record"):
            self.verify()

    def test_redirect_downgrade_is_rejected_before_following(self) -> None:
        """Regresses following an authenticated asset request through a same-host HTTP downgrade."""
        asset = self.first_asset()
        self.state.asset_responses[asset["id"]] = AssetResponse(
            status=302,
            redirect=(
                f"http://127.0.0.1:{self.server.server_port}/plaintext-asset"
            ),
        )

        with self.assertRaisesRegex(verifier.VerificationError, "unsafe release asset redirect"):
            self.verify()

        self.assertFalse(any(path == "/plaintext-asset" for path, _auth in self.state.requests))

    def test_cross_origin_redirect_is_rejected_without_forwarding_authorization(self) -> None:
        """Regresses leaking Authorization while following an asset redirect to an untrusted origin."""
        asset = self.first_asset()
        self.state.asset_responses[asset["id"]] = AssetResponse(
            status=302,
            redirect="https://evil.example/collect-token",
        )

        with self.assertRaisesRegex(verifier.VerificationError, "unsafe release asset redirect"):
            self.verify()

        asset_requests = [
            auth
            for path, auth in self.state.requests
            if path.endswith(f"/releases/assets/{asset['id']}")
        ]
        self.assertEqual(asset_requests, [f"Bearer {TOKEN}"])
        self.assertFalse(any(path == "/collect-token" for path, _auth in self.state.requests))

    def test_oversized_asset_response_is_rejected(self) -> None:
        """Regresses writing bytes beyond the API-declared asset size plus the single-byte probe."""
        asset = self.first_asset()
        oversized = self.state.asset_bytes[asset["id"]] + b"x"
        self.state.asset_responses[asset["id"]] = AssetResponse(body=oversized)

        with self.assertRaisesRegex(verifier.VerificationError, "oversized"):
            self.verify()

    def test_truncated_asset_response_is_rejected(self) -> None:
        """Regresses accepting an early EOF whose bytes are fewer than the API-declared asset size."""
        asset = self.first_asset()
        content = self.state.asset_bytes[asset["id"]]
        self.state.asset_responses[asset["id"]] = AssetResponse(
            body=content[:-1],
            content_length=len(content),
        )

        with self.assertRaisesRegex(verifier.VerificationError, "truncated"):
            self.verify()

    def test_slow_trickle_exceeds_whole_request_deadline(self) -> None:
        """Regresses per-read timeouts that permit a trickled response to exceed the overall deadline."""
        asset = self.first_asset()
        self.state.asset_responses[asset["id"]] = AssetResponse(delay_after_first_byte=0.25)

        with self.assertRaisesRegex(verifier.VerificationError, "whole-request deadline"):
            self.verify(client=self.client(download_deadline=0.05))

    def test_oversized_json_response_is_rejected_before_parsing(self) -> None:
        """Regresses unbounded buffering of attacker-controlled GitHub release JSON responses."""
        with self.assertRaisesRegex(verifier.VerificationError, "exceeded the permitted 128 bytes"):
            self.verify(client=self.client(json_limit=128))

    def test_asset_content_type_is_enforced(self) -> None:
        """Regresses treating an HTML error body as a successfully downloaded release asset."""
        asset = self.first_asset()
        self.state.asset_responses[asset["id"]] = AssetResponse(content_type="text/html")

        with self.assertRaisesRegex(verifier.VerificationError, "unsafe Content-Type"):
            self.verify()

    def test_asset_http_error_status_is_enforced(self) -> None:
        """Regresses consuming a bounded error response as though it were a successful asset download."""
        asset = self.first_asset()
        self.state.asset_responses[asset["id"]] = AssetResponse(status=503)

        with self.assertRaisesRegex(verifier.VerificationError, "returned HTTP 503"):
            self.verify()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_destination_root_is_rejected(self) -> None:
        """Regresses deleting or writing through a caller-controlled symlink destination root."""
        target = self.root / "target"
        target.mkdir()
        destination = self.root / "release-assets"
        destination.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(verifier.VerificationError, "symlink component"):
            self.verify(destination=destination)

        self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_symlink_destination_ancestor_is_rejected(self) -> None:
        """Regresses traversing a symlink hidden in an ancestor component of the download root."""
        target = self.root / "target"
        target.mkdir()
        ancestor = self.root / "linked-parent"
        ancestor.symlink_to(target, target_is_directory=True)

        with self.assertRaisesRegex(verifier.VerificationError, "symlink component"):
            self.verify(destination=ancestor / "release-assets")

        self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_existing_symlink_output_file_is_not_followed(self) -> None:
        """Regresses following a pre-positioned asset-name symlink and overwriting its external target."""
        destination = self.root / "release-assets"
        destination.mkdir()
        external = self.root / "external"
        external.write_bytes(b"do-not-touch")
        (destination / self.first_asset()["name"]).symlink_to(external)

        with self.assertRaisesRegex(verifier.VerificationError, "destination is not empty"):
            self.verify(destination=destination)

        self.assertEqual(external.read_bytes(), b"do-not-touch")

    def test_checksum_manifest_mismatch_is_rejected(self) -> None:
        """Regresses accepting a signed asset set whose checksum does not authenticate its payload."""
        assert self.state.release is not None
        asset = next(item for item in self.state.release["assets"] if item["name"] == "install.ps1.sha256")
        forged = f"{'0' * 64}  install.ps1\n".encode()
        self.state.asset_bytes[asset["id"]] = forged
        asset["size"] = len(forged)

        with self.assertRaisesRegex(verifier.VerificationError, "does not authenticate install.ps1"):
            self.verify()

    def test_signature_manifest_mismatch_is_rejected(self) -> None:
        """Regresses accepting a payload whose downloaded minisign signature is forged."""
        assert self.state.release is not None
        asset = next(item for item in self.state.release["assets"] if item["name"] == "install.ps1.minisig")
        forged = b"not a minisign signature\n"
        self.state.asset_bytes[asset["id"]] = forged
        asset["size"] = len(forged)

        with self.assertRaisesRegex(verifier.VerificationError, "does not authenticate install.ps1"):
            self.verify()

    def test_missing_rsign_is_reported_as_contextual_verification_error(self) -> None:
        """Regresses leaking a raw executable OSError instead of a payload-specific verification failure."""
        missing = str(self.root / "missing-rsign")

        with self.assertRaisesRegex(
            verifier.VerificationError,
            "cannot run minisign verifier.*missing-rsign.*install.ps1",
        ):
            self.verify(rsign=missing)

    def test_windows_binary_checksum_marker_is_accepted(self) -> None:
        """Regresses rejecting the valid binary-mode checksum marker emitted by Windows sha256sum."""
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

        self.assertEqual(self.verify(), 572)

    def test_post_verification_release_drift_is_rejected(self) -> None:
        """Regresses returning success after signed verification when the exact release snapshot drifts."""
        marker = self.root / "signature-ran"
        self.state.marker = marker
        assert self.state.release is not None
        drifted = copy.deepcopy(self.state.release)
        drifted["published_at"] = "2026-07-25T12:00:01Z"
        self.state.release_after_marker = drifted
        rsign = self._write_rsign(marker)

        with self.assertRaisesRegex(verifier.VerificationError, "changed while.*verified"):
            self.verify(rsign=rsign)

        self.assertTrue(marker.exists())

    def test_same_commit_top_level_tag_object_swap_is_rejected_after_verification(self) -> None:
        """Regresses missing a post-signature ref swap to another annotated object peeling to the same commit."""
        marker = self.root / "signature-ran"
        self.state.marker = marker
        self.state.ref_object_after_marker = SWAPPED_TAG_OBJECT
        rsign = self._write_rsign(marker)

        with self.assertRaisesRegex(verifier.VerificationError, "exact annotated tag object"):
            self.verify(rsign=rsign)

        paths = [path for path, _auth in self.state.requests]
        self.assertEqual(paths.count(f"/repos/{REPOSITORY}/git/ref/tags/{TAG}"), 2)


if __name__ == "__main__":
    unittest.main()
