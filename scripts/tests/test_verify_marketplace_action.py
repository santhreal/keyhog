"""Behavioral and adversarial contracts for the Marketplace Action verifier."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import sys
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "verify_marketplace_action.py"
SPEC = importlib.util.spec_from_file_location("verify_marketplace_action", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REPOSITORY = "santhreal/keyhog"
ACTION_TAG = "v0"
RELEASE_TAG = "v0.5.47"
COMMIT = "1" * 40
OTHER_COMMIT = "2" * 40
ACTION_TAG_SHA = "3" * 40
RELEASE_TAG_SHA = "4" * 40
NESTED_TAG_SHA = "5" * 40
MOVED_RELEASE_TAG_SHA = "6" * 40
ACTION_NAME = "KeyHog Secret Scanner"
LISTING_URL = "https://github.com/marketplace/actions/keyhog-secret-scanner"
RELEASE_URL = f"https://github.com/{REPOSITORY}/releases/tag/{RELEASE_TAG}"
CATEGORIES = ("security", "continuous-integration")
ACTION_YAML = f'''name: "{ACTION_NAME}"
description: Scan checked-out content.
branding:
    icon: shield
    color: red
runs:
    using: composite
    steps: []
'''.encode()
ACTION_SHA = hashlib.sha1(
    f"blob {len(ACTION_YAML)}\0".encode("ascii") + ACTION_YAML
).hexdigest()


class OpenPGPFixture:
    """Generate one isolated signing identity for cryptographic verifier tests."""

    def __init__(self, identity: str) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="keyhog-test-gpg-")
        self._homedir = self._temporary.name
        generated = self._run(
            [
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                identity,
                "ed25519",
                "cert",
                "0",
            ]
        )
        if generated.returncode != 0:
            raise RuntimeError(generated.stderr.decode("utf-8", "replace"))
        listed = self._run(["--with-colons", "--fingerprint", "--list-keys"])
        fingerprints = [
            fields[9]
            for line in listed.stdout.decode().splitlines()
            if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
        ]
        if not fingerprints:
            raise RuntimeError("fixture key has no fingerprint")
        self.fingerprint = fingerprints[0].upper()
        added = self._run(
            [
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-add-key",
                self.fingerprint,
                "ed25519",
                "sign",
                "0",
            ]
        )
        if added.returncode != 0:
            raise RuntimeError(added.stderr.decode("utf-8", "replace"))
        listed = self._run(["--with-colons", "--fingerprint", "--list-keys"])
        fingerprints = [
            fields[9].upper()
            for line in listed.stdout.decode().splitlines()
            if (fields := line.split(":"))[0] == "fpr" and len(fields) > 9
        ]
        if len(fingerprints) < 2:
            raise RuntimeError("fixture key has no signing subkey fingerprint")
        self.signing_fingerprint = fingerprints[-1]
        exported = self._run(["--armor", "--export", self.fingerprint])
        if exported.returncode != 0 or not exported.stdout:
            raise RuntimeError("fixture public key export failed")
        self.public_key = exported.stdout
        canonical = self._run(["--export", self.fingerprint])
        if canonical.returncode != 0 or not canonical.stdout:
            raise RuntimeError("fixture canonical public key export failed")
        self.key_sha256 = hashlib.sha256(canonical.stdout).hexdigest()
        self.binary_public_key = canonical.stdout

    def _run(
        self, arguments: list[str], *, input_data: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "gpg",
                "--batch",
                "--no-tty",
                "--no-options",
                "--homedir",
                self._homedir,
                *arguments,
            ],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )

    def sign(self, payload: str) -> str:
        signed = self._run(
            [
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--armor",
                "--local-user",
                f"{self.signing_fingerprint}!",
                "--detach-sign",
                "--output",
                "-",
            ],
            input_data=payload.encode(),
        )
        if signed.returncode != 0:
            raise RuntimeError(signed.stderr.decode("utf-8", "replace"))
        return signed.stdout.decode()

    def export_secret_key(self) -> bytes:
        exported = self._run(
            [
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--armor",
                "--export-secret-keys",
                self.fingerprint,
            ]
        )
        if exported.returncode != 0 or not exported.stdout:
            raise RuntimeError("fixture secret key export failed")
        return exported.stdout

    def close(self) -> None:
        self._temporary.cleanup()


def listing_html(
    *,
    action_name: str = ACTION_NAME,
    repository: str = REPOSITORY,
    action_ref: str = RELEASE_TAG,
    categories: tuple[str, ...] = CATEGORIES,
    canonical_url: str = LISTING_URL,
) -> str:
    category_links = "".join(
        f'<a href="/marketplace?type=actions&amp;category={category}">{category}</a>'
        for category in categories
    )
    first, rest = action_name.split(" ", 1)
    return (
        "<html><head>"
        f'<link rel="canonical" href="{canonical_url}">'
        "</head><body><main>"
        f"<h1>{first} <span>{rest}</span></h1>"
        f'<a href="https://github.com/{repository}/?tab=readme">repository</a>'
        f"{category_links}"
        f"<pre><code>- uses: {repository}@{action_ref}</code></pre>"
        "</main></body></html>"
    )


@dataclass
class ResponseSpec:
    raw: bytes
    status: int = 200
    content_type: str = "application/json"
    final_url: str | None = None
    content_length: str | None = "auto"
    content_encoding: str = "identity"
    after_read: Callable[[], None] | None = None


class FakeResponse:
    def __init__(self, url: str, spec: ResponseSpec) -> None:
        self.status = spec.status
        self._url = spec.final_url or url
        self._raw = spec.raw
        self._offset = 0
        self._after_read = spec.after_read
        self.headers: dict[str, str] = {
            "Content-Type": spec.content_type,
            "Content-Encoding": spec.content_encoding,
        }
        if spec.content_length == "auto":
            self.headers["Content-Length"] = str(len(spec.raw))
        elif spec.content_length is not None:
            self.headers["Content-Length"] = spec.content_length

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def getcode(self) -> int:
        return self.status

    def read(self, size: int) -> bytes:
        return self.read1(size)

    def read1(self, size: int) -> bytes:
        chunk = self._raw[self._offset : self._offset + size]
        self._offset += len(chunk)
        if self._after_read is not None:
            self._after_read()
        return chunk


@dataclass
class MarketplaceState:
    private: bool = False
    action_commit: str = COMMIT
    release_commit: str = COMMIT
    action_ref_sequence: list[str] = field(default_factory=list)
    release_ref_sequence: list[str] = field(default_factory=list)
    release_tag_sha_sequence: list[str] = field(default_factory=list)
    action_ref_calls: int = 0
    release_ref_calls: int = 0
    action_tag_sha: str | None = None
    release_tag_sha: str | None = RELEASE_TAG_SHA
    tag_objects: dict[str, dict[str, Any]] = field(default_factory=dict)
    release_verified: bool = True
    release_payload: str = ""
    release_signature: str = ""
    release_draft: bool = False
    release_prerelease: bool = False
    release_url: str = RELEASE_URL
    release_published_at: str | None = "2026-07-27T00:00:00Z"
    action_yaml: bytes = ACTION_YAML
    action_sha: str = ACTION_SHA
    action_encoding: str = "base64"
    listing: str = field(default_factory=listing_html)
    listing_spec: ResponseSpec | None = None
    overrides: dict[str, ResponseSpec] = field(default_factory=dict)


class FakeTransport:
    """Origin-agnostic transport; production URL construction remains real."""

    def __init__(self, state: MarketplaceState) -> None:
        self.state = state
        self.requests: list[urllib.request.Request] = []

    @staticmethod
    def _json(value: Any) -> ResponseSpec:
        return ResponseSpec(json.dumps(value).encode())

    @staticmethod
    def _sequence(values: list[str], fallback: str, offset: int) -> str:
        if not values:
            return fallback
        return values[min(offset, len(values) - 1)]

    def _route(self, request: urllib.request.Request) -> ResponseSpec:
        url = request.full_url
        if url in self.state.overrides:
            return self.state.overrides[url]
        parsed = urllib.parse.urlsplit(url)
        path = parsed.path
        if url == LISTING_URL:
            return self.state.listing_spec or ResponseSpec(
                self.state.listing.encode(), content_type="text/html; charset=utf-8"
            )
        if path == f"/repos/{REPOSITORY}":
            return self._json(
                {"full_name": REPOSITORY, "private": self.state.private}
            )
        if path == f"/repos/{REPOSITORY}/git/ref/tags/{ACTION_TAG}":
            commit = self._sequence(
                self.state.action_ref_sequence,
                self.state.action_commit,
                self.state.action_ref_calls,
            )
            self.state.action_ref_calls += 1
            if self.state.action_tag_sha is None:
                obj = {"type": "commit", "sha": commit}
            else:
                obj = {"type": "tag", "sha": self.state.action_tag_sha}
            return self._json({"object": obj})
        if path == f"/repos/{REPOSITORY}/git/ref/tags/{RELEASE_TAG}":
            offset = self.state.release_ref_calls
            commit = self._sequence(
                self.state.release_ref_sequence,
                self.state.release_commit,
                offset,
            )
            self.state.release_ref_calls += 1
            if self.state.release_tag_sha is None:
                obj = {"type": "commit", "sha": commit}
            else:
                tag_sha = self._sequence(
                    self.state.release_tag_sha_sequence,
                    self.state.release_tag_sha,
                    offset,
                )
                obj = {"type": "tag", "sha": tag_sha}
            return self._json({"object": obj})
        tag_prefix = f"/repos/{REPOSITORY}/git/tags/"
        if path.startswith(tag_prefix):
            sha = path.removeprefix(tag_prefix)
            if sha in self.state.tag_objects:
                return self._json(self.state.tag_objects[sha])
            if sha == RELEASE_TAG_SHA:
                return self._json(
                    {
                        "sha": RELEASE_TAG_SHA,
                        "verification": {
                            "verified": self.state.release_verified,
                            "payload": self.state.release_payload,
                            "signature": self.state.release_signature,
                        },
                        "object": {
                            "type": "commit",
                            "sha": self.state.release_commit,
                        },
                    }
                )
        if path == f"/repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}":
            return self._json(
                {
                    "id": 47,
                    "html_url": self.state.release_url,
                    "tag_name": RELEASE_TAG,
                    "draft": self.state.release_draft,
                    "prerelease": self.state.release_prerelease,
                    "published_at": self.state.release_published_at,
                }
            )
        if path == f"/repos/{REPOSITORY}/contents/action.yml":
            query = urllib.parse.parse_qs(parsed.query)
            if query != {"ref": [COMMIT]}:
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return self._json(
                {
                    "type": "file",
                    "encoding": self.state.action_encoding,
                    "content": base64.b64encode(self.state.action_yaml).decode(),
                    "sha": self.state.action_sha,
                }
            )
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    def open(
        self, request: urllib.request.Request, *, timeout: float
    ) -> FakeResponse:
        del timeout
        self.requests.append(request)
        return FakeResponse(request.full_url, self._route(request))


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class MarketplaceActionVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.expected_signer = OpenPGPFixture(
            "Expected KeyHog Release Signer <expected@example.test>"
        )
        cls.foreign_signer = OpenPGPFixture(
            "Foreign Release Signer <foreign@example.test>"
        )
        cls.release_payload = cls._tag_payload(COMMIT)
        cls.release_signature = cls.expected_signer.sign(cls.release_payload)
        cls.foreign_signature = cls.foreign_signer.sign(cls.release_payload)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.expected_signer.close()
        cls.foreign_signer.close()

    @staticmethod
    def _tag_payload(commit: str) -> str:
        return (
            f"object {commit}\n"
            "type commit\n"
            f"tag {RELEASE_TAG}\n"
            "tagger KeyHog Release <release@example.test> 1785110400 +0000\n"
            "\n"
            f"Release {RELEASE_TAG}\n"
        )

    def setUp(self) -> None:
        self.state = MarketplaceState(
            release_payload=self.release_payload,
            release_signature=self.release_signature,
        )
        self.transport = FakeTransport(self.state)

    def client(
        self,
        *,
        token: str = "test-token",
        timeout: float = 2,
        clock: Callable[[], float] | None = None,
    ) -> Any:
        arguments: dict[str, Any] = {
            "timeout": timeout,
            "opener": self.transport,
        }
        if clock is not None:
            arguments["clock"] = clock
        return MODULE.GitHubClient(token, **arguments)

    def verify(
        self,
        *,
        release_signer_fingerprint: str | None = None,
        release_signing_key: bytes | None = None,
    ) -> Any:
        return MODULE.verify(
            self.client(),
            repository=REPOSITORY,
            action_tag=ACTION_TAG,
            release_tag=RELEASE_TAG,
            listing_url=LISTING_URL,
            action_name=ACTION_NAME,
            categories=CATEGORIES,
            release_signer_fingerprint=(
                release_signer_fingerprint or self.expected_signer.fingerprint
            ),
            release_signing_key=(
                release_signing_key or self.expected_signer.public_key
            ),
        )

    def test_complete_receipt_binds_every_public_identity_without_token_on_html(
        self,
    ) -> None:
        """Success binds signed release, immutable metadata, listing ref, and categories."""

        receipt = self.verify()
        self.assertEqual(
            receipt,
            MODULE.ListingReceipt(
                schema_version=1,
                repository=REPOSITORY,
                action_tag=ACTION_TAG,
                release_tag=RELEASE_TAG,
                release_tag_sha=RELEASE_TAG_SHA,
                release_signer_fingerprint=self.expected_signer.fingerprint,
                release_signing_key_sha256=self.expected_signer.key_sha256,
                release_id=47,
                release_url=RELEASE_URL,
                release_published_at="2026-07-27T00:00:00Z",
                commit=COMMIT,
                root_action_sha=ACTION_SHA,
                action_name=ACTION_NAME,
                listing_url=LISTING_URL,
                marketplace_ref=RELEASE_TAG,
                categories=CATEGORIES,
            ),
        )
        listing_requests = [
            request for request in self.transport.requests if request.full_url == LISTING_URL
        ]
        self.assertEqual(len(listing_requests), 1)
        self.assertIsNone(listing_requests[0].get_header("Authorization"))
        api_requests = [
            request
            for request in self.transport.requests
            if request.full_url.startswith(f"{MODULE.API_ORIGIN}/")
        ]
        self.assertTrue(api_requests)
        self.assertTrue(
            all(
                request.get_header("Authorization") == "Bearer test-token"
                for request in api_requests
            )
        )
        self.assertIn(
            f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}/contents/action.yml?ref={COMMIT}",
            [request.full_url for request in api_requests],
        )

    def test_annotated_tags_are_peeled_by_sha_path_and_ignore_object_urls(self) -> None:
        """Tag peeling never trusts a server-provided absolute URL."""

        self.state.action_tag_sha = ACTION_TAG_SHA
        self.state.tag_objects[ACTION_TAG_SHA] = {
            "sha": ACTION_TAG_SHA,
            "url": "https://attacker.invalid/steal-token",
            "object": {"type": "tag", "sha": NESTED_TAG_SHA},
        }
        self.state.tag_objects[NESTED_TAG_SHA] = {
            "sha": NESTED_TAG_SHA,
            "url": "http://api.github.com/downgrade",
            "object": {"type": "commit", "sha": COMMIT},
        }
        receipt = self.verify()
        self.assertEqual(receipt.commit, COMMIT)
        requested = [request.full_url for request in self.transport.requests]
        self.assertIn(
            f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}/git/tags/{ACTION_TAG_SHA}",
            requested,
        )
        self.assertIn(
            f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}/git/tags/{NESTED_TAG_SHA}",
            requested,
        )
        self.assertFalse(any("attacker.invalid" in url for url in requested))
        self.assertFalse(any(url.startswith("http://") for url in requested))

    def test_cli_emits_exact_schema_and_has_no_api_base_escape(self) -> None:
        """The production CLI exposes only pinned origins and a versioned receipt."""

        arguments = [
            "--repository",
            REPOSITORY,
            "--action-tag",
            ACTION_TAG,
            "--release-tag",
            RELEASE_TAG,
            "--release-signing-key",
            "/fixture/release-signing-key.asc",
            "--release-signer-fingerprint",
            self.expected_signer.fingerprint,
            "--listing-url",
            LISTING_URL,
            "--action-name",
            ACTION_NAME,
            "--category",
            CATEGORIES[0],
            "--category",
            CATEGORIES[1],
            "--timeout",
            "2",
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(MODULE, "GitHubClient", return_value=self.client()),
            mock.patch.object(
                MODULE,
                "_read_release_signing_key",
                return_value=self.expected_signer.public_key,
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = MODULE.main(arguments)
        self.assertEqual(status, 0, stderr.getvalue())
        output = json.loads(stdout.getvalue())
        self.assertEqual(
            set(output),
            {
                "schema_version",
                "repository",
                "action_tag",
                "release_tag",
                "release_tag_sha",
                "release_signer_fingerprint",
                "release_signing_key_sha256",
                "release_id",
                "release_url",
                "release_published_at",
                "commit",
                "root_action_sha",
                "action_name",
                "listing_url",
                "marketplace_ref",
                "categories",
            },
        )
        self.assertEqual(output["schema_version"], 1)
        self.assertEqual(
            output["release_signer_fingerprint"], self.expected_signer.fingerprint
        )
        self.assertEqual(
            output["release_signing_key_sha256"], self.expected_signer.key_sha256
        )
        missing_fingerprint = arguments.copy()
        fingerprint_offset = missing_fingerprint.index("--release-signer-fingerprint")
        del missing_fingerprint[fingerprint_offset : fingerprint_offset + 2]
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(missing_fingerprint)
        parse_stderr = io.StringIO()
        with redirect_stderr(parse_stderr), self.assertRaises(SystemExit):
            MODULE.parse_args(arguments + ["--api-base", "https://attacker.invalid"])

    def test_invalid_boundaries_fail_before_transport_access(self) -> None:
        """Malformed identities never become ambiguous remote paths or receipts."""

        cases = [
            {"repository": "../.."},
            {"action_tag": "v0.1"},
            {"release_tag": "v0"},
            {"release_tag": "v0.5.47-rc.1"},
            {"release_tag": "v1.5.47"},
            {"listing_url": "HTTPS://github.com/marketplace/actions/keyhog-secret-scanner"},
            {"listing_url": f"{LISTING_URL}?ref=v0"},
            {"action_name": ""},
            {"categories": ("security",)},
            {"categories": ("security", "security")},
            {"release_signer_fingerprint": ""},
            {"release_signer_fingerprint": "not-a-full-fingerprint"},
            {"release_signing_key": b""},
            {"release_signing_key": b"not an OpenPGP public key"},
        ]
        defaults: dict[str, Any] = {
            "repository": REPOSITORY,
            "action_tag": ACTION_TAG,
            "release_tag": RELEASE_TAG,
            "listing_url": LISTING_URL,
            "action_name": ACTION_NAME,
            "categories": CATEGORIES,
            "release_signer_fingerprint": self.expected_signer.fingerprint,
            "release_signing_key": self.expected_signer.public_key,
        }
        for changes in cases:
            with self.subTest(changes=changes):
                self.transport.requests.clear()
                with self.assertRaises(MODULE.VerificationError):
                    MODULE.verify(self.client(), **(defaults | changes))
                self.assertEqual(self.transport.requests, [])

    def test_release_must_be_distinct_signed_and_public_stable(self) -> None:
        """A lightweight, unverified, draft, prerelease, or redirected release fails."""

        mutations = [
            ("release_tag_sha", None, "lightweight"),
            ("release_verified", False, "complete verified signature"),
            ("release_draft", True, "public stable"),
            ("release_prerelease", True, "public stable"),
            (
                "release_url",
                "https://attacker.invalid/santhreal/keyhog/releases/tag/v0.5.47",
                "non-canonical",
            ),
            (
                "release_url",
                RELEASE_URL.replace("https://", "HTTPS://"),
                "non-canonical",
            ),
            (
                "release_url",
                RELEASE_URL.replace("v0.5.47", "v0%2E5%2E47"),
                "non-canonical",
            ),
            ("release_published_at", None, "publication timestamp"),
            ("release_published_at", "2026-13-40T25:61:61Z", "invalid publication"),
        ]
        for attribute, value, message in mutations:
            with self.subTest(attribute=attribute):
                self.setUp()
                setattr(self.state, attribute, value)
                with self.assertRaisesRegex(MODULE.VerificationError, message):
                    self.verify()

    def test_release_signature_rejects_a_valid_foreign_signer(self) -> None:
        """GitHub validity cannot substitute for the enrolled santhreal fingerprint."""

        self.state.release_signature = self.foreign_signature
        with self.assertRaisesRegex(
            MODULE.VerificationError, "expected enrolled fingerprint"
        ):
            self.verify()
        self.setUp()
        with self.assertRaisesRegex(
            MODULE.VerificationError, "expected OpenPGP identity"
        ):
            self.verify(release_signing_key=self.foreign_signer.public_key)
        self.assertEqual(self.transport.requests, [])

    def test_release_key_requires_one_exact_canonical_public_export(self) -> None:
        """Garbage, multiple keys, secret packets, NUL, and oversize keys fail."""

        invalid_keys = [
            b"prefix" + self.expected_signer.public_key,
            self.expected_signer.public_key + b"\n",
            self.expected_signer.public_key + b"\x00",
            self.expected_signer.public_key + self.foreign_signer.public_key,
            self.expected_signer.export_secret_key(),
            self.expected_signer.binary_public_key,
            b"x" * (MODULE.MAX_SIGNING_KEY_BYTES + 1),
        ]
        for public_key in invalid_keys:
            with self.subTest(size=len(public_key), prefix=public_key[:16]):
                self.setUp()
                with self.assertRaises(MODULE.VerificationError):
                    self.verify(release_signing_key=public_key)
                self.assertEqual(self.transport.requests, [])

    def test_primary_and_signing_subkey_fingerprints_are_both_bound(self) -> None:
        """The enrolled primary or actual signing-subkey fingerprint may be pinned."""

        receipt = self.verify(
            release_signer_fingerprint=self.expected_signer.signing_fingerprint
        )
        self.assertEqual(
            receipt.release_signer_fingerprint,
            self.expected_signer.signing_fingerprint,
        )

    def test_missing_gpg_and_forged_status_text_fail_closed(self) -> None:
        """Missing verifier binary or status-looking signature text cannot pass."""

        with mock.patch.object(
            MODULE.subprocess, "run", side_effect=FileNotFoundError
        ):
            with self.assertRaisesRegex(MODULE.VerificationError, "gpg is required"):
                self.verify()
        self.assertEqual(self.transport.requests, [])
        self.setUp()
        self.state.release_signature = (
            f"[GNUPG:] GOODSIG {self.expected_signer.fingerprint} forged\n"
            f"[GNUPG:] VALIDSIG {self.expected_signer.fingerprint} 0 0 0 0 0 0 0 00 "
            f"{self.expected_signer.fingerprint}\n"
        )
        with self.assertRaisesRegex(
            MODULE.VerificationError, "expected enrolled fingerprint"
        ):
            self.verify()

    def test_signature_payload_bytes_and_limits_are_exact(self) -> None:
        """Newline, Unicode, or oversize payload changes invalidate the proof."""

        altered_payloads = [
            self.release_payload + "\n",
            self.release_payload.replace("\n", "\r\n"),
            self.release_payload + "é",
            self.release_payload + "\ud800",
        ]
        for payload in altered_payloads:
            with self.subTest(payload=repr(payload[-16:])):
                self.setUp()
                self.state.release_payload = payload
                with self.assertRaises(MODULE.VerificationError):
                    self.verify()
        with MODULE._ReleaseSigner(
            self.expected_signer.fingerprint,
            self.expected_signer.public_key,
        ) as signer:
            with self.assertRaisesRegex(
                MODULE.VerificationError, "exceeds verification limits"
            ):
                signer.verify(
                    {
                        "verified": True,
                        "payload": "x" * (MODULE.MAX_SIGNATURE_BYTES + 1),
                        "signature": "x",
                    },
                    tag=RELEASE_TAG,
                    annotated_object={"type": "commit", "sha": COMMIT},
                )

    def test_stale_tag_or_tag_movement_cannot_form_receipt(self) -> None:
        """Both refs must resolve to one commit and remain stable through verification."""

        self.state.release_commit = OTHER_COMMIT
        self.state.release_payload = self._tag_payload(OTHER_COMMIT)
        self.state.release_signature = self.expected_signer.sign(
            self.state.release_payload
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "stable release tag"):
            self.verify()
        self.setUp()
        self.state.action_ref_sequence = [COMMIT, OTHER_COMMIT]
        with self.assertRaisesRegex(MODULE.VerificationError, "moved during"):
            self.verify()
        root_requests = [
            request.full_url
            for request in self.transport.requests
            if "/contents/action.yml" in request.full_url
        ]
        self.assertEqual(
            root_requests,
            [
                f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}/contents/action.yml?ref={COMMIT}"
            ],
        )
        self.setUp()
        self.state.release_tag_sha_sequence = [
            RELEASE_TAG_SHA,
            MOVED_RELEASE_TAG_SHA,
        ]
        self.state.tag_objects[MOVED_RELEASE_TAG_SHA] = {
            "sha": MOVED_RELEASE_TAG_SHA,
            "verification": {
                "verified": True,
                "payload": self.state.release_payload,
                "signature": self.state.release_signature,
            },
            "object": {"type": "commit", "sha": COMMIT},
        }
        with self.assertRaisesRegex(MODULE.VerificationError, "moved during"):
            self.verify()
        release_tag_objects = [
            request.full_url
            for request in self.transport.requests
            if f"/git/tags/{RELEASE_TAG_SHA}" in request.full_url
            or f"/git/tags/{MOVED_RELEASE_TAG_SHA}" in request.full_url
        ]
        self.assertEqual(
            release_tag_objects,
            [
                f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}/git/tags/{RELEASE_TAG_SHA}",
                f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}/git/tags/{MOVED_RELEASE_TAG_SHA}",
            ],
        )

    def test_mismatched_or_cyclic_annotated_objects_fail_closed(self) -> None:
        """Every annotated object is fetched by and bound to its expected SHA."""

        self.state.action_tag_sha = ACTION_TAG_SHA
        self.state.tag_objects[ACTION_TAG_SHA] = {
            "sha": NESTED_TAG_SHA,
            "object": {"type": "commit", "sha": COMMIT},
        }
        with self.assertRaisesRegex(MODULE.VerificationError, "mismatched"):
            self.verify()
        self.setUp()
        self.state.action_tag_sha = ACTION_TAG_SHA
        self.state.tag_objects[ACTION_TAG_SHA] = {
            "sha": ACTION_TAG_SHA,
            "object": {"type": "tag", "sha": ACTION_TAG_SHA},
        }
        with self.assertRaisesRegex(MODULE.VerificationError, "cycle"):
            self.verify()

    def test_root_blob_is_computed_from_immutable_bytes(self) -> None:
        """The receipt never trusts an API-reported blob identity."""

        self.state.action_sha = "f" * 40
        with self.assertRaisesRegex(MODULE.VerificationError, "blob identity"):
            self.verify()
        self.setUp()
        self.state.action_encoding = "utf-8"
        with self.assertRaisesRegex(MODULE.VerificationError, "base64 file"):
            self.verify()

    def test_structural_yaml_rejects_comments_blocks_and_duplicates(self) -> None:
        """Textual lookalikes cannot substitute for effective top-level metadata."""

        adversarial = [
            b"""# name: 'KeyHog Secret Scanner'\n# description: x\n# branding:\n# runs:\n""",
            ACTION_YAML + b"name: 'Other'\n",
            ACTION_YAML.replace(
                b"    using: composite\n",
                b"    using: composite\n    using: node20\n",
            ),
            b"""name: 'Other'\ndescription: |\n  name: 'KeyHog Secret Scanner'\n  branding:\nbranding:\n  icon: shield\n  color: red\nruns:\n  steps: []\n  # using: composite\n""",
            ACTION_YAML.replace(
                f'name: "{ACTION_NAME}"\n'.encode(),
                f"name: {ACTION_NAME}\n  node20\n".encode(),
            ),
            ACTION_YAML.replace(
                b"    using: composite\n",
                b"    using: composite\n      node20\n",
            ),
            ACTION_YAML.replace(
                f'name: "{ACTION_NAME}"\n'.encode(),
                b"name: >-\n  KeyHog Secret Scanner\n",
            ),
            ACTION_YAML.replace(
                b"    using: composite\n",
                b"    using: >-\n      composite\n",
            ),
        ]
        for action_yaml in adversarial:
            with self.subTest(action_yaml=action_yaml):
                self.setUp()
                self.state.action_yaml = action_yaml
                self.state.action_sha = hashlib.sha1(
                    f"blob {len(action_yaml)}\0".encode("ascii") + action_yaml
                ).hexdigest()
                with self.assertRaises(MODULE.VerificationError):
                    self.verify()

    def test_structural_yaml_rejects_multiple_or_ended_documents(self) -> None:
        """A second YAML document cannot override or duplicate verified metadata."""

        adversarial = [
            ACTION_YAML + b"---\nname: 'Other'\n",
            b"---\n" + ACTION_YAML + b"---\nname: 'Other'\n",
            ACTION_YAML + b"...\n",
            b"---\n---\n" + ACTION_YAML,
        ]
        for action_yaml in adversarial:
            with self.subTest(action_yaml=action_yaml):
                self.setUp()
                self.state.action_yaml = action_yaml
                self.state.action_sha = hashlib.sha1(
                    f"blob {len(action_yaml)}\0".encode("ascii") + action_yaml
                ).hexdigest()
                with self.assertRaisesRegex(
                    MODULE.VerificationError, "YAML document"
                ):
                    self.verify()

    def test_missing_pyyaml_is_a_controlled_dependency_failure(self) -> None:
        """The verifier never falls back to an ambient or partial YAML parser."""

        with mock.patch.object(MODULE, "yaml", None):
            with self.assertRaisesRegex(MODULE.VerificationError, "PyYAML is required"):
                MODULE.verify_action_metadata(
                    ACTION_YAML.decode("utf-8"), expected_name=ACTION_NAME
                )

    def test_structural_yaml_accepts_supported_scalar_styles(self) -> None:
        """Semantic validation is independent of quote and indentation style."""

        action_yaml = f"""---
name: {ACTION_NAME}
description: 'Scan checked-out content.'
branding:
  icon: 'shield'
  color: "red"
runs:
  using: 'composite'
  steps: []
""".encode()
        self.state.action_yaml = action_yaml
        self.state.action_sha = hashlib.sha1(
            f"blob {len(action_yaml)}\0".encode("ascii") + action_yaml
        ).hexdigest()
        self.assertEqual(self.verify().root_action_sha, self.state.action_sha)

    def test_marketplace_semantics_reject_source_text_lookalikes(self) -> None:
        """Comments, scripts, data attributes, and stale refs are not listing evidence."""

        self.state.listing = (
            f'<link rel="canonical" href="{LISTING_URL}">'
            f"<!-- <h1>{ACTION_NAME}</h1><a href='/{REPOSITORY}'>repo</a> -->"
            f"<script>uses: {REPOSITORY}@{ACTION_TAG}</script>"
            f'<div data-href="/{REPOSITORY}">{ACTION_NAME}</div>'
        )
        with self.assertRaises(MODULE.VerificationError):
            self.verify()
        self.setUp()
        self.state.listing = listing_html(action_ref=ACTION_TAG)
        with self.assertRaisesRegex(MODULE.VerificationError, "signed release ref"):
            self.verify()
        self.setUp()
        self.state.listing = listing_html(action_ref="v9")
        with self.assertRaisesRegex(MODULE.VerificationError, "signed release ref"):
            self.verify()
        self.setUp()
        self.state.listing = listing_html(categories=(CATEGORIES[0],))
        with self.assertRaisesRegex(MODULE.VerificationError, "category links"):
            self.verify()

    def test_marketplace_ignores_global_and_readme_only_identity_evidence(
        self,
    ) -> None:
        """README-visible or global identity text cannot impersonate listing chrome."""

        evidence = (
            f"<h1>{ACTION_NAME}</h1>"
            f'<a href="/{REPOSITORY}">repo</a>'
            '<a href="/marketplace?category=security&type=actions">security</a>'
            '<a href="/marketplace?category=continuous-integration&type=actions">ci</a>'
            f"<code>uses: {REPOSITORY}@{RELEASE_TAG}</code>"
        )
        bodies = [
            (
                f'<link rel="canonical" href="{LISTING_URL}">'
                f"{evidence}<main><p>unrelated chrome</p></main>"
            ),
            (
                f'<link rel="canonical" href="{LISTING_URL}">'
                f'<main><article class="markdown-body">{evidence}</article></main>'
            ),
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.setUp()
                self.state.listing = body
                with self.assertRaises(MODULE.VerificationError):
                    self.verify()

    def test_marketplace_rejects_duplicate_attributes_and_extra_categories(
        self,
    ) -> None:
        """Duplicate href tricks and a third category cannot alter listing identity."""

        self.state.listing = listing_html().replace(
            f'<a href="https://github.com/{REPOSITORY}/?tab=readme">',
            f'<a href="/{REPOSITORY}" href="/foreign/repository">',
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "duplicate HTML"):
            self.verify()
        self.setUp()
        self.state.listing = listing_html(
            categories=(*CATEGORIES, "code-quality")
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "exactly match"):
            self.verify()

    def test_marketplace_rejects_unpaired_surrogate_as_controlled_error(self) -> None:
        """A non-Unicode scalar in supplied HTML fails as VerificationError."""

        with self.assertRaisesRegex(MODULE.VerificationError, "valid UTF-8"):
            MODULE.verify_listing_page(
                listing_html() + "\ud800",
                listing_url=LISTING_URL,
                repository=REPOSITORY,
                action_name=ACTION_NAME,
                required_ref=RELEASE_TAG,
                categories=CATEGORIES,
            )

    def test_marketplace_requires_exact_canonical_final_url(self) -> None:
        """Same-origin path redirects and canonical-link substitutions both fail."""

        self.state.listing_spec = ResponseSpec(
            listing_html().encode(),
            content_type="text/html",
            final_url="https://github.com/marketplace/actions/another-action",
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "redirected away"):
            self.verify()
        self.setUp()
        self.state.listing = listing_html(
            canonical_url="https://github.com/marketplace/actions/another-action"
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "canonical URL"):
            self.verify()

    def test_marketplace_parser_normalizes_visible_text_and_links(self) -> None:
        """Entities, nested heading markup, and normalized GitHub links remain valid."""

        name = "KeyHog & Scanner"
        body = (
            f'<link rel="canonical" href="{LISTING_URL}">'
            "<main>"
            "<h1>KeyHog <span>&amp; Scanner</span></h1>"
            f'<a href="/{REPOSITORY}/?tab=readme">repo</a>'
            '<a href="/marketplace?category=security&type=actions">security</a>'
            '<a href="/marketplace?category=continuous-integration">ci</a>'
            f"<code>uses: {REPOSITORY}@{RELEASE_TAG}</code>"
            "</main>"
        )
        marketplace_ref = MODULE.verify_listing_page(
            body,
            listing_url=LISTING_URL,
            repository=REPOSITORY,
            action_name=name,
            required_ref=RELEASE_TAG,
            categories=CATEGORIES,
        )
        self.assertEqual(marketplace_ref, RELEASE_TAG)

    def test_http_requires_exact_200_mime_and_final_url(self) -> None:
        """Partial, wrong-media, or redirected API objects are never authoritative."""

        repo_url = f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}"
        cases = [
            ResponseSpec(b"{}", status=206),
            ResponseSpec(b"{}", content_type="text/plain"),
            ResponseSpec(b"{}", final_url="https://attacker.invalid/repo"),
            ResponseSpec(b"{}", content_encoding="gzip"),
        ]
        for response in cases:
            with self.subTest(response=response):
                self.setUp()
                self.state.overrides[repo_url] = response
                with self.assertRaises(MODULE.VerificationError):
                    self.verify()

    def test_length_json_and_utf8_failures_are_bounded(self) -> None:
        """Invalid lengths and parsers fail as VerificationError within byte limits."""

        repo_url = f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}"
        malformed = [
            ResponseSpec(b"{}", content_length="-1"),
            ResponseSpec(b"{}", content_length=str(MODULE.MAX_JSON_BYTES + 1)),
            ResponseSpec(b"{", content_type="application/json"),
            ResponseSpec(b'{"a":1,"a":2}', content_type="application/json"),
            ResponseSpec(b"[]", content_type="application/json"),
        ]
        for response in malformed:
            with self.subTest(response=response):
                self.setUp()
                self.state.overrides[repo_url] = response
                with self.assertRaises(MODULE.VerificationError):
                    self.verify()
        self.setUp()
        self.state.listing_spec = ResponseSpec(
            b"\xff", content_type="text/html; charset=utf-8"
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "not UTF-8"):
            self.verify()

    def test_actual_body_limit_and_whole_request_deadline(self) -> None:
        """Undeclared bodies are capped and slow reads cannot evade the deadline."""

        request = urllib.request.Request(f"{MODULE.API_ORIGIN}/bounded")
        oversized = ResponseSpec(
            b"12345", content_type="application/json", content_length=None
        )
        self.state.overrides[request.full_url] = oversized
        with self.assertRaisesRegex(MODULE.VerificationError, "exceeds"):
            self.client()._read(
                request,
                limit=4,
                context="bounded response",
                media_types=frozenset({"application/json"}),
            )
        self.setUp()
        clock = FakeClock()
        slow = ResponseSpec(
            b"{}",
            content_type="application/json",
            after_read=lambda: clock.advance(2),
        )
        self.state.overrides[request.full_url] = slow
        with self.assertRaisesRegex(MODULE.VerificationError, "deadline"):
            self.client(timeout=1, clock=clock)._read(
                request,
                limit=4,
                context="slow response",
                media_types=frozenset({"application/json"}),
            )

    def test_origin_and_redirect_policy_never_dispatches_untrusted_request(self) -> None:
        """Absolute API URLs and every urllib redirect are rejected before trust moves."""

        with self.assertRaisesRegex(MODULE.VerificationError, "origin-relative"):
            self.client().json("https://attacker.invalid/steal")
        self.assertEqual(self.transport.requests, [])
        handler = MODULE._NoRedirectHandler()
        request = urllib.request.Request(f"{MODULE.API_ORIGIN}/repos/{REPOSITORY}")
        self.assertIsNone(
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://api.github.com/downgrade",
            )
        )

    def test_cli_rejects_nonfinite_timeout_before_network(self) -> None:
        """NaN is not a loophole in the finite whole-request deadline."""

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status = MODULE.main(
                [
                    "--repository",
                    REPOSITORY,
                    "--action-tag",
                    ACTION_TAG,
                    "--release-tag",
                    RELEASE_TAG,
                    "--release-signing-key",
                    "/unused/key.asc",
                    "--release-signer-fingerprint",
                    self.expected_signer.fingerprint,
                    "--listing-url",
                    LISTING_URL,
                    "--action-name",
                    ACTION_NAME,
                    "--category",
                    CATEGORIES[0],
                    "--category",
                    CATEGORIES[1],
                    "--timeout",
                    "nan",
                ]
            )
        self.assertEqual(status, 2)
        self.assertIn("finite", stderr.getvalue())
        self.assertEqual(self.transport.requests, [])


if __name__ == "__main__":
    unittest.main()
