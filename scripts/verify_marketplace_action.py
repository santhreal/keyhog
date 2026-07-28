#!/usr/bin/env python3
"""Verify that a GitHub Marketplace Action listing resolves shipped release bytes."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import sys
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from html.parser import HTMLParser
from typing import Any, Callable

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by deployment environments
    yaml = None

API_ORIGIN = "https://api.github.com"
GITHUB_ORIGIN = "https://github.com"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACTION_TAG = re.compile(r"^v(0|[1-9][0-9]*)$")
RELEASE_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_TAG_OBJECTS = 32
READ_CHUNK_BYTES = 64 * 1024
RECEIPT_SCHEMA_VERSION = 1
MAX_SIGNING_KEY_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 2 * 1024 * 1024
GPG_TIMEOUT_SECONDS = 15


class VerificationError(RuntimeError):
    """The public Marketplace listing is absent, stale, or ambiguous."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so no credential or proof can change origin or path."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class _InvalidJSON(ValueError):
    pass


def _reject_json_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _InvalidJSON(f"duplicate key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise _InvalidJSON(f"non-finite number {value}")


def _validate_json_unicode(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise VerificationError(
                "GitHub JSON contains a non-Unicode scalar value"
            ) from error
    elif isinstance(value, dict):
        for key, item in value.items():
            _validate_json_unicode(key)
            _validate_json_unicode(item)
    elif isinstance(value, list):
        for item in value:
            _validate_json_unicode(item)


class GitHubClient:
    """Bounded, origin-pinned GitHub API and Marketplace client."""

    def __init__(
        self,
        token: str,
        *,
        timeout: float,
        opener: Any | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 120:
            raise VerificationError("timeout must be finite, greater than 0, and at most 120 seconds")
        self.token = token
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(_NoRedirectHandler())
        self.clock = clock

    def _request(
        self, url: str, *, accept: str, authenticated: bool
    ) -> urllib.request.Request:
        headers = {
            "Accept": accept,
            "Accept-Encoding": "identity",
            "User-Agent": "keyhog-marketplace-publication-verifier",
        }
        if authenticated:
            if not url.startswith(f"{API_ORIGIN}/"):
                raise VerificationError("refusing an authenticated request outside api.github.com")
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
        return urllib.request.Request(url, headers=headers)

    def _remaining(self, deadline: float, *, context: str) -> float:
        remaining = deadline - self.clock()
        if remaining <= 0:
            raise VerificationError(f"{context} exceeded the {self.timeout:g}-second deadline")
        return remaining

    @staticmethod
    def _set_socket_timeout(response: Any, timeout: float) -> None:
        fp = getattr(response, "fp", None)
        raw = getattr(fp, "raw", None)
        sock = getattr(raw, "_sock", None)
        if sock is not None:
            sock.settimeout(timeout)

    def _read(
        self,
        request: urllib.request.Request,
        *,
        limit: int,
        context: str,
        media_types: frozenset[str],
    ) -> bytes:
        deadline = self.clock() + self.timeout
        try:
            with self.opener.open(
                request, timeout=self._remaining(deadline, context=context)
            ) as response:
                if response.geturl() != request.full_url:
                    raise VerificationError(f"{context} redirected away from its canonical URL")
                status = getattr(response, "status", None)
                if status is None:
                    status = response.getcode()
                if status != 200:
                    raise VerificationError(f"{context} returned HTTP {status}; expected HTTP 200")
                content_type = response.headers.get("Content-Type", "")
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type not in media_types:
                    expected = ", ".join(sorted(media_types))
                    raise VerificationError(
                        f"{context} returned Content-Type {media_type or '<missing>'}; expected {expected}"
                    )
                content_encoding = response.headers.get("Content-Encoding", "identity")
                if content_encoding.strip().lower() not in ("", "identity"):
                    raise VerificationError(
                        f"{context} returned unsupported Content-Encoding {content_encoding!r}"
                    )
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    normalized = declared.strip()
                    if re.fullmatch(r"[0-9]+", normalized) is None:
                        raise VerificationError(
                            f"{context} returned an invalid Content-Length"
                        )
                    declared_size = int(normalized)
                    if declared_size > limit:
                        raise VerificationError(
                            f"{context} is {declared_size} bytes, above the {limit}-byte verification limit"
                        )
                body = bytearray()
                reader = getattr(response, "read1", response.read)
                while len(body) <= limit:
                    remaining = self._remaining(deadline, context=context)
                    self._set_socket_timeout(response, remaining)
                    chunk = reader(min(READ_CHUNK_BYTES, limit + 1 - len(body)))
                    if self.clock() > deadline:
                        raise VerificationError(
                            f"{context} exceeded the {self.timeout:g}-second deadline"
                        )
                    if not chunk:
                        break
                    if not isinstance(chunk, bytes):
                        raise VerificationError(f"{context} returned a non-byte response body")
                    body.extend(chunk)
        except VerificationError:
            raise
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise VerificationError(f"{context} returned HTTP 404") from error
            raise VerificationError(f"{context} returned HTTP {error.code}") from error
        except Exception as error:
            raise VerificationError(f"cannot read {context}: {error}") from error
        if len(body) > limit:
            raise VerificationError(
                f"{context} exceeds the {limit}-byte verification limit"
            )
        return bytes(body)

    def json(self, path: str) -> dict[str, Any]:
        """Read one bounded object from the pinned GitHub API origin."""

        parsed = urllib.parse.urlsplit(path)
        if (
            not path.startswith("/")
            or path.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
        ):
            raise VerificationError("GitHub API request must be an origin-relative path")
        url = API_ORIGIN + path
        request = self._request(
            url, accept="application/vnd.github+json", authenticated=True
        )
        raw = self._read(
            request,
            limit=MAX_JSON_BYTES,
            context=f"GitHub API {url}",
            media_types=frozenset(
                {"application/json", "application/vnd.github+json"}
            ),
        )
        try:
            text = raw.decode("utf-8")
            value = json.loads(
                text,
                object_pairs_hook=_reject_json_duplicates,
                parse_constant=_reject_json_constant,
            )
            _validate_json_unicode(value)
        except (UnicodeDecodeError, json.JSONDecodeError, _InvalidJSON, RecursionError) as error:
            raise VerificationError(
                f"GitHub API {url} did not return valid JSON"
            ) from error
        if not isinstance(value, dict):
            raise VerificationError(f"GitHub API {url} did not return an object")
        return value

    def marketplace_html(self, url: str) -> str:
        """Read one bounded canonical Marketplace page without credentials."""

        url = validate_listing_url(url)
        request = self._request(url, accept="text/html", authenticated=False)
        raw = self._read(
            request,
            limit=MAX_HTML_BYTES,
            context=f"Marketplace listing {url}",
            media_types=frozenset({"text/html"}),
        )
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise VerificationError(
                f"Marketplace listing {url} is not UTF-8 HTML"
            ) from error


@dataclass(frozen=True)
class ListingReceipt:
    """Versioned public identity proven by the verifier."""

    schema_version: int
    repository: str
    action_tag: str
    release_tag: str
    release_tag_sha: str
    release_signer_fingerprint: str
    release_signing_key_sha256: str
    release_id: int
    release_url: str
    release_published_at: str
    commit: str
    root_action_sha: str
    action_name: str
    listing_url: str
    marketplace_ref: str
    categories: tuple[str, ...]


def _repository(value: str) -> str:
    parts = value.split("/")
    if (
        len(parts) != 2
        or OWNER.fullmatch(parts[0]) is None
        or REPOSITORY_NAME.fullmatch(parts[1]) is None
        or parts[1] in (".", "..")
    ):
        raise VerificationError("repository must be a valid GitHub OWNER/REPOSITORY")
    return value


def _tags(action_tag: str, release_tag: str) -> tuple[str, str]:
    action_match = ACTION_TAG.fullmatch(action_tag)
    release_match = RELEASE_TAG.fullmatch(release_tag)
    if action_match is None:
        raise VerificationError("action tag must be a floating vMAJOR tag")
    if release_match is None:
        raise VerificationError("release tag must be an exact stable vMAJOR.MINOR.PATCH tag")
    if action_tag == release_tag or action_match.group(1) != release_match.group(1):
        raise VerificationError(
            "action tag and release tag must be distinct and use the same major version"
        )
    return action_tag, release_tag


def _categories(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    categories = tuple(values)
    if (
        len(categories) != 2
        or len(set(categories)) != 2
        or any(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", category) is None
            for category in categories
        )
    ):
        raise VerificationError(
            "exactly two distinct canonical Marketplace category slugs are required"
        )
    return categories


def _action_name(value: str) -> str:
    normalized = " ".join(value.split())
    if (
        not normalized
        or normalized != value
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise VerificationError(
            "action name must be a non-empty single-line Marketplace display name"
        )
    return value


def _signer_fingerprint(value: str) -> str:
    normalized = value.upper()
    if (
        value != value.strip()
        or re.fullmatch(r"(?:[0-9A-F]{40}|[0-9A-F]{64})", normalized) is None
    ):
        raise VerificationError(
            "release signer fingerprint must be a full 40- or 64-hex fingerprint"
        )
    return normalized


class _ReleaseSigner:
    """Verify signed Git tag payloads against one operator-enrolled OpenPGP key."""

    def __init__(self, expected_fingerprint: str, public_key: bytes) -> None:
        self.fingerprint = _signer_fingerprint(expected_fingerprint)
        if (
            not isinstance(public_key, bytes)
            or not public_key
            or b"\x00" in public_key
            or len(public_key) > MAX_SIGNING_KEY_BYTES
        ):
            raise VerificationError(
                "release signing key must be non-empty canonical ASCII armor "
                f"without NUL and at most {MAX_SIGNING_KEY_BYTES} bytes"
            )
        self._temporary = tempfile.TemporaryDirectory(
            prefix="keyhog-marketplace-gpg-"
        )
        self._homedir = self._temporary.name
        try:
            imported = self._run(["--status-fd=1", "--import"], input_data=public_key)
            if imported.returncode != 0:
                raise VerificationError(
                    "release signing key is not an importable OpenPGP public key"
                )
            listed = self._run(["--with-colons", "--fingerprint", "--list-keys"])
            primary_fingerprints: list[str] = []
            all_fingerprints: set[str] = set()
            awaiting_primary = False
            for line in listed.stdout.decode("utf-8", "replace").splitlines():
                fields = line.split(":")
                record = fields[0]
                if record == "pub":
                    awaiting_primary = True
                elif record == "sub":
                    awaiting_primary = False
                elif record == "fpr" and len(fields) > 9:
                    fingerprint = fields[9].upper()
                    all_fingerprints.add(fingerprint)
                    if awaiting_primary:
                        primary_fingerprints.append(fingerprint)
                        awaiting_primary = False
            if (
                listed.returncode != 0
                or len(primary_fingerprints) != 1
                or self.fingerprint not in all_fingerprints
            ):
                raise VerificationError(
                    "release signing key does not contain exactly one expected OpenPGP identity"
                )
            secrets = self._run(["--with-colons", "--list-secret-keys"])
            if any(
                line.startswith(("sec:", "ssb:"))
                for line in secrets.stdout.decode("utf-8", "replace").splitlines()
            ):
                raise VerificationError(
                    "release signing key input must not contain private key material"
                )
            self._primary_fingerprint = primary_fingerprints[0]
            exported = self._run(["--export", self._primary_fingerprint])
            armored = self._run(
                ["--armor", "--export", self._primary_fingerprint]
            )
            if (
                exported.returncode != 0
                or armored.returncode != 0
                or not exported.stdout
                or public_key != armored.stdout
            ):
                raise VerificationError(
                    "release signing key must be one exact canonical public key export"
                )
            self.key_sha256 = hashlib.sha256(exported.stdout).hexdigest()
        except Exception:
            self.close()
            raise

    def _run(
        self, arguments: list[str], *, input_data: bytes | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        command = [
            "gpg",
            "--batch",
            "--no-tty",
            "--no-options",
            "--homedir",
            self._homedir,
            "--no-auto-key-retrieve",
            "--auto-key-locate",
            "clear",
            *arguments,
        ]
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        try:
            return subprocess.run(
                command,
                input=input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=GPG_TIMEOUT_SECONDS,
                env=environment,
            )
        except FileNotFoundError as error:
            raise VerificationError(
                "gpg is required to verify the enrolled release signer"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise VerificationError(
                "gpg exceeded the release-signature verification deadline"
            ) from error

    @staticmethod
    def _signed_headers(
        payload: str, *, tag: str, annotated_object: dict[str, Any]
    ) -> None:
        header, separator, _message = payload.partition("\n\n")
        fields: dict[str, str] = {}
        for line in header.splitlines():
            key, space, value = line.partition(" ")
            if key in {"object", "type", "tag"}:
                if not space or key in fields:
                    raise VerificationError(
                        f"release tag {tag} has ambiguous signed Git tag headers"
                    )
                fields[key] = value
        if (
            not separator
            or fields.get("tag") != tag
            or fields.get("object") != annotated_object.get("sha")
            or fields.get("type") != annotated_object.get("type")
        ):
            raise VerificationError(
                f"release tag {tag} signature payload does not bind its Git object"
            )

    def verify(
        self,
        verification: Any,
        *,
        tag: str,
        annotated_object: Any,
    ) -> None:
        if (
            not isinstance(verification, dict)
            or verification.get("verified") is not True
            or not isinstance(verification.get("payload"), str)
            or not isinstance(verification.get("signature"), str)
            or not isinstance(annotated_object, dict)
        ):
            raise VerificationError(
                f"release tag {tag} does not expose a complete verified signature"
            )
        payload = verification["payload"]
        signature = verification["signature"]
        try:
            payload_bytes = payload.encode("utf-8")
            signature_bytes = signature.encode("utf-8")
        except UnicodeEncodeError as error:
            raise VerificationError(
                f"release tag {tag} signature material is not valid Unicode"
            ) from error
        if (
            not payload_bytes
            or len(payload_bytes) > MAX_SIGNATURE_BYTES
            or not signature_bytes
            or len(signature_bytes) > MAX_SIGNATURE_BYTES
        ):
            raise VerificationError(
                f"release tag {tag} signature material exceeds verification limits"
            )
        self._signed_headers(payload, tag=tag, annotated_object=annotated_object)
        payload_path = os.path.join(self._homedir, "tag-payload")
        signature_path = os.path.join(self._homedir, "tag-signature")
        try:
            with open(payload_path, "wb") as payload_file:
                payload_file.write(payload_bytes)
            with open(signature_path, "wb") as signature_file:
                signature_file.write(signature_bytes)
            verified = self._run(
                ["--status-fd=1", "--verify", signature_path, payload_path]
            )
        finally:
            for path in (payload_path, signature_path):
                try:
                    os.remove(path)
                except FileNotFoundError:
                    pass
        valid_signers: list[tuple[str, str]] = []
        for line in verified.stdout.decode("utf-8", "replace").splitlines():
            if not line.startswith("[GNUPG:] VALIDSIG "):
                continue
            fields = line.split()
            signing_fingerprint = fields[2].upper() if len(fields) > 2 else ""
            primary_fingerprint = fields[-1].upper() if len(fields) > 11 else ""
            valid_signers.append((signing_fingerprint, primary_fingerprint))
        good_signatures = [
            line
            for line in verified.stdout.decode("utf-8", "replace").splitlines()
            if line.startswith("[GNUPG:] GOODSIG ")
        ]
        if (
            verified.returncode != 0
            or len(good_signatures) != 1
            or len(valid_signers) != 1
            or self.fingerprint not in valid_signers[0]
        ):
            raise VerificationError(
                f"release tag {tag} is not signed by the expected enrolled fingerprint"
            )

    def close(self) -> None:
        self._temporary.cleanup()

    def __enter__(self) -> _ReleaseSigner:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def resolve_tag(
    client: GitHubClient,
    repository: str,
    tag: str,
    release_signer: _ReleaseSigner | None = None,
) -> tuple[str, str | None]:
    """Resolve a tag by object SHA and optionally require a verified top-level tag."""

    quoted = urllib.parse.quote(tag, safe="")
    value = client.json(f"/repos/{repository}/git/ref/tags/{quoted}")
    obj = value.get("object")
    seen: set[str] = set()
    top_tag_sha: str | None = None
    for _depth in range(MAX_TAG_OBJECTS + 1):
        if not isinstance(obj, dict):
            raise VerificationError(f"tag {tag} has no Git object")
        kind = obj.get("type")
        sha = obj.get("sha")
        if not isinstance(sha, str) or COMMIT.fullmatch(sha) is None:
            raise VerificationError(f"tag {tag} resolved to an invalid Git identity")
        if kind == "commit":
            if release_signer is not None and top_tag_sha is None:
                raise VerificationError(
                    f"release tag {tag} is lightweight rather than a signed annotated tag"
                )
            return sha, top_tag_sha
        if kind != "tag":
            raise VerificationError(
                f"tag {tag} resolves to unsupported Git object type {kind!r}"
            )
        if sha in seen:
            raise VerificationError(f"tag {tag} contains an annotated-tag cycle")
        if len(seen) >= MAX_TAG_OBJECTS:
            raise VerificationError(
                f"tag {tag} exceeds the {MAX_TAG_OBJECTS}-object annotated-tag limit"
            )
        if top_tag_sha is None:
            top_tag_sha = sha
        seen.add(sha)
        annotated = client.json(f"/repos/{repository}/git/tags/{sha}")
        if annotated.get("sha") != sha:
            raise VerificationError(f"tag {tag} returned a mismatched tag object")
        if release_signer is not None and len(seen) == 1:
            release_signer.verify(
                annotated.get("verification"),
                tag=tag,
                annotated_object=annotated.get("object"),
            )
        obj = annotated.get("object")
    raise AssertionError("unreachable tag resolution state")


def _release_timestamp(value: Any, *, repository: str, release_tag: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,9})?Z",
            value,
        )
        is None
    ):
        raise VerificationError(
            f"{repository} release {release_tag} lacks an RFC3339 UTC publication timestamp"
        )
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise VerificationError(
            f"{repository} release {release_tag} has an invalid publication timestamp"
        ) from error
    return value


def public_release(
    client: GitHubClient, repository: str, release_tag: str
) -> tuple[int, str, str]:
    """Require one published, non-prerelease GitHub Release for the exact tag."""

    quoted = urllib.parse.quote(release_tag, safe="")
    value = client.json(f"/repos/{repository}/releases/tags/{quoted}")
    release_id = value.get("id")
    release_url = value.get("html_url")
    published_at = value.get("published_at")
    if (
        not isinstance(release_id, int)
        or isinstance(release_id, bool)
        or release_id <= 0
        or value.get("tag_name") != release_tag
        or value.get("draft") is not False
        or value.get("prerelease") is not False
        or not isinstance(release_url, str)
    ):
        raise VerificationError(
            f"{repository} release {release_tag} is not a public stable GitHub Release"
        )
    expected_url = f"https://github.com/{repository}/releases/tag/{release_tag}"
    if release_url != expected_url:
        raise VerificationError(
            f"{repository} release {release_tag} returned a non-canonical public URL"
        )
    return release_id, release_url, _release_timestamp(
        published_at, repository=repository, release_tag=release_tag
    )






def verify_action_metadata(raw: str, *, expected_name: str) -> None:
    """Parse the complete YAML document and validate effective Action metadata."""

    if yaml is None:
        raise VerificationError(
            "PyYAML is required for full root action.yml semantic verification"
        )

    class UniqueSafeLoader(yaml.SafeLoader):
        pass

    def construct_unique_mapping(
        loader: Any, node: Any, deep: bool = False
    ) -> dict[Any, Any]:
        loader.flatten_mapping(node)
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as error:
                raise VerificationError(
                    "root action.yml contains an unhashable mapping key"
                ) from error
            if duplicate:
                raise VerificationError(
                    f"root action.yml contains duplicate key {key!r}"
                )
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueSafeLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_unique_mapping,
    )
    try:
        events = list(yaml.parse(raw, Loader=UniqueSafeLoader))
        if any(
            isinstance(event, yaml.events.DocumentEndEvent) and event.explicit
            for event in events
        ):
            raise VerificationError(
                "root action.yml must not contain an explicit YAML document end"
            )
        value = yaml.load(raw, Loader=UniqueSafeLoader)
        root_node = yaml.compose(raw, Loader=UniqueSafeLoader)
    except VerificationError:
        raise
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as error:
        raise VerificationError(
            f"root action.yml is not one complete valid YAML document: {error}"
        ) from error
    if not isinstance(value, dict) or not isinstance(root_node, yaml.MappingNode):
        raise VerificationError("root action.yml must be one top-level mapping")

    def mapping_node(node: Any, key: str) -> Any:
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
                return value_node
        raise VerificationError(f"root action.yml lacks top-level {key!r}")

    def child_node(node: Any, parent: str, key: str) -> Any:
        if not isinstance(node, yaml.MappingNode):
            raise VerificationError(f"root action.yml {parent} must be a mapping")
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
                return value_node
        raise VerificationError(
            f"root action.yml lacks required Marketplace metadata {parent}.{key}"
        )

    def plain_scalar(node: Any, label: str) -> None:
        if not isinstance(node, yaml.ScalarNode) or node.style in {"|", ">"}:
            raise VerificationError(
                f"root action.yml {label} must be one non-block scalar"
            )

    name_node = mapping_node(root_node, "name")
    description_node = mapping_node(root_node, "description")
    branding_node = mapping_node(root_node, "branding")
    runs_node = mapping_node(root_node, "runs")
    icon_node = child_node(branding_node, "branding", "icon")
    color_node = child_node(branding_node, "branding", "color")
    using_node = child_node(runs_node, "runs", "using")
    for node, label in (
        (name_node, "name"),
        (description_node, "description"),
        (icon_node, "branding.icon"),
        (color_node, "branding.color"),
        (using_node, "runs.using"),
    ):
        plain_scalar(node, label)

    name = value.get("name")
    description = value.get("description")
    branding = value.get("branding")
    runs = value.get("runs")
    if (
        not isinstance(name, str)
        or name != expected_name
        or not isinstance(description, str)
        or not description.strip()
    ):
        raise VerificationError(
            "root action.yml does not expose the expected Marketplace identity"
        )
    if not isinstance(branding, dict) or not isinstance(runs, dict):
        raise VerificationError("root action.yml branding and runs must be mappings")
    icon = branding.get("icon")
    color = branding.get("color")
    using = runs.get("using")
    if not isinstance(icon, str) or not isinstance(color, str):
        raise VerificationError(
            "root action.yml branding fields must be string scalars"
        )
    if re.fullmatch(r"[a-z0-9-]+", icon) is None or color not in {
        "white",
        "yellow",
        "blue",
        "green",
        "orange",
        "red",
        "purple",
        "gray-dark",
    }:
        raise VerificationError(
            "root action.yml branding is not valid Marketplace metadata"
        )
    if using != "composite":
        raise VerificationError("root action.yml runs.using must be 'composite'")


def _git_blob_sha(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def root_action(
    client: GitHubClient, repository: str, commit: str, expected_name: str
) -> str:
    """Require root composite metadata at the already resolved immutable commit."""

    value = client.json(f"/repos/{repository}/contents/action.yml?ref={commit}")
    if value.get("type") != "file" or value.get("encoding") != "base64":
        raise VerificationError(
            f"{repository}@{commit} does not expose root action.yml as a base64 file"
        )
    content = value.get("content")
    reported_sha = value.get("sha")
    if not isinstance(content, str) or not isinstance(reported_sha, str):
        raise VerificationError(
            f"{repository}@{commit} returned incomplete root action.yml metadata"
        )
    try:
        encoded = "".join(content.split())
        raw = base64.b64decode(encoded, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as error:
        raise VerificationError(
            f"{repository}@{commit} root action.yml is not valid base64 UTF-8"
        ) from error
    computed_sha = _git_blob_sha(raw)
    if reported_sha != computed_sha:
        raise VerificationError(
            f"{repository}@{commit} root action.yml blob identity does not match its bytes"
        )
    verify_action_metadata(text, expected_name=expected_name)
    return computed_sha


def _normalized_text(chunks: list[str]) -> str:
    return " ".join("".join(chunks).split())


class _MarketplaceParser(HTMLParser):
    """Collect only listing chrome inside main and outside rendered README content."""

    def __init__(self, *, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.canonical_urls: list[str] = []
        self.links: list[str] = []
        self.headings: list[list[str]] = []
        self.code_text: list[str] = []
        self.invalid_duplicate_attributes = False
        self.main_elements = 0
        self._main_depth = 0
        self._hidden_depth = 0
        self._excluded_elements: list[str] = []
        self._heading_depth = 0
        self._code_depth = 0

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes: dict[str, str | None] = {}
        for key, value in attrs:
            lowered_key = key.lower()
            if lowered_key in attributes:
                self.invalid_duplicate_attributes = True
            else:
                attributes[lowered_key] = value
        lowered = tag.lower()
        if lowered in {"script", "style", "template", "noscript"}:
            self._hidden_depth += 1
            return
        if self._hidden_depth:
            return
        if lowered == "link" and attributes.get("href"):
            rel = (attributes.get("rel") or "").lower().split()
            if "canonical" in rel:
                self.canonical_urls.append(
                    urllib.parse.urljoin(self.base_url, attributes["href"] or "")
                )
        if lowered == "main":
            self._main_depth += 1
            self.main_elements += 1
        classes = set((attributes.get("class") or "").split())
        if self._main_depth and (
            lowered == "article"
            or "markdown-body" in classes
            or "js-readme" in classes
        ):
            self._excluded_elements.append(lowered)
        if (
            not self._main_depth
            or self._excluded_elements
            or self._hidden_depth
        ):
            return
        if lowered == "a" and attributes.get("href"):
            self.links.append(
                urllib.parse.urljoin(self.base_url, attributes["href"] or "")
            )
        if lowered in {"h1", "h2"}:
            self._heading_depth += 1
            self.headings.append([])
        if lowered in {"code", "pre"}:
            self._code_depth += 1

    def handle_endtag(self, tag: str) -> None:
        lowered = tag.lower()
        if lowered in {"script", "style", "template", "noscript"}:
            if self._hidden_depth:
                self._hidden_depth -= 1
            return
        if self._hidden_depth:
            return
        if not self._excluded_elements:
            if lowered in {"h1", "h2"} and self._heading_depth:
                self._heading_depth -= 1
            if lowered in {"code", "pre"} and self._code_depth:
                self._code_depth -= 1
        if self._excluded_elements and lowered == self._excluded_elements[-1]:
            self._excluded_elements.pop()
        if lowered == "main" and self._main_depth:
            self._main_depth -= 1

    def handle_data(self, data: str) -> None:
        if (
            not self._main_depth
            or self._hidden_depth
            or self._excluded_elements
        ):
            return
        if self._heading_depth and self.headings:
            self.headings[-1].append(data)
        if self._code_depth:
            self.code_text.append(data)


def _is_repository_link(value: str, repository: str) -> bool:
    parsed = urllib.parse.urlsplit(value)
    return (
        parsed.scheme == "https"
        and parsed.hostname == "github.com"
        and parsed.port is None
        and parsed.username is None
        and parsed.password is None
        and urllib.parse.unquote(parsed.path).rstrip("/").casefold()
        == f"/{repository}".casefold()
    )


def _marketplace_category(value: str) -> str | None:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path.rstrip("/") != "/marketplace"
        or parsed.fragment
    ):
        return None
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if set(query) - {"category", "type"}:
        return None
    categories = query.get("category", [])
    action_types = query.get("type", [])
    if len(categories) != 1 or action_types not in ([], ["actions"]):
        return None
    category = categories[0]
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", category) is None:
        return None
    return category


def verify_listing_page(
    body: str,
    *,
    listing_url: str,
    repository: str,
    action_name: str,
    required_ref: str,
    categories: tuple[str, ...],
) -> str:
    """Bind canonical rendered Marketplace semantics to repository, name, and ref."""

    try:
        body.encode("utf-8")
        parser = _MarketplaceParser(base_url=listing_url)
        parser.feed(body)
        parser.close()
    except (UnicodeEncodeError, ValueError) as error:
        raise VerificationError(
            f"Marketplace listing {listing_url} is not valid UTF-8 HTML"
        ) from error
    if parser.invalid_duplicate_attributes:
        raise VerificationError(
            f"Marketplace listing {listing_url} contains duplicate HTML attributes"
        )
    if parser.main_elements != 1:
        raise VerificationError(
            f"Marketplace listing {listing_url} must contain one canonical main element"
        )
    if parser.canonical_urls != [listing_url]:
        raise VerificationError(
            f"Marketplace listing {listing_url} lacks one exact canonical URL"
        )
    headings = {_normalized_text(chunks) for chunks in parser.headings}
    if action_name not in headings:
        raise VerificationError(
            f"Marketplace listing {listing_url} does not render Action heading {action_name!r}"
        )
    if not any(_is_repository_link(link, repository) for link in parser.links):
        raise VerificationError(
            f"Marketplace listing {listing_url} does not link to https://github.com/{repository}"
        )
    rendered_categories = {
        category
        for link in parser.links
        if (category := _marketplace_category(link)) is not None
    }
    if rendered_categories != set(categories):
        raise VerificationError(
            f"Marketplace listing {listing_url} category links do not exactly match {sorted(categories)}"
        )
    code = _normalized_text(parser.code_text)
    uses = re.compile(
        rf"(?:^|\s)uses\s*:\s*{re.escape(repository)}@(?P<ref>v[0-9A-Za-z.+-]+)(?:\s|$)",
        re.IGNORECASE,
    )
    matched_refs = {match.group("ref") for match in uses.finditer(code)}
    if matched_refs != {required_ref}:
        raise VerificationError(
            f"Marketplace listing {listing_url} must render only signed release ref {required_ref}"
        )
    return required_ref


def validate_listing_url(value: str) -> str:
    """Require one byte-canonical github.com Marketplace Action URL."""

    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or re.fullmatch(
            r"/marketplace/actions/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", parsed.path
        )
        is None
    ):
        raise VerificationError(
            "listing URL must be the canonical /marketplace/actions/SLUG page without credentials, query, or fragment"
        )
    canonical = f"{GITHUB_ORIGIN}{parsed.path}"
    if value != canonical:
        raise VerificationError(
            "listing URL must use the byte-canonical https://github.com origin"
        )
    return value


def verify(
    client: GitHubClient,
    *,
    repository: str,
    action_tag: str,
    release_tag: str,
    listing_url: str,
    action_name: str,
    categories: list[str] | tuple[str, ...],
    release_signer_fingerprint: str,
    release_signing_key: bytes,
) -> ListingReceipt:
    """Bind Marketplace publication to one enrolled signer and immutable release."""

    requested_repository = _repository(repository)
    action_tag, release_tag = _tags(action_tag, release_tag)
    listing_url = validate_listing_url(listing_url)
    action_name = _action_name(action_name)
    categories = _categories(categories)
    with _ReleaseSigner(
        release_signer_fingerprint, release_signing_key
    ) as release_signer:
        repo = client.json(f"/repos/{requested_repository}")
        canonical_repository = repo.get("full_name")
        if (
            not isinstance(canonical_repository, str)
            or canonical_repository.casefold() != requested_repository.casefold()
            or repo.get("private") is not False
        ):
            raise VerificationError(
                f"{requested_repository} is not the expected public repository"
            )
        repository = _repository(canonical_repository)
        action_commit, _action_tag_sha = resolve_tag(
            client, repository, action_tag
        )
        release_commit, release_tag_sha = resolve_tag(
            client,
            repository,
            release_tag,
            release_signer=release_signer,
        )
        if action_commit != release_commit:
            raise VerificationError(
                f"floating Action tag {action_tag} resolves to {action_commit}, but stable release tag "
                f"{release_tag} resolves to {release_commit}"
            )
        release_id, release_url, release_published_at = public_release(
            client, repository, release_tag
        )
        action_sha = root_action(client, repository, action_commit, action_name)
        listing = client.marketplace_html(listing_url)
        marketplace_ref = verify_listing_page(
            listing,
            listing_url=listing_url,
            repository=repository,
            action_name=action_name,
            required_ref=release_tag,
            categories=categories,
        )
        current_action_commit, _current_action_tag_sha = resolve_tag(
            client, repository, action_tag
        )
        current_release_commit, current_release_tag_sha = resolve_tag(
            client,
            repository,
            release_tag,
            release_signer=release_signer,
        )
        if (
            current_action_commit != action_commit
            or current_release_commit != release_commit
            or current_release_tag_sha != release_tag_sha
        ):
            raise VerificationError("Action or release tag moved during verification")
        if release_tag_sha is None:
            raise AssertionError("signed release tag did not expose its tag-object SHA")
        return ListingReceipt(
            schema_version=RECEIPT_SCHEMA_VERSION,
            repository=repository,
            action_tag=action_tag,
            release_tag=release_tag,
            release_tag_sha=release_tag_sha,
            release_signer_fingerprint=release_signer.fingerprint,
            release_signing_key_sha256=release_signer.key_sha256,
            release_id=release_id,
            release_url=release_url,
            release_published_at=release_published_at,
            commit=action_commit,
            root_action_sha=action_sha,
            action_name=action_name,
            listing_url=listing_url,
            marketplace_ref=marketplace_ref,
            categories=categories,
        )


def _read_release_signing_key(path: str) -> bytes:
    try:
        with open(path, "rb") as key_file:
            public_key = key_file.read(MAX_SIGNING_KEY_BYTES + 1)
    except OSError as error:
        raise VerificationError(f"cannot read release signing key: {error}") from error
    if not public_key or len(public_key) > MAX_SIGNING_KEY_BYTES:
        raise VerificationError(
            f"release signing key must contain at most {MAX_SIGNING_KEY_BYTES} bytes"
        )
    return public_key


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="GitHub OWNER/REPOSITORY")
    parser.add_argument(
        "--action-tag",
        required=True,
        help="floating Marketplace Action vMAJOR tag, such as v0",
    )
    parser.add_argument(
        "--release-tag", required=True, help="exact signed public stable vMAJOR.MINOR.PATCH release tag"
    )
    parser.add_argument(
        "--release-signing-key",
        required=True,
        help="path to the enrolled OpenPGP release-signing public key",
    )
    parser.add_argument(
        "--release-signer-fingerprint",
        required=True,
        help="full expected OpenPGP primary or signing fingerprint",
    )
    parser.add_argument(
        "--listing-url", required=True, help="public github.com/marketplace/actions URL"
    )
    parser.add_argument(
        "--action-name", required=True, help="exact root action.yml and Marketplace name"
    )
    parser.add_argument(
        "--category",
        action="append",
        dest="categories",
        required=True,
        help="required Marketplace category slug; pass exactly twice",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="whole-request deadline in seconds"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0 or args.timeout > 120:
        print(
            "error: --timeout must be finite, greater than 0, and at most 120 seconds",
            file=sys.stderr,
        )
        return 2
    try:
        release_signing_key = _read_release_signing_key(args.release_signing_key)
        client = GitHubClient(
            os.environ.get("GITHUB_TOKEN", ""), timeout=args.timeout
        )
        receipt = verify(
            client,
            repository=args.repository,
            action_tag=args.action_tag,
            release_tag=args.release_tag,
            listing_url=args.listing_url,
            action_name=args.action_name,
            categories=args.categories,
            release_signer_fingerprint=args.release_signer_fingerprint,
            release_signing_key=release_signing_key,
        )
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
