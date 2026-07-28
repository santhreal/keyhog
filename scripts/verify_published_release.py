#!/usr/bin/env python3
"""Verify the immutable public GitHub release verdict before crate publication."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, BinaryIO

PUBLIC_KEY = "RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go"
PUBLIC_REPOSITORY = "santhreal/keyhog"
PUBLIC_API_BASE = "https://api.github.com"
ASSET_DOWNLOAD_HOSTS = frozenset(
    {
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)
LOWERCASE_SHA = re.compile(r"^[0-9a-f]{40}$")
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
JSON_DEADLINE_SECONDS = 30.0
DOWNLOAD_DEADLINE_SECONDS = 120.0
MAX_REDIRECTS = 3
_READ_SIZE = 64 * 1024
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class VerificationError(RuntimeError):
    """The release is not a complete immutable publication verdict."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Expose redirects so the client can validate each hop before following it."""

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


def _url_origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise VerificationError(f"unsafe URL: {url!r}")
    try:
        port = parsed.port
    except ValueError as error:
        raise VerificationError(f"unsafe URL: {url!r}") from error
    return parsed.scheme, parsed.hostname.lower(), port or (443 if parsed.scheme == "https" else 80)


def _validate_base_url(api_base: str) -> tuple[str, bool]:
    base = api_base.rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if base == PUBLIC_API_BASE:
        return base, True
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise VerificationError(
            "non-public GitHub API clients are restricted to an explicitly constructed loopback server"
        )
    return base, False


def _content_type(response: Any) -> str:
    return response.headers.get_content_type().lower()


def _content_length(response: Any, *, label: str) -> int | None:
    raw = response.headers.get("Content-Length")
    if raw is None:
        return None
    try:
        length = int(raw)
    except (TypeError, ValueError) as error:
        raise VerificationError(f"{label} returned an invalid Content-Length") from error
    if length < 0:
        raise VerificationError(f"{label} returned an invalid Content-Length")
    return length


def _remaining(deadline: float, *, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise VerificationError(f"{label} exceeded its whole-request deadline")
    return remaining


def _set_read_timeout(response: Any, timeout: float) -> None:
    """Reduce the live socket timeout as the whole-request deadline approaches."""

    fp = getattr(response, "fp", None)
    raw = getattr(fp, "raw", None)
    sock = getattr(raw, "_sock", None)
    if sock is not None:
        sock.settimeout(timeout)


def _read_bounded(response: Any, *, limit: int, deadline: float, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = _remaining(deadline, label=label)
        _set_read_timeout(response, remaining)
        allowance = min(_READ_SIZE, limit + 1 - total)
        try:
            chunk = response.read1(allowance) if hasattr(response, "read1") else response.read(allowance)
        except (TimeoutError, socket.timeout) as error:
            raise VerificationError(f"{label} exceeded its whole-request deadline") from error
        except http.client.IncompleteRead as error:
            chunk = error.partial
            if chunk:
                chunks.append(chunk)
                total += len(chunk)
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise VerificationError(f"{label} exceeded the permitted {limit} bytes")
        _remaining(deadline, label=label)
    return b"".join(chunks)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise VerificationError(f"GitHub JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> Any:
    raise VerificationError(f"GitHub JSON contains nonstandard constant {value!r}")


class GitHubClient:
    """Authenticated GitHub client with fixed production and explicit loopback modes."""

    def __init__(
        self,
        api_base: str,
        token: str,
        *,
        json_deadline: float = JSON_DEADLINE_SECONDS,
        download_deadline: float = DOWNLOAD_DEADLINE_SECONDS,
        json_limit: int = MAX_JSON_BYTES,
    ) -> None:
        self.api_base, self.is_public = _validate_base_url(api_base)
        if not token:
            raise VerificationError("GH_TOKEN is required to prove the published release")
        if json_deadline <= 0 or download_deadline <= 0 or json_limit <= 0:
            raise VerificationError("GitHub client request bounds must be positive")
        self.token = token
        self.json_deadline = json_deadline
        self.download_deadline = download_deadline
        self.json_limit = json_limit
        self.opener = urllib.request.build_opener(_NoRedirectHandler())

    @classmethod
    def public(cls, token: str) -> GitHubClient:
        """Construct the only client permitted for production CLI verification."""

        return cls(PUBLIC_API_BASE, token)

    def _request(self, url: str, *, accept: str, authenticated: bool) -> urllib.request.Request:
        headers = {
            "Accept": accept,
            "User-Agent": "keyhog-crate-publication-verdict",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        return urllib.request.Request(url, headers=headers)

    def _api_url(self, path: str) -> str:
        if not path.startswith("/") or path.startswith("//"):
            raise VerificationError(f"unsafe GitHub API path: {path!r}")
        return self.api_base + path

    def json(self, path: str) -> dict[str, Any]:
        label = f"GitHub API {path}"
        deadline = time.monotonic() + self.json_deadline
        request = self._request(
            self._api_url(path), accept="application/vnd.github+json", authenticated=True
        )
        try:
            with self.opener.open(
                request, timeout=_remaining(deadline, label=label)
            ) as response:
                if response.status != 200:
                    raise VerificationError(f"{label} returned HTTP {response.status}")
                if response.geturl() != request.full_url:
                    raise VerificationError(f"{label} redirected unexpectedly")
                if _content_type(response) not in {
                    "application/json",
                    "application/vnd.github+json",
                }:
                    raise VerificationError(f"{label} returned an unsafe Content-Type")
                length = _content_length(response, label=label)
                if length is not None and length > self.json_limit:
                    raise VerificationError(
                        f"{label} exceeded the permitted {self.json_limit} bytes"
                    )
                raw = _read_bounded(
                    response, limit=self.json_limit, deadline=deadline, label=label
                )
        except urllib.error.HTTPError as error:
            raise VerificationError(f"{label} returned HTTP {error.code}") from error
        except VerificationError:
            raise
        except (TimeoutError, socket.timeout) as error:
            raise VerificationError(f"{label} exceeded its whole-request deadline") from error
        except Exception as error:
            raise VerificationError(f"cannot read {label}: {error}") from error
        try:
            value = json.loads(
                raw,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VerificationError(f"{label} did not return valid JSON") from error
        if not isinstance(value, dict):
            raise VerificationError(f"{label} did not return an object")
        return value

    def _asset_network_url(self, canonical_url: str) -> str:
        if self.is_public:
            return canonical_url
        return self.api_base + urllib.parse.urlsplit(canonical_url).path

    @staticmethod
    def _validate_redirect(url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        try:
            port = parsed.port
        except ValueError as error:
            raise VerificationError(f"unsafe release asset redirect: {url!r}") from error
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.hostname.lower() not in ASSET_DOWNLOAD_HOSTS
            or port not in {None, 443}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise VerificationError(f"unsafe release asset redirect: {url!r}")

    def _open_asset(self, canonical_url: str, *, deadline: float, label: str) -> Any:
        current_url = self._asset_network_url(canonical_url)
        authenticated = True
        for redirects in range(MAX_REDIRECTS + 1):
            request = self._request(
                current_url, accept="application/octet-stream", authenticated=authenticated
            )
            try:
                response = self.opener.open(
                    request, timeout=_remaining(deadline, label=label)
                )
            except urllib.error.HTTPError as error:
                if error.code not in _REDIRECT_STATUSES:
                    raise VerificationError(f"{label} returned HTTP {error.code}") from error
                response = error
            if response.status not in _REDIRECT_STATUSES:
                if response.status != 200:
                    response.close()
                    raise VerificationError(f"{label} returned HTTP {response.status}")
                final_url = response.geturl()
                if self.is_public:
                    parsed = urllib.parse.urlsplit(final_url)
                    final_is_api = final_url == canonical_url
                    final_is_asset_host = (
                        parsed.scheme == "https"
                        and parsed.hostname is not None
                        and parsed.hostname.lower() in ASSET_DOWNLOAD_HOSTS
                        and parsed.port in {None, 443}
                        and parsed.username is None
                        and parsed.password is None
                        and not parsed.fragment
                    )
                    if not final_is_api and not final_is_asset_host:
                        response.close()
                        raise VerificationError(f"{label} ended at an unsafe URL")
                elif final_url != current_url:
                    response.close()
                    raise VerificationError(f"{label} redirected unexpectedly")
                return response
            location = response.headers.get("Location")
            response.close()
            if redirects == MAX_REDIRECTS:
                raise VerificationError(f"{label} exceeded {MAX_REDIRECTS} redirects")
            if not location:
                raise VerificationError(f"{label} returned a redirect without Location")
            redirected_url = urllib.parse.urljoin(current_url, location)
            self._validate_redirect(redirected_url)
            if _url_origin(redirected_url) == _url_origin(current_url):
                raise VerificationError(f"{label} redirected to an unexpected same-origin URL")
            current_url = redirected_url
            authenticated = False
        raise AssertionError("unreachable redirect loop")

    def download(self, url: str, destination: Path, *, expected_size: int) -> None:
        label = f"release asset {destination.name}"
        if type(expected_size) is not int or expected_size <= 0 or expected_size > MAX_ASSET_BYTES:
            raise VerificationError(f"{label} has an unsafe declared size {expected_size}")
        if os.path.lexists(destination):
            raise VerificationError(f"refusing existing release asset path {destination}")
        temporary = destination.with_name(f".{destination.name}.download")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temporary, flags, 0o600)
        except OSError as error:
            raise VerificationError(f"cannot create safe temporary asset {temporary}: {error}") from error
        deadline = time.monotonic() + self.download_deadline
        try:
            with os.fdopen(descriptor, "wb") as output:
                with self._open_asset(url, deadline=deadline, label=label) as response:
                    if _content_type(response) != "application/octet-stream":
                        raise VerificationError(f"{label} returned an unsafe Content-Type")
                    length = _content_length(response, label=label)
                    if length is not None and length != expected_size:
                        kind = "oversized" if length > expected_size else "truncated"
                        raise VerificationError(
                            f"{label} is {kind}: declared {expected_size}, Content-Length {length}"
                        )
                    raw = _read_bounded(
                        response,
                        limit=expected_size,
                        deadline=deadline,
                        label=label,
                    )
                    if len(raw) != expected_size:
                        raise VerificationError(
                            f"{label} is truncated: declared {expected_size}, downloaded {len(raw)}"
                        )
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
            if os.path.lexists(destination):
                raise VerificationError(f"refusing existing release asset path {destination}")
            os.replace(temporary, destination)
        except VerificationError:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        except (TimeoutError, socket.timeout) as error:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise VerificationError(f"{label} exceeded its whole-request deadline") from error
        except Exception as error:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise VerificationError(f"cannot download {label}: {error}") from error


def expected_asset_names() -> set[str]:
    """Return the exact signed cross-platform release manifest."""

    payloads = ["install.sh", "install.ps1"]
    for base in (
        "keyhog-linux-x86_64",
        "keyhog-macos-aarch64",
        "keyhog-macos-x86_64",
        "keyhog-windows-x86_64.exe",
    ):
        payloads.extend((base, f"{base}.gpu-literals.tar.gz"))
    names: set[str] = set()
    for payload in payloads:
        for signed_asset in (payload, f"{payload}.spdx.json"):
            names.update(
                (
                    signed_asset,
                    f"{signed_asset}.sha256",
                    f"{signed_asset}.minisig",
                )
            )
    return names


def _published_at(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise VerificationError("release has no published_at verdict")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise VerificationError(f"release published_at is invalid: {value!r}") from error
    if parsed.tzinfo is None:
        raise VerificationError(f"release published_at is not timezone-qualified: {value!r}")
    return value


def _canonical_asset_url(asset_id: int) -> str:
    return f"{PUBLIC_API_BASE}/repos/{PUBLIC_REPOSITORY}/releases/assets/{asset_id}"


def release_snapshot(
    value: dict[str, Any], *, tag: str, release_id: int | None = None
) -> tuple[Any, ...]:
    """Validate and normalize the public release identity and exact asset listing."""

    actual_id = value.get("id")
    if type(actual_id) is not int or actual_id <= 0:
        raise VerificationError(f"release for {tag} has no positive immutable ID")
    if release_id is not None and actual_id != release_id:
        raise VerificationError(
            f"release ID changed for {tag}: expected {release_id}, received {actual_id}"
        )
    if value.get("tag_name") != tag:
        raise VerificationError(
            f"release ID {actual_id} names tag {value.get('tag_name')!r}, expected {tag!r}"
        )
    if value.get("immutable") is not True:
        raise VerificationError(f"release {actual_id} for {tag} is not immutable")
    if value.get("draft") is not False:
        raise VerificationError(f"release {actual_id} for {tag} is still draft")
    if value.get("prerelease") is not False:
        raise VerificationError(f"release {actual_id} for {tag} is a prerelease")
    published_at = _published_at(value.get("published_at"))
    assets = value.get("assets")
    if not isinstance(assets, list):
        raise VerificationError(f"release {actual_id} for {tag} has no asset manifest")
    normalized: list[tuple[int, str, int, str, str]] = []
    for asset in assets:
        if not isinstance(asset, dict):
            raise VerificationError(f"release {actual_id} contains a malformed asset record")
        asset_id = asset.get("id")
        name = asset.get("name")
        size = asset.get("size")
        state = asset.get("state")
        url = asset.get("url")
        if (
            type(asset_id) is not int
            or asset_id <= 0
            or not isinstance(name, str)
            or type(size) is not int
            or size <= 0
            or size > MAX_ASSET_BYTES
            or state != "uploaded"
            or url != _canonical_asset_url(asset_id)
        ):
            raise VerificationError(f"release {actual_id} contains an unsafe asset record: {asset!r}")
        normalized.append((asset_id, name, size, state, url))
    if len({asset[0] for asset in normalized}) != len(normalized):
        raise VerificationError(f"release {actual_id} contains duplicate asset IDs")
    if len({asset[1] for asset in normalized}) != len(normalized):
        raise VerificationError(f"release {actual_id} contains duplicate asset names")
    actual_names = {asset[1] for asset in normalized}
    expected_names = expected_asset_names()
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise VerificationError(
            f"release {actual_id} exact signed asset manifest is incomplete: "
            f"missing={missing}, extra={extra}"
        )
    return (
        actual_id,
        tag,
        True,
        False,
        False,
        published_at,
        tuple(sorted(normalized)),
    )


def _verify_checksum(payload: Path, manifest: Path) -> None:
    raw = manifest.read_text(encoding="utf-8")
    expected_line = re.fullmatch(r"([0-9a-f]{64}) [ *]([^/\r\n]+)\n", raw)
    if expected_line is None or expected_line.group(2) != payload.name:
        raise VerificationError(
            f"checksum manifest {manifest.name} is not the exact SHA-256 entry for {payload.name}"
        )
    with payload.open("rb") as source:
        actual = hashlib.file_digest(source, "sha256").hexdigest()
    if actual != expected_line.group(1):
        raise VerificationError(
            f"checksum manifest {manifest.name} does not authenticate {payload.name}: "
            f"expected {expected_line.group(1)}, actual {actual}"
        )


def _verify_signature(payload: Path, signature: Path, rsign: str) -> None:
    try:
        result = subprocess.run(
            [rsign, "verify", "-q", "-P", PUBLIC_KEY, "-x", str(signature), str(payload)],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise VerificationError(
            f"cannot run minisign verifier {rsign!r} for {payload.name}: {error}"
        ) from error
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise VerificationError(
            f"minisign signature {signature.name} does not authenticate {payload.name}: {detail}"
        )


def _assert_tag_object(
    client: GitHubClient,
    *,
    escaped_tag: str,
    tag: str,
    expected_tag_object: str,
    expected_commit: str,
    release_id: int,
) -> None:
    ref_path = f"/repos/{PUBLIC_REPOSITORY}/git/ref/tags/{escaped_tag}"
    ref = client.json(ref_path)
    ref_object = ref.get("object")
    expected_ref = f"refs/tags/{tag}"
    expected_ref_object = {
        "type": "tag",
        "sha": expected_tag_object,
        "url": (
            f"{PUBLIC_API_BASE}/repos/{PUBLIC_REPOSITORY}/git/tags/"
            f"{expected_tag_object}"
        ),
    }
    if ref.get("ref") != expected_ref or ref_object != expected_ref_object:
        raise VerificationError(
            f"published release {release_id} tag {tag} does not reference exact annotated "
            f"tag object {expected_tag_object}"
        )
    tag_path = f"/repos/{PUBLIC_REPOSITORY}/git/tags/{expected_tag_object}"
    tag_object = client.json(tag_path)
    peeled = tag_object.get("object")
    expected_peeled = {
        "type": "commit",
        "sha": expected_commit,
        "url": (
            f"{PUBLIC_API_BASE}/repos/{PUBLIC_REPOSITORY}/git/commits/"
            f"{expected_commit}"
        ),
    }
    if (
        tag_object.get("sha") != expected_tag_object
        or tag_object.get("tag") != tag
        or peeled != expected_peeled
    ):
        raise VerificationError(
            f"annotated tag object {expected_tag_object} for {tag} does not peel directly "
            f"to expected commit {expected_commit}"
        )


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _validate_destination_chain(destination: Path, *, create: bool) -> Path:
    absolute = _absolute_path(destination)
    if absolute == Path(absolute.anchor):
        raise VerificationError("refusing filesystem root as release destination")
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if not create:
                raise VerificationError(f"release destination component disappeared: {current}")
            try:
                os.mkdir(current, 0o700)
            except OSError as error:
                raise VerificationError(
                    f"cannot create release destination component {current}: {error}"
                ) from error
            metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise VerificationError(f"release destination contains symlink component: {current}")
        if not stat.S_ISDIR(metadata.st_mode):
            raise VerificationError(f"release destination component is not a directory: {current}")
    return absolute


def _prepare_destination(destination: Path) -> Path:
    absolute = _validate_destination_chain(destination, create=True)
    try:
        with os.scandir(absolute) as entries:
            if next(entries, None) is not None:
                raise VerificationError(f"release destination is not empty: {absolute}")
    except OSError as error:
        raise VerificationError(f"cannot inspect release destination {absolute}: {error}") from error
    return absolute


def verify_release(
    *,
    tag: str,
    expected_commit: str,
    expected_tag_object: str,
    expected_release_id: int | None,
    destination: Path,
    client: GitHubClient,
    rsign: str,
) -> int:
    """Download and prove one exact public release by immutable ID."""

    if not LOWERCASE_SHA.fullmatch(expected_commit):
        raise VerificationError(f"expected commit is not a lowercase 40-hex SHA: {expected_commit!r}")
    if not LOWERCASE_SHA.fullmatch(expected_tag_object):
        raise VerificationError(
            f"expected tag object is not a lowercase 40-hex SHA: {expected_tag_object!r}"
        )
    escaped_tag = urllib.parse.quote(tag, safe="")
    by_tag_path = f"/repos/{PUBLIC_REPOSITORY}/releases/tags/{escaped_tag}"
    by_tag = client.json(by_tag_path)
    first = release_snapshot(by_tag, tag=tag)
    release_id = first[0]
    if expected_release_id is not None and (
        type(expected_release_id) is not int or expected_release_id <= 0
    ):
        raise VerificationError(
            f"expected release ID is not a positive integer: {expected_release_id!r}"
        )
    if expected_release_id is not None and release_id != expected_release_id:
        raise VerificationError(
            f"release event ID {expected_release_id} does not match {tag} release ID {release_id}"
        )
    by_id_path = f"/repos/{PUBLIC_REPOSITORY}/releases/{release_id}"
    before = release_snapshot(client.json(by_id_path), tag=tag, release_id=release_id)
    if first != before:
        raise VerificationError(f"release {release_id} changed between tag and immutable-ID lookup")
    _assert_tag_object(
        client,
        escaped_tag=escaped_tag,
        tag=tag,
        expected_tag_object=expected_tag_object,
        expected_commit=expected_commit,
        release_id=release_id,
    )

    destination = _prepare_destination(destination)
    for _asset_id, name, size, _state, url in before[6]:
        _validate_destination_chain(destination, create=False)
        client.download(url, destination / name, expected_size=size)

    payloads = sorted(
        name
        for name in expected_asset_names()
        if not name.endswith((".sha256", ".minisig"))
    )
    for name in payloads:
        _verify_checksum(destination / name, destination / f"{name}.sha256")
        _verify_signature(destination / name, destination / f"{name}.minisig", rsign)

    final = release_snapshot(client.json(by_id_path), tag=tag, release_id=release_id)
    if final != before:
        raise VerificationError(
            f"release {release_id} changed while its signed manifest was verified"
        )
    _assert_tag_object(
        client,
        escaped_tag=escaped_tag,
        tag=tag,
        expected_tag_object=expected_tag_object,
        expected_commit=expected_commit,
        release_id=release_id,
    )
    _validate_destination_chain(destination, create=False)
    return release_id


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tag-object", required=True)
    parser.add_argument("--expected-release-id", type=int)
    parser.add_argument("--download-dir", required=True, type=Path)
    options = parser.parse_args(arguments)
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise VerificationError("GH_TOKEN is required to prove the published release")
    rsign = os.environ.get("RSIGN_BIN", "rsign")
    release_id = verify_release(
        tag=options.tag,
        expected_commit=options.expected_commit,
        expected_tag_object=options.expected_tag_object,
        expected_release_id=options.expected_release_id,
        destination=options.download_dir,
        client=GitHubClient.public(token),
        rsign=rsign,
    )
    print(f"verified immutable published release {release_id} for {options.tag}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
