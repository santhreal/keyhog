#!/usr/bin/env python3
"""Verify the immutable public GitHub release verdict before crate publication."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

PUBLIC_KEY = "RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go"
COMMIT = re.compile(r"^[0-9a-f]{40}$")


class VerificationError(RuntimeError):
    """The release is not a complete immutable publication verdict."""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward the GitHub token to an asset storage origin."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        redirected = super().redirect_request(request, fp, code, msg, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(newurl).netloc != urllib.parse.urlsplit(
            request.full_url
        ).netloc:
            redirected.remove_header("Authorization")
        return redirected


class GitHubClient:
    """Small authenticated GitHub API client with bounded requests."""

    def __init__(self, api_base: str, token: str) -> None:
        self.api_base = api_base.rstrip("/")
        self.token = token
        self.opener = urllib.request.build_opener(_SafeRedirectHandler())

    def _request(self, path: str, *, accept: str) -> urllib.request.Request:
        url = path if path.startswith(("http://", "https://")) else self.api_base + path
        return urllib.request.Request(
            url,
            headers={
                "Accept": accept,
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "keyhog-crate-publication-verdict",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    def json(self, path: str) -> dict[str, Any]:
        request = self._request(path, accept="application/vnd.github+json")
        try:
            with self.opener.open(request, timeout=30) as response:
                value = json.load(response)
        except urllib.error.HTTPError as error:
            raise VerificationError(f"GitHub API {path} returned HTTP {error.code}") from error
        except Exception as error:
            raise VerificationError(f"cannot read GitHub API {path}: {error}") from error
        if not isinstance(value, dict):
            raise VerificationError(f"GitHub API {path} did not return an object")
        return value

    def download(self, url: str, destination: Path) -> None:
        request = self._request(url, accept="application/octet-stream")
        temporary = destination.with_suffix(destination.suffix + ".download")
        try:
            with self.opener.open(request, timeout=60) as response, temporary.open("wb") as output:
                for chunk in iter(lambda: response.read(1024 * 1024), b""):
                    output.write(chunk)
        except Exception as error:
            temporary.unlink(missing_ok=True)
            raise VerificationError(f"cannot download release asset {destination.name}: {error}") from error
        os.replace(temporary, destination)


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
        names.update((payload, f"{payload}.sha256", f"{payload}.minisig"))
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


def release_snapshot(value: dict[str, Any], *, tag: str, release_id: int | None = None) -> tuple[Any, ...]:
    """Validate and normalize the public release identity and exact asset listing."""

    actual_id = value.get("id")
    if not isinstance(actual_id, int) or actual_id <= 0:
        raise VerificationError(f"release for {tag} has no positive immutable ID")
    if release_id is not None and actual_id != release_id:
        raise VerificationError(
            f"release ID changed for {tag}: expected {release_id}, received {actual_id}"
        )
    if value.get("tag_name") != tag:
        raise VerificationError(
            f"release ID {actual_id} names tag {value.get('tag_name')!r}, expected {tag!r}"
        )
    if value.get("draft") is not False:
        raise VerificationError(f"release {actual_id} for {tag} is still draft")
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
            not isinstance(asset_id, int)
            or asset_id <= 0
            or not isinstance(name, str)
            or not isinstance(size, int)
            or size <= 0
            or state != "uploaded"
            or not isinstance(url, str)
            or not url
        ):
            raise VerificationError(f"release {actual_id} contains an incomplete asset record: {asset!r}")
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
            f"release {actual_id} exact signed asset manifest is incomplete: missing={missing}, extra={extra}"
        )
    return (actual_id, tag, published_at, tuple(sorted(normalized)))


def _verify_checksum(payload: Path, manifest: Path) -> None:
    raw = manifest.read_text(encoding="utf-8")
    expected_line = re.fullmatch(r"([0-9a-f]{64})  ([^/\r\n]+)\n", raw)
    if expected_line is None or expected_line.group(2) != payload.name:
        raise VerificationError(
            f"checksum manifest {manifest.name} is not the exact SHA-256 entry for {payload.name}"
        )
    actual = hashlib.sha256(payload.read_bytes()).hexdigest()
    if actual != expected_line.group(1):
        raise VerificationError(
            f"checksum manifest {manifest.name} does not authenticate {payload.name}: "
            f"expected {expected_line.group(1)}, actual {actual}"
        )


def _verify_signature(payload: Path, signature: Path, rsign: str) -> None:
    result = subprocess.run(
        [rsign, "verify", "-q", "-P", PUBLIC_KEY, "-x", str(signature), str(payload)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise VerificationError(
            f"minisign signature {signature.name} does not authenticate {payload.name}: {detail}"
        )


def verify_release(
    *,
    repository: str,
    tag: str,
    expected_commit: str,
    expected_release_id: int | None,
    destination: Path,
    client: GitHubClient,
    rsign: str,
) -> int:
    """Download and prove one exact public release by immutable ID."""

    if not COMMIT.fullmatch(expected_commit):
        raise VerificationError(f"expected commit is not a lowercase 40-hex SHA: {expected_commit!r}")
    escaped_repository = "/".join(urllib.parse.quote(part, safe="") for part in repository.split("/"))
    escaped_tag = urllib.parse.quote(tag, safe="")
    by_tag = client.json(f"/repos/{escaped_repository}/releases/tags/{escaped_tag}")
    first = release_snapshot(by_tag, tag=tag)
    release_id = first[0]
    if expected_release_id is not None and release_id != expected_release_id:
        raise VerificationError(
            f"release event ID {expected_release_id} does not match {tag} release ID {release_id}"
        )
    by_id_path = f"/repos/{escaped_repository}/releases/{release_id}"
    by_id = client.json(by_id_path)
    before = release_snapshot(by_id, tag=tag, release_id=release_id)
    if first != before:
        raise VerificationError(f"release {release_id} changed between tag and immutable-ID lookup")
    commit = client.json(f"/repos/{escaped_repository}/commits/{escaped_tag}").get("sha")
    if commit != expected_commit:
        raise VerificationError(
            f"published release {release_id} tag {tag} resolves to commit {commit!r}, "
            f"expected {expected_commit}"
        )

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for _asset_id, name, size, _state, url in before[3]:
        path = destination / name
        client.download(url, path)
        if path.stat().st_size != size:
            raise VerificationError(
                f"release asset {name} size changed: API declared {size}, downloaded {path.stat().st_size}"
            )

    after = release_snapshot(client.json(by_id_path), tag=tag, release_id=release_id)
    if after != before:
        raise VerificationError(f"release {release_id} changed while its signed manifest was downloaded")

    payloads = sorted(
        name
        for name in expected_asset_names()
        if not name.endswith((".sha256", ".minisig"))
    )
    for name in payloads:
        payload = destination / name
        _verify_checksum(payload, destination / f"{name}.sha256")
        _verify_signature(payload, destination / f"{name}.minisig", rsign)
    return release_id


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-release-id", type=int)
    parser.add_argument("--download-dir", required=True, type=Path)
    options = parser.parse_args(arguments)
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise VerificationError("GH_TOKEN is required to prove the published release")
    api_base = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    rsign = os.environ.get("RSIGN_BIN", "rsign")
    release_id = verify_release(
        repository=options.repository,
        tag=options.tag,
        expected_commit=options.expected_commit,
        expected_release_id=options.expected_release_id,
        destination=options.download_dir,
        client=GitHubClient(api_base, token),
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
