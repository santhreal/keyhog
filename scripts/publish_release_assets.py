#!/usr/bin/env python3
"""Publish an exact signed release asset set through immutable GitHub release IDs."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


class PublicationError(RuntimeError):
    """A release could not be proven complete without exposing a partial result."""


@dataclass(frozen=True)
class Response:
    """Decoded GitHub response plus pagination metadata."""

    value: Any
    link: str | None

RECEIPT_SCHEMA = "keyhog-release-publication-v1"


@dataclass(frozen=True)
class AssetProof:
    """An exact release asset identity carried between workflow jobs."""

    name: str
    size: int
    sha256: str

    @classmethod
    def from_value(cls, value: Any) -> AssetProof:
        if not isinstance(value, dict) or set(value) != {"name", "size", "sha256"}:
            raise PublicationError("publication receipt contains an invalid asset proof")
        name = value["name"]
        size = value["size"]
        sha256 = value["sha256"]
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            raise PublicationError("publication receipt contains an invalid asset proof")
        return cls(name=name, size=size, sha256=sha256)

    def value(self) -> dict[str, Any]:
        return {"name": self.name, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class PublicationReceipt:
    """Signed proof binding one immutable draft, source commit, and asset set."""

    repository: str
    release_id: int
    tag: str
    commit: str
    prerelease: bool
    notes_sha256: str
    assets: tuple[AssetProof, ...]

    @classmethod
    def from_value(cls, value: Any) -> PublicationReceipt:
        expected_keys = {
            "schema",
            "repository",
            "release_id",
            "tag",
            "commit",
            "prerelease",
            "notes_sha256",
            "assets",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise PublicationError("publication receipt has an invalid schema")
        repository = value["repository"]
        release_id = value["release_id"]
        tag = value["tag"]
        commit = value["commit"]
        prerelease = value["prerelease"]
        notes_sha256 = value["notes_sha256"]
        raw_assets = value["assets"]
        if (
            value["schema"] != RECEIPT_SCHEMA
            or not isinstance(repository, str)
            or repository.count("/") != 1
            or any(not part for part in repository.split("/"))
            or not isinstance(release_id, int)
            or isinstance(release_id, bool)
            or release_id <= 0
            or not isinstance(tag, str)
            or not tag
            or not isinstance(commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            or not isinstance(prerelease, bool)
            or prerelease != ("-" in tag)
            or not isinstance(notes_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", notes_sha256) is None
            or not isinstance(raw_assets, list)
            or not raw_assets
        ):
            raise PublicationError("publication receipt has invalid release proof fields")
        assets = tuple(AssetProof.from_value(asset) for asset in raw_assets)
        if assets != tuple(sorted(assets, key=lambda asset: asset.name)) or len(
            {asset.name for asset in assets}
        ) != len(assets):
            raise PublicationError(
                "publication receipt asset proofs must have unique sorted names"
            )
        return cls(
            repository=repository,
            release_id=release_id,
            tag=tag,
            commit=commit,
            prerelease=prerelease,
            notes_sha256=notes_sha256,
            assets=assets,
        )

    @classmethod
    def read(cls, path: Path) -> PublicationReceipt:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PublicationError(
                f"cannot read publication receipt {path}: {error}"
            ) from error
        return cls.from_value(value)

    def value(self) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA,
            "repository": self.repository,
            "release_id": self.release_id,
            "tag": self.tag,
            "commit": self.commit,
            "prerelease": self.prerelease,
            "notes_sha256": self.notes_sha256,
            "assets": [asset.value() for asset in self.assets],
        }

    def write(self, path: Path) -> None:
        content = json.dumps(
            self.value(), ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        try:
            path.write_text(f"{content}\n", encoding="utf-8")
        except OSError as error:
            raise PublicationError(
                f"cannot write publication receipt {path}: {error}"
            ) from error


class _NoRedirect(HTTPRedirectHandler):
    """Expose signed asset redirects so credentials are not forwarded off-origin."""

    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


class GitHubClient:
    """Small authenticated REST client for release and asset publication."""

    def __init__(self, token: str, api_base: str, upload_base: str) -> None:
        if not token:
            raise PublicationError("GH_TOKEN is required to publish release assets")
        self._token = token
        self._api_base = api_base.rstrip("/")
        self._upload_base = upload_base.rstrip("/")

    def api(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> Response:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        return self._request(
            method, f"{self._api_base}{path}", body, "application/json"
        )

    def upload(self, path: str, content: bytes) -> Response:
        return self._request(
            "POST",
            f"{self._upload_base}{path}",
            content,
            "application/octet-stream",
        )

    def download_asset(self, path: str) -> bytes:
        """Download one draft asset without forwarding the API token on redirect."""

        url = f"{self._api_base}{path}"
        request = Request(
            url,
            method="GET",
            headers={
                "Accept": "application/octet-stream",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with build_opener(_NoRedirect).open(request, timeout=60) as response:
                return response.read()
        except HTTPError as error:
            if error.code not in {301, 302, 303, 307, 308}:
                detail = error.read().decode("utf-8", errors="replace")[:1000]
                raise PublicationError(
                    f"GitHub API GET {url} failed with HTTP {error.code}: {detail}"
                ) from error
            location = error.headers.get("Location")
            parsed = urlsplit(location) if location else None
            if (
                parsed is None
                or parsed.scheme != "https"
                or not parsed.netloc
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise PublicationError(
                    "GitHub returned an unsafe release asset redirect"
                ) from error
            try:
                with urlopen(
                    Request(location, headers={"Accept": "application/octet-stream"}),
                    timeout=60,
                ) as response:
                    return response.read()
            except (HTTPError, URLError) as redirect_error:
                raise PublicationError(
                    f"GitHub release asset redirect failed: {redirect_error}"
                ) from redirect_error
        except URLError as error:
            raise PublicationError(
                f"GitHub API GET {url} failed: {error.reason}"
            ) from error

    def pages(self, path: str) -> Iterable[list[dict[str, Any]]]:
        next_path: str | None = path
        while next_path is not None:
            response = self.api("GET", next_path)
            if not isinstance(response.value, list):
                raise PublicationError(
                    f"GitHub pagination returned a non-list for {next_path}"
                )
            yield response.value
            next_path = _next_link_path(response.link, self._api_base)

    def _request(
        self,
        method: str,
        url: str,
        body: bytes | None,
        content_type: str,
    ) -> Response:
        request = Request(
            url,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": content_type,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=60) as response:
                raw = response.read()
                value = json.loads(raw) if raw else None
                return Response(value=value, link=response.headers.get("Link"))
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:1000]
            raise PublicationError(
                f"GitHub API {method} {url} failed with HTTP {error.code}: {detail}"
            ) from error
        except URLError as error:
            raise PublicationError(
                f"GitHub API {method} {url} failed: {error.reason}"
            ) from error


def _next_link_path(link: str | None, api_base: str) -> str | None:
    if not link:
        return None
    for part in link.split(","):
        target, *parameters = part.strip().split(";")
        if not any(parameter.strip() == 'rel="next"' for parameter in parameters):
            continue
        if not (target.startswith("<") and target.endswith(">")):
            raise PublicationError(
                f"GitHub returned a malformed pagination link: {part}"
            )
        url = target[1:-1]
        if not url.startswith(f"{api_base.rstrip('/')}/"):
            raise PublicationError(
                "GitHub pagination escaped the configured API origin"
            )
        return url[len(api_base.rstrip("/")) :]
    return None


def _release_id(release: dict[str, Any]) -> int:
    value = release.get("id")
    if not isinstance(value, int) or value <= 0:
        raise PublicationError(
            "GitHub returned a release without a positive integer ID"
        )
    return value


def _asset_id(asset: dict[str, Any]) -> int:
    value = asset.get("id")
    if not isinstance(value, int) or value <= 0:
        raise PublicationError("GitHub returned an asset without a positive integer ID")
    return value


def _asset_name(asset: dict[str, Any]) -> str:
    value = asset.get("name")
    if not isinstance(value, str) or not value:
        raise PublicationError("GitHub returned an asset without a name")
    return value


def _asset_size(asset: dict[str, Any]) -> int:
    value = asset.get("size")
    if not isinstance(value, int) or value < 0:
        raise PublicationError("GitHub returned an asset without a non-negative size")
    return value


def create_deterministic_archive(source: Path, output: Path) -> None:
    """Write a byte-reproducible tar.gz with normalized tar and gzip metadata."""

    if not source.is_dir() or not source.name:
        raise PublicationError(f"archive source is not a directory: {source}")
    entries = [source, *sorted(source.rglob("*"), key=lambda path: path.relative_to(source).as_posix())]
    try:
        with output.open("wb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
                ) as archive:
                    for path in entries:
                        if path.is_symlink() or not (path.is_dir() or path.is_file()):
                            raise PublicationError(
                                f"archive source contains an unsupported entry: {path}"
                            )
                        relative = path.relative_to(source)
                        archive_name = source.name
                        if relative.parts:
                            archive_name = f"{archive_name}/{relative.as_posix()}"
                        info = archive.gettarinfo(str(path), arcname=archive_name)
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        info.mtime = 0
                        info.mode = 0o755 if path.is_dir() else 0o644
                        info.pax_headers = {}
                        if path.is_file():
                            with path.open("rb") as content:
                                archive.addfile(info, content)
                        else:
                            archive.addfile(info)
    except OSError as error:
        raise PublicationError(
            f"cannot create deterministic archive {output}: {error}"
        ) from error


def _validate_release(
    value: Any,
    *,
    release_id: int,
    tag: str,
    release_notes: str,
    draft: bool,
) -> None:
    """Require the immutable release identity and requested visibility."""

    if not isinstance(value, dict):
        raise PublicationError("GitHub release mutation returned a non-object")
    actual_id = _release_id(value)
    actual_tag = value.get("tag_name")
    actual_name = value.get("name")
    expected_prerelease = "-" in tag
    actual_body = value.get("body")
    actual_prerelease = value.get("prerelease")
    if (
        actual_id != release_id
        or actual_tag != tag
        or actual_name != tag
        or actual_body != release_notes
        or value.get("draft") is not draft
        or actual_prerelease is not expected_prerelease
    ):
        raise PublicationError(
            "release identity and body do not match the requested immutable release; "
            f"expected id={release_id}, tag={tag!r}, name={tag!r}, body={release_notes!r}, "
            f"draft={draft!r}, prerelease={expected_prerelease!r}; actual id={actual_id}, "
            f"tag={actual_tag!r}, name={actual_name!r}, body={actual_body!r}, "
            f"draft={value.get('draft')!r}, prerelease={actual_prerelease!r}"
        )

def _notes_digest(notes: str) -> str:
    return hashlib.sha256(notes.encode("utf-8")).hexdigest()


def _validate_receipt_release(
    value: Any, receipt: PublicationReceipt, *, draft: bool
) -> None:
    """Require exact signed metadata for the receipt's immutable release ID."""

    if not isinstance(value, dict):
        raise PublicationError("GitHub release mutation returned a non-object")
    body = value.get("body")
    published_at = value.get("published_at")
    if (
        _release_id(value) != receipt.release_id
        or value.get("tag_name") != receipt.tag
        or value.get("name") != receipt.tag
        or not isinstance(body, str)
        or _notes_digest(body) != receipt.notes_sha256
        or value.get("draft") is not draft
        or value.get("prerelease") is not receipt.prerelease
        or (not draft and (not isinstance(published_at, str) or not published_at))
    ):
        raise PublicationError(
            "release identity and body do not match the signed publication receipt; "
            f"expected id={receipt.release_id}, tag={receipt.tag!r}, "
            f"notes_sha256={receipt.notes_sha256}, draft={draft!r}, "
            f"prerelease={receipt.prerelease!r}; actual id={value.get('id')!r}, "
            f"tag={value.get('tag_name')!r}, name={value.get('name')!r}, "
            f"draft={value.get('draft')!r}, prerelease={value.get('prerelease')!r}, "
            f"published_at={published_at!r}"
        )


def _assert_tag_commit(
    client: GitHubClient,
    repository_path: str,
    tag: str,
    expected_commit: str,
) -> None:
    """Prove the exact tag ref still resolves to the commit whose bytes were built."""

    if re.fullmatch(r"[0-9a-f]{40}", expected_commit) is None:
        raise PublicationError("expected release commit must be a 40-character Git SHA")
    encoded_tag = quote(tag, safe="")
    value = client.api(
        "GET", f"/repos/{repository_path}/git/ref/tags/{encoded_tag}"
    ).value
    if not isinstance(value, dict) or value.get("ref") != f"refs/tags/{tag}":
        raise PublicationError(
            f"GitHub did not return the exact release ref refs/tags/{tag}"
        )
    target = value.get("object")
    visited: set[str] = set()
    while isinstance(target, dict) and target.get("type") == "tag":
        object_sha = target.get("sha")
        if (
            not isinstance(object_sha, str)
            or re.fullmatch(r"[0-9a-f]{40}", object_sha) is None
            or object_sha in visited
        ):
            raise PublicationError(f"release tag {tag} has an invalid tag-object chain")
        visited.add(object_sha)
        if len(visited) > 16:
            raise PublicationError(f"release tag {tag} has an excessive tag-object chain")
        annotated = client.api(
            "GET", f"/repos/{repository_path}/git/tags/{object_sha}"
        ).value
        if not isinstance(annotated, dict):
            raise PublicationError("GitHub annotated-tag resolution returned a non-object")
        target = annotated.get("object")
    actual_commit = target.get("sha") if isinstance(target, dict) else None
    if (
        not isinstance(target, dict)
        or target.get("type") != "commit"
        or actual_commit != expected_commit
    ):
        raise PublicationError(
            f"release tag {tag} does not resolve to built commit {expected_commit}; "
            f"GitHub reports {actual_commit!r}"
        )


def _set_and_confirm_draft(
    client: GitHubClient,
    release_path: str,
    *,
    release_id: int,
    tag: str,
    release_notes: str,
) -> None:
    """Move the exact release to a private draft and verify durable API state."""

    payload = {
        "tag_name": tag,
        "name": tag,
        "body": release_notes,
        "draft": True,
        "prerelease": "-" in tag,
    }
    updated = client.api("PATCH", release_path, payload=payload).value
    _validate_release(
        updated,
        release_id=release_id,
        tag=tag,
        release_notes=release_notes,
        draft=True,
    )
    confirmed = client.api("GET", release_path).value
    _validate_release(
        confirmed,
        release_id=release_id,
        tag=tag,
        release_notes=release_notes,
        draft=True,
    )

def _set_and_confirm_receipt_draft(
    client: GitHubClient, release_path: str, receipt: PublicationReceipt
) -> None:
    """Reprivatize only the receipt's immutable release and confirm the rollback."""

    updated = client.api("PATCH", release_path, payload={"draft": True}).value
    _validate_receipt_release(updated, receipt, draft=True)
    confirmed = client.api("GET", release_path).value
    _validate_receipt_release(confirmed, receipt, draft=True)

def _validate_assets(paths: Iterable[Path]) -> list[Path]:
    assets = sorted(paths, key=lambda path: path.name)
    if not assets:
        raise PublicationError("at least one signed release asset is required")
    names = [path.name for path in assets]
    if len(names) != len(set(names)):
        raise PublicationError("release asset basenames must be unique")
    by_name = dict(zip(names, assets, strict=True))
    for path in assets:
        if path.name in {"", ".", ".."} or not path.is_file():
            raise PublicationError(f"release asset is not a readable file: {path}")
    for checksum in (path for path in assets if path.name.endswith(".sha256")):
        target_name = checksum.name.removesuffix(".sha256")
        target = by_name.get(target_name)
        if target is None:
            raise PublicationError(
                f"checksum manifest {checksum.name} names missing asset {target_name}"
            )
        try:
            with target.open("rb") as content:
                digest = hashlib.file_digest(content, "sha256").hexdigest()
            actual = checksum.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise PublicationError(
                f"cannot verify checksum manifest {checksum}: {error}"
            ) from error
        accepted = {
            f"{digest}  {target_name}\n",
            f"{digest} *{target_name}\n",
        }
        if actual not in accepted:
            raise PublicationError(
                f"checksum manifest {checksum.name} does not match {target_name}"
            )
    return assets

def _proof_for_path(path: Path) -> AssetProof:
    try:
        with path.open("rb") as content:
            digest = hashlib.file_digest(content, "sha256").hexdigest()
        size = path.stat().st_size
    except OSError as error:
        raise PublicationError(f"cannot hash release asset {path}: {error}") from error
    return AssetProof(name=path.name, size=size, sha256=digest)


def _remote_asset_proofs(
    client: GitHubClient, releases_path: str, assets_path: str
) -> tuple[AssetProof, ...]:
    assets = [
        asset for page in client.pages(f"{assets_path}?per_page=100") for asset in page
    ]
    proofs: list[AssetProof] = []
    for asset in assets:
        asset_id = _asset_id(asset)
        name = _asset_name(asset)
        size = _asset_size(asset)
        content = client.download_asset(f"{releases_path}/assets/{asset_id}")
        if len(content) != size:
            raise PublicationError(
                f"downloaded release asset size does not match {name}; "
                f"expected={size}, actual={len(content)}"
            )
        proofs.append(
            AssetProof(
                name=name,
                size=size,
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    return tuple(sorted(proofs, key=lambda proof: proof.name))


def _assert_remote_assets(
    client: GitHubClient,
    releases_path: str,
    assets_path: str,
    expected: tuple[AssetProof, ...],
) -> None:
    actual = _remote_asset_proofs(client, releases_path, assets_path)
    if actual != expected:
        raise PublicationError(
            "published release manifest does not equal the signed expected manifest; "
            f"expected={expected!r}, actual={actual!r}"
        )


def prepare_release(
    client: GitHubClient,
    repository: str,
    tag: str,
    asset_paths: Iterable[Path],
    release_notes: str,
    expected_commit: str,
) -> PublicationReceipt:
    """Privately stage exact assets and return the proof a later job may publish."""

    if repository.count("/") != 1 or any(not part for part in repository.split("/")):
        raise PublicationError("repository must use the owner/name form")
    if not tag:
        raise PublicationError("release tag must not be empty")
    notes = release_notes.strip()
    if not notes:
        raise PublicationError("release notes must not be empty")
    if "see changelog" in notes.casefold():
        raise PublicationError(
            "release notes must contain the version's changes, not a changelog pointer"
        )
    assets = _validate_assets(asset_paths)
    expected_assets = tuple(_proof_for_path(asset) for asset in assets)
    repository_path = quote(repository, safe="/")
    _assert_tag_commit(client, repository_path, tag, expected_commit)
    releases_path = f"/repos/{repository_path}/releases"
    matching = [
        release
        for page in client.pages(f"{releases_path}?per_page=100")
        for release in page
        if release.get("tag_name") == tag
    ]
    if len(matching) > 1:
        raise PublicationError(f"multiple GitHub releases claim tag {tag}")
    if matching:
        release_id = _release_id(matching[0])
    else:
        created = client.api(
            "POST",
            releases_path,
            payload={
                "tag_name": tag,
                "name": tag,
                "body": notes,
                "draft": True,
                "prerelease": "-" in tag,
            },
        ).value
        if not isinstance(created, dict):
            raise PublicationError("GitHub release creation returned a non-object")
        release_id = _release_id(created)

    receipt = PublicationReceipt(
        repository=repository,
        release_id=release_id,
        tag=tag,
        commit=expected_commit,
        prerelease="-" in tag,
        notes_sha256=_notes_digest(notes),
        assets=expected_assets,
    )
    release_path = f"{releases_path}/{release_id}"
    assets_path = f"{release_path}/assets"
    current = client.api("GET", release_path).value
    if isinstance(current, dict) and current.get("draft") is False:
        _validate_receipt_release(current, receipt, draft=False)
        _assert_remote_assets(client, releases_path, assets_path, receipt.assets)
        _assert_tag_commit(client, repository_path, tag, expected_commit)
        return receipt

    _set_and_confirm_draft(
        client,
        release_path,
        release_id=release_id,
        tag=tag,
        release_notes=notes,
    )
    existing = [
        asset for page in client.pages(f"{assets_path}?per_page=100") for asset in page
    ]
    for asset in existing:
        client.api(
            "DELETE",
            f"{releases_path}/assets/{_asset_id(asset)}",
        )

    for asset in assets:
        encoded_name = quote(asset.name, safe="")
        try:
            content = asset.read_bytes()
        except OSError as error:
            raise PublicationError(f"cannot read release asset {asset}: {error}") from error
        uploaded = client.upload(
            f"{assets_path}?name={encoded_name}", content
        ).value
        if not isinstance(uploaded, dict):
            raise PublicationError(
                f"GitHub upload returned a non-object for {asset.name}"
            )
        uploaded_identity = (_asset_name(uploaded), _asset_size(uploaded))
        expected_identity = (asset.name, len(content))
        if uploaded_identity != expected_identity:
            raise PublicationError(
                f"GitHub upload identity does not match {asset.name}; "
                f"expected={expected_identity!r}, actual={uploaded_identity!r}"
            )

    _assert_remote_assets(client, releases_path, assets_path, receipt.assets)
    _assert_tag_commit(client, repository_path, tag, expected_commit)
    confirmed = client.api("GET", release_path).value
    _validate_receipt_release(confirmed, receipt, draft=True)
    return receipt


def publish_prepared_release(
    client: GitHubClient, receipt: PublicationReceipt
) -> int:
    """Publish one signed immutable-ID receipt, or prove the rerun already did."""

    repository_path = quote(receipt.repository, safe="/")
    releases_path = f"/repos/{repository_path}/releases"
    release_path = f"{releases_path}/{receipt.release_id}"
    assets_path = f"{release_path}/assets"
    _assert_tag_commit(client, repository_path, receipt.tag, receipt.commit)
    current = client.api("GET", release_path).value
    if isinstance(current, dict) and current.get("draft") is False:
        _validate_receipt_release(current, receipt, draft=False)
        _assert_remote_assets(client, releases_path, assets_path, receipt.assets)
        _assert_tag_commit(client, repository_path, receipt.tag, receipt.commit)
        return receipt.release_id

    _validate_receipt_release(current, receipt, draft=True)
    _assert_remote_assets(client, releases_path, assets_path, receipt.assets)
    _assert_tag_commit(client, repository_path, receipt.tag, receipt.commit)
    try:
        published = client.api(
            "PATCH", release_path, payload={"draft": False}
        ).value
        _validate_receipt_release(published, receipt, draft=False)
        confirmed = client.api("GET", release_path).value
        _validate_receipt_release(confirmed, receipt, draft=False)
        _assert_tag_commit(client, repository_path, receipt.tag, receipt.commit)
    except PublicationError as error:
        try:
            _set_and_confirm_receipt_draft(client, release_path, receipt)
        except PublicationError as rollback_error:
            raise PublicationError(
                f"{error}; additionally failed to return release "
                f"{receipt.release_id} to draft: {rollback_error}"
            ) from rollback_error
        raise
    return receipt.release_id


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Privately stage and atomically publish signed KeyHog releases."
    )
    parser.add_argument(
        "--api-base",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    parser.add_argument(
        "--upload-base",
        default=os.environ.get("GITHUB_UPLOAD_URL", "https://uploads.github.com"),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("assets", nargs="+", type=Path)
    prepare.add_argument("--tag", default=os.environ.get("KEYHOG_RELEASE_TAG"))
    prepare.add_argument(
        "--repository", default=os.environ.get("GITHUB_REPOSITORY")
    )
    prepare.add_argument("--notes-file", required=True, type=Path)
    prepare.add_argument(
        "--commit", default=os.environ.get("KEYHOG_RELEASE_COMMIT")
    )
    prepare.add_argument("--receipt", required=True, type=Path)

    publish = commands.add_parser("publish")
    publish.add_argument("--receipt", required=True, type=Path)
    publish.add_argument(
        "--repository", default=os.environ.get("GITHUB_REPOSITORY")
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    client = GitHubClient(
        token=os.environ.get("GH_TOKEN", ""),
        api_base=args.api_base,
        upload_base=args.upload_base,
    )
    if args.command == "prepare":
        if not args.tag:
            raise PublicationError("--tag or KEYHOG_RELEASE_TAG is required")
        if not args.repository:
            raise PublicationError("--repository or GITHUB_REPOSITORY is required")
        if not args.commit:
            raise PublicationError("--commit or KEYHOG_RELEASE_COMMIT is required")
        try:
            release_notes = args.notes_file.read_text(encoding="utf-8")
        except OSError as error:
            raise PublicationError(
                f"cannot read release notes from {args.notes_file}: {error}"
            ) from error
        receipt = prepare_release(
            client,
            args.repository,
            args.tag,
            args.assets,
            release_notes,
            args.commit,
        )
        receipt.write(args.receipt)
        print(
            f"prepared draft release {receipt.release_id} with "
            f"{len(receipt.assets)} exact assets"
        )
        return 0

    receipt = PublicationReceipt.read(args.receipt)
    if not args.repository:
        raise PublicationError("--repository or GITHUB_REPOSITORY is required")
    if args.repository != receipt.repository:
        raise PublicationError(
            "signed publication receipt repository does not match GITHUB_REPOSITORY"
        )
    release_id = publish_prepared_release(client, receipt)
    print(f"published release {release_id} from exact signed receipt")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PublicationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error
