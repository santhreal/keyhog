#!/usr/bin/env python3
"""Publish an exact signed release asset set through immutable GitHub release IDs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class PublicationError(RuntimeError):
    """A release could not be proven complete without exposing a partial result."""


@dataclass(frozen=True)
class Response:
    """Decoded GitHub response plus pagination metadata."""

    value: Any
    link: str | None


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


def _validate_assets(paths: Iterable[Path]) -> list[Path]:
    assets = sorted(paths, key=lambda path: path.name)
    if not assets:
        raise PublicationError("at least one signed release asset is required")
    names = [path.name for path in assets]
    if len(names) != len(set(names)):
        raise PublicationError("release asset basenames must be unique")
    for path in assets:
        if path.name in {"", ".", ".."} or not path.is_file():
            raise PublicationError(f"release asset is not a readable file: {path}")
    return assets


def publish_release(
    client: GitHubClient,
    repository: str,
    tag: str,
    asset_paths: Iterable[Path],
) -> int:
    """Replace one release's assets while it is private, then publish exact bytes."""

    if repository.count("/") != 1 or any(not part for part in repository.split("/")):
        raise PublicationError("repository must use the owner/name form")
    if not tag:
        raise PublicationError("release tag must not be empty")
    assets = _validate_assets(asset_paths)
    repository_path = quote(repository, safe="/")
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
                "body": f"Prebuilt keyhog binaries for {tag}. See CHANGELOG.md.",
                "draft": True,
                "prerelease": "-" in tag,
            },
        ).value
        if not isinstance(created, dict):
            raise PublicationError("GitHub release creation returned a non-object")
        release_id = _release_id(created)

    release_path = f"{releases_path}/{release_id}"
    client.api("PATCH", release_path, payload={"draft": True})

    assets_path = f"{release_path}/assets"
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
        client.upload(f"{assets_path}?name={encoded_name}", asset.read_bytes())

    actual = sorted(
        _asset_name(asset)
        for page in client.pages(f"{assets_path}?per_page=100")
        for asset in page
    )
    wanted = [asset.name for asset in assets]
    if actual != wanted:
        raise PublicationError(
            "published release manifest does not equal the signed expected manifest; "
            f"expected={wanted!r}, actual={actual!r}"
        )

    client.api("PATCH", release_path, payload={"draft": False})
    return release_id


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Atomically publish an exact set of signed KeyHog release assets."
    )
    parser.add_argument("assets", nargs="+", type=Path)
    parser.add_argument("--tag", default=os.environ.get("KEYHOG_RELEASE_TAG"))
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument(
        "--api-base",
        default=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    parser.add_argument(
        "--upload-base",
        default=os.environ.get("GITHUB_UPLOAD_URL", "https://uploads.github.com"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.tag:
        raise PublicationError("--tag or KEYHOG_RELEASE_TAG is required")
    if not args.repository:
        raise PublicationError("--repository or GITHUB_REPOSITORY is required")
    client = GitHubClient(
        token=os.environ.get("GH_TOKEN", ""),
        api_base=args.api_base,
        upload_base=args.upload_base,
    )
    release_id = publish_release(client, args.repository, args.tag, args.assets)
    print(f"published release {release_id} with {len(args.assets)} exact assets")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PublicationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error
