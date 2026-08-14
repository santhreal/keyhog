#!/usr/bin/env python3
"""Fail before workspace publication when registry fallbacks are unavailable."""

from __future__ import annotations

import argparse
import json
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


class PreflightError(ValueError):
    """The workspace cannot be packaged from crates.io dependencies."""


def registry_fallbacks(manifest: Path) -> list[tuple[str, str]]:
    """Return versioned Git dependencies Cargo will rewrite for publication."""
    document = tomllib.loads(manifest.read_text(encoding="utf-8"))
    dependencies = document.get("workspace", {}).get("dependencies", {})
    fallbacks: set[tuple[str, str]] = set()
    for alias, value in dependencies.items():
        if not isinstance(value, dict) or "git" not in value or "version" not in value:
            continue
        package = value.get("package", alias)
        version = value["version"]
        if not isinstance(package, str) or not isinstance(version, str):
            raise PreflightError(f"workspace dependency {alias} has an invalid package or version")
        if not version.startswith("=") or len(version) == 1:
            raise PreflightError(
                f"publishable Git dependency {package} must use an exact registry version"
            )
        fallbacks.add((package, version[1:]))
    return sorted(fallbacks)


def crate_version_visible(package: str, version: str, timeout: float = 30) -> bool:
    """Return whether crates.io exposes one exact package version."""
    url = "https://crates.io/api/v1/crates/{}/{}".format(
        urllib.parse.quote(package, safe=""), urllib.parse.quote(version, safe="")
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "keyhog-auto-release-preflight"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise PreflightError(
                    f"crates.io returned HTTP {response.status} for {package} {version}"
                )
            document = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise PreflightError(
            f"crates.io returned HTTP {error.code} for {package} {version}"
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise PreflightError(f"cannot verify {package} {version} on crates.io: {error}") from error
    published = document.get("version", {})
    return published.get("num") == version and published.get("yanked") is False


def verify(manifest: Path) -> list[tuple[str, str]]:
    """Verify every registry fallback before any workspace crate is uploaded."""
    dependencies = registry_fallbacks(manifest)
    missing = [
        f"{package} {version}"
        for package, version in dependencies
        if not crate_version_visible(package, version)
    ]
    if missing:
        raise PreflightError(
            "required registry dependencies are not published: " + ", ".join(missing)
        )
    return dependencies


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("Cargo.toml"))
    args = parser.parse_args()
    try:
        dependencies = verify(args.manifest)
    except (OSError, tomllib.TOMLDecodeError, PreflightError) as error:
        parser.error(str(error))
    print(f"Verified {len(dependencies)} registry fallback dependencies.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
