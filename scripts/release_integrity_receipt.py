#!/usr/bin/env python3
"""Generate a deterministic receipt for one synchronized workspace release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import tomllib
from pathlib import Path


CRATES = (
    "keyhog-core",
    "keyhog-profile",
    "keyhog-verifier",
    "keyhog-sources",
    "keyhog-scanner",
    "keyhog",
)
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


class ReceiptError(ValueError):
    """The repository state cannot produce an unambiguous release receipt."""


def workspace_version(root: Path) -> str:
    """Read and validate the canonical stable workspace version."""
    try:
        value = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))[
            "workspace"
        ]["package"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise ReceiptError(f"cannot read workspace version: {error}") from error
    if not isinstance(value, str) or VERSION_RE.fullmatch(value) is None:
        raise ReceiptError(f"workspace version is not canonical stable SemVer: {value!r}")
    return value


def locked_workspace_versions(root: Path) -> dict[str, str]:
    """Read the exact six publishable workspace versions from Cargo.lock."""
    try:
        document = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReceiptError(f"cannot read Cargo.lock: {error}") from error
    found: dict[str, str] = {}
    for package in document.get("package", []):
        name = package.get("name")
        if name in CRATES:
            if name in found:
                raise ReceiptError(f"Cargo.lock contains duplicate workspace package {name}")
            version = package.get("version")
            if not isinstance(version, str):
                raise ReceiptError(f"Cargo.lock package {name} has no string version")
            found[name] = version
    missing = [name for name in CRATES if name not in found]
    if missing:
        raise ReceiptError(f"Cargo.lock is missing workspace packages: {', '.join(missing)}")
    return found


def build_receipt(root: Path, commit: str, version: str | None = None) -> dict[str, object]:
    """Build one source-derived receipt without timestamps or host-dependent fields."""
    if COMMIT_RE.fullmatch(commit) is None:
        raise ReceiptError("commit must be a lowercase 40-character Git object id")
    canonical = workspace_version(root)
    if version is not None and version != canonical:
        raise ReceiptError(
            f"requested version {version!r} does not match workspace version {canonical!r}"
        )
    locked = locked_workspace_versions(root)
    mismatched = [name for name in CRATES if locked[name] != canonical]
    if mismatched:
        detail = ", ".join(f"{name}={locked[name]}" for name in mismatched)
        raise ReceiptError(f"workspace lock versions do not match {canonical}: {detail}")
    lock_bytes = (root / "Cargo.lock").read_bytes()
    return {
        "cargo_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "commit": commit,
        "crates": [
            {"name": name, "publish_order": index, "version": canonical}
            for index, name in enumerate(CRATES, start=1)
        ],
        "repository": "santhreal/keyhog",
        "schema": "keyhog-release-integrity-v1",
        "tag": f"v{canonical}",
        "trusted_publisher": {
            "owner": "santhreal",
            "repository": "keyhog",
            "workflow": "release.yml",
        },
        "version": canonical,
    }


def render_receipt(receipt: dict[str, object]) -> str:
    """Render byte-stable UTF-8 JSON for artifact checksums and offline comparison."""
    return json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_atomic(path: Path, content: str) -> None:
    """Replace the output atomically so interrupted runs never leave partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a reproducible receipt for the synchronized KeyHog crates.io release."
    )
    parser.add_argument("--commit", required=True, help="lowercase 40-character release commit id")
    parser.add_argument("--version", help="expected canonical workspace version")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = build_receipt(args.root.resolve(), args.commit, args.version)
        write_atomic(args.output, render_receipt(receipt))
    except (OSError, ReceiptError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
