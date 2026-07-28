#!/usr/bin/env python3
"""Generate and verify deterministic, offline SPDX release SBOMs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from collections import Counter
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote
if __package__:
    from scripts.release_dependency_receipt import (
        DEPENDENCY_PROFILES,
        GENERATOR as RECEIPT_GENERATOR,
        HYPERSCAN_VERSION,
        NATIVE_BUILD_SCHEMA,
        NATIVE_LINK_SCHEMA,
        RECEIPT_SCHEMA,
        PKG_CONFIG_VERSION,
        ReceiptError,
        derive_receipt,
        generate_native_build_receipt,
        generate_native_link_receipt,
        prove_tagged_source,
        generate_receipt,
    )
else:
    from release_dependency_receipt import (  # type: ignore[no-redef]
        DEPENDENCY_PROFILES,
        GENERATOR as RECEIPT_GENERATOR,
        HYPERSCAN_VERSION,
        NATIVE_BUILD_SCHEMA,
        NATIVE_LINK_SCHEMA,
        RECEIPT_SCHEMA,
        PKG_CONFIG_VERSION,
        ReceiptError,
        derive_receipt,
        generate_native_build_receipt,
        generate_native_link_receipt,
        prove_tagged_source,
        generate_receipt,
    )

SCHEMA = "keyhog-release-sbom-manifest-v2"
GENERATOR_NAME = "keyhog-release-sbom"
GENERATOR_VERSION = "2.0.0"
SPDX_VERSION = "SPDX-2.3"
MANIFEST_NAME = "release-sbom-manifest.json"

# This is deliberately an exact inventory. Adding a release target requires updating
# the generator and its behavioral target test before publication can succeed.
SUPPORTED_ASSETS: dict[str, tuple[str, str]] = {
    "install.ps1": ("installer", "any"),
    "install.sh": ("installer", "any"),
    "keyhog-linux-x86_64": ("binary", "x86_64-unknown-linux-gnu"),
    "keyhog-macos-aarch64": ("binary", "aarch64-apple-darwin"),
    "keyhog-macos-x86_64": ("binary", "x86_64-apple-darwin"),
    "keyhog-windows-x86_64.exe": ("binary", "x86_64-pc-windows-msvc"),
    "keyhog-linux-x86_64.gpu-literals.tar.gz": (
        "gpu-bundle", "x86_64-unknown-linux-gnu"
    ),
    "keyhog-macos-aarch64.gpu-literals.tar.gz": (
        "gpu-bundle", "aarch64-apple-darwin"
    ),
    "keyhog-macos-x86_64.gpu-literals.tar.gz": (
        "gpu-bundle", "x86_64-apple-darwin"
    ),
    "keyhog-windows-x86_64.exe.gpu-literals.tar.gz": (
        "gpu-bundle", "x86_64-pc-windows-msvc"
    ),
}

# The installer documents are executable release software. Their exact tagged
# byte identities and runtime contracts are deliberately reviewed here: a
# command-surface change cannot silently inherit a stale SBOM inventory.
INSTALLER_SOURCE_SHA256 = {
    "install.ps1": "f13ff428fe25a5261ec8a21c0ace4b07ff63e71cdcff136508a765a3087ca443",
    "install.sh": "fde09407387604ee229d1ad99580192395c70767b213b3e913e4d80cace1214a",
}
INSTALLER_RUNTIME_TOOLS = {
    "install.sh": (
        ("sh", "POSIX-compatible interpreter", "all invocations", True),
        ("awk", "text and response parser", "all invocations", True),
        ("basename", "path basename extraction", "all invocations", True),
        ("cat", "file streaming", "all invocations", True),
        ("chmod", "installed executable permissions", "installation", True),
        ("cp", "local asset installation", "local installation", False),
        ("curl", "HTTPS release downloader", "remote installation", False),
        ("cut", "text field extraction", "diagnostics and calibration", False),
        ("date", "calibration timing", "calibration", False),
        ("dirname", "path parent extraction", "all invocations", True),
        ("docker", "Docker source calibration", "when Docker is available", False),
        ("find", "calibration fixture discovery", "calibration", False),
        ("git", "Git source calibration", "when Git is available", False),
        ("grep", "text filtering", "all invocations", True),
        ("head", "bounded output selection", "diagnostics and calibration", False),
        ("ldd", "Linux dynamic-library diagnostics", "Linux when ldd is available", False),
        ("minisign", "release signature verification", "verified installation", False),
        ("mkdir", "installation directory creation", "installation", True),
        ("mktemp", "temporary file and directory creation", "all invocations", True),
        ("mv", "atomic installed-file replacement", "installation", True),
        ("python3", "local HTTP calibration server", "URL calibration when available", False),
        ("python", "local HTTP calibration server fallback", "URL calibration without python3", False),
        ("rm", "temporary-file cleanup", "all invocations", True),
        ("sed", "text transformation", "all invocations", True),
        ("sha256sum", "SHA-256 verification", "when sha256sum is available", False),
        ("shasum", "SHA-256 verification fallback", "when sha256sum is unavailable", False),
        ("sleep", "calibration server readiness", "URL calibration", False),
        ("sort", "deterministic text ordering", "diagnostics and calibration", False),
        ("tail", "bounded output selection", "diagnostics and calibration", False),
        ("tar", "GPU literal bundle extraction", "GPU bundle installation", False),
        ("tr", "text transformation", "diagnostics and calibration", False),
        ("uname", "platform detection", "remote installation", False),
    ),
    "install.ps1": (
        ("Windows PowerShell", "version 5 or newer interpreter", "all invocations", True),
        ("Get-FileHash", "SHA-256 verification", "all installations", True),
        ("Invoke-WebRequest", "HTTPS release downloader", "remote installation", False),
        ("minisign", "release signature verification", "verified installation", False),
        ("tar.exe", "GPU literal bundle extraction", "GPU bundle installation", False),
    ),
}

_HEX40 = re.compile(r"[0-9a-f]{40}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9_.+-]+")
_TREE_LINE = re.compile(r"^(\d+)\|([A-Za-z0-9_.+-]+) v(\S+)(?: .*?)?\|(.*)$")


class SbomError(RuntimeError):
    """The release inputs cannot produce a complete, trustworthy SBOM."""


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    source: str | None
    checksum: str | None
    dependencies: tuple[str, ...]

    @property
    def identity(self) -> str:
        return "\0".join((self.name, self.version, self.source or "workspace"))

    @property
    def spdx_id(self) -> str:
        suffix = hashlib.sha256(self.identity.encode("utf-8")).hexdigest()[:20]
        return f"SPDXRef-CargoPackage-{suffix}"


@dataclass(frozen=True)
class Artifact:
    name: str
    kind: str
    target: str
    size: int
    sha256: str
    dependency_receipt_sha256: str | None
    native_build_receipt_sha256: str | None
    native_link_receipt_sha256: str | None

    @classmethod
    def from_value(cls, value: Any) -> "Artifact":
        if not isinstance(value, dict) or set(value) != {
            "dependencyReceiptSha256",
            "kind",
            "name",
            "nativeBuildReceiptSha256",
            "nativeLinkReceiptSha256",
            "sha256",
            "size",
            "target",
        }:
            raise SbomError("manifest contains an invalid artifact entry")
        name = value["name"]
        if not isinstance(name, str) or name not in SUPPORTED_ASSETS:
            raise SbomError(f"manifest contains unsupported release asset: {name!r}")
        expected_kind, expected_target = SUPPORTED_ASSETS[name]
        size = value["size"]
        digest = value["sha256"]
        receipt_digest = value["dependencyReceiptSha256"]
        build_digest = value["nativeBuildReceiptSha256"]
        link_digest = value["nativeLinkReceiptSha256"]
        receipt_valid = (
            isinstance(receipt_digest, str)
            and _HEX64.fullmatch(receipt_digest) is not None
            if expected_kind in {"binary", "gpu-bundle"}
            else receipt_digest is None
        )
        native_valid = (
            isinstance(build_digest, str)
            and _HEX64.fullmatch(build_digest) is not None
            and isinstance(link_digest, str)
            and _HEX64.fullmatch(link_digest) is not None
            if name == "keyhog-linux-x86_64"
            else build_digest is None and link_digest is None
        )
        if (
            value["kind"] != expected_kind
            or value["target"] != expected_target
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
            or not isinstance(digest, str)
            or _HEX64.fullmatch(digest) is None
            or not receipt_valid
            or not native_valid
        ):
            raise SbomError(f"manifest metadata is invalid for release asset {name}")
        return cls(
            name, expected_kind, expected_target, size, digest,
            receipt_digest, build_digest, link_digest
        )

    def value(self) -> dict[str, Any]:
        return {
            "dependencyReceiptSha256": self.dependency_receipt_sha256,
            "kind": self.kind,
            "name": self.name,
            "nativeBuildReceiptSha256": self.native_build_receipt_sha256,
            "nativeLinkReceiptSha256": self.native_link_receipt_sha256,
            "sha256": self.sha256,
            "size": self.size,
            "target": self.target,
        }


@dataclass(frozen=True)
class ReleaseManifest:
    tag: str
    commit: str
    tag_object: str
    cargo_lock_sha256: str
    artifacts: tuple[Artifact, ...]

    @classmethod
    def from_value(cls, value: Any) -> "ReleaseManifest":
        if not isinstance(value, dict) or set(value) != {
            "artifacts",
            "generator",
            "schema",
            "source",
            "tag",
        }:
            raise SbomError("release SBOM manifest has an invalid schema")
        generator = value["generator"]
        source = value["source"]
        if generator != {
            "name": GENERATOR_NAME,
            "spdxVersion": SPDX_VERSION,
            "version": GENERATOR_VERSION,
        }:
            raise SbomError("release SBOM manifest generator identity does not match")
        if not isinstance(source, dict) or set(source) != {
            "cargoLockSha256",
            "commit",
            "tagObject",
        }:
            raise SbomError("release SBOM manifest has invalid source identity")
        commit = source["commit"]
        lock_digest = source["cargoLockSha256"]
        tag_object = source["tagObject"]
        tag = value["tag"]
        if (
            value["schema"] != SCHEMA
            or not isinstance(tag, str)
            or not tag
            or any(character.isspace() for character in tag)
            or not isinstance(commit, str)
            or _HEX40.fullmatch(commit) is None
            or not isinstance(tag_object, str)
            or _HEX40.fullmatch(tag_object) is None
            or not isinstance(lock_digest, str)
            or _HEX64.fullmatch(lock_digest) is None
            or not isinstance(value["artifacts"], list)
        ):
            raise SbomError("release SBOM manifest has invalid release identity")
        artifacts = tuple(Artifact.from_value(item) for item in value["artifacts"])
        names = tuple(artifact.name for artifact in artifacts)
        expected = tuple(sorted(SUPPORTED_ASSETS))
        if names != expected:
            missing = sorted(set(expected) - set(names))
            extra = sorted(set(names) - set(expected))
            raise SbomError(
                "release SBOM manifest is incomplete or unordered "
                f"(missing={missing}, extra={extra}, names={list(names)})"
            )
        return cls(tag, commit, tag_object, lock_digest, artifacts)

    @classmethod
    def read(cls, path: Path) -> "ReleaseManifest":
        return cls.from_value(_load_json(path, "release SBOM manifest"))

    def value(self) -> dict[str, Any]:
        return {
            "artifacts": [artifact.value() for artifact in self.artifacts],
            "generator": {
                "name": GENERATOR_NAME,
                "spdxVersion": SPDX_VERSION,
                "version": GENERATOR_VERSION,
            },
            "schema": SCHEMA,
            "source": {
                "cargoLockSha256": self.cargo_lock_sha256,
                "commit": self.commit,
                "tagObject": self.tag_object,
            },
            "tag": self.tag,
        }

    def write(self, path: Path) -> None:
        _atomic_write(path, _canonical_json(self.value()))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _require_regular_file(path: Path, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise SbomError(f"{description} is not a regular non-symlink file: {path}")


def _load_json(path: Path, description: str) -> Any:
    _require_regular_file(path, description)
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SbomError(f"cannot read {description} {path}: {error}") from error


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _atomic_write(path: Path, content: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        temporary_path.replace(path)
    except OSError as error:
        raise SbomError(f"cannot write {path}: {error}") from error


def _sha256(path: Path) -> str:
    _require_regular_file(path, "hash input")
    try:
        with path.open("rb") as content:
            return hashlib.file_digest(content, "sha256").hexdigest()
    except OSError as error:
        raise SbomError(f"cannot hash {path}: {error}") from error


def _git(source_dir: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(source_dir), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = ""
        if isinstance(error, subprocess.CalledProcessError):
            detail = error.stderr.decode("utf-8", errors="replace").strip()
        raise SbomError(
            f"cannot prove tagged source with git {' '.join(arguments)}"
            + (f": {detail}" if detail else "")
        ) from error
    return completed.stdout


def _validate_tagged_source(
    source_dir: Path,
    tag: str,
    commit: str,
    tag_object: str,
    cargo_lock_sha256: str,
) -> tuple[bytes, str]:
    if _HEX40.fullmatch(commit) is None:
        raise SbomError("source commit must be a lowercase 40-character SHA-1")
    if _HEX40.fullmatch(tag_object) is None:
        raise SbomError("tag object must be a lowercase 40-character SHA-1")
    try:
        actual_commit, actual_tag_object, lock_bytes = prove_tagged_source(
            source_dir, tag
        )
    except ReceiptError as error:
        raise SbomError(str(error)) from error
    if actual_commit != commit:
        raise SbomError(
            f"source checkout is {actual_commit}, not manifest commit {commit}"
        )
    if actual_tag_object != tag_object:
        raise SbomError(
            f"tag object is {actual_tag_object}, not manifest tag object {tag_object}"
        )
    actual_lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    if actual_lock_digest != cargo_lock_sha256:
        raise SbomError(
            "Cargo.lock digest does not match manifest "
            f"(expected {cargo_lock_sha256}, got {actual_lock_digest})"
        )
    timestamp = _git(source_dir, "show", "-s", "--format=%cI", commit).decode().strip()
    try:
        instant = dt.datetime.fromisoformat(timestamp).astimezone(dt.timezone.utc)
    except ValueError as error:
        raise SbomError(f"git returned an invalid commit timestamp: {timestamp!r}") from error
    created = instant.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return lock_bytes, created


def _parse_dependency(value: str) -> tuple[str, str | None, str | None]:
    source: str | None = None
    core = value
    if value.endswith(")") and " (" in value:
        core, source_part = value.rsplit(" (", 1)
        source = source_part[:-1]
        if not source:
            raise SbomError(f"Cargo.lock contains malformed dependency {value!r}")
    parts = core.split(" ")
    if len(parts) not in (1, 2) or not _PACKAGE_NAME.fullmatch(parts[0]):
        raise SbomError(f"Cargo.lock contains malformed dependency {value!r}")
    version = parts[1] if len(parts) == 2 else None
    if version == "":
        raise SbomError(f"Cargo.lock contains malformed dependency {value!r}")
    return parts[0], version, source


def parse_cargo_lock(lock_bytes: bytes) -> tuple[LockedPackage, ...]:
    try:
        decoded = lock_bytes.decode("utf-8")
        value = tomllib.loads(decoded)
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise SbomError(f"Cargo.lock is malformed: {error}") from error
    if not isinstance(value, dict) or value.get("version") not in (3, 4):
        raise SbomError("Cargo.lock must use supported lockfile version 3 or 4")
    raw_packages = value.get("package")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise SbomError("Cargo.lock contains no packages")
    packages: list[LockedPackage] = []
    for raw in raw_packages:
        if not isinstance(raw, dict):
            raise SbomError("Cargo.lock contains a malformed package")
        name = raw.get("name")
        version = raw.get("version")
        source = raw.get("source")
        checksum = raw.get("checksum")
        dependencies = raw.get("dependencies", [])
        if (
            not isinstance(name, str)
            or _PACKAGE_NAME.fullmatch(name) is None
            or not isinstance(version, str)
            or not version
            or (source is not None and (not isinstance(source, str) or not source))
            or (
                checksum is not None
                and (not isinstance(checksum, str) or _HEX64.fullmatch(checksum) is None)
            )
            or not isinstance(dependencies, list)
            or any(not isinstance(dependency, str) for dependency in dependencies)
        ):
            raise SbomError(f"Cargo.lock contains invalid package metadata for {name!r}")
        if source is not None and checksum is None and source.startswith("registry+"):
            raise SbomError(f"registry package {name} {version} is missing its checksum")
        packages.append(
            LockedPackage(name, version, source, checksum, tuple(dependencies))
        )
    identities = [package.identity for package in packages]
    if len(identities) != len(set(identities)):
        raise SbomError("Cargo.lock contains duplicate package identities")
    packages.sort(key=lambda package: package.identity)
    _resolved_dependencies(packages)
    return tuple(packages)


def _resolved_dependencies(
    packages: Iterable[LockedPackage],
) -> dict[str, tuple[LockedPackage, ...]]:
    package_list = tuple(packages)
    resolved: dict[str, tuple[LockedPackage, ...]] = {}
    for package in package_list:
        dependencies: list[LockedPackage] = []
        for dependency in package.dependencies:
            name, version, source = _parse_dependency(dependency)
            candidates = [candidate for candidate in package_list if candidate.name == name]
            if version is not None:
                candidates = [
                    candidate for candidate in candidates if candidate.version == version
                ]
            if source is not None:
                candidates = [
                    candidate for candidate in candidates if candidate.source == source
                ]
            if len(candidates) != 1:
                raise SbomError(
                    f"dependency {dependency!r} of {package.name} {package.version} "
                    f"resolves to {len(candidates)} locked packages"
                )
            dependencies.append(candidates[0])
        resolved[package.identity] = tuple(
            sorted(dependencies, key=lambda dependency: dependency.identity)
        )
    return resolved
def _dependency_receipt_path(dependency_dir: Path, asset_name: str) -> Path:
    return dependency_dir / f"{asset_name}.dependencies.json"


def _receipt_graph(
    path: Path,
    *,
    asset_name: str,
    target: str,
    commit: str,
    tag: str,
    tag_object: str,
    lock_digest: str,
    locked_packages: tuple[LockedPackage, ...],
) -> tuple[
    str,
    tuple[LockedPackage, ...],
    dict[str, tuple[str, ...]],
    dict[str, tuple[str, ...]],
]:
    value = _load_json(path, "binary dependency receipt")
    if not isinstance(value, dict) or set(value) != {
        "artifact",
        "cargoTree",
        "generator",
        "graphSha256",
        "packages",
        "profile",
        "schema",
        "source",
    }:
        raise SbomError(f"dependency receipt has invalid schema: {path.name}")
    expected_target, expected_root, default_features, selected_features = (
        DEPENDENCY_PROFILES[asset_name]
    )
    profile = value["profile"]
    if (
        value["schema"] != RECEIPT_SCHEMA
        or value["generator"] != RECEIPT_GENERATOR
        or value["artifact"] != {"name": asset_name, "target": target}
        or target != expected_target
        or value["source"]
        != {
            "cargoLockSha256": lock_digest,
            "commit": commit,
            "tag": tag,
            "tagObject": tag_object,
        }
        or not isinstance(profile, dict)
        or set(profile) != {"defaultFeatures", "features", "root", "rootPackage"}
        or profile["defaultFeatures"] is not default_features
        or profile["features"] != list(selected_features)
        or profile["rootPackage"] != expected_root
        or not isinstance(profile["root"], str)
        or not isinstance(value["packages"], list)
        or not value["packages"]
        or not isinstance(value["cargoTree"], list)
        or not value["cargoTree"]
        or any(not isinstance(line, str) for line in value["cargoTree"])
    ):
        raise SbomError(f"dependency receipt identity does not match {asset_name}")
    locked_by_identity = {package.identity: package for package in locked_packages}
    lock_edges = {
        identity: {dependency.identity for dependency in dependencies}
        for identity, dependencies in _resolved_dependencies(locked_packages).items()
    }
    selected: list[LockedPackage] = []
    edges: dict[str, tuple[str, ...]] = {}
    features: dict[str, tuple[str, ...]] = {}
    identities: list[str] = []
    package_metadata: dict[str, dict[str, str | None]] = {}
    for raw in value["packages"]:
        if not isinstance(raw, dict) or set(raw) != {
            "dependencies",
            "features",
            "license",
            "name",
            "repository",
            "source",
            "version",
        }:
            raise SbomError(f"dependency receipt has malformed package: {path.name}")
        name = raw["name"]
        version = raw["version"]
        source = raw["source"]
        dependencies = raw["dependencies"]
        package_features = raw["features"]
        license_value = raw["license"]
        repository = raw["repository"]
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or (source is not None and not isinstance(source, str))
            or (license_value is not None and not isinstance(license_value, str))
            or (repository is not None and not isinstance(repository, str))
            or not isinstance(dependencies, list)
            or any(not isinstance(item, str) for item in dependencies)
            or dependencies != sorted(set(dependencies))
            or not isinstance(package_features, list)
            or any(not isinstance(item, str) for item in package_features)
            or package_features != sorted(set(package_features))
        ):
            raise SbomError(f"dependency receipt has invalid package fields: {path.name}")
        identity = "\0".join((name, version, source or "workspace"))
        locked = locked_by_identity.get(identity)
        if locked is None:
            raise SbomError(
                f"dependency receipt package is absent from Cargo.lock: {name} {version}"
            )
        identities.append(identity)
        selected.append(locked)
        edges[identity] = tuple(dependencies)
        features[identity] = tuple(package_features)
        package_metadata[identity] = {
            "license": license_value,
            "repository": repository,
        }
    if identities != sorted(set(identities)):
        raise SbomError(f"dependency receipt packages are duplicated or unordered: {path.name}")
    selected_identities = set(identities)
    graph_digest = hashlib.sha256(
        _canonical_json({"packages": value["packages"], "root": profile["root"]})
    ).hexdigest()
    if value["graphSha256"] != graph_digest:
        raise SbomError(f"dependency receipt graph digest does not match: {path.name}")
    root = profile["root"]
    if root not in selected_identities:
        raise SbomError(f"dependency receipt root is missing: {path.name}")
    root_package = locked_by_identity[root]
    if root_package.name != expected_root or root_package.source is not None:
        raise SbomError(
            f"dependency receipt root is not the expected {expected_root} workspace package"
        )
    if package_metadata[root] != {
        "license": "MIT OR Apache-2.0",
        "repository": "https://github.com/santhreal/keyhog",
    }:
        raise SbomError(
            f"dependency receipt root license/repository identity is invalid: {path.name}"
        )
    for identity, dependencies in edges.items():
        if not set(dependencies) <= selected_identities:
            raise SbomError(f"dependency receipt edge names a missing package: {path.name}")
        if not set(dependencies) <= lock_edges[identity]:
            raise SbomError(f"dependency receipt fabricates a Cargo.lock edge: {path.name}")
    by_name_version: dict[tuple[str, str], list[str]] = {}
    for package in selected:
        by_name_version.setdefault((package.name, package.version), []).append(
            package.identity
        )
    evidence_edges = {identity: set() for identity in selected_identities}
    evidence_features: dict[str, tuple[str, ...]] = {}
    stack: dict[int, str] = {}
    evidence_root: str | None = None
    for line in value["cargoTree"]:
        match = _TREE_LINE.fullmatch(line)
        if match is None:
            raise SbomError(f"dependency receipt cargoTree is malformed: {path.name}")
        depth, name, version = int(match[1]), match[2], match[3]
        candidates = by_name_version.get((name, version), [])
        if len(candidates) != 1:
            raise SbomError(
                f"dependency receipt cargoTree package is ambiguous: {name} {version}"
            )
        identity = candidates[0]
        line_features = set(filter(None, match[4].split(",")))
        evidence_features[identity] = tuple(
            sorted(set(evidence_features.get(identity, ())) | line_features)
        )
        if depth == 0:
            if evidence_root is not None:
                raise SbomError(f"dependency receipt cargoTree has multiple roots")
            evidence_root = identity
        else:
            parent = stack.get(depth - 1)
            if parent is None:
                raise SbomError(f"dependency receipt cargoTree skips a parent")
            evidence_edges[parent].add(identity)
        stack[depth] = identity
        for stale in [item for item in stack if item > depth]:
            del stack[stale]
    if (
        evidence_root != root
        or set(evidence_features) != selected_identities
        or evidence_features != features
        or {
            identity: tuple(sorted(dependencies))
            for identity, dependencies in evidence_edges.items()
        }
        != edges
    ):
        raise SbomError(
            f"dependency receipt graph is not the exact cargoTree closure: {path.name}"
        )
    reachable: set[str] = set()
    pending = [root]
    while pending:
        identity = pending.pop()
        if identity not in reachable:
            reachable.add(identity)
            pending.extend(edges[identity])
    if reachable != selected_identities:
        raise SbomError(f"dependency receipt includes unreachable packages: {path.name}")
    return root, tuple(selected), edges, features, package_metadata


def _native_build_receipt_path(dependency_dir: Path) -> Path:
    return dependency_dir / "keyhog-linux-x86_64.native-build.json"


def _native_link_receipt_path(dependency_dir: Path) -> Path:
    return dependency_dir / "keyhog-linux-x86_64.native-link.json"


def _valid_archive_members(value: Any, *, start_index: int = 0) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for offset, member in enumerate(value, start=start_index):
        if (
            not isinstance(member, dict)
            or set(member) != {"index", "name", "sha256", "size"}
            or member["index"] != offset
            or not isinstance(member["name"], str)
            or not member["name"]
            or "\0" in member["name"]
            or "\n" in member["name"]
            or "\r" in member["name"]
            or not isinstance(member["size"], int)
            or isinstance(member["size"], bool)
            or member["size"] < 0
            or not isinstance(member["sha256"], str)
            or _HEX64.fullmatch(member["sha256"]) is None
        ):
            return False
    return True


def _native_receipts(
    dependency_dir: Path,
    *,
    commit: str,
    tag: str,
    tag_object: str,
    artifact: Artifact,
) -> dict[str, Any]:
    build_path = _native_build_receipt_path(dependency_dir)
    link_path = _native_link_receipt_path(dependency_dir)
    build = _load_json(build_path, "native build dependency receipt")
    link = _load_json(link_path, "native link dependency receipt")
    source = {"commit": commit, "tag": tag, "tagObject": tag_object}
    if (
        not isinstance(build, dict)
        or set(build)
        != {
            "artifact",
            "generator",
            "hyperscanRoot",
            "schema",
            "source",
            "staticHyperscan",
        }
        or build["schema"] != NATIVE_BUILD_SCHEMA
        or build["generator"] != RECEIPT_GENERATOR
        or build["source"] != source
        or build["artifact"] != {"name": artifact.name}
        or not isinstance(build["hyperscanRoot"], str)
        or not Path(build["hyperscanRoot"]).is_absolute()
        or str(Path(build["hyperscanRoot"])) != build["hyperscanRoot"]
        or not isinstance(build["staticHyperscan"], dict)
    ):
        raise SbomError("Linux native build receipt identity is invalid")
    static = build["staticHyperscan"]
    if (
        set(static)
        != {
            "archiveFile",
            "archiveMembers",
            "archiveMembersSha256",
            "archiveSha256",
            "license",
            "name",
            "pkgConfigFile",
            "pkgConfigSha256",
            "pkgConfigVersion",
            "version",
        }
        or static["archiveFile"] != "lib/libhs.a"
        or static["pkgConfigFile"] != "lib/pkgconfig/libhs.pc"
        or static["name"] != "Hyperscan"
        or static["version"] != HYPERSCAN_VERSION
        or static["license"] != "BSD-3-Clause"
        or static["pkgConfigVersion"] != PKG_CONFIG_VERSION
        or not _valid_archive_members(static["archiveMembers"])
        or not isinstance(static["archiveMembersSha256"], str)
        or _HEX64.fullmatch(static["archiveMembersSha256"]) is None
        or hashlib.sha256(_canonical_json(static["archiveMembers"])).hexdigest()
        != static["archiveMembersSha256"]
        or not isinstance(static["archiveSha256"], str)
        or _HEX64.fullmatch(static["archiveSha256"]) is None
        or not isinstance(static["pkgConfigSha256"], str)
        or _HEX64.fullmatch(static["pkgConfigSha256"]) is None
    ):
        raise SbomError("Linux static Hyperscan provenance is invalid")
    if (
        not isinstance(link, dict)
        or set(link)
        != {
            "artifact",
            "buildReceiptSha256",
            "dynamicLibraries",
            "generator",
            "linkMapSelectedMembers",
            "linkMapSha256",
            "nativeRlib",
            "schema",
            "source",
        }
        or link["schema"] != NATIVE_LINK_SCHEMA
        or link["generator"] != RECEIPT_GENERATOR
        or link["source"] != source
        or link["artifact"] != {"name": artifact.name, "sha256": artifact.sha256}
        or link["buildReceiptSha256"] != _sha256(build_path)
        or not isinstance(link["linkMapSha256"], str)
        or _HEX64.fullmatch(link["linkMapSha256"]) is None
        or not isinstance(link["linkMapSelectedMembers"], list)
        or not link["linkMapSelectedMembers"]
        or any(
            not isinstance(member, str)
            or not member
            or "\n" in member
            or "\r" in member
            for member in link["linkMapSelectedMembers"]
        )
        or not isinstance(link["nativeRlib"], dict)
        or set(link["nativeRlib"])
        != {
            "membersSha256",
            "name",
            "originalPath",
            "sha256",
            "staticSuffixMembersSha256",
        }
        or re.fullmatch(
            r"libhyperscan_sys-[0-9a-f]{16}\.rlib",
            link["nativeRlib"].get("name", ""),
        )
        is None
        or not isinstance(link["nativeRlib"].get("originalPath"), str)
        or not Path(link["nativeRlib"]["originalPath"]).is_absolute()
        or Path(link["nativeRlib"]["originalPath"]).name
        != link["nativeRlib"]["name"]
        or str(Path(link["nativeRlib"]["originalPath"]))
        != link["nativeRlib"]["originalPath"]
        or any(
            not isinstance(link["nativeRlib"].get(key), str)
            or _HEX64.fullmatch(link["nativeRlib"][key]) is None
            for key in (
                "membersSha256",
                "sha256",
                "staticSuffixMembersSha256",
            )
        )
        or link["nativeRlib"]["staticSuffixMembersSha256"]
        != static["archiveMembersSha256"]
        or any(
            count
            > sum(
                1
                for member in static["archiveMembers"]
                if member["name"] == name
            )
            for name, count in Counter(link["linkMapSelectedMembers"]).items()
        )
        or not isinstance(link["dynamicLibraries"], list)
        or not link["dynamicLibraries"]
    ):
        raise SbomError("Linux native link receipt identity is invalid")
    names: list[str] = []
    for library in link["dynamicLibraries"]:
        if (
            not isinstance(library, dict)
            or set(library) != {"name", "sha256"}
            or not isinstance(library["name"], str)
            or not library["name"]
            or Path(library["name"]).name != library["name"]
            or "\\" in library["name"]
            or library["name"].lower().startswith(("libhs", "libhyperscan"))
            or not isinstance(library["sha256"], str)
            or _HEX64.fullmatch(library["sha256"]) is None
        ):
            raise SbomError("Linux native link receipt has malformed library")
        names.append(library["name"])
    if names != sorted(set(names)):
        raise SbomError("Linux native link libraries are duplicated or unordered")
    return {
        "native": {
            "buildReceiptSha256": _sha256(build_path),
            "dynamicLibraries": link["dynamicLibraries"],
            "linkReceiptSha256": _sha256(link_path),
            "linkMapSelectedMembers": link["linkMapSelectedMembers"],
            "nativeRlib": link["nativeRlib"],
            "pkgConfigVersion": static["pkgConfigVersion"],
            "staticHyperscan": static,
        }
    }


def _artifact_from_path(
    name: str, asset_dir: Path, dependency_dir: Path
) -> Artifact:
    kind, target = SUPPORTED_ASSETS[name]
    path = asset_dir / name
    _require_regular_file(path, "release asset")
    stat = path.stat()
    if stat.st_size <= 0:
        raise SbomError(f"required release asset is empty: {path}")
    receipt_digest = (
        _sha256(_dependency_receipt_path(dependency_dir, name))
        if kind in {"binary", "gpu-bundle"}
        else None
    )
    build_digest = (
        _sha256(_native_build_receipt_path(dependency_dir))
        if name == "keyhog-linux-x86_64"
        else None
    )
    link_digest = (
        _sha256(_native_link_receipt_path(dependency_dir))
        if name == "keyhog-linux-x86_64"
        else None
    )
    return Artifact(
        name,
        kind,
        target,
        stat.st_size,
        _sha256(path),
        receipt_digest,
        build_digest,
        link_digest,
    )


def _validate_exact_receipt(
    source_dir: Path,
    path: Path,
    asset_name: str,
    tag: str,
) -> None:
    actual = _load_json(path, "binary dependency receipt")
    try:
        expected = derive_receipt(source_dir, asset_name, tag)
    except ReceiptError as error:
        raise SbomError(str(error)) from error
    if actual != expected:
        raise SbomError(
            f"dependency receipt is not the independently derived Cargo graph: {path.name}"
        )

def _validate_installer_sources(
    source_dir: Path, asset_dir: Path, commit: str
) -> None:
    for name in ("install.sh", "install.ps1"):
        path = asset_dir / name
        _require_regular_file(path, "installer release asset")
        try:
            actual = path.read_bytes()
        except OSError as error:
            raise SbomError(f"cannot read installer release asset {path}: {error}") from error
        tagged = _git(source_dir, "show", f"{commit}:{name}")
        if actual != tagged:
            raise SbomError(
                f"installer release asset does not match tagged source: {name}"
            )
        tagged_digest = hashlib.sha256(tagged).hexdigest()
        if tagged_digest != INSTALLER_SOURCE_SHA256[name]:
            raise SbomError(
                f"installer command surface has not been reviewed for the runtime SBOM: {name}"
            )



def create_release_manifest(
    source_dir: Path,
    asset_dir: Path,
    dependency_dir: Path,
    tag: str,
    source_commit: str,
) -> ReleaseManifest:
    lock_path = source_dir / "Cargo.lock"
    lock_digest = _sha256(lock_path)
    tag_object = os.environ.get("KEYHOG_RELEASE_TAG_OBJECT", "")
    lock_bytes, _created = _validate_tagged_source(
        source_dir,
        tag,
        source_commit,
        tag_object,
        lock_digest,
    )
    locked_packages = parse_cargo_lock(lock_bytes)
    artifacts = tuple(
        _artifact_from_path(name, asset_dir, dependency_dir)
        for name in sorted(SUPPORTED_ASSETS)
    )
    _validate_installer_sources(source_dir, asset_dir, source_commit)
    for artifact in artifacts:
        if artifact.kind in {"binary", "gpu-bundle"}:
            _validate_exact_receipt(
                source_dir,
                _dependency_receipt_path(dependency_dir, artifact.name),
                artifact.name,
                tag,
            )
            _receipt_graph(
                _dependency_receipt_path(dependency_dir, artifact.name),
                asset_name=artifact.name,
                target=artifact.target,
                commit=source_commit,
                tag=tag,
                tag_object=tag_object,
                lock_digest=lock_digest,
                locked_packages=locked_packages,
            )
        if artifact.name == "keyhog-linux-x86_64":
            _native_receipts(
                dependency_dir,
                commit=source_commit,
                tag=tag,
                tag_object=tag_object,
                artifact=artifact,
            )
    return ReleaseManifest(tag, source_commit, tag_object, lock_digest, artifacts)


def _validate_artifacts(manifest: ReleaseManifest, asset_dir: Path) -> None:
    for artifact in manifest.artifacts:
        path = asset_dir / artifact.name
        try:
            size = path.stat().st_size
        except OSError as error:
            raise SbomError(f"required release asset is missing: {path}") from error
        digest = _sha256(path)
        if size != artifact.size or digest != artifact.sha256:
            raise SbomError(
                f"release asset {artifact.name} does not match manifest "
                f"(expected size={artifact.size} sha256={artifact.sha256}, "
                f"got size={size} sha256={digest})"
            )


def _cargo_package_value(
    package: LockedPackage,
    features: tuple[str, ...],
    metadata: dict[str, str | None],
) -> dict[str, Any]:
    feature_text = ",".join(features) if features else "(none)"
    license_value = metadata["license"] or "NOASSERTION"
    repository = metadata["repository"]
    source_parts = [
        "Cargo.lock source: " + (package.source or "workspace at tagged commit"),
        f"resolved features: {feature_text}",
    ]
    if repository:
        source_parts.append(f"repository: {repository}")
    value: dict[str, Any] = {
        "SPDXID": package.spdx_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceLocator": (
                    f"pkg:cargo/{quote(package.name, safe='')}@"
                    f"{quote(package.version, safe='')}"
                ),
                "referenceType": "purl",
            }
        ],
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": license_value,
        "name": package.name,
        "sourceInfo": "; ".join(source_parts),
        "supplier": "NOASSERTION",
        "versionInfo": package.version,
    }
    if package.checksum is not None:
        value["checksums"] = [
            {"algorithm": "SHA256", "checksumValue": package.checksum}
        ]
    return value


def _sbom_value(
    manifest: ReleaseManifest,
    artifact: Artifact,
    graph: tuple[
        str,
        tuple[LockedPackage, ...],
        dict[str, tuple[str, ...]],
        dict[str, tuple[str, ...]],
        dict[str, dict[str, str | None]],
    ]
    | None,
    native: dict[str, Any] | None,
    created: str,
) -> dict[str, Any]:
    metadata = {
        "artifact": artifact.value(),
        "cargoLockSha256": manifest.cargo_lock_sha256,
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "schema": SCHEMA,
        "sourceCommit": manifest.commit,
        "tag": manifest.tag,
    }
    artifact_package: dict[str, Any] = {
        "SPDXID": "SPDXRef-ReleaseArtifact",
        "checksums": [{"algorithm": "SHA256", "checksumValue": artifact.sha256}],
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "MIT OR Apache-2.0",
        "name": artifact.name,
        "packageFileName": artifact.name,
        "primaryPackagePurpose": {
            "binary": "APPLICATION",
            "gpu-bundle": "ARCHIVE",
            "installer": "INSTALL",
        }[artifact.kind],
        "sourceInfo": (
            (
                "Installer script from tagged commit "
                f"{manifest.commit}; selects only authenticated platform payloads"
            )
            if artifact.kind == "installer"
            else (
                f"Generated from tagged commit {manifest.commit}; "
                f"target {artifact.target}; Cargo.lock SHA-256 "
                f"{manifest.cargo_lock_sha256}"
            )
        ),
        "versionInfo": manifest.tag,
    }
    relationships: list[dict[str, str]] = [
        {
            "relatedSpdxElement": "SPDXRef-ReleaseArtifact",
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
    ]
    packages: tuple[LockedPackage, ...] = ()
    features: dict[str, tuple[str, ...]] = {}
    package_metadata: dict[str, dict[str, str | None]] = {}
    if graph is not None:
        root, packages, edges, features, package_metadata = graph
        by_identity = {package.identity: package for package in packages}
        relationships.append(
            {
                "relatedSpdxElement": by_identity[root].spdx_id,
                "relationshipType": (
                    "GENERATED_FROM"
                    if artifact.kind == "gpu-bundle"
                    else "DEPENDS_ON"
                ),
                "spdxElementId": "SPDXRef-ReleaseArtifact",
            }
        )
        for identity, dependencies in edges.items():
            for dependency in dependencies:
                relationships.append(
                    {
                        "relatedSpdxElement": by_identity[dependency].spdx_id,
                        "relationshipType": "DEPENDS_ON",
                        "spdxElementId": by_identity[identity].spdx_id,
                    }
                )
    native_packages: list[dict[str, Any]] = []
    if native is not None:
        metadata["native"] = native["native"]
        for library in native["native"]["dynamicLibraries"]:
            native_id = (
                "SPDXRef-Native-"
                + hashlib.sha256(
                    (library["name"] + "\0" + library["sha256"]).encode()
                ).hexdigest()[:20]
            )
            native_packages.append(
                {
                    "SPDXID": native_id,
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": library["sha256"],
                        }
                    ],
                    "copyrightText": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "name": library["name"],
                }
            )
            relationships.append(
                {
                    "relatedSpdxElement": native_id,
                    "relationshipType": "DEPENDS_ON",
                    "spdxElementId": "SPDXRef-ReleaseArtifact",
                }
            )
        static = native["native"]["staticHyperscan"]
        static_id = "SPDXRef-StaticHyperscan"
        native_packages.append(
            {
                "SPDXID": static_id,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": static["archiveSha256"],
                    }
                ],
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": (
                            f"pkg:generic/hyperscan@{static['version']}"
                        ),
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": static["license"],
                "name": static["name"],
                "sourceInfo": (
                    f"{static['archiveFile']} statically linked; "
                    f"{static['pkgConfigFile']} SHA-256 "
                    f"{static['pkgConfigSha256']}"
                ),
                "versionInfo": static["version"],
            }
        )
        relationships.append(
            {
                "relatedSpdxElement": static_id,
                "relationshipType": "STATIC_LINK",
                "spdxElementId": "SPDXRef-ReleaseArtifact",
            }
        )
    contract_packages: list[dict[str, Any]] = []
    if artifact.kind == "installer":
        if artifact.name == "install.sh":
            compatible = [
                candidate
                for candidate in manifest.artifacts
                if candidate.kind in {"binary", "gpu-bundle"}
                and "windows" not in candidate.name
            ]
            runtime_tools = INSTALLER_RUNTIME_TOOLS[artifact.name]
        else:
            compatible = [
                candidate
                for candidate in manifest.artifacts
                if candidate.kind in {"binary", "gpu-bundle"}
                and "windows" in candidate.name
            ]
            runtime_tools = INSTALLER_RUNTIME_TOOLS[artifact.name]
        for payload in compatible:
            payload_id = (
                "SPDXRef-InstallerPayload-"
                + hashlib.sha256(payload.name.encode()).hexdigest()[:20]
            )
            contract_packages.append(
                {
                    "SPDXID": payload_id,
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": payload.sha256}
                    ],
                    "copyrightText": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "MIT OR Apache-2.0",
                    "name": payload.name,
                    "packageFileName": payload.name,
                    "sourceInfo": (
                        "Compatible signed release payload; installer also "
                        "requires its published checksum and minisign signature"
                    ),
                    "versionInfo": manifest.tag,
                }
            )
            relationships.append(
                {
                    "comment": "Conditionally selected for the detected platform",
                    "relatedSpdxElement": "SPDXRef-ReleaseArtifact",
                    "relationshipType": "OPTIONAL_DEPENDENCY_OF",
                    "spdxElementId": payload_id,
                }
            )
        for tool_name, purpose, condition, required in runtime_tools:
            tool_id = (
                "SPDXRef-InstallerRuntime-"
                + hashlib.sha256(tool_name.encode()).hexdigest()[:20]
            )
            contract_packages.append(
                {
                    "SPDXID": tool_id,
                    "copyrightText": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "name": tool_name,
                    "sourceInfo": purpose,
                    "supplier": "NOASSERTION",
                }
            )
            relationships.append(
                {
                    "comment": condition,
                    "relatedSpdxElement": "SPDXRef-ReleaseArtifact",
                    "relationshipType": (
                        "RUNTIME_DEPENDENCY_OF"
                        if required
                        else "OPTIONAL_DEPENDENCY_OF"
                    ),
                    "spdxElementId": tool_id,
                }
            )
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    package_values = [
        _cargo_package_value(
            package, features[package.identity], package_metadata[package.identity]
        )
        for package in packages
    ]
    namespace_name = quote(artifact.name, safe="")
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "comment": json.dumps(metadata, sort_keys=True, separators=(",", ":")),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {GENERATOR_NAME}-{GENERATOR_VERSION}"],
            "licenseListVersion": "3.25",
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://spdx.keyhog.dev/releases/"
            f"{manifest.commit}/{namespace_name}/{artifact.sha256}"
        ),
        "name": f"KeyHog {manifest.tag} {artifact.name}",
        "packages": [
            artifact_package,
            *package_values,
            *native_packages,
            *contract_packages,
        ],
        "relationships": relationships,
        "spdxVersion": SPDX_VERSION,
    }


def _expected_sboms(
    source_dir: Path,
    asset_dir: Path,
    dependency_dir: Path,
    manifest: ReleaseManifest,
) -> dict[str, bytes]:
    lock_bytes, created = _validate_tagged_source(
        source_dir,
        manifest.tag,
        manifest.commit,
        manifest.tag_object,
        manifest.cargo_lock_sha256,
    )
    locked_packages = parse_cargo_lock(lock_bytes)
    _validate_artifacts(manifest, asset_dir)
    _validate_installer_sources(source_dir, asset_dir, manifest.commit)
    documents: dict[str, bytes] = {}
    for artifact in manifest.artifacts:
        graph = None
        if artifact.kind in {"binary", "gpu-bundle"}:
            receipt_path = _dependency_receipt_path(dependency_dir, artifact.name)
            _validate_exact_receipt(
                source_dir,
                receipt_path,
                artifact.name,
                manifest.tag,
            )
            if _sha256(receipt_path) != artifact.dependency_receipt_sha256:
                raise SbomError(
                    f"dependency receipt digest does not match manifest: {receipt_path.name}"
                )
            graph = _receipt_graph(
                receipt_path,
                asset_name=artifact.name,
                target=artifact.target,
                commit=manifest.commit,
                tag=manifest.tag,
                lock_digest=manifest.cargo_lock_sha256,
                tag_object=manifest.tag_object,
                locked_packages=locked_packages,
            )
        native = None
        if artifact.name == "keyhog-linux-x86_64":
            build_path = _native_build_receipt_path(dependency_dir)
            link_path = _native_link_receipt_path(dependency_dir)
            if (
                _sha256(build_path) != artifact.native_build_receipt_sha256
                or _sha256(link_path) != artifact.native_link_receipt_sha256
            ):
                raise SbomError("native receipt digests do not match manifest")
            native = _native_receipts(
                dependency_dir,
                commit=manifest.commit,
                tag=manifest.tag,
                tag_object=manifest.tag_object,
                artifact=artifact,
            )
        documents[artifact.name] = _canonical_json(
            _sbom_value(manifest, artifact, graph, native, created)
        )
    return documents


def generate_sboms(
    source_dir: Path,
    asset_dir: Path,
    dependency_dir: Path,
    manifest: ReleaseManifest,
    output_dir: Path,
) -> tuple[Path, ...]:
    expected = _expected_sboms(source_dir, asset_dir, dependency_dir, manifest)
    outputs: list[Path] = []
    for artifact_name, content in expected.items():
        sbom_path = output_dir / f"{artifact_name}.spdx.json"
        _atomic_write(sbom_path, content)
        digest = hashlib.sha256(content).hexdigest()
        checksum_path = output_dir / f"{sbom_path.name}.sha256"
        _atomic_write(checksum_path, f"{digest}  {sbom_path.name}\n".encode("ascii"))
        outputs.extend((sbom_path, checksum_path))
    return tuple(outputs)


def verify_sboms(
    source_dir: Path,
    asset_dir: Path,
    dependency_dir: Path,
    manifest: ReleaseManifest,
    sbom_dir: Path,
) -> None:
    expected = _expected_sboms(source_dir, asset_dir, dependency_dir, manifest)
    expected_names = {
        name
        for artifact_name in expected
        for name in (
            f"{artifact_name}.spdx.json",
            f"{artifact_name}.spdx.json.sha256",
        )
    }
    try:
        actual_names = {
            path.name
            for path in sbom_dir.iterdir()
            if path.is_file()
            and (path.name.endswith(".spdx.json") or path.name.endswith(".spdx.json.sha256"))
        }
    except OSError as error:
        raise SbomError(f"cannot inspect SBOM directory {sbom_dir}: {error}") from error
    if actual_names != expected_names:
        raise SbomError(
            "SBOM output inventory is incomplete "
            f"(missing={sorted(expected_names - actual_names)}, "
            f"unexpected={sorted(actual_names - expected_names)})"
        )
    for artifact_name, content in expected.items():
        sbom_path = sbom_dir / f"{artifact_name}.spdx.json"
        try:
            actual = sbom_path.read_bytes()
        except OSError as error:
            raise SbomError(f"cannot read SBOM {sbom_path}: {error}") from error
        if actual != content:
            raise SbomError(f"SBOM bytes do not match release inputs: {sbom_path.name}")
        # Parse separately so diagnostics distinguish malformed JSON from byte drift.
        _load_json(sbom_path, "SPDX document")
        digest = hashlib.sha256(actual).hexdigest()
        expected_checksum = f"{digest}  {sbom_path.name}\n"
        checksum_path = sbom_dir / f"{sbom_path.name}.sha256"
        try:
            checksum = checksum_path.read_text(encoding="ascii")
        except (OSError, UnicodeError) as error:
            raise SbomError(f"cannot read SBOM checksum {checksum_path}: {error}") from error
        if checksum != expected_checksum:
            raise SbomError(f"SBOM checksum does not match: {checksum_path.name}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate and verify deterministic SPDX 2.3 release SBOMs offline."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    receipt = commands.add_parser(
        "dependency-receipt", help="capture one exact package-scoped Cargo graph offline"
    )
    receipt.add_argument("--source-dir", type=Path, default=Path("."))
    receipt.add_argument("--asset-name", choices=sorted(DEPENDENCY_PROFILES), required=True)
    receipt.add_argument("--tag", required=True)
    receipt.add_argument("--output", type=Path, required=True)

    native_build = commands.add_parser(
        "native-build-receipt",
        help="capture exact static Hyperscan inputs before Cargo build",
    )
    native_build.add_argument("--source-dir", type=Path, default=Path("."))
    native_build.add_argument("--tag", required=True)
    native_build.add_argument("--hyperscan-root", type=Path, required=True)
    native_build.add_argument("--output", type=Path, required=True)

    native_link = commands.add_parser(
        "native-link-receipt",
        help="reprove static inputs and capture final Linux binary linkage",
    )
    native_link.add_argument("--source-dir", type=Path, default=Path("."))
    native_link.add_argument("--tag", required=True)
    native_link.add_argument("--binary", type=Path, required=True)
    native_link.add_argument(
        "--linked-native-archive", type=Path, required=True
    )
    native_link.add_argument(
        "--linked-native-path", type=Path, required=True
    )
    native_link.add_argument("--build-receipt", type=Path, required=True)
    native_link.add_argument("--link-map", type=Path, required=True)
    native_link.add_argument("--output", type=Path, required=True)

    manifest = commands.add_parser("manifest", help="hash the exact release inputs")
    manifest.add_argument("--source-dir", type=Path, default=Path("."))
    manifest.add_argument("--asset-dir", type=Path, required=True)
    manifest.add_argument("--dependency-dir", type=Path, required=True)
    manifest.add_argument("--tag", required=True)
    manifest.add_argument("--source-commit", required=True)
    manifest.add_argument("--output", type=Path, default=Path(MANIFEST_NAME))

    for name in ("generate", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--source-dir", type=Path, default=Path("."))
        command.add_argument("--asset-dir", type=Path, required=True)
        command.add_argument("--dependency-dir", type=Path, required=True)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "dependency-receipt":
        generate_receipt(args.source_dir, args.asset_name, args.tag, args.output)
        print(f"wrote exact dependency receipt {args.output}")
        return 0
    if args.command == "native-build-receipt":
        generate_native_build_receipt(
            args.source_dir, args.tag, args.hyperscan_root, args.output
        )
        print(f"wrote exact native build receipt {args.output}")
        return 0
    if args.command == "native-link-receipt":
        generate_native_link_receipt(
            args.source_dir,
            args.tag,
            args.binary,
            args.build_receipt,
            args.link_map,
            args.linked_native_archive,
            args.linked_native_path,
            args.output,
        )
        print(f"wrote exact native link receipt {args.output}")
        return 0
    if args.command == "manifest":
        manifest = create_release_manifest(
            args.source_dir,
            args.asset_dir,
            args.dependency_dir,
            args.tag,
            args.source_commit,
        )
        manifest.write(args.output)
        print(f"wrote {args.output} for {len(manifest.artifacts)} release assets")
        return 0
    manifest = ReleaseManifest.read(args.manifest)
    if args.command == "generate":
        outputs = generate_sboms(
            args.source_dir,
            args.asset_dir,
            args.dependency_dir,
            manifest,
            args.output_dir,
        )
        print(f"wrote {len(outputs) // 2} deterministic SPDX documents")
        return 0
    verify_sboms(
        args.source_dir,
        args.asset_dir,
        args.dependency_dir,
        manifest,
        args.output_dir,
    )
    print(f"verified {len(manifest.artifacts)} deterministic SPDX documents")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SbomError, ReceiptError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
