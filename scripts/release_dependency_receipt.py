#!/usr/bin/env python3
"""Capture exact package-scoped Cargo and native release dependency receipts."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "keyhog-release-dependency-receipt-v2"
NATIVE_BUILD_SCHEMA = "keyhog-release-native-build-receipt-v1"
NATIVE_LINK_SCHEMA = "keyhog-release-native-link-receipt-v1"
GENERATOR = {"name": "keyhog-release-sbom", "version": "2.0.0"}
HYPERSCAN_VERSION = "5.4.2"
PKG_CONFIG_VERSION = "1.8.1"

# asset -> target, root package, default features, selected features
DEPENDENCY_PROFILES: dict[str, tuple[str, str, bool, tuple[str, ...]]] = {
    "keyhog-linux-x86_64": (
        "x86_64-unknown-linux-gnu", "keyhog", True, ("static-hyperscan",),
    ),
    "keyhog-macos-aarch64": (
        "aarch64-apple-darwin", "keyhog", False, ("gpu", "portable"),
    ),
    "keyhog-macos-x86_64": (
        "x86_64-apple-darwin", "keyhog", False, ("gpu", "portable"),
    ),
    "keyhog-windows-x86_64.exe": (
        "x86_64-pc-windows-msvc", "keyhog", False, ("portable",),
    ),
    "keyhog-linux-x86_64.gpu-literals.tar.gz": (
        "x86_64-unknown-linux-gnu", "keyhog-scanner", False,
        ("decode", "entropy", "ml", "multiline", "simd", "simdsieve"),
    ),
    "keyhog-macos-aarch64.gpu-literals.tar.gz": (
        "aarch64-apple-darwin", "keyhog-scanner", False,
        ("decode", "entropy", "ml", "multiline"),
    ),
    "keyhog-macos-x86_64.gpu-literals.tar.gz": (
        "x86_64-apple-darwin", "keyhog-scanner", False,
        ("decode", "entropy", "ml", "multiline"),
    ),
    "keyhog-windows-x86_64.exe.gpu-literals.tar.gz": (
        "x86_64-pc-windows-msvc", "keyhog-scanner", False,
        ("decode", "entropy", "ml", "multiline"),
    ),
}
BINARY_PROFILES = {
    name: (target, default, features)
    for name, (target, root, default, features) in DEPENDENCY_PROFILES.items()
    if root == "keyhog"
}
_TREE_LINE = re.compile(r"^(\d+)\|([A-Za-z0-9_.+-]+) v(\S+)(?: .*?)?\|(.*)$")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class ReceiptError(RuntimeError):
    """Release dependency evidence cannot be proven exact."""


def _identity(name: str, version: str, source: str | None) -> str:
    return "\0".join((name, version, source or "workspace"))


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _git(source_dir: Path, *arguments: str, text: bool = False) -> bytes | str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(source_dir), *arguments],
            stderr=subprocess.PIPE,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = ""
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            detail = error.stderr if isinstance(error.stderr, str) else error.stderr.decode(errors="replace")
            detail = detail.strip()
        raise ReceiptError(
            f"cannot prove receipt source with git {' '.join(arguments)}"
            + (f": {detail}" if detail else "")
        ) from error


def prove_tagged_source(
    source_dir: Path, tag: str, allow_native_link_map: bool = False
) -> tuple[str, str, bytes]:
    if not tag or any(character.isspace() for character in tag):
        raise ReceiptError("release tag is empty or contains whitespace")
    _git(source_dir, "check-ref-format", f"refs/tags/{tag}")
    commit = str(
        _git(source_dir, "rev-parse", "--verify", "HEAD^{commit}", text=True)
    ).strip()
    tagged = str(
        _git(
            source_dir,
            "rev-parse",
            "--verify",
            f"refs/tags/{tag}^{{commit}}",
            text=True,
        )
    ).strip()
    tag_object = str(
        _git(source_dir, "rev-parse", "--verify", f"refs/tags/{tag}", text=True)
    ).strip()
    expected_tag_object = os.environ.get("KEYHOG_RELEASE_TAG_OBJECT")
    if expected_tag_object is None or re.fullmatch(r"[0-9a-f]{40}", expected_tag_object) is None:
        raise ReceiptError(
            "KEYHOG_RELEASE_TAG_OBJECT must be the authenticated lowercase tag-object SHA"
        )
    if tag_object != expected_tag_object:
        raise ReceiptError(
            f"tag object {tag_object} does not match authenticated "
            f"KEYHOG_RELEASE_TAG_OBJECT {expected_tag_object}"
        )
    if commit != tagged:
        raise ReceiptError(f"HEAD {commit} does not match tag {tag} commit {tagged}")
    status = bytes(
        _git(
            source_dir,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
    )
    allowed_names = set(DEPENDENCY_PROFILES) | {
        f"{name}.dependencies.json" for name in DEPENDENCY_PROFILES
    }
    allowed_names |= {
        "keyhog-linux-x86_64.native-build.json",
        "keyhog-linux-x86_64.native-link.json",
    }
    if allow_native_link_map:
        allowed_names.add("keyhog-linux-x86_64.link.map")
    for entry in filter(None, status.split(b"\0")):
        try:
            line = entry.decode()
        except UnicodeError as error:
            raise ReceiptError("git status contains a non-UTF-8 path") from error
        if not line.startswith("?? "):
            raise ReceiptError("dependency receipt source has tracked changes")
        relative = line[3:]
        if relative not in allowed_names:
            raise ReceiptError(f"untracked source input is not allowed: {relative}")
    tracked = bytes(_git(source_dir, "ls-files", "-z")).split(b"\0")
    paths = sorted(path.decode() for path in tracked if path)
    if "Cargo.lock" not in paths or "Cargo.toml" not in paths:
        raise ReceiptError("tagged source does not track Cargo.lock and Cargo.toml")
    for relative in paths:
        path = source_dir / relative
        if path.is_symlink() or not path.is_file():
            raise ReceiptError(f"tracked source input is not a regular file: {relative}")
        try:
            working = path.read_bytes()
        except OSError as error:
            raise ReceiptError(f"cannot read tracked source input {relative}: {error}") from error
        if working != bytes(_git(source_dir, "show", f"{commit}:{relative}")):
            raise ReceiptError(f"tracked source input does not match tag {tag}: {relative}")
    return commit, tag_object, (source_dir / "Cargo.lock").read_bytes()


# Kept as a stable test/helper name for callers introduced with v1.
_prove_tagged_source = prove_tagged_source


def receipt_from_metadata(
    metadata: Any,
    *,
    tree_output: str,
    asset_name: str,
    commit: str,
    tag: str,
    tag_object: str,
    cargo_lock_sha256: str,
) -> dict[str, Any]:
    """Build a receipt from package-scoped, target-filtered cargo-tree evidence."""
    if asset_name not in DEPENDENCY_PROFILES:
        raise ReceiptError(f"unsupported release asset for dependency receipt: {asset_name}")
    target, root_name, default_features, selected_features = DEPENDENCY_PROFILES[asset_name]
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise ReceiptError("cargo metadata omits packages")
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for package in metadata["packages"]:
        if not isinstance(package, dict):
            raise ReceiptError("cargo metadata contains malformed package")
        name, version, source = package.get("name"), package.get("version"), package.get("source")
        if not isinstance(name, str) or not isinstance(version, str) or (source is not None and not isinstance(source, str)):
            raise ReceiptError("cargo metadata contains invalid package identity")
        license_value = package.get("license")
        repository = package.get("repository")
        if (
            license_value is not None and not isinstance(license_value, str)
        ) or (repository is not None and not isinstance(repository, str)):
            raise ReceiptError("cargo metadata contains invalid license or repository")
        candidates.setdefault((name, version), []).append(package)

    packages: dict[str, dict[str, Any]] = {}
    edges: dict[str, set[str]] = {}
    stack: dict[int, str] = {}
    root: str | None = None
    for line in tree_output.splitlines():
        match = _TREE_LINE.fullmatch(line)
        if match is None:
            raise ReceiptError(f"cargo tree returned malformed line: {line!r}")
        depth, name, version, raw_features = int(match[1]), match[2], match[3], match[4]
        matches = candidates.get((name, version), [])
        if len(matches) != 1:
            raise ReceiptError(f"cargo tree package {name} {version} maps to {len(matches)} metadata packages")
        package = matches[0]
        identity = _identity(name, version, package.get("source"))
        features = sorted(filter(None, raw_features.split(",")))
        previous = packages.get(identity)
        if previous is None:
            packages[identity] = {
                "dependencies": [],
                "features": features,
                "name": name,
                "license": package.get("license"),
                "repository": package.get("repository"),
                "source": package.get("source"),
                "version": version,
            }
        else:
            previous["features"] = sorted(
                set(previous["features"]) | set(features)
            )
        edges.setdefault(identity, set())
        if depth == 0:
            if root is not None or name != root_name:
                raise ReceiptError("cargo tree does not contain exactly one expected root")
            root = identity
        else:
            parent = stack.get(depth - 1)
            if parent is None:
                raise ReceiptError("cargo tree depth skipped a parent")
            edges.setdefault(parent, set()).add(identity)
        stack[depth] = identity
        for stale in [item for item in stack if item > depth]:
            del stack[stale]
    if root is None or not packages:
        raise ReceiptError("cargo tree is empty")
    for identity, dependencies in edges.items():
        packages[identity]["dependencies"] = sorted(dependencies)
    ordered = [packages[identity] for identity in sorted(packages)]
    graph_digest = hashlib.sha256(_canonical({"packages": ordered, "root": root})).hexdigest()
    return {
        "artifact": {"name": asset_name, "target": target},
        "cargoTree": tree_output.splitlines(),
        "generator": GENERATOR,
        "graphSha256": graph_digest,
        "packages": ordered,
        "profile": {
            "defaultFeatures": default_features,
            "features": list(selected_features),
            "root": root,
            "rootPackage": root_name,
        },
        "schema": RECEIPT_SCHEMA,
        "source": {
            "cargoLockSha256": cargo_lock_sha256,
            "commit": commit,
            "tag": tag,
            "tagObject": tag_object,
        },
    }


def _cargo_profile_command(asset_name: str) -> tuple[list[str], list[str]]:
    cargo_bin = os.environ.get("CARGO_BIN", "cargo")
    if not cargo_bin:
        raise ReceiptError("CARGO_BIN must name the trusted Cargo executable")
    target, root, default_features, selected_features = DEPENDENCY_PROFILES[asset_name]
    common = ["--locked", "--offline", "--target", target]
    tree = [
        cargo_bin, "tree", *common, "-p", root, "--edges", "normal,build",
        "--prefix", "depth", "--format", "|{p}|{f}",
    ]
    metadata = [cargo_bin, "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", target]
    if not default_features:
        tree.append("--no-default-features")
        metadata.append("--no-default-features")
    if selected_features:
        feature_value = ",".join(selected_features)
        tree.extend(("--features", feature_value))
        metadata.extend(("--features", ",".join(f"{root}/{feature}" for feature in selected_features)))
    return tree, metadata


def derive_receipt(
    source_dir: Path, asset_name: str, tag: str
) -> dict[str, Any]:
    if asset_name not in DEPENDENCY_PROFILES:
        raise ReceiptError(f"unsupported release asset for dependency receipt: {asset_name}")
    commit, tag_object, lock_bytes = prove_tagged_source(source_dir, tag)
    tree_command, metadata_command = _cargo_profile_command(asset_name)
    try:
        tree_output = subprocess.check_output(
            tree_command, cwd=source_dir, stderr=subprocess.PIPE, text=True
        )
        metadata = json.loads(
            subprocess.check_output(
                metadata_command, cwd=source_dir, stderr=subprocess.PIPE
            )
        )
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        detail = (
            error.stderr.decode(errors="replace")
            if isinstance(error, subprocess.CalledProcessError)
            and isinstance(error.stderr, bytes)
            else str(error)
        )
        raise ReceiptError(
            f"cannot derive package-scoped offline Cargo graph: {detail.strip()}"
        ) from error
    return receipt_from_metadata(
        metadata,
        tree_output=tree_output,
        asset_name=asset_name,
        commit=commit,
        tag=tag,
        tag_object=tag_object,
        cargo_lock_sha256=hashlib.sha256(lock_bytes).hexdigest(),
    )


def generate_receipt(
    source_dir: Path, asset_name: str, tag: str, output: Path
) -> None:
    receipt = derive_receipt(source_dir, asset_name, tag)
    try:
        output.write_bytes(_canonical(receipt))
    except OSError as error:
        raise ReceiptError(f"cannot write dependency receipt {output}: {error}") from error


def _archive_members(path: Path) -> list[dict[str, Any]]:
    """Parse a SysV/GNU/BSD ar archive without collapsing duplicate members."""
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ReceiptError(f"cannot read archive {path}: {error}") from error
    if not data.startswith(b"!<arch>\n"):
        raise ReceiptError(f"archive has invalid ar magic: {path}")
    offset = 8
    string_table = b""
    members: list[dict[str, Any]] = []
    while offset < len(data):
        if offset + 60 > len(data):
            raise ReceiptError(f"archive has a truncated member header: {path}")
        header = data[offset : offset + 60]
        if header[58:60] != b"`\n":
            raise ReceiptError(f"archive has an invalid member header: {path}")
        try:
            raw_name = header[:16].decode("ascii").strip()
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeError, ValueError) as error:
            raise ReceiptError(f"archive has an invalid member header: {path}") from error
        start = offset + 60
        end = start + size
        if size < 0 or end > len(data):
            raise ReceiptError(f"archive has a truncated member body: {path}")
        body = data[start:end]
        name = raw_name
        content = body
        if raw_name == "//":
            string_table = body
        elif raw_name in {"/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"}:
            pass
        else:
            if raw_name.startswith("#1/"):
                try:
                    name_length = int(raw_name[3:])
                    name = body[:name_length].decode("utf-8")
                except (ValueError, UnicodeError) as error:
                    raise ReceiptError(f"archive has an invalid BSD member name: {path}") from error
                if name_length > len(body):
                    raise ReceiptError(f"archive has a truncated BSD member name: {path}")
                content = body[name_length:]
            elif raw_name.startswith("/") and raw_name[1:].isdigit():
                table_offset = int(raw_name[1:])
                if table_offset >= len(string_table):
                    raise ReceiptError(f"archive has an invalid GNU member name: {path}")
                terminator = string_table.find(b"/\n", table_offset)
                if terminator < 0:
                    raise ReceiptError(f"archive has an unterminated GNU member name: {path}")
                try:
                    name = string_table[table_offset:terminator].decode("utf-8")
                except UnicodeError as error:
                    raise ReceiptError(f"archive has a non-UTF-8 member name: {path}") from error
            else:
                name = raw_name.removesuffix("/")
            if not name or "\0" in name or "\n" in name or "\r" in name:
                raise ReceiptError(f"archive has an unsafe member name: {path}")
            members.append(
                {
                    "index": len(members),
                    "name": name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }
            )
        offset = end + (size % 2)
    if offset != len(data) or not members:
        raise ReceiptError(f"archive has invalid padding or no members: {path}")
    return members


def _members_sha256(members: list[dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical(members)).hexdigest()


def _file_sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ReceiptError(f"dependency input is not a regular non-symlink file: {path}")
    with path.open("rb") as content:
        return hashlib.file_digest(content, "sha256").hexdigest()


def _write_receipt(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ReceiptError(f"receipt output is not a regular non-symlink path: {path}")
    try:
        path.write_bytes(_canonical(value))
    except OSError as error:
        raise ReceiptError(f"cannot write receipt {path}: {error}") from error


def generate_native_build_receipt(
    source_dir: Path, tag: str, hyperscan_root: Path, output: Path
) -> None:
    """Capture the exact static archive and pkg-config file before linking."""
    commit, tag_object, _lock = prove_tagged_source(source_dir, tag)
    if hyperscan_root.is_symlink() or not hyperscan_root.is_dir():
        raise ReceiptError("HYPERSCAN_ROOT must be a real directory")
    root = hyperscan_root.resolve()
    archive = root / "lib" / "libhs.a"
    pkg_config_file = root / "lib" / "pkgconfig" / "libhs.pc"
    archive_digest = _file_sha256(archive)
    archive_members = _archive_members(archive)
    archive_members_digest = _members_sha256(archive_members)
    pkg_config_digest = _file_sha256(pkg_config_file)
    env = {
        **os.environ,
        "PKG_CONFIG_PATH": str(pkg_config_file.parent),
        "PKG_CONFIG_LIBDIR": str(pkg_config_file.parent),
    }
    try:
        hyperscan = subprocess.check_output(
            ["pkg-config", "--modversion", "libhs"], text=True, env=env
        ).strip()
        pkg_config = subprocess.check_output(
            ["pkg-config", "--version"], text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError(f"cannot prove static Hyperscan inputs: {error}") from error
    if hyperscan != HYPERSCAN_VERSION or pkg_config != PKG_CONFIG_VERSION:
        raise ReceiptError(
            f"native tool identity drift: hyperscan={hyperscan!r} "
            f"pkg-config={pkg_config!r}"
        )
    value = {
        "artifact": {"name": "keyhog-linux-x86_64"},
        "generator": GENERATOR,
        "hyperscanRoot": str(root),
        "schema": NATIVE_BUILD_SCHEMA,
        "source": {"commit": commit, "tag": tag, "tagObject": tag_object},
        "staticHyperscan": {
            "archiveFile": "lib/libhs.a",
            "archiveMembers": archive_members,
            "archiveMembersSha256": archive_members_digest,
            "archiveSha256": archive_digest,
            "license": "BSD-3-Clause",
            "name": "Hyperscan",
            "pkgConfigFile": "lib/pkgconfig/libhs.pc",
            "pkgConfigSha256": pkg_config_digest,
            "pkgConfigVersion": pkg_config,
            "version": hyperscan,
        },
    }
    _write_receipt(output, value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json_file(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ReceiptError(f"receipt is not a regular non-symlink file: {path}")
    try:
        value = json.loads(
            path.read_bytes(), object_pairs_hook=_reject_duplicate_keys
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise ReceiptError(f"cannot read receipt {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReceiptError(f"receipt is not an object: {path}")
    return value

def generate_native_link_receipt(
    source_dir: Path,
    tag: str,
    binary: Path,
    build_receipt: Path,
    link_map: Path,
    linked_native_archive: Path,
    linked_native_path: Path,
    output: Path,
) -> None:
    """Bind libhs.a through the exact linked rlib into the final binary."""
    expected_map = source_dir.resolve() / "keyhog-linux-x86_64.link.map"
    if link_map.resolve() != expected_map:
        raise ReceiptError(f"native link map must be exactly {expected_map}")
    link_map_digest = _file_sha256(link_map)
    linked_rlib_digest = _file_sha256(linked_native_archive)
    if linked_native_path.is_symlink() or not linked_native_path.is_file():
        raise ReceiptError("linked native archive path receipt must be a regular file")
    try:
        linked_path_text = linked_native_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReceiptError(f"cannot read linked native archive path: {error}") from error
    if linked_path_text.endswith("\n"):
        linked_path_text = linked_path_text[:-1]
    linked_path = Path(linked_path_text)
    if (
        not linked_path_text
        or "\n" in linked_path_text
        or "\r" in linked_path_text
        or not linked_path.is_absolute()
        or str(linked_path) != linked_path_text
        or re.fullmatch(
            r"libhyperscan_sys-[0-9a-f]{16}\.rlib", linked_path.name
        )
        is None
    ):
        raise ReceiptError("linked native archive path identity is invalid")
    commit, tag_object, _lock = prove_tagged_source(
        source_dir, tag, allow_native_link_map=True
    )
    build = _read_json_file(build_receipt)
    source = {"commit": commit, "tag": tag, "tagObject": tag_object}
    static = build.get("staticHyperscan")
    root_text = build.get("hyperscanRoot")
    if (
        set(build)
        != {
            "artifact",
            "generator",
            "hyperscanRoot",
            "schema",
            "source",
            "staticHyperscan",
        }
        or build["schema"] != NATIVE_BUILD_SCHEMA
        or build["generator"] != GENERATOR
        or build["source"] != source
        or build["artifact"] != {"name": "keyhog-linux-x86_64"}
        or not isinstance(root_text, str)
        or not Path(root_text).is_absolute()
        or str(Path(root_text)) != root_text
        or not isinstance(static, dict)
        or set(static)
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
        or static["license"] != "BSD-3-Clause"
        or static["version"] != HYPERSCAN_VERSION
        or static["pkgConfigVersion"] != PKG_CONFIG_VERSION
        or not isinstance(static["archiveMembers"], list)
        or not isinstance(static["archiveMembersSha256"], str)
        or _HEX64.fullmatch(static["archiveMembersSha256"]) is None
        or not isinstance(static["archiveSha256"], str)
        or _HEX64.fullmatch(static["archiveSha256"]) is None
        or not isinstance(static["pkgConfigSha256"], str)
        or _HEX64.fullmatch(static["pkgConfigSha256"]) is None
    ):
        raise ReceiptError("native build receipt identity is invalid")
    root = Path(root_text)
    if root.is_symlink() or not root.is_dir():
        raise ReceiptError("native build receipt Hyperscan root is not a real directory")
    archive = root / static["archiveFile"]
    current_members = _archive_members(archive)
    if (
        _file_sha256(archive) != static["archiveSha256"]
        or current_members != static["archiveMembers"]
        or _members_sha256(current_members) != static["archiveMembersSha256"]
        or _file_sha256(root / static["pkgConfigFile"])
        != static["pkgConfigSha256"]
    ):
        raise ReceiptError("static Hyperscan inputs changed before or during linking")
    rlib_members = _archive_members(linked_native_archive)
    if rlib_members != current_members:
        raise ReceiptError(
            "linked hyperscan_sys rlib does not embed the exact ordered libhs.a members"
        )
    try:
        link_map_bytes = link_map.read_bytes()
    except OSError as error:
        raise ReceiptError(f"cannot read native link map {link_map}: {error}") from error
    boundary = b"\nDiscarded input sections\n"
    if link_map_bytes.count(boundary) != 1:
        raise ReceiptError("native link map has an invalid archive-selection boundary")
    archive_selection = link_map_bytes.split(boundary, 1)[0]
    referenced_paths = {
        match.decode("utf-8")
        for match in re.findall(
            rb"(?m)^(/[^\s(]*/libhyperscan_sys-[0-9a-f]{16}\.rlib)\(",
            archive_selection,
        )
    }
    if referenced_paths != {linked_path_text}:
        raise ReceiptError(
            "native link map does not exclusively reference the captured hyperscan_sys rlib"
        )
    reference = (linked_path_text + "(").encode()
    try:
        selected_members = [
            member.decode("utf-8")
            for member in re.findall(
                rb"(?m)^" + re.escape(reference) + rb"([^\r\n)]+)\)",
                archive_selection,
            )
        ]
    except UnicodeError as error:
        raise ReceiptError("native link map has a non-UTF-8 rlib member") from error
    available = Counter(member["name"] for member in current_members)
    selected = Counter(selected_members)
    if (
        not selected_members
        or any(count > available.get(name, 0) for name, count in selected.items())
    ):
        raise ReceiptError(
            "native link map selects members outside the exact embedded libhs.a multiset"
        )
    binary_digest = _file_sha256(binary)
    try:
        ldd = subprocess.check_output(
            ["ldd", str(binary)], text=True, stderr=subprocess.STDOUT
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ReceiptError(f"cannot inspect Linux binary linkage: {error}") from error
    libraries: list[dict[str, str]] = []
    names: set[str] = set()
    for raw in ldd.splitlines():
        line = raw.strip()
        if not line or "statically linked" in line or "linux-vdso" in line:
            continue
        raw_name = line.split(" ", 1)[0]
        name = Path(raw_name).name
        path_text = (
            line.split("=>", 1)[1].strip().split(" ", 1)[0]
            if "=>" in line
            else line.split(" ", 1)[0]
        )
        path = Path(path_text)
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ReceiptError(f"unresolved ldd dependency: {line}") from error
        if (
            not name
            or name in names
            or ("=>" in line and (raw_name != name or "\\" in raw_name))
            or not path.is_absolute()
            or resolved.is_symlink()
            or not resolved.is_file()
        ):
            raise ReceiptError(f"invalid or duplicate ldd dependency: {line}")
        if name.lower().startswith(("libhs", "libhyperscan")):
            raise ReceiptError("Linux binary links Hyperscan dynamically")
        names.add(name)
        libraries.append({"name": name, "sha256": _file_sha256(resolved)})
    libraries.sort(key=lambda library: library["name"])
    if not libraries:
        raise ReceiptError("Linux binary runtime dependency graph is empty")
    if _file_sha256(linked_native_archive) != linked_rlib_digest:
        raise ReceiptError("captured linked hyperscan_sys rlib changed during derivation")
    value = {
        "artifact": {
            "name": "keyhog-linux-x86_64",
            "sha256": binary_digest,
        },
        "buildReceiptSha256": _file_sha256(build_receipt),
        "dynamicLibraries": libraries,
        "generator": GENERATOR,
        "linkMapSelectedMembers": selected_members,
        "linkMapSha256": link_map_digest,
        "nativeRlib": {
            "membersSha256": _members_sha256(rlib_members),
            "name": linked_path.name,
            "originalPath": linked_path_text,
            "sha256": linked_rlib_digest,
            "staticSuffixMembersSha256": _members_sha256(rlib_members),
        },
        "schema": NATIVE_LINK_SCHEMA,
        "source": source,
    }
    _write_receipt(output, value)
