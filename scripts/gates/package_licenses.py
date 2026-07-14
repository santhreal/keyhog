#!/usr/bin/env python3
"""Verify canonical license bytes in publishable crates and package archives."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


REPO = Path(__file__).resolve().parents[2]
LICENSE_NAMES = ("LICENSE-MIT", "LICENSE-APACHE")


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    root: Path

    @property
    def archive_root(self) -> str:
        return f"{self.name}-{self.version}"


def load_toml(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def is_publishable(package: dict[str, object]) -> bool:
    publish = package.get("publish", True)
    return publish is not False and publish != []


def package_version(package: dict[str, object], workspace_version: str) -> str:
    version = package.get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        return workspace_version
    raise ValueError("package.version must be a string or inherit from the workspace")


def publishable_packages(repo: Path) -> list[Package]:
    root_manifest = load_toml(repo / "Cargo.toml")
    workspace = root_manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise ValueError("root Cargo.toml has no [workspace] table")
    workspace_package = workspace.get("package")
    if not isinstance(workspace_package, dict) or not isinstance(
        workspace_package.get("version"), str
    ):
        raise ValueError("root Cargo.toml has no [workspace.package] version")
    workspace_version = workspace_package["version"]
    members = workspace.get("members")
    if not isinstance(members, list) or not all(isinstance(item, str) for item in members):
        raise ValueError("root Cargo.toml workspace.members must be a string array")

    manifests: set[Path] = set()
    for member in members:
        matches = sorted(repo.glob(member))
        if not matches:
            raise ValueError(f"workspace member pattern has no matches: {member}")
        for match in matches:
            manifest = match / "Cargo.toml" if match.is_dir() else match
            if not manifest.is_file():
                raise ValueError(f"workspace member has no Cargo.toml: {match}")
            manifests.add(manifest.resolve())

    packages: list[Package] = []
    for manifest in sorted(manifests):
        document = load_toml(manifest)
        package = document.get("package")
        if not isinstance(package, dict):
            raise ValueError(f"{manifest.relative_to(repo)} has no [package] table")
        if not is_publishable(package):
            continue
        name = package.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{manifest.relative_to(repo)} has no package name")
        version = package_version(package, workspace_version)
        packages.append(Package(name=name, version=version, root=manifest.parent))
    if not packages:
        raise ValueError("workspace has no publishable packages")
    archive_roots = [package.archive_root for package in packages]
    if len(archive_roots) != len(set(archive_roots)):
        raise ValueError("publishable packages do not have unique name/version identities")
    return packages


def cargo_metadata(repo: Path) -> dict[str, object]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
    ]
    completed = subprocess.run(
        command,
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(f"cargo metadata failed: {detail}")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("cargo metadata did not return an object")
    return document


def validate_publish_tiers(
    repo: Path, packages: list[Package], tiers: list[list[str]]
) -> list[str]:
    failures: list[str] = []
    declared = [name for tier in tiers for name in tier]
    duplicates = sorted({name for name in declared if declared.count(name) > 1})
    if duplicates:
        failures.append("packages appear in multiple publish tiers: " + ", ".join(duplicates))

    expected = {package.name for package in packages}
    actual = set(declared)
    missing = sorted(expected - actual)
    foreign = sorted(actual - expected)
    if missing:
        failures.append("publish tiers omit packages: " + ", ".join(missing))
    if foreign:
        failures.append("publish tiers contain unknown packages: " + ", ".join(foreign))
    if failures:
        return failures

    tier_index = {
        package_name: index
        for index, tier in enumerate(tiers)
        for package_name in tier
    }
    metadata = cargo_metadata(repo)
    metadata_packages = metadata.get("packages")
    if not isinstance(metadata_packages, list):
        return ["cargo metadata has no packages array"]
    by_name = {
        package.get("name"): package
        for package in metadata_packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }
    for package in packages:
        metadata_package = by_name.get(package.name)
        if not isinstance(metadata_package, dict):
            failures.append(f"cargo metadata omitted publishable package {package.name}")
            continue
        dependencies = metadata_package.get("dependencies")
        if not isinstance(dependencies, list):
            failures.append(f"cargo metadata omitted dependencies for {package.name}")
            continue
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                failures.append(f"cargo metadata contains an invalid dependency for {package.name}")
                continue
            dependency_name = dependency.get("name")
            dependency_kind = dependency.get("kind")
            if dependency_name not in expected or dependency_kind not in (None, "build"):
                continue
            if tier_index[dependency_name] >= tier_index[package.name]:
                kind = "build" if dependency_kind == "build" else "normal"
                failures.append(
                    f"{package.name} tier {tier_index[package.name] + 1} has a {kind} "
                    f"dependency on {dependency_name} tier {tier_index[dependency_name] + 1}; "
                    "internal publish dependencies must be in an earlier tier"
                )
    return failures


def canonical_licenses(repo: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for name in LICENSE_NAMES:
        path = repo / name
        if not path.is_file():
            raise ValueError(f"missing canonical license: {path}")
        payloads[name] = path.read_bytes()
    return payloads


def verify_crate_roots(
    repo: Path, packages: list[Package], canonical: dict[str, bytes]
) -> list[str]:
    failures: list[str] = []
    for package in packages:
        relative_root = package.root.relative_to(repo)
        for name, expected in canonical.items():
            path = package.root / name
            if not path.is_file():
                failures.append(f"{relative_root}: missing {name}")
                continue
            actual = path.read_bytes()
            if actual != expected:
                failures.append(
                    f"{relative_root}/{name}: bytes differ from root {name} "
                    f"(expected {len(expected)}, found {len(actual)})"
                )
    return failures


def archive_package(members: list[tarfile.TarInfo], packages: list[Package]) -> Package:
    roots: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(f"unsafe archive member path: {member.name!r}")
        if path.parts:
            roots.add(path.parts[0])
    matches = [package for package in packages if package.archive_root in roots]
    if len(matches) != 1:
        expected = ", ".join(package.archive_root for package in packages)
        raise ValueError(
            f"expected exactly one publishable package root ({expected}); "
            f"found {', '.join(sorted(roots)) or 'none'}"
        )
    package = matches[0]
    foreign_roots = roots - {package.archive_root}
    if foreign_roots:
        raise ValueError(f"contains foreign top-level roots: {', '.join(sorted(foreign_roots))}")
    return package


def verify_archive(
    archive_path: Path, packages: list[Package], canonical: dict[str, bytes]
) -> tuple[Package | None, list[str]]:
    failures: list[str] = []
    try:
        with tarfile.open(archive_path, mode="r:*") as archive:
            members = archive.getmembers()
            package = archive_package(members, packages)
            for name, expected in canonical.items():
                member_name = f"{package.archive_root}/{name}"
                matches = [member for member in members if member.name == member_name]
                if len(matches) != 1:
                    failures.append(
                        f"{archive_path}: expected one {member_name}, found {len(matches)}"
                    )
                    continue
                member = matches[0]
                if not member.isfile():
                    failures.append(f"{archive_path}: {member_name} is not a regular file")
                    continue
                if member.size != len(expected):
                    failures.append(
                        f"{archive_path}: {member_name} has {member.size} bytes, "
                        f"expected {len(expected)}"
                    )
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    failures.append(f"{archive_path}: cannot read {member_name}")
                    continue
                actual = extracted.read(len(expected) + 1)
                if actual != expected:
                    failures.append(
                        f"{archive_path}: {member_name} bytes differ from root {name}"
                    )
            return package, failures
    except (OSError, tarfile.TarError, ValueError) as error:
        failures.append(f"{archive_path}: {error}")
        return None, failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-package-names",
        action="store_true",
        help="print the discovered publishable package names and exit",
    )
    parser.add_argument(
        "--require-all-archives",
        action="store_true",
        help="require exactly one archive for every publishable package",
    )
    parser.add_argument(
        "--publish-tier",
        action="append",
        nargs="+",
        default=[],
        metavar="PACKAGE",
        help="declare one ordered publish tier and validate internal dependency edges",
    )
    parser.add_argument(
        "archives",
        nargs="*",
        type=Path,
        help="generated .crate archives to inspect in addition to crate roots",
    )
    args = parser.parse_args(argv)

    try:
        packages = publishable_packages(REPO)
        if args.print_package_names:
            if args.archives or args.require_all_archives or args.publish_tier:
                parser.error("--print-package-names cannot be combined with archive checks")
            for package in packages:
                print(package.name)
            return 0
        if args.publish_tier:
            if args.archives or args.require_all_archives:
                parser.error("--publish-tier cannot be combined with archive checks")
            failures = validate_publish_tiers(REPO, packages, args.publish_tier)
            if failures:
                print("Publish tier verification failed:", file=sys.stderr)
                for failure in failures:
                    print(f"- {failure}", file=sys.stderr)
                return 1
            print(
                f"validated {len(packages)} publishable packages across "
                f"{len(args.publish_tier)} dependency-ordered tiers"
            )
            return 0
        canonical = canonical_licenses(REPO)
    except (OSError, tomllib.TOMLDecodeError, ValueError) as error:
        print(f"package license gate could not load repository metadata: {error}", file=sys.stderr)
        return 1

    failures = verify_crate_roots(REPO, packages, canonical)
    checked_archives: set[str] = set()
    for raw_archive in args.archives:
        archive_path = raw_archive.resolve()
        if archive_path.suffix != ".crate":
            failures.append(f"{raw_archive}: archive path must end in .crate")
            continue
        if not archive_path.is_file():
            failures.append(f"{raw_archive}: archive does not exist or is not a file")
            continue
        package, archive_failures = verify_archive(archive_path, packages, canonical)
        failures.extend(archive_failures)
        if package is not None:
            if package.name in checked_archives:
                failures.append(f"{raw_archive}: duplicate archive for {package.name}")
            checked_archives.add(package.name)

    if args.require_all_archives:
        missing = sorted({package.name for package in packages} - checked_archives)
        if missing:
            failures.append(
                "missing package archives for: " + ", ".join(missing)
            )

    if failures:
        print("Package license verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        f"verified canonical license bytes in {len(packages)} publishable crate roots"
        f" and {len(checked_archives)} package archives"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
