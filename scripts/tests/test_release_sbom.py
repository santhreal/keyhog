"""Behavioral contracts for deterministic, fail-closed release SBOMs."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from typing import Any

from scripts.release_dependency_receipt import (
    DEPENDENCY_PROFILES,
    GENERATOR as RECEIPT_GENERATOR,
    NATIVE_BUILD_SCHEMA,
    NATIVE_LINK_SCHEMA,
    ReceiptError,
    _prove_tagged_source,
    derive_receipt as derive_dependency_receipt,
    generate_native_build_receipt,
    generate_native_link_receipt,
    receipt_from_metadata,
)
from scripts.release_sbom import (
    GENERATOR_NAME,
    GENERATOR_VERSION,
    SPDX_VERSION,
    SUPPORTED_ASSETS,
    ReleaseManifest,
    SbomError,
    create_release_manifest,
    generate_sboms,
    main,
    _validate_installer_sources,
    parse_cargo_lock,
    verify_sboms,
)

COMMIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_DATE": "2026-01-02T03:04:05+00:00",
    "GIT_COMMITTER_DATE": "2026-01-02T03:04:05+00:00",
}

_EXPECTED_RECEIPTS: dict[tuple[str, str], dict[str, Any]] = {}
def _derive_fixture_receipt(
    source_dir: Path, asset_name: str, tag: str
) -> dict[str, Any]:
    receipt = _EXPECTED_RECEIPTS[(str(source_dir.resolve()), asset_name)]
    if receipt["source"]["tag"] != tag:
        raise ReceiptError("fixture tag mismatch")
    return copy.deepcopy(receipt)
VALID_LOCK = b'''# generated test lock
version = 4

[[package]]
name = "keyhog"
version = "1.2.3"
dependencies = ["serde"]

[[package]]
name = "keyhog-scanner"
version = "1.2.3"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["itoa"]
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "itoa"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

[[package]]
name = "other-feature-only"
version = "9.9.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''


def _run(*arguments: str, cwd: Path, env: dict[str, str] | None = None) -> str:
    command = list(arguments)
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed with exit {completed.returncode} in {cwd}: {command!r}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed.stdout.strip()


def _write_ar(path: Path, members: list[tuple[str, bytes]]) -> None:
    content = bytearray(b"!<arch>\n")
    for name, body in members:
        encoded_name = (name + "/").encode("ascii")
        if len(encoded_name) > 16:
            raise ValueError("test ar member name is too long")
        header = (
            encoded_name.ljust(16)
            + b"0".ljust(12)
            + b"0".ljust(6)
            + b"0".ljust(6)
            + b"100644".ljust(8)
            + str(len(body)).encode("ascii").ljust(10)
            + b"`\n"
        )
        content.extend(header)
        content.extend(body)
        if len(body) % 2:
            content.extend(b"\n")
    path.write_bytes(content)


def _member_receipts(members: list[tuple[str, bytes]]) -> list[dict[str, Any]]:
    return [
        {
            "index": index,
            "name": name,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size": len(body),
        }
        for index, (name, body) in enumerate(members)
    ]


def _canonical_digest(value: Any) -> str:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class ReleaseFixture:
    def __init__(self, root: Path, lock_bytes: bytes = VALID_LOCK) -> None:
        self.root = root
        self.source = root / "source"
        self.assets = root / "assets"
        self.source.mkdir()
        self.assets.mkdir()
        (self.source / "Cargo.lock").write_bytes(lock_bytes)
        (self.source / "Cargo.toml").write_text(
            '[workspace]\nmembers = []\n', encoding="utf-8"
        )
        project_root = Path(__file__).resolve().parents[2]
        (self.source / "install.sh").write_bytes(
            (project_root / "install.sh").read_bytes()
        )
        (self.source / "install.ps1").write_bytes(
            (project_root / "install.ps1").read_bytes()
        )
        _run("git", "init", "-q", cwd=self.source)
        _run("git", "config", "user.name", "SBOM Test", cwd=self.source)
        _run("git", "config", "user.email", "sbom@example.invalid", cwd=self.source)
        _run(
            "git", "add", "Cargo.lock", "Cargo.toml", "install.sh", "install.ps1",
            cwd=self.source,
        )
        _run(
            "git",
            "commit",
            "-q",
            "-m",
            "tagged source",
            cwd=self.source,
            env=COMMIT_ENV,
        )
        self.commit = _run("git", "rev-parse", "HEAD", cwd=self.source)
        self.tag = "v1.2.3"
        _run("git", "tag", self.tag, cwd=self.source)
        self.tag_object = _run(
            "git", "rev-parse", f"refs/tags/{self.tag}", cwd=self.source
        )
        os.environ["KEYHOG_RELEASE_TAG_OBJECT"] = self.tag_object
        for index, name in enumerate(sorted(SUPPORTED_ASSETS), start=1):
            if name in {"install.sh", "install.ps1"}:
                content = (self.source / name).read_bytes()
            else:
                content = f"release bytes {index} for {name}\n".encode("ascii")
            (self.assets / name).write_bytes(content)
        metadata = {
            "packages": [
                {
                    "id": "keyhog",
                    "license": "MIT OR Apache-2.0",
                    "name": "keyhog",
                    "repository": "https://github.com/santhreal/keyhog",
                    "version": "1.2.3",
                    "source": None,
                },
                {
                    "id": "serde",
                    "name": "serde",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "MIT OR Apache-2.0",
                    "repository": "https://github.com/serde-rs/serde",
                },
                {
                    "id": "keyhog-scanner",
                    "name": "keyhog-scanner",
                    "version": "1.2.3",
                    "source": None,
                    "license": "MIT OR Apache-2.0",
                    "repository": "https://github.com/santhreal/keyhog",
                },
                {
                    "id": "itoa",
                    "name": "itoa",
                    "version": "1.0.0",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "MIT OR Apache-2.0",
                    "repository": "https://github.com/dtolnay/itoa",
                },
                {
                    "id": "other",
                    "name": "other-feature-only",
                    "version": "9.9.9",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "license": "MIT",
                    "repository": None,
                },
            ],
        }
        lock_digest = hashlib.sha256(lock_bytes).hexdigest()
        for name, (_target, root_name, _default, _features) in DEPENDENCY_PROFILES.items():
            tree_output = (
                f"0|{root_name} v1.2.3|portable\n"
                "1|serde v1.0.0|std\n"
                "2|itoa v1.0.0|\n"
            )
            receipt = receipt_from_metadata(
                metadata,
                tree_output=tree_output,
                asset_name=name,
                commit=self.commit,
                tag=self.tag,
                tag_object=self.tag_object,
                cargo_lock_sha256=lock_digest,
            )
            (self.assets / f"{name}.dependencies.json").write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            _EXPECTED_RECEIPTS[
                (str(self.source.resolve()), name)
            ] = copy.deepcopy(receipt)
        linux = self.assets / "keyhog-linux-x86_64"
        source = {
            "commit": self.commit,
            "tag": self.tag,
            "tagObject": self.tag_object,
        }
        static_members = _member_receipts([("database.o", b"database")])
        rlib_members = static_members
        native_build = {
            "artifact": {"name": linux.name},
            "generator": RECEIPT_GENERATOR,
            "hyperscanRoot": "/opt/keyhog-hyperscan",
            "schema": NATIVE_BUILD_SCHEMA,
            "source": source,
            "staticHyperscan": {
                "archiveFile": "lib/libhs.a",
                "archiveMembers": static_members,
                "archiveMembersSha256": _canonical_digest(static_members),
                "archiveSha256": "c" * 64,
                "license": "BSD-3-Clause",
                "name": "Hyperscan",
                "pkgConfigFile": "lib/pkgconfig/libhs.pc",
                "pkgConfigSha256": "f" * 64,
                "pkgConfigVersion": "1.8.1",
                "version": "5.4.2",
            },
        }
        build_path = self.assets / "keyhog-linux-x86_64.native-build.json"
        build_path.write_text(
            json.dumps(native_build, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        native_link = {
            "artifact": {
                "name": linux.name,
                "sha256": hashlib.sha256(linux.read_bytes()).hexdigest(),
            },
            "buildReceiptSha256": hashlib.sha256(build_path.read_bytes()).hexdigest(),
            "dynamicLibraries": [
                {"name": "libc.so.6", "sha256": "d" * 64},
            ],
            "generator": RECEIPT_GENERATOR,
            "linkMapSelectedMembers": ["database.o"],
            "linkMapSha256": "e" * 64,
            "nativeRlib": {
                "membersSha256": _canonical_digest(rlib_members),
                "name": "libhyperscan_sys-0123456789abcdef.rlib",
                "originalPath": (
                    "/tmp/rustcFixture/libhyperscan_sys-0123456789abcdef.rlib"
                ),
                "sha256": "b" * 64,
                "staticSuffixMembersSha256": _canonical_digest(static_members),
            },
            "schema": NATIVE_LINK_SCHEMA,
            "source": source,
        }
        (self.assets / "keyhog-linux-x86_64.native-link.json").write_text(
            json.dumps(native_link, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    def manifest(self) -> ReleaseManifest:
        return create_release_manifest(
            self.source, self.assets, self.assets, self.tag, self.commit
        )


class ReleaseSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.derive_patcher = mock.patch(
            "scripts.release_sbom.derive_receipt",
            side_effect=_derive_fixture_receipt,
        )
        self.derive_patcher.start()
        self.addCleanup(self.derive_patcher.stop)

    def test_deterministic_round_trip_and_cli_verification(self) -> None:
        """Prevent nondeterministic bytes or a CLI that cannot verify its own output."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            manifest_path = Path(directory) / "release-sbom-manifest.json"
            first = Path(directory) / "first"
            second = Path(directory) / "second"

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "manifest",
                            "--source-dir",
                            str(fixture.source),
                            "--asset-dir",
                            str(fixture.assets),
                            "--dependency-dir",
                            str(fixture.assets),
                            "--tag",
                            fixture.tag,
                            "--source-commit",
                            fixture.commit,
                            "--output",
                            str(manifest_path),
                        ]
                    ),
                    0,
                )
                for output in (first, second):
                    self.assertEqual(
                        main(
                            [
                                "generate",
                                "--source-dir",
                                str(fixture.source),
                                "--asset-dir",
                                str(fixture.assets),
                                "--dependency-dir",
                                str(fixture.assets),
                                "--manifest",
                                str(manifest_path),
                                "--output-dir",
                                str(output),
                            ]
                        ),
                        0,
                    )
                self.assertEqual(
                    main(
                        [
                            "verify",
                            "--source-dir",
                            str(fixture.source),
                            "--asset-dir",
                            str(fixture.assets),
                            "--dependency-dir",
                            str(fixture.assets),
                            "--manifest",
                            str(manifest_path),
                            "--output-dir",
                            str(first),
                        ]
                    ),
                    0,
                )

            self.assertEqual(
                {path.name: path.read_bytes() for path in first.iterdir()},
                {path.name: path.read_bytes() for path in second.iterdir()},
            )
            self.assertEqual(len(list(first.glob("*.spdx.json"))), 10)
            self.assertEqual(len(list(first.glob("*.spdx.json.sha256"))), 10)
            for checksum in first.glob("*.spdx.json.sha256"):
                sbom = first / checksum.name.removesuffix(".sha256")
                self.assertEqual(
                    checksum.read_text(encoding="ascii"),
                    f"{hashlib.sha256(sbom.read_bytes()).hexdigest()}  {sbom.name}\n",
                )

    def test_every_supported_target_has_bound_spdx_document(self) -> None:
        """Prevent target omissions and false binary/GPU/installer dependency semantics."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            manifest = fixture.manifest()
            output = Path(directory) / "sboms"
            generate_sboms(fixture.source, fixture.assets, fixture.assets, manifest, output)

            self.assertEqual(
                {path.name.removesuffix(".spdx.json") for path in output.glob("*.spdx.json")},
                set(SUPPORTED_ASSETS),
            )
            for artifact in manifest.artifacts:
                document = json.loads(
                    (output / f"{artifact.name}.spdx.json").read_text(encoding="utf-8")
                )
                metadata = json.loads(document["comment"])
                self.assertEqual(document["spdxVersion"], SPDX_VERSION)
                self.assertEqual(
                    document["creationInfo"]["creators"],
                    [f"Tool: {GENERATOR_NAME}-{GENERATOR_VERSION}"],
                )
                self.assertEqual(metadata["sourceCommit"], fixture.commit)
                self.assertEqual(metadata["cargoLockSha256"], manifest.cargo_lock_sha256)
                self.assertEqual(metadata["artifact"], artifact.value())
                self.assertEqual(metadata["artifact"]["target"], SUPPORTED_ASSETS[artifact.name][1])
                artifact_package = document["packages"][0]
                self.assertEqual(
                    artifact_package["checksums"],
                    [{"algorithm": "SHA256", "checksumValue": artifact.sha256}],
                )
                package_names = {
                    package["name"] for package in document["packages"][1:]
                }
                dependency_relationships = [
                    relationship
                    for relationship in document["relationships"]
                    if relationship["relationshipType"] == "DEPENDS_ON"
                ]
                if artifact.kind in {"binary", "gpu-bundle"}:
                    serde = next(
                        package
                        for package in document["packages"]
                        if package["name"] == "serde"
                    )
                    self.assertEqual(
                        serde["licenseDeclared"], "MIT OR Apache-2.0"
                    )
                    self.assertEqual(
                        serde["externalRefs"][0]["referenceLocator"],
                        "pkg:cargo/serde@1.0.0",
                    )
                    self.assertIn(
                        "https://github.com/serde-rs/serde",
                        serde["sourceInfo"],
                    )
                if artifact.kind == "binary":
                    expected = {"keyhog", "serde", "itoa"}
                    if artifact.name == "keyhog-linux-x86_64":
                        expected |= {"Hyperscan", "libc.so.6"}
                        self.assertEqual(
                            metadata["native"]["staticHyperscan"]["version"], "5.4.2"
                        )
                        hyperscan = next(
                            package
                            for package in document["packages"]
                            if package["name"] == "Hyperscan"
                        )
                        self.assertEqual(
                            hyperscan["checksums"][0]["checksumValue"], "c" * 64
                        )
                        static_links = [
                            relationship
                            for relationship in document["relationships"]
                            if relationship["relationshipType"] == "STATIC_LINK"
                        ]
                        self.assertEqual(len(static_links), 1)
                    self.assertEqual(package_names, expected)
                    self.assertNotIn("other-feature-only", package_names)
                    self.assertEqual(
                        len(dependency_relationships),
                        4 if artifact.name == "keyhog-linux-x86_64" else 3,
                    )
                elif artifact.kind == "gpu-bundle":
                    self.assertEqual(
                        package_names, {"keyhog-scanner", "serde", "itoa"}
                    )
                    generated = [
                        relationship
                        for relationship in document["relationships"]
                        if relationship["relationshipType"] == "GENERATED_FROM"
                    ]
                    self.assertEqual(len(generated), 1)
                    self.assertEqual(len(dependency_relationships), 2)
                else:
                    self.assertNotIn("Cargo.lock", artifact_package["sourceInfo"])
                    payloads = {
                        package["name"]: package
                        for package in document["packages"][1:]
                        if "checksums" in package
                    }
                    expected_payloads = {
                        candidate.name: candidate
                        for candidate in manifest.artifacts
                        if candidate.kind in {"binary", "gpu-bundle"}
                        and (
                            ("windows" in candidate.name)
                            == (artifact.name == "install.ps1")
                        )
                    }
                    self.assertEqual(set(payloads), set(expected_payloads))
                    for name, candidate in expected_payloads.items():
                        self.assertEqual(
                            payloads[name]["checksums"],
                            [
                                {
                                    "algorithm": "SHA256",
                                    "checksumValue": candidate.sha256,
                                }
                            ],
                        )
                    runtime_packages = {
                        package["name"]: package["SPDXID"]
                        for package in document["packages"]
                        if package["SPDXID"].startswith(
                            "SPDXRef-InstallerRuntime-"
                        )
                    }
                    expected_runtime = (
                        {
                            "sh", "awk", "basename", "cat", "chmod", "cp",
                            "curl", "cut", "date", "dirname", "docker", "find",
                            "git", "grep", "head", "ldd", "minisign", "mkdir",
                            "mktemp", "mv", "python3", "python", "rm", "sed",
                            "sha256sum", "shasum", "sleep", "sort", "tail",
                            "tar", "tr", "uname",
                        }
                        if artifact.name == "install.sh"
                        else {
                            "Windows PowerShell",
                            "Get-FileHash",
                            "Invoke-WebRequest",
                            "minisign",
                            "tar.exe",
                        }
                    )
                    self.assertEqual(set(runtime_packages), expected_runtime)
                    runtime_relationships = {
                        relationship["spdxElementId"]: relationship
                        for relationship in document["relationships"]
                        if relationship["spdxElementId"]
                        in set(runtime_packages.values())
                    }
                    self.assertEqual(
                        set(runtime_relationships), set(runtime_packages.values())
                    )
                    for relationship in runtime_relationships.values():
                        self.assertTrue(relationship.get("comment"))
                        self.assertIn(
                            relationship["relationshipType"],
                            {"RUNTIME_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF"},
                        )
                    required_names = (
                        {
                            "sh", "awk", "basename", "cat", "chmod", "dirname",
                            "grep", "mkdir", "mktemp", "mv", "rm", "sed",
                        }
                        if artifact.name == "install.sh"
                        else {"Windows PowerShell", "Get-FileHash"}
                    )
                    actual_required = {
                        name
                        for name, identifier in runtime_packages.items()
                        if runtime_relationships[identifier]["relationshipType"]
                        == "RUNTIME_DEPENDENCY_OF"
                    }
                    self.assertEqual(actual_required, required_names)

    def test_installer_command_surface_requires_explicit_sbom_review(self) -> None:
        """Prevent a newly invoked installer command from inheriting stale tool dependencies."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            _validate_installer_sources(
                fixture.source, fixture.assets, fixture.commit
            )
            script = fixture.source / "install.sh"
            script.write_bytes(script.read_bytes() + b"\nnew-runtime-tool --version\n")
            (fixture.assets / "install.sh").write_bytes(script.read_bytes())
            _run("git", "add", "install.sh", cwd=fixture.source)
            _run(
                "git", "commit", "-q", "-m", "new installer command",
                cwd=fixture.source, env=COMMIT_ENV,
            )
            changed_commit = _run(
                "git", "rev-parse", "HEAD", cwd=fixture.source
            )
            with self.assertRaisesRegex(SbomError, "has not been reviewed"):
                _validate_installer_sources(
                    fixture.source, fixture.assets, changed_commit
                )

    def test_source_and_artifact_digest_mismatches_fail_closed(self) -> None:
        """Prevent substituted source or payload bytes from inheriting trusted SBOMs."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            manifest = fixture.manifest()
            bad_source_value = manifest.value()
            bad_source_value["source"]["cargoLockSha256"] = "0" * 64
            with self.assertRaisesRegex(SbomError, "Cargo.lock digest does not match"):
                generate_sboms(fixture.source, fixture.assets, fixture.assets, ReleaseManifest.from_value(bad_source_value), Path(directory) / "source-mismatch")
            (fixture.source / "Cargo.lock").write_bytes(VALID_LOCK + b"\n# modified\n")
            with self.assertRaisesRegex(SbomError, "tracked changes"):
                generate_sboms(fixture.source, fixture.assets, fixture.assets, manifest, Path(directory) / "dirty-source")
            (fixture.source / "Cargo.lock").write_bytes(VALID_LOCK)


            (fixture.assets / "keyhog-linux-x86_64").write_bytes(b"substituted\n")
            with self.assertRaisesRegex(SbomError, "does not match manifest"):
                generate_sboms(fixture.source, fixture.assets, fixture.assets, manifest, Path(directory) / "artifact-mismatch")

    def test_tag_or_checkout_commit_mismatch_fails_closed(self) -> None:
        """Prevent an untagged checkout from producing evidence for a release tag."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            manifest = fixture.manifest()
            (fixture.source / "next").write_text("different source\n", encoding="utf-8")
            _run("git", "add", "next", cwd=fixture.source)
            _run(
                "git",
                "commit",
                "-q",
                "-m",
                "different checkout",
                cwd=fixture.source,
                env=COMMIT_ENV,
            )
            with self.assertRaisesRegex(SbomError, "does not match tag"):
                generate_sboms(fixture.source, fixture.assets, fixture.assets, manifest, Path(directory) / "commit-mismatch")

    def test_malformed_lockfile_and_manifest_are_rejected(self) -> None:
        """Prevent malformed or duplicate-key inputs from being partially accepted."""
        malformed_locks = (
            b"this is not toml = [",
            b'version = 2\n[[package]]\nname = "x"\nversion = "1"\n',
            b'version = 4\n[[package]]\nname = "x"\nversion = "1"\nsource = "registry+x"\n',
        )
        for lock_bytes in malformed_locks:
            with self.subTest(lock_bytes=lock_bytes):
                with self.assertRaises(SbomError):
                    parse_cargo_lock(lock_bytes)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text('{"schema":"one","schema":"two"}\n', encoding="utf-8")
            with self.assertRaisesRegex(SbomError, "duplicate JSON key"):
                ReleaseManifest.read(path)

    def test_dependency_receipt_executes_exact_offline_cargo_profile(self) -> None:
        """Prevent mocked validators from hiding the real Cargo re-derivation contract."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            asset_name = "keyhog-linux-x86_64"
            expected = json.loads(
                (
                    fixture.assets / f"{asset_name}.dependencies.json"
                ).read_text(encoding="utf-8")
            )
            metadata = {
                "packages": [
                    {
                        "id": package["name"],
                        "license": package["license"],
                        "name": package["name"],
                        "repository": package["repository"],
                        "source": package["source"],
                        "version": package["version"],
                    }
                    for package in expected["packages"]
                ]
            }
            real_check_output = subprocess.check_output
            cargo_commands: list[list[str]] = []

            def checked_output(command: list[str], *args: Any, **kwargs: Any) -> Any:
                if command[0] != "/verified/cargo":
                    return real_check_output(command, *args, **kwargs)
                cargo_commands.append(command)
                if command[1] == "tree":
                    return "\n".join(expected["cargoTree"]) + "\n"
                return json.dumps(metadata).encode()

            with mock.patch.dict(
                os.environ, {"CARGO_BIN": "/verified/cargo"}
            ), mock.patch(
                "scripts.release_dependency_receipt.subprocess.check_output",
                side_effect=checked_output,
            ):
                self.assertEqual(
                    derive_dependency_receipt(
                        fixture.source, asset_name, fixture.tag
                    ),
                    expected,
                )
            self.assertEqual(len(cargo_commands), 2)
            self.assertTrue(
                all(command[0] == "/verified/cargo" for command in cargo_commands)
            )
            tree, metadata_command = cargo_commands
            self.assertIn("--offline", tree)
            self.assertIn("x86_64-unknown-linux-gnu", tree)
            self.assertIn("static-hyperscan", tree)
            self.assertIn("--offline", metadata_command)
            self.assertIn(
                "keyhog/static-hyperscan",
                metadata_command,
            )

    def test_dependency_receipt_rejects_empty_cargo_binary(self) -> None:
        """Prevent an empty trusted executable setting from falling back to ambient Cargo."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            with mock.patch.dict(os.environ, {"CARGO_BIN": ""}):
                with self.assertRaisesRegex(
                    ReceiptError, "CARGO_BIN must name the trusted Cargo executable"
                ):
                    derive_dependency_receipt(
                        fixture.source, "keyhog-linux-x86_64", fixture.tag
                    )

    def test_dependency_receipt_requires_exact_clean_tagged_inputs(self) -> None:
        """Prevent dirty, hidden, or Cargo-config-poisoned source receipts."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            commit, tag_object, lock_bytes = _prove_tagged_source(
                fixture.source, fixture.tag
            )
            self.assertEqual(commit, fixture.commit)
            self.assertEqual(tag_object, fixture.tag_object)
            self.assertEqual(lock_bytes, VALID_LOCK)
            (fixture.source / "Cargo.toml").write_text(
                "[workspace]\nmembers = [\"modified\"]\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ReceiptError, "tracked changes"):
                _prove_tagged_source(fixture.source, fixture.tag)

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            cargo_config = fixture.source / ".cargo"
            cargo_config.mkdir()
            (cargo_config / "config.toml").write_text(
                '[source.crates-io]\nreplace-with = "poison"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReceiptError, "untracked source input"):
                _prove_tagged_source(fixture.source, fixture.tag)

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            _run(
                "git",
                "update-index",
                "--assume-unchanged",
                "Cargo.lock",
                cwd=fixture.source,
            )
            (fixture.source / "Cargo.lock").write_bytes(VALID_LOCK + b"\n# hidden drift\n")
            with self.assertRaisesRegex(ReceiptError, "does not match tag"):
                _prove_tagged_source(fixture.source, fixture.tag)

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            (fixture.source / "next").write_text("untagged commit\n", encoding="utf-8")
            _run("git", "add", "next", cwd=fixture.source)
            _run(
                "git",
                "commit",
                "-q",
                "-m",
                "untagged build source",
                cwd=fixture.source,
                env=COMMIT_ENV,
            )
            with self.assertRaisesRegex(ReceiptError, "does not match tag"):
                _prove_tagged_source(fixture.source, fixture.tag)

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            allowed = fixture.source / "keyhog-linux-x86_64.native-build.json"
            allowed.write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                _prove_tagged_source(fixture.source, fixture.tag)[0],
                fixture.commit,
            )
            allowed.unlink()
            nested = fixture.source / "nested"
            nested.mkdir()
            (nested / allowed.name).write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ReceiptError, "untracked source input"):
                _prove_tagged_source(fixture.source, fixture.tag)
            (nested / allowed.name).unlink()
            nested.rmdir()

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            with mock.patch.dict(
                os.environ,
                {"KEYHOG_RELEASE_TAG_OBJECT": "0" * 40},
            ):
                with self.assertRaisesRegex(ReceiptError, "tag object"):
                    _prove_tagged_source(fixture.source, fixture.tag)

    def test_missing_locked_package_is_rejected(self) -> None:
        """Prevent unresolved Cargo edges from silently dropping locked packages."""
        missing_dependency = b'''version = 4\n[[package]]\nname = "keyhog-cli"\nversion = "1.2.3"\ndependencies = ["not-locked 9.9.9"]\n'''
        with self.assertRaisesRegex(SbomError, "resolves to 0 locked packages"):
            parse_cargo_lock(missing_dependency)

    def test_missing_release_asset_and_incomplete_manifest_are_rejected(self) -> None:
        """Prevent publication when any payload, receipt, or manifest entry is absent."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            (fixture.assets / "install.ps1").unlink()
            with self.assertRaisesRegex(SbomError, "regular non-symlink file"):
                fixture.manifest()

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            asset = fixture.assets / "install.sh"
            asset.unlink()
            asset.symlink_to(fixture.assets / "install.ps1")
            with self.assertRaisesRegex(SbomError, "non-symlink"):
                fixture.manifest()

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            (fixture.assets / "install.sh").write_bytes(b"substituted installer\n")
            with self.assertRaisesRegex(SbomError, "does not match tagged source"):
                fixture.manifest()

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            (fixture.assets / "keyhog-linux-x86_64.dependencies.json").unlink()
            with self.assertRaisesRegex(SbomError, "regular non-symlink file"):
                fixture.manifest()

        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            value: dict[str, Any] = fixture.manifest().value()
            value["artifacts"] = value["artifacts"][:-1]
            with self.assertRaisesRegex(SbomError, "manifest is incomplete"):
                ReleaseManifest.from_value(value)

    def test_dependency_receipt_digest_drift_is_rejected(self) -> None:
        """Prevent cross-job dependency receipt substitution after manifest binding."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            manifest = fixture.manifest()
            receipt = fixture.assets / "keyhog-linux-x86_64.dependencies.json"
            receipt.write_bytes(receipt.read_bytes() + b" ")
            with self.assertRaisesRegex(SbomError, "receipt digest does not match"):
                generate_sboms(
                    fixture.source,
                    fixture.assets,
                    fixture.assets,
                    manifest,
                    Path(directory) / "receipt-drift",
                )

    def test_native_receipt_rejects_static_provenance_drift(self) -> None:
        """Prevent dynamic or wrongly identified static Hyperscan provenance."""
        for case in ("dynamic-hyperscan", "version", "archive-hash", "pkg-config-hash"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = ReleaseFixture(Path(directory))
                build_path = fixture.assets / "keyhog-linux-x86_64.native-build.json"
                link_path = fixture.assets / "keyhog-linux-x86_64.native-link.json"
                path = link_path if case == "dynamic-hyperscan" else build_path
                receipt = json.loads(path.read_text(encoding="utf-8"))
                if case == "dynamic-hyperscan":
                    receipt["dynamicLibraries"].append(
                        {"name": "libhs.so.5", "sha256": "f" * 64}
                    )
                elif case == "version":
                    receipt["staticHyperscan"]["version"] = "5.4.3"
                elif case == "archive-hash":
                    receipt["staticHyperscan"]["archiveSha256"] = "x" * 64
                else:
                    receipt["staticHyperscan"]["pkgConfigSha256"] = "x" * 64
                path.write_text(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(SbomError):
                    fixture.manifest()

    def test_native_build_and_link_receipts_bind_exact_files(self) -> None:
        """Prevent archive/rlib/link-map twins from breaking the static-link chain."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            hyperscan = Path(directory) / "hyperscan"
            archive = hyperscan / "lib" / "libhs.a"
            pc_file = hyperscan / "lib" / "pkgconfig" / "libhs.pc"
            archive.parent.mkdir(parents=True)
            pc_file.parent.mkdir(parents=True)
            static_members = [
                ("duplicate.o", b"first duplicate"),
                ("duplicate.o", b"second duplicate"),
                ("hs_scan.o", b"scanner"),
            ]
            _write_ar(archive, static_members)
            pc_file.write_bytes(b"Version: 5.4.2\n")
            binary = Path(directory) / "keyhog-linux-x86_64"
            binary.write_bytes(b"linked binary\n")
            runtime = Path(directory) / "libc.so.6"
            runtime.write_bytes(b"runtime library\n")
            build_path = Path(directory) / "native-build.json"
            link_path = Path(directory) / "native-link.json"
            link_map = fixture.source / "keyhog-linux-x86_64.link.map"
            linked_archive = Path(directory) / "linked-native.rlib"
            linked_path = Path(directory) / "linked-native.path"
            original_rlib = (
                "/tmp/keyhog-rustc/libhyperscan_sys-0123456789abcdef.rlib"
            )
            linked_path.write_text(original_rlib + "\n", encoding="utf-8")
            archive_selection = "".join(
                f"{original_rlib}({name})\n" for name, _body in static_members
            )
            ignored_references = "".join(
                f"{original_rlib}(duplicate.o)\n" for _ in range(20)
            )
            expected_map = (
                archive_selection
                + "\nDiscarded input sections\n"
                + ignored_references
            )
            real_check_output = subprocess.check_output
            ldd_output = [f"libc.so.6 => {runtime} (0x1)\n"]

            def checked_output(command: list[str], *args: Any, **kwargs: Any) -> Any:
                if command[:2] == ["pkg-config", "--modversion"]:
                    return "5.4.2\n"
                if command[:2] == ["pkg-config", "--version"]:
                    return "1.8.1\n"
                if command[0] == "ldd":
                    return ldd_output[0]
                return real_check_output(command, *args, **kwargs)

            def link_once() -> None:
                generate_native_link_receipt(
                    fixture.source,
                    fixture.tag,
                    binary,
                    build_path,
                    link_map,
                    linked_archive,
                    linked_path,
                    link_path,
                )

            with mock.patch(
                "scripts.release_dependency_receipt.subprocess.check_output",
                side_effect=checked_output,
            ):
                generate_native_build_receipt(
                    fixture.source,
                    fixture.tag,
                    hyperscan,
                    build_path,
                )
                link_map.write_text(expected_map, encoding="utf-8")
                _write_ar(linked_archive, static_members)

                _write_ar(archive, list(reversed(static_members)))
                with self.assertRaisesRegex(ReceiptError, "changed"):
                    link_once()
                _write_ar(archive, static_members)

                adversarial_rlibs = {
                    "decoy": [("decoy.o", b"decoy")] + static_members,
                    "missing": static_members[:-1],
                    "extra": static_members + [("extra.o", b"extra")],
                }
                for case, members in adversarial_rlibs.items():
                    with self.subTest(case=case):
                        _write_ar(linked_archive, members)
                        with self.assertRaisesRegex(ReceiptError, "does not embed"):
                            link_once()

                _write_ar(linked_archive, static_members)
                link_once()
                link = json.loads(link_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    link["artifact"]["sha256"],
                    hashlib.sha256(binary.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    link["linkMapSelectedMembers"],
                    [name for name, _body in static_members],
                )
                self.assertEqual(
                    link["nativeRlib"]["sha256"],
                    hashlib.sha256(linked_archive.read_bytes()).hexdigest(),
                )

                _write_ar(
                    linked_archive,
                    static_members[:-1] + [("hs_scan.o", b"altered")],
                )
                with self.assertRaisesRegex(ReceiptError, "does not embed"):
                    link_once()
                _write_ar(linked_archive, static_members)

                other_rlib = (
                    "/tmp/keyhog-rustc/libhyperscan_sys-fedcba9876543210.rlib"
                )
                link_map.write_text(
                    f"{other_rlib}(hs_scan.o)\n"
                    "\nDiscarded input sections\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ReceiptError, "exclusively reference"):
                    link_once()

                link_map.write_text(
                    archive_selection
                    + f"{original_rlib}(rust.o)\n"
                    + "\nDiscarded input sections\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ReceiptError, "outside"):
                    link_once()

                link_map.write_text(expected_map, encoding="utf-8")
                ldd_output[0] = f"fake/libc.so.6 => {runtime} (0x1)\n"
                with self.assertRaisesRegex(ReceiptError, "invalid"):
                    link_once()

    def test_pre_manifest_rejects_inexact_cargo_closures(self) -> None:
        """Prevent graph-shape, license, or source identity tampering."""
        for case in ("root-only", "subset", "extra", "edge", "license", "source"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                fixture = ReleaseFixture(Path(directory))
                path = fixture.assets / "keyhog-linux-x86_64.dependencies.json"
                receipt = json.loads(path.read_text(encoding="utf-8"))
                root = receipt["profile"]["root"]
                if case == "root-only":
                    root_package = next(
                        package
                        for package in receipt["packages"]
                        if "\0".join(
                            (
                                package["name"],
                                package["version"],
                                package["source"] or "workspace",
                            )
                        )
                        == root
                    )
                    root_package["dependencies"] = []
                    receipt["packages"] = [root_package]
                elif case == "subset":
                    receipt["packages"] = [
                        package
                        for package in receipt["packages"]
                        if package["name"] != "itoa"
                    ]
                    next(
                        package
                        for package in receipt["packages"]
                        if package["name"] == "serde"
                    )["dependencies"] = []
                elif case == "extra":
                    receipt["packages"].append(
                        {
                            "dependencies": [],
                            "features": [],
                            "name": "other-feature-only",
                            "source": "registry+https://github.com/rust-lang/crates.io-index",
                            "version": "9.9.9",
                        }
                    )
                    receipt["packages"].sort(
                        key=lambda package: "\0".join(
                            (
                                package["name"],
                                package["version"],
                                package["source"] or "workspace",
                            )
                        )
                    )
                elif case == "edge":
                    next(
                        package
                        for package in receipt["packages"]
                        if package["name"] == "keyhog"
                    )["dependencies"] = []
                elif case == "license":
                    next(
                        package
                        for package in receipt["packages"]
                        if package["name"] == "keyhog"
                    )["license"] = "GPL-3.0-only"
                else:
                    next(
                        package
                        for package in receipt["packages"]
                        if package["name"] == "serde"
                    )["source"] = "registry+https://example.invalid/index"
                graph = {"packages": receipt["packages"], "root": root}
                receipt["graphSha256"] = hashlib.sha256(
                    (
                        json.dumps(graph, sort_keys=True, separators=(",", ":"))
                        + "\n"
                    ).encode()
                ).hexdigest()
                path.write_text(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":"))
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(SbomError):
                    fixture.manifest()

    def test_verify_rejects_sbom_checksum_drift_and_incomplete_output(self) -> None:
        """Prevent checksum drift or incomplete deterministic SPDX inventories."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = ReleaseFixture(Path(directory))
            manifest = fixture.manifest()
            output = Path(directory) / "sboms"
            generate_sboms(fixture.source, fixture.assets, fixture.assets, manifest, output)
            checksum = output / "install.sh.spdx.json.sha256"
            checksum.write_text("0" * 64 + "  install.sh.spdx.json\n", encoding="ascii")
            with self.assertRaisesRegex(SbomError, "checksum does not match"):
                verify_sboms(fixture.source, fixture.assets, fixture.assets, manifest, output)

            checksum.unlink()
            with self.assertRaisesRegex(SbomError, "output inventory is incomplete"):
                verify_sboms(fixture.source, fixture.assets, fixture.assets, manifest, output)


class WorkflowReceiptIsolationTests(unittest.TestCase):
    def test_sign_and_smoke_rederive_from_clean_nested_source_checkout(self) -> None:
        """Prevents sibling automation/artifact workdirs from dirtying real Cargo proof."""
        workflow = (
            Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")
        self.assertGreaterEqual(workflow.count("path: source"), 2)
        self.assertGreaterEqual(
            workflow.count('--source-dir "$GITHUB_WORKSPACE/source"'), 4
        )
        self.assertNotIn("--allow-untracked-path", workflow)

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "source"
            (source / "src").mkdir(parents=True)
            (source / "Cargo.toml").write_text(
                "[package]\n"
                'name = "keyhog"\n'
                'version = "0.5.48"\n'
                'edition = "2021"\n\n'
                "[features]\n"
                "default = []\n"
                "static-hyperscan = []\n",
                encoding="utf-8",
            )
            (source / "src" / "main.rs").write_text(
                'fn main() { println!("fixture"); }\n', encoding="utf-8"
            )
            _run(os.environ.get("CARGO_BIN", "cargo"), "generate-lockfile", "--offline", cwd=source)
            _run("git", "init", "-q", cwd=source)
            _run("git", "config", "user.name", "Release Test", cwd=source)
            _run("git", "config", "user.email", "release@example.invalid", cwd=source)
            _run("git", "add", ".", cwd=source)
            _run("git", "commit", "-q", "-m", "fixture", cwd=source, env=COMMIT_ENV)
            tag = "v0.5.48"
            _run(
                "git",
                "tag",
                "-a",
                tag,
                "-m",
                "fixture tag",
                cwd=source,
                env=COMMIT_ENV,
            )
            tag_object = subprocess.check_output(
                ["git", "-C", str(source), "rev-parse", tag], text=True
            ).strip()

            for sibling in (
                "automation",
                "keyhog-release-dist",
                "keyhog-release-signed",
                "keyhog-linux-candidate",
                "keyhog-sbom-candidate",
            ):
                path = workspace / sibling
                path.mkdir()
                (path / "workflow-output").write_text("outside source\n", encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {"KEYHOG_RELEASE_TAG_OBJECT": tag_object},
            ):
                sign_receipt = derive_dependency_receipt(
                    source, "keyhog-linux-x86_64", tag
                )
                smoke_receipt = derive_dependency_receipt(
                    source, "keyhog-linux-x86_64", tag
                )

            self.assertEqual(sign_receipt, smoke_receipt)
            self.assertEqual(sign_receipt["source"]["tagObject"], tag_object)
            self.assertEqual(sign_receipt["artifact"]["name"], "keyhog-linux-x86_64")


if __name__ == "__main__":
    unittest.main()
