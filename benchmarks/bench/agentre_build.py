"""Reproducible, nonexecuting build of the pinned AgentRE Linux binaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Mapping

from .agentre_provenance import LINUX_TASKS, SOURCE_ARTIFACTS
from .corpora.agentre_recovery import (
    AgentREMaterializationError,
    AgentRERecoveryMaterializer,
)

GCC_IMAGE = (
    "docker.io/library/gcc@"
    "sha256:82549aa8f90ada3236a8be70c74543132a76662ef33f0c3271ed802b81584a82"
)
GCC_IMAGE_DIGEST = GCC_IMAGE.rsplit("@", 1)[1]
BUILD_SCHEMA = "agentre-linux-build-v2"
BUILD_TIMEOUT_SECONDS = 120
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_BINARY_SHA256 = {
    "level1_TCPServer": "ec0d8f5fd74780825d3f017edd225e3c44439345777d50ba93ff8f4c8017f85b",
    "level2_XorEncodedStrings": "cbb074b86229804be71df95f056dca953450fcc32e14d83c4be083d9410b1674",
    "level3_anti-debugging_reverseShell": "010728e492b16402d5f584b164c2a26c798c818afbeb880ed80049efad0561de",
    "level4_polymorphicReverseShell": "3e748366fd41ce8161234b5aa61ec7a7789e684f30c0aeb692da41a7cd1a705c",
    "level5_MultistageReverseShell": "d70c0434153e73235a89230f46ca240129e71f5ae586169ce67627181ebebbfe",
    "level6_ICMP_Covert_Channel_Shell": "792f8bce9597ab607667cbb742a594a1590391c87e4a392f9e0f0c57fb900c88",
    "level7_DNS_TunnelReverse_Shell": "5721a08211e1e75e2c367641364ddd92a26b6202c4aac3fac0afecb515fa5243",
    "level8_Process_hollowing_reverse_shell": "bf2e709646bdba99370fba89857e262e9c083f0ee217a4a28d54827c4608d834",
    "level9_SharedObjectInjectionReverseShell": "25f55d69cfbfd854e54f165db38d605fadf022e1ffbd3fa3195e73b639e52bc6",
    "level10_fully_obfuscated_AES_Encrypted_Shell": "2d3a81aa5d48f3e4e67d475e39108baaceb265e70351d5517a0ce38f7580c5ff",
    "level11_ForkBombReverseShell": "089cb2fd287cfdc412e4a33678bb12953e7d66f48ee0f52def8fab8e545b18cc",
    "level12_JIT_Compiled_Shellcode": "783e294cb5f743a2378584527bf979ddbc5c22dcdae6c0742a9d6dab3ee9f545",
    "level13_MetamorphicDropper": "261d05fa6476dcb6c6bb9a38de0d5f71d843916c01c4f73f194f7b8ae661c495",
}

Runner = Callable[[list[str], pathlib.Path, int], None]
_RECEIPT_FIELDS = {
    "schema",
    "image",
    "image_digest",
    "platform",
    "network",
    "task_selection",
    "binaries",
}


class AgentREBuildError(RuntimeError):
    """The official binary build could not be reproduced exactly."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _compile_flags(difficulty: int) -> list[str]:
    if difficulty == 9:
        return [
            "-O0",
            "-fno-stack-protector",
            "-no-pie",
            "-z",
            "execstack",
            "-shared",
            "-fPIC",
            "-ldl",
        ]
    return ["-O0", "-fno-stack-protector", "-no-pie", "-z", "execstack", "-static"]


def _stable_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_bounded(path: pathlib.Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AgentREBuildError(
            f"could not safely open AgentRE binary {path}: {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o333:
            raise AgentREBuildError(
                f"AgentRE binary is not a sealed regular file: {path}"
            )
        if opened.st_size > MAX_BINARY_BYTES:
            raise AgentREBuildError(
                f"AgentRE binary exceeds {MAX_BINARY_BYTES} bytes: {path}"
            )
        payload = os.read(descriptor, MAX_BINARY_BYTES + 1)
        if os.read(descriptor, 1) or len(payload) > MAX_BINARY_BYTES:
            raise AgentREBuildError(
                f"AgentRE binary exceeds {MAX_BINARY_BYTES} bytes: {path}"
            )
        closed_over = os.fstat(descriptor)
        current = path.lstat()
        if _stable_identity(opened) != _stable_identity(
            closed_over
        ) or not os.path.samestat(closed_over, current):
            raise AgentREBuildError(f"AgentRE binary changed while being read: {path}")
        return payload
    except OSError as exc:
        raise AgentREBuildError(f"could not read AgentRE binary {path}: {exc}") from exc
    finally:
        os.close(descriptor)


def _validate_elf(payload: bytes, *, shared: bool, name: str) -> None:
    if len(payload) < 64 or payload[:7] != b"\x7fELF\x02\x01\x01":
        raise AgentREBuildError(f"AgentRE binary is not ELF64 little-endian: {name}")
    elf_type, machine = struct.unpack_from("<HH", payload, 16)
    expected_type = 3 if shared else 2
    if elf_type != expected_type or machine != 62:
        raise AgentREBuildError(
            f"AgentRE binary identity mismatch for {name}: "
            f"expected type={expected_type}, machine=62; observed type={elf_type}, machine={machine}"
        )


def _diagnostic(handle: tempfile._TemporaryFileWrapper | object) -> str:
    handle.seek(0)
    raw = handle.read(MAX_DIAGNOSTIC_BYTES + 1)
    if len(raw) > MAX_DIAGNOSTIC_BYTES:
        raw = raw[:MAX_DIAGNOSTIC_BYTES] + b" [truncated]"
    return " ".join(raw.decode("utf-8", "replace").split())


def _remove_tree(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = pathlib.Path(current)
        current_path.chmod(0o700)
        for name in directories:
            child = current_path / name
            if not child.is_symlink():
                child.chmod(0o700)
        for name in files:
            child = current_path / name
            if not child.is_symlink():
                child.chmod(0o600)
    shutil.rmtree(root, ignore_errors=True)


def _fsync_path(path: pathlib.Path, *, directory: bool = False) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _docker_runner(argv: list[str], _output: pathlib.Path, timeout: int) -> None:
    container_name = argv[argv.index("--name") + 1]
    with tempfile.TemporaryFile() as diagnostic:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=diagnostic,
            stderr=subprocess.STDOUT,
            start_new_session=(os.name == "posix"),
        )
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait()
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
            raise AgentREBuildError(
                f"AgentRE compiler timed out after {timeout}s for {container_name}: "
                f"{_diagnostic(diagnostic)}"
            ) from exc
        if status != 0:
            raise AgentREBuildError(
                f"AgentRE compiler exited {status} for {container_name}: {_diagnostic(diagnostic)}"
            )


class AgentREBinaryBuilder:
    """Build and validate the 13 official Linux artifacts without executing them."""

    def __init__(
        self,
        output_dir: str | pathlib.Path | None = None,
        *,
        materializer: AgentRERecoveryMaterializer | None = None,
        _runner: Runner | None = None,
        _expected: Mapping[str, str] | None = None,
    ):
        self.root = pathlib.Path(
            output_dir or _BENCH_ROOT / "corpora" / "agentre-binaries-v2"
        )
        self.materializer = materializer or AgentRERecoveryMaterializer()
        self._runner = _runner or _docker_runner
        self._expected = dict(
            EXPECTED_BINARY_SHA256 if _expected is None else _expected
        )

    def _inventory(self) -> dict[str, str]:
        expected_names = {task.binary_name for task in LINUX_TASKS}
        if set(self._expected) != expected_names:
            raise AgentREBuildError(
                "AgentRE pinned binary digest inventory is incomplete"
            )
        return {artifact.path: artifact.sha256 for artifact in SOURCE_ARTIFACTS}

    def _task_selection_receipt(self) -> dict[str, object]:
        try:
            selection = self.materializer.task_selection()
        except AgentREMaterializationError as exc:
            raise AgentREBuildError(
                f"AgentRE task selection could not be verified: {exc}"
            ) from exc
        if selection.tasks != LINUX_TASKS:
            raise AgentREBuildError(
                "AgentRE task selection does not match the reviewed Linux slice"
            )
        return selection.receipt()

    def _validate_tree(self, root: pathlib.Path) -> dict[str, object]:
        task_selection = self._task_selection_receipt()
        try:
            root_stat = root.lstat()
        except FileNotFoundError as exc:
            raise AgentREBuildError(
                f"AgentRE binary corpus is absent at {root}"
            ) from exc
        if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_mode & 0o222:
            raise AgentREBuildError(
                f"AgentRE binary corpus is not a sealed directory: {root}"
            )
        expected_files = {task.binary_name for task in LINUX_TASKS} | {
            "build-receipt.json"
        }
        observed = {entry.name for entry in root.iterdir()}
        if observed != expected_files:
            raise AgentREBuildError(
                f"AgentRE binary inventory mismatch: missing={sorted(expected_files - observed)}, "
                f"unexpected={sorted(observed - expected_files)}"
            )
        receipt_path = root / "build-receipt.json"
        try:
            receipt_raw = _read_bounded(receipt_path)
            receipt = json.loads(receipt_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentREBuildError(f"AgentRE build receipt is invalid: {exc}") from exc
        if (
            not isinstance(receipt, dict)
            or set(receipt) != _RECEIPT_FIELDS
            or receipt.get("schema") != BUILD_SCHEMA
        ):
            raise AgentREBuildError("AgentRE build receipt schema is invalid")
        if (
            receipt.get("image") != GCC_IMAGE
            or receipt.get("image_digest") != GCC_IMAGE_DIGEST
        ):
            raise AgentREBuildError(
                "AgentRE build receipt compiler identity is invalid"
            )
        if receipt.get("platform") != "linux/amd64" or receipt.get("network") != "none":
            raise AgentREBuildError(
                "AgentRE build receipt isolation identity is invalid"
            )
        if receipt.get("task_selection") != task_selection:
            raise AgentREBuildError(
                "AgentRE build receipt task selection identity is invalid"
            )
        binaries = receipt.get("binaries")
        if not isinstance(binaries, list) or len(binaries) != len(LINUX_TASKS):
            raise AgentREBuildError("AgentRE build receipt binary inventory is invalid")
        by_name = {row.get("name"): row for row in binaries if isinstance(row, dict)}
        sources = self._inventory()
        for task in LINUX_TASKS:
            payload = _read_bounded(root / task.binary_name)
            _validate_elf(payload, shared=task.difficulty == 9, name=task.binary_name)
            digest = _sha256(payload)
            if digest != self._expected[task.binary_name]:
                raise AgentREBuildError(
                    f"AgentRE binary digest mismatch for {task.binary_name}: "
                    f"expected {self._expected[task.binary_name]}, observed {digest}"
                )
            expected_row = {
                "name": task.binary_name,
                "sha256": digest,
                "size": len(payload),
                "source": task.source_path,
                "source_sha256": sources[task.source_path],
                "compile_flags": _compile_flags(task.difficulty),
            }
            if by_name.get(task.binary_name) != expected_row:
                raise AgentREBuildError(
                    f"AgentRE build receipt row is invalid for {task.binary_name}"
                )
        return receipt

    def validate(self) -> dict[str, object]:
        """Validate the complete sealed output and its compiler-bound receipt."""

        return self._validate_tree(self.root)

    def build(self) -> pathlib.Path:
        """Compile in a pinned offline container and atomically publish exact artifacts."""

        if self.root.exists() or self.root.is_symlink():
            self.validate()
            return self.root
        task_selection = self._task_selection_receipt()
        sources = self.materializer.read_pinned_texts(
            task.source_path for task in LINUX_TASKS
        )
        source_by_path = {
            task.source_path: text for task, (_path, text) in zip(LINUX_TASKS, sources)
        }
        self._inventory()
        self.root.parent.mkdir(parents=True, exist_ok=True)
        staging = self.root.parent / f".{self.root.name}-{uuid.uuid4().hex}.staging"
        inputs = staging / "inputs"
        outputs = staging / "outputs"
        inputs.mkdir(parents=True, mode=0o700)
        outputs.mkdir(mode=0o700)
        try:
            for task in LINUX_TASKS:
                destination = inputs / pathlib.Path(task.source_path).name
                destination.write_text(
                    source_by_path[task.source_path], encoding="utf-8"
                )
                destination.chmod(0o400)
            inputs.chmod(0o500)
            rows = []
            uid_gid = (
                f"{os.getuid()}:{os.getgid()}"
                if hasattr(os, "getuid")
                else "65534:65534"
            )
            for task in LINUX_TASKS:
                source_name = pathlib.Path(task.source_path).name
                output = outputs / task.binary_name
                flags = _compile_flags(task.difficulty)
                container = f"keyhog-agentre-{uuid.uuid4().hex}"
                argv = [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    container,
                    "--user",
                    uid_gid,
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "128",
                    "--memory",
                    "1g",
                    "--cpus",
                    "2",
                    "--platform",
                    "linux/amd64",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=268435456",
                    "-v",
                    f"{inputs.resolve()}:/src:ro",
                    "-v",
                    f"{outputs.resolve()}:/out",
                    "-w",
                    "/src",
                    GCC_IMAGE,
                    "gcc",
                    *flags,
                    "-o",
                    f"/out/{task.binary_name}",
                    f"/src/{source_name}",
                    "-lm",
                ]
                self._runner(argv, output, BUILD_TIMEOUT_SECONDS)
                output.chmod(0o400)
                payload = _read_bounded(output)
                _validate_elf(
                    payload, shared=task.difficulty == 9, name=task.binary_name
                )
                digest = _sha256(payload)
                if digest != self._expected[task.binary_name]:
                    raise AgentREBuildError(
                        f"AgentRE binary digest mismatch for {task.binary_name}: "
                        f"expected {self._expected[task.binary_name]}, observed {digest}"
                    )
                rows.append(
                    {
                        "name": task.binary_name,
                        "sha256": digest,
                        "size": len(payload),
                        "source": task.source_path,
                        "source_sha256": self._inventory()[task.source_path],
                        "compile_flags": flags,
                    }
                )
            receipt = {
                "schema": BUILD_SCHEMA,
                "image": GCC_IMAGE,
                "image_digest": GCC_IMAGE_DIGEST,
                "platform": "linux/amd64",
                "network": "none",
                "task_selection": task_selection,
                "binaries": rows,
            }
            receipt_path = outputs / "build-receipt.json"
            receipt_path.write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            receipt_path.chmod(0o400)
            for task in LINUX_TASKS:
                _fsync_path(outputs / task.binary_name)
            _fsync_path(receipt_path)
            outputs.chmod(0o500)
            _fsync_path(outputs, directory=True)
            self._validate_tree(outputs)
            if self.root.exists() or self.root.is_symlink():
                raise AgentREBuildError(
                    f"AgentRE binary destination appeared during build: {self.root}"
                )
            # Some NFS servers require write permission on a directory being renamed.
            outputs.chmod(0o700)
            outputs.rename(self.root)
            self.root.chmod(0o500)
            _fsync_path(self.root.parent, directory=True)
            self.validate()
            return self.root
        except BaseException:
            _remove_tree(staging)
            raise
        finally:
            _remove_tree(staging)


def main() -> None:
    """Materialize, build, or validate the official Linux recovery slice."""

    parser = argparse.ArgumentParser(
        description="Build the pinned AgentRE Linux binaries without executing them."
    )
    parser.add_argument(
        "--ensure",
        action="store_true",
        help="materialize pinned sources and build binaries if absent",
    )
    args = parser.parse_args()
    builder = AgentREBinaryBuilder()
    if args.ensure:
        builder.materializer.materialize()
        root = builder.build()
    else:
        builder.validate()
        root = builder.root
    print(root)


if __name__ == "__main__":
    main()
