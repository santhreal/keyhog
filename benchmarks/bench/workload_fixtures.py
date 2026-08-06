"""Deterministic canonical inputs and answer keys for every performance workload."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import time
import stat
import tempfile
import zipfile
from dataclasses import dataclass

from .workload_catalog import Workload, load_workload_catalog

FIXTURE_SCHEMA_VERSION = 1
CANARY = "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"
CANARY_SHA256 = hashlib.sha256(CANARY.encode()).hexdigest()
CANARY_LINE = f"GITHUB_TOKEN={CANARY}\n".encode()


class WorkloadFixtureError(RuntimeError):
    """A canonical fixture that could not be materialized exactly."""


@dataclass(frozen=True)
class FixtureReceipt:
    """Exact generated input and answer identity for one workload."""

    workload_id: str
    input_sha256: str
    answer_sha256: str
    input_bytes: int
    input_files: int
    expected_findings: int
    expected_coverage_gap: bool
    root: pathlib.Path

    def to_json(self) -> dict[str, object]:
        return {
            "schema_version": FIXTURE_SCHEMA_VERSION,
            "workload_id": self.workload_id,
            "input_sha256": self.input_sha256,
            "answer_sha256": self.answer_sha256,
            "input_bytes": self.input_bytes,
            "input_files": self.input_files,
            "expected_findings": self.expected_findings,
            "expected_coverage_gap": self.expected_coverage_gap,
        }


def _scaled(value: int, scale: float, minimum: int = 1) -> int:
    if not 0.0 < scale <= 1.0:
        raise WorkloadFixtureError(f"fixture scale must be in (0, 1], got {scale}")
    return max(minimum, int(value * scale))


def _write_sized(path: pathlib.Path, size: int, payload: bytes = CANARY_LINE) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    if size < len(payload):
        path.write_bytes(payload[:size])
        return size
    with path.open("wb") as handle:
        handle.write(payload)
        remaining = size - len(payload)
        block = b"const ordinary_value = 1234567890;\n" * 2048
        while remaining:
            chunk = block[:remaining]
            handle.write(chunk)
            remaining -= len(chunk)
    return size


def _answer(path: str, line: int = 1) -> dict[str, object]:
    return {
        "detector_id": "github-classic-pat",
        "credential_sha256": CANARY_SHA256,
        "path": path,
        "line": line,
    }


def _write_answers(root: pathlib.Path, answers: list[dict[str, object]]) -> pathlib.Path:
    answer_path = root / "answers.json"
    answer_path.write_text(
        json.dumps(answers, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return answer_path


def _digest_tree(root: pathlib.Path) -> tuple[str, int, int]:
    hasher = hashlib.sha256()
    total_bytes = 0
    file_count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        if path.is_symlink():
            target = os.readlink(path).encode()
            hasher.update(b"L")
            hasher.update(len(relative).to_bytes(8, "little"))
            hasher.update(relative)
            hasher.update(len(target).to_bytes(8, "little"))
            hasher.update(target)
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        file_count += 1
        total_bytes += len(data)
        hasher.update(b"F")
        hasher.update(len(relative).to_bytes(8, "little"))
        hasher.update(relative)
        hasher.update(stat.S_IMODE(path.stat().st_mode).to_bytes(4, "little"))
        hasher.update(len(data).to_bytes(8, "little"))
        hasher.update(data)
    return hasher.hexdigest(), total_bytes, file_count


def _filesystem_fixture(
    workload: Workload, input_root: pathlib.Path, scale: float
) -> tuple[list[dict[str, object]], bool]:
    wid = workload.workload_id
    if wid == "filesystem-empty-directory":
        (input_root / "empty").mkdir(parents=True, exist_ok=True)
        return [], True
    if wid == "filesystem-single-large-file":
        size = _scaled(300 * 1024 * 1024, scale, len(CANARY_LINE))
        _write_sized(input_root / "one-large.txt", size)
        return [_answer("one-large.txt")], False
    if wid == "filesystem-many-small-files":
        count = _scaled(3000, scale)
        size = _scaled(100 * 1024, scale, len(CANARY_LINE))
        answers = []
        for index in range(count):
            path = input_root / "many-small" / f"file-{index:06}.txt"
            _write_sized(path, size, CANARY_LINE if index == 0 else b"ordinary source\n")
            if index == 0:
                answers.append(_answer(path.relative_to(input_root).as_posix()))
        return answers, False
    if wid == "filesystem-flat-many-files":
        count = _scaled(200_000, scale)
        answers = []
        for index in range(count):
            path = input_root / "flat" / f"f{index:06}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(CANARY_LINE if index == count - 1 else b"ordinary\n")
            if index == count - 1:
                answers.append(_answer(path.relative_to(input_root).as_posix()))
        return answers, False
    if wid == "filesystem-deep-directory-tree":
        depth = _scaled(4096, scale)
        base = input_root / "deep"
        base.mkdir(parents=True, exist_ok=True)
        fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
        retained = [fd]
        try:
            for _ in range(depth):
                os.mkdir("d", dir_fd=retained[-1])
                child = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=retained[-1])
                retained.append(child)
                if len(retained) > 3:
                    os.close(retained.pop(0))
            leaf = os.open(
                "secret.env",
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o644,
                dir_fd=retained[-1],
            )
            with os.fdopen(leaf, "wb") as handle:
                handle.write(CANARY_LINE)
        finally:
            for open_fd in retained:
                os.close(open_fd)
        shallow = base / "shallow.env"
        shallow_bytes = b"# shallow marker, no credential\n"
        shallow.write_bytes(shallow_bytes)
        deep_relative = "deep/" + "d/" * depth + "secret.env"
        hasher = hashlib.sha256()
        for relative, data in sorted(
            ((deep_relative, CANARY_LINE), ("deep/shallow.env", shallow_bytes))
        ):
            encoded = relative.encode()
            hasher.update(b"F")
            hasher.update(len(encoded).to_bytes(8, "little"))
            hasher.update(encoded)
            hasher.update((0o644).to_bytes(4, "little"))
            hasher.update(len(data).to_bytes(8, "little"))
            hasher.update(data)
        identity = {
            "input_sha256": hasher.hexdigest(),
            "input_bytes": len(CANARY_LINE) + len(shallow_bytes),
            "input_files": 2,
        }
        (input_root.parent / ".deep-input-identity.json").write_text(
            json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8"
        )
        return [_answer(deep_relative)], False
    if wid == "filesystem-one-long-line":
        size = _scaled(50 * 1024 * 1024, scale, len(CANARY_LINE))
        payload = CANARY_LINE.rstrip(b"\n")
        _write_sized(input_root / "single-line.json", size, payload)
        return [_answer("single-line.json")], False
    if wid == "filesystem-over-size-limit":
        size = _scaled(101 * 1024 * 1024, scale, len(CANARY_LINE))
        _write_sized(input_root / "over-limit.log", size)
        return [], True
    if wid == "filesystem-binary-rejection":
        path = input_root / "rejected.elf"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF\x00\x00" + CANARY_LINE + b"\x00" * 1024)
        return [], True
    if wid == "filesystem-no-extension":
        path = input_root / "credentials"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(CANARY_LINE)
        return [_answer("credentials")], False
    if wid == "filesystem-mixed-encodings":
        encodings = {
            "utf8.txt": CANARY_LINE,
            "utf8-bom.txt": b"\xef\xbb\xbf" + CANARY_LINE,
            "utf16le.txt": CANARY_LINE.decode().encode("utf-16le"),
            "utf16be.txt": CANARY_LINE.decode().encode("utf-16be"),
            "latin1.txt": CANARY_LINE.decode().encode("latin-1"),
            "shift-jis.txt": CANARY_LINE.decode().encode("shift_jis"),
            "invalid-utf8.txt": b"\xff\xfe" + CANARY_LINE,
            "mixed.txt": b"ordinary\n\xff" + CANARY_LINE,
        }
        answers = []
        for name, data in encodings.items():
            path = input_root / "encodings" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            answers.append(_answer(path.relative_to(input_root).as_posix()))
        return answers, False
    if wid == "filesystem-sparse-files":
        answers = []
        for name, at_end in (("start.sparse", False), ("end.sparse", True)):
            path = input_root / "sparse" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            apparent = _scaled(64 * 1024 * 1024, scale, len(CANARY_LINE))
            with path.open("wb") as handle:
                if at_end:
                    handle.seek(apparent - len(CANARY_LINE))
                handle.write(CANARY_LINE)
                if not at_end:
                    handle.truncate(apparent)
            answers.append(_answer(path.relative_to(input_root).as_posix()))
        absent = input_root / "sparse" / "absent.sparse"
        with absent.open("wb") as handle:
            handle.truncate(_scaled(64 * 1024 * 1024, scale))
        return answers, False
    if wid == "filesystem-changing-size":
        growing = input_root / "changing" / "growing.txt"
        shrinking = input_root / "changing" / "shrinking.txt"
        _write_sized(growing, _scaled(1024 * 1024, scale, len(CANARY_LINE)))
        _write_sized(shrinking, _scaled(1024 * 1024, scale, len(CANARY_LINE)))
        (input_root / "changing" / "mutator.json").write_text(
            json.dumps({"append": "growing.txt", "truncate": "shrinking.txt"}, sort_keys=True)
            + "\n"
        )
        return [
            _answer(growing.relative_to(input_root).as_posix()),
            _answer(shrinking.relative_to(input_root).as_posix()),
        ], False
    if wid == "filesystem-symlink-cycle":
        base = input_root / "links"
        base.mkdir(parents=True, exist_ok=True)
        target = base / "target.env"
        target.write_bytes(CANARY_LINE)
        os.symlink(".", base / "self")
        os.symlink("b", base / "a")
        os.symlink("a", base / "b")
        os.symlink("missing", base / "dangling")
        return [_answer(target.relative_to(input_root).as_posix())], False
    if wid == "filesystem-unreadable-tree":
        locked = input_root / "locked"
        locked.mkdir(parents=True, exist_ok=True)
        secret = locked / "secret.env"
        secret.write_bytes(CANARY_LINE)
        (input_root / "unreadable-plan.json").write_text(
            json.dumps({"paths": ["locked", "locked/secret.env"], "mode": 0}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return [], True
    if wid == "filesystem-encoded-midfile":
        import base64

        encoded = base64.b64encode(CANARY_LINE)
        size = _scaled(4 * 1024 * 1024, scale, len(encoded) + 2)
        prefix = b"A" * ((size - len(encoded)) // 2)
        path = input_root / "encoded" / "middle.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(prefix + encoded + b"A" * (size - len(prefix) - len(encoded)))
        return [_answer(path.relative_to(input_root).as_posix())], False
    if wid == "filesystem-multiple-roots":
        answers = []
        for index in range(3):
            path = input_root / f"root-{index}" / "secret.env"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(CANARY_LINE)
            answers.append(_answer(path.relative_to(input_root).as_posix()))
        return answers, False
    if wid == "filesystem-compressed-archive":
        archive = input_root / "archive.zip"
        archive.parent.mkdir(parents=True, exist_ok=True)
        info = zipfile.ZipInfo("nested/secret.env", date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o100644 << 16
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            handle.writestr(info, CANARY_LINE)
        return [_answer("archive.zip:nested/secret.env")], False
    if wid in {"filesystem-binary-strings", "filesystem-binary-decompiler"}:
        path = input_root / "program.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x7fELF" + b"\x00" * 64 + CANARY_LINE + b"\x00" * 64)
        return [_answer("program.bin")], False
    path = input_root / "tiny.env"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(CANARY_LINE)
    return [_answer("tiny.env")], False


def _generic_fixture(
    workload: Workload, input_root: pathlib.Path
) -> tuple[list[dict[str, object]], bool]:
    family = workload.family
    if family == "stdin":
        path = input_root / "stdin.bin"
        if workload.workload_id == "stdin-empty":
            path.write_bytes(b"")
            return [], True
        size = {
            "stdin-tiny": len(CANARY_LINE),
            "stdin-medium": 64 * 1024,
            "stdin-large-bounded": 8 * 1024 * 1024,
        }[workload.workload_id]
        _write_sized(path, size)
        return [_answer("stdin.bin")], workload.workload_id == "stdin-large-bounded"
    if family == "daemon":
        suffix = {
            "daemon-warm-single-file": "request/secret.env",
            "daemon-warm-stdin": "request/stdin.bin",
            "daemon-mass-filesystem": "request/tree/secret.env",
            "daemon-mass-remote": "responses/secret.env",
        }[workload.workload_id]
        path = input_root / suffix
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(CANARY_LINE)
        (input_root / "transport.json").write_text(json.dumps({
            "family": family, "surface": workload.surface,
            "payload": path.relative_to(input_root).as_posix(),
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return [_answer(path.relative_to(input_root).as_posix())], False
    if family == "web":
        responses = input_root / "responses"
        responses.mkdir(parents=True)
        workload_id = workload.workload_id
        if workload_id == "web-javascript":
            paths = [responses / "app.js"]
            paths[0].write_bytes(b"const token = \"" + CANARY.encode() + b"\";\n")
        elif workload_id == "web-source-map":
            paths = [responses / "app.js.map"]
            paths[0].write_text(json.dumps({
                "version": 3, "file": "app.js", "sources": ["src.js"],
                "names": [], "mappings": "",
                "sourcesContent": [CANARY_LINE.decode()],
            }, sort_keys=True) + "\n", encoding="utf-8")
        elif workload_id == "web-wasm-binary":
            paths = [responses / "module.wasm"]
            paths[0].write_bytes(b"\x00asm\x01\x00\x00\x00" + CANARY_LINE)
        elif workload_id == "web-multiple-urls":
            paths = [responses / "a.js", responses / "b.js"]
            for index, path in enumerate(paths):
                path.write_bytes(f"// response {index}\n".encode() + CANARY_LINE)
        else:
            raise WorkloadFixtureError(f"unsupported web fixture {workload_id!r}")
        relative_paths = [path.relative_to(input_root).as_posix() for path in paths]
        (input_root / "transport.json").write_text(json.dumps({
            "family": family, "surface": workload.surface, "payloads": relative_paths,
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return [_answer(path) for path in relative_paths], False
    if family == "concurrency":
        answers = []
        for index in range(4):
            path = input_root / f"partition-{index}" / "secret.env"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(CANARY_LINE)
            answers.append(_answer(path.relative_to(input_root).as_posix()))
        return answers, False
    suffix = {
        "stdin": "stdin.bin",
        "git": "repository/secret.env",
        "github": "responses/repository-secret.env",
        "gitlab": "responses/project-secret.env",
        "bitbucket": "responses/repository-secret.env",
        "cloud": "objects/secret.env",
        "container": "layers/rootfs/secret.env",
        "web": "responses/app.js",
        "slack": "responses/messages.json",
        "daemon": "request/secret.env",
        "incremental": "tree/secret.env",
        "watch": "events/secret.env",
        "system": "mounts/home/secret.env",
        "verification": "findings/secret.env",
    }.get(family, "payload/secret.env")
    path = input_root / suffix
    path.parent.mkdir(parents=True, exist_ok=True)
    if family == "slack":
        path.write_text(
            json.dumps({"messages": [{"text": CANARY_LINE.decode().strip()}]}, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        line = 1
    else:
        path.write_bytes(CANARY_LINE)
        line = 1
    transport = input_root / "transport.json"
    transport.write_text(
        json.dumps(
            {
                "family": family,
                "surface": workload.surface,
                "payload": path.relative_to(input_root).as_posix(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    expected_gap = workload.workload_id in {
        "git-shallow-clone", "github-organization-repositories",
        "gitlab-group-projects", "bitbucket-workspace-repositories",
    }
    return [_answer(path.relative_to(input_root).as_posix(), line)], expected_gap



def _remove_fixture_tree_iterative(path: pathlib.Path) -> None:
    """Remove an owned fixture without Python recursion or PATH_MAX traversal."""
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        root_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd)
        stack = [(root_fd, os.scandir(root_fd), parent_fd, path.name)]
        while stack:
            directory_fd, entries, containing_fd, name = stack[-1]
            try:
                entry = next(entries)
            except StopIteration:
                entries.close(); os.close(directory_fd); stack.pop()
                os.rmdir(name, dir_fd=containing_fd)
                continue
            if entry.is_dir(follow_symlinks=False):
                child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory_fd)
                stack.append((child_fd, os.scandir(child_fd), directory_fd, entry.name))
            else:
                os.unlink(entry.name, dir_fd=directory_fd)
    finally:
        os.close(parent_fd)

def materialize_fixture(
    workload: Workload,
    output_root: str | pathlib.Path,
    *,
    scale: float = 1.0,
) -> FixtureReceipt:
    """Materialize one fixture atomically and return its exact byte identities."""
    if not 0.0 < scale <= 1.0:
        raise WorkloadFixtureError(f"fixture scale must be in (0, 1], got {scale}")
    destination = pathlib.Path(output_root) / workload.workload_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = pathlib.Path(tempfile.mkdtemp(
        prefix=f".{workload.workload_id}-", dir=destination.parent
    ))
    try:
        staging = temporary
        input_root = staging / "input"
        input_root.mkdir()
        if workload.family == "filesystem":
            answers, expected_gap = _filesystem_fixture(workload, input_root, scale)
        else:
            answers, expected_gap = _generic_fixture(workload, input_root)
        answer_path = _write_answers(staging, answers)
        deep_identity_path = staging / ".deep-input-identity.json"
        if deep_identity_path.is_file():
            deep_identity = json.loads(deep_identity_path.read_text(encoding="utf-8"))
            deep_identity_path.unlink()
            input_sha256 = str(deep_identity["input_sha256"])
            input_bytes = int(deep_identity["input_bytes"])
            input_files = int(deep_identity["input_files"])
        else:
            input_sha256, input_bytes, input_files = _digest_tree(input_root)
        answer_bytes = answer_path.read_bytes()
        receipt = FixtureReceipt(
            workload_id=workload.workload_id,
            input_sha256=input_sha256,
            answer_sha256=hashlib.sha256(answer_bytes).hexdigest(),
            input_bytes=input_bytes,
            input_files=input_files,
            expected_findings=len(answers),
            expected_coverage_gap=expected_gap,
            root=destination,
        )
        (staging / "fixture.json").write_text(
            json.dumps(receipt.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        backup: pathlib.Path | None = None
        if destination.exists():
            marker = destination / "fixture.json"
            if not marker.is_file():
                raise WorkloadFixtureError(
                    f"refusing to replace unowned fixture directory {destination}"
                )
            backup = destination.with_name(
                f".{destination.name}.old-{os.getpid()}-{time.time_ns()}"
            )
            destination.rename(backup)
        try:
            staging.rename(destination)
        except Exception:
            if backup is not None and not destination.exists():
                backup.rename(destination)
            raise
        if backup is not None:
            _remove_fixture_tree_iterative(backup)
        return receipt
    finally:
        if temporary.exists():
            _remove_fixture_tree_iterative(temporary)


def materialize_catalog(
    catalog_path: str | pathlib.Path,
    output_root: str | pathlib.Path,
    *,
    scale: float = 1.0,
    only: set[str] | None = None,
) -> tuple[FixtureReceipt, ...]:
    """Materialize every selected catalog workload in deterministic ID order."""
    catalog = load_workload_catalog(catalog_path)
    known = {workload.workload_id for workload in catalog.workloads}
    unknown = sorted((only or set()) - known)
    if unknown:
        raise WorkloadFixtureError(f"unknown workload fixture ids: {unknown}")
    rows = [
        materialize_fixture(workload, output_root, scale=scale)
        for workload in sorted(catalog.workloads, key=lambda item: item.workload_id)
        if only is None or workload.workload_id in only
    ]
    return tuple(rows)



def fixture_lock_payload(
    catalog_path: str | pathlib.Path, receipts: tuple[FixtureReceipt, ...]
) -> dict[str, object]:
    """Bind one complete receipt set to the exact workload catalog bytes."""
    catalog_file = pathlib.Path(catalog_path)
    catalog = load_workload_catalog(catalog_file)
    expected = {workload.workload_id for workload in catalog.workloads}
    observed = {receipt.workload_id for receipt in receipts}
    if observed != expected:
        raise WorkloadFixtureError(
            "fixture lock requires every catalog workload exactly once; "
            f"missing={sorted(expected - observed)}, extra={sorted(observed - expected)}"
        )
    if len(observed) != len(receipts):
        raise WorkloadFixtureError("fixture lock contains duplicate workload receipts")
    return {
        "schema_version": FIXTURE_SCHEMA_VERSION,
        "catalog_sha256": hashlib.sha256(catalog_file.read_bytes()).hexdigest(),
        "workloads": [
            receipt.to_json()
            for receipt in sorted(receipts, key=lambda item: item.workload_id)
        ],
    }


def write_fixture_lock(
    path: str | pathlib.Path, payload: dict[str, object]
) -> None:
    """Write one canonical fixture lock atomically beside its destination."""
    destination = pathlib.Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    try:
        temporary.write_text(data, encoding="utf-8")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def validate_fixture_lock(
    catalog_path: str | pathlib.Path, lock_path: str | pathlib.Path
) -> dict[str, object]:
    """Validate one committed full-catalog input and answer digest lock."""
    catalog_file = pathlib.Path(catalog_path)
    lock_file = pathlib.Path(lock_path)
    try:
        payload = json.loads(lock_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkloadFixtureError(f"cannot load fixture lock {lock_file}: {exc}") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version", "catalog_sha256", "workloads"
    }:
        raise WorkloadFixtureError("fixture lock must contain schema, catalog digest, and workloads")
    if payload["schema_version"] != FIXTURE_SCHEMA_VERSION:
        raise WorkloadFixtureError(
            f"fixture lock schema_version must be {FIXTURE_SCHEMA_VERSION}"
        )
    expected_catalog_sha = hashlib.sha256(catalog_file.read_bytes()).hexdigest()
    if payload["catalog_sha256"] != expected_catalog_sha:
        raise WorkloadFixtureError(
            "fixture lock catalog digest does not match workload-catalog.toml"
        )
    catalog = load_workload_catalog(catalog_file)
    expected_ids = {workload.workload_id for workload in catalog.workloads}
    raw_rows = payload["workloads"]
    if not isinstance(raw_rows, list):
        raise WorkloadFixtureError("fixture lock workloads must be an array")
    expected_fields = {
        "schema_version", "workload_id", "input_sha256", "answer_sha256",
        "input_bytes", "input_files", "expected_findings", "expected_coverage_gap",
    }
    seen: set[str] = set()
    for index, row in enumerate(raw_rows):
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise WorkloadFixtureError(
                f"fixture lock workload[{index}] fields must be exactly {sorted(expected_fields)}"
            )
        workload_id = row["workload_id"]
        if not isinstance(workload_id, str) or workload_id not in expected_ids:
            raise WorkloadFixtureError(
                f"fixture lock workload[{index}] has unknown id {workload_id!r}"
            )
        if workload_id in seen:
            raise WorkloadFixtureError(f"fixture lock duplicates workload {workload_id!r}")
        seen.add(workload_id)
        for field in ("input_sha256", "answer_sha256"):
            value = row[field]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise WorkloadFixtureError(
                    f"fixture lock {workload_id}.{field} must be lowercase SHA-256"
                )
        for field in ("input_bytes", "input_files", "expected_findings"):
            value = row[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise WorkloadFixtureError(
                    f"fixture lock {workload_id}.{field} must be non-negative integer"
                )
        if not isinstance(row["expected_coverage_gap"], bool):
            raise WorkloadFixtureError(
                f"fixture lock {workload_id}.expected_coverage_gap must be boolean"
            )
    if seen != expected_ids:
        raise WorkloadFixtureError(
            "fixture lock does not cover the complete catalog; "
            f"missing={sorted(expected_ids - seen)}"
        )
    return payload

def _main() -> int:
    parser = argparse.ArgumentParser(description="Materialize canonical workload fixtures")
    parser.add_argument("--catalog", default="workload-catalog.toml")
    parser.add_argument("--out", required=True)
    parser.add_argument("--scale", type=float, default=1.0)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--lock-out")
    args = parser.parse_args()
    receipts = materialize_catalog(
        args.catalog,
        args.out,
        scale=args.scale,
        only=set(args.only) if args.only else None,
    )
    if args.lock_out:
        write_fixture_lock(args.lock_out, fixture_lock_payload(args.catalog, receipts))
    print(json.dumps([receipt.to_json() for receipt in receipts], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
