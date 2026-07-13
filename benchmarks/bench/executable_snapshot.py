"""Immutable executable-byte evidence for benchmark subprocesses."""

from __future__ import annotations

import contextlib
import hashlib
import os
import pathlib
import shutil
import tempfile
import types
from dataclasses import dataclass
from typing import BinaryIO, Iterator


@dataclass(frozen=True)
class ExecutableSnapshot:
    path: pathlib.Path
    launch_path: pathlib.Path
    sha256: str
    pass_fds: tuple[int, ...] = ()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_handle(handle: BinaryIO) -> str:
    handle.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    handle.seek(0)
    return digest.hexdigest()


def _stable_posix_launch_path(descriptor: int) -> pathlib.Path:
    for root in (pathlib.Path("/proc/self/fd"), pathlib.Path("/dev/fd")):
        candidate = root / str(descriptor)
        if candidate.exists():
            return candidate
    raise RuntimeError(
        "this POSIX host has no executable descriptor path under /proc/self/fd "
        "or /dev/fd, so immutable benchmark execution cannot be guaranteed"
    )


def _cleanup_snapshot(
    path: pathlib.Path | None,
    identity: tuple[int, int] | None,
) -> OSError | RuntimeError | None:
    if path is None:
        return None
    try:
        stat = path.stat()
    except FileNotFoundError:
        return RuntimeError(f"benchmark snapshot path disappeared before cleanup: {path}")
    except OSError as exc:
        return exc
    if identity is not None and (stat.st_dev, stat.st_ino) != identity:
        return RuntimeError(
            f"benchmark snapshot path was replaced before cleanup: {path}"
        )
    try:
        path.chmod(0o700)
        path.unlink()
    except OSError as exc:
        return exc
    return None


@contextlib.contextmanager
def sibling_executable_snapshot(binary: str) -> Iterator[ExecutableSnapshot]:
    """Copy one opened executable beside its source and launch its held inode."""
    source: BinaryIO | None = None
    guard: BinaryIO | None = None
    snapshot_path: pathlib.Path | None = None
    snapshot_identity: tuple[int, int] | None = None
    primary: BaseException | None = None
    primary_tb: types.TracebackType | None = None
    secondary: BaseException | None = None

    try:
        candidate = pathlib.Path(binary)
        if not candidate.is_file():
            resolved = shutil.which(binary)
            if resolved is None:
                raise RuntimeError(
                    f"cannot snapshot benchmark binary {binary!r}: file not found"
                )
            candidate = pathlib.Path(resolved)
        candidate = candidate.resolve(strict=True)
        basename_artifacts = [
            path for path in (
                candidate.with_name(f"{candidate.name}.local"),
                candidate.with_name(f"{candidate.name}.manifest"),
            )
            if path.exists()
        ]
        if basename_artifacts:
            rendered = ", ".join(path.name for path in basename_artifacts)
            raise RuntimeError(
                "cannot snapshot an executable with basename-coupled loader artifacts "
                f"({rendered}). Use a self-contained KeyHog artifact"
            )
        source = candidate.open("rb")
        try:
            descriptor, raw_snapshot = tempfile.mkstemp(
                prefix=f".{candidate.stem}.bench.",
                suffix=candidate.suffix,
                dir=candidate.parent,
            )
        except OSError as exc:
            raise RuntimeError(
                f"cannot create a benchmark snapshot beside {candidate}: {exc}. "
                "Point the benchmark at a writable private runtime bundle"
            ) from exc
        snapshot_path = pathlib.Path(raw_snapshot)
        created_stat = os.fstat(descriptor)
        snapshot_identity = (created_stat.st_dev, created_stat.st_ino)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as destination:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
                destination.write(chunk)
        source.close()
        source = None
        snapshot_path.chmod(0o500)
        guard = snapshot_path.open("rb")
        stat = os.fstat(guard.fileno())
        if (stat.st_dev, stat.st_ino) != snapshot_identity:
            raise RuntimeError(
                "benchmark binary snapshot path was replaced while it was prepared"
            )
        expected = digest.hexdigest()
        observed = _sha256_handle(guard)
        if observed != expected:
            raise RuntimeError(
                "benchmark binary snapshot changed while it was created: "
                f"expected SHA-256 {expected}, found {observed}"
            )
        if os.name == "nt":
            launch_path = snapshot_path
            pass_fds: tuple[int, ...] = ()
        else:
            launch_path = _stable_posix_launch_path(guard.fileno())
            pass_fds = (guard.fileno(),)
        snapshot = ExecutableSnapshot(
            path=snapshot_path,
            launch_path=launch_path,
            sha256=expected,
            pass_fds=pass_fds,
        )
        yield snapshot
    except BaseException as exc:
        primary = exc
        primary_tb = exc.__traceback__
    finally:
        if source is not None:
            source.close()
        if guard is not None:
            try:
                observed = _sha256_handle(guard)
                if "expected" in locals() and observed != expected:
                    raise RuntimeError(
                        "benchmark binary snapshot changed during the scan: "
                        f"expected SHA-256 {expected}, found {observed}"
                    )
            except BaseException as exc:
                if primary is None:
                    primary = exc
                    primary_tb = exc.__traceback__
                else:
                    secondary = exc
            guard.close()
        cleanup_error = _cleanup_snapshot(snapshot_path, snapshot_identity)
        if cleanup_error is not None:
            detail = RuntimeError(
                f"failed to remove benchmark snapshot {snapshot_path}: {cleanup_error}"
            )
            if secondary is not None:
                detail = RuntimeError(f"{secondary}; {detail}")
            secondary = detail
        if primary is not None:
            if secondary is not None:
                raise primary.with_traceback(primary_tb) from secondary
            raise primary.with_traceback(primary_tb)
        if secondary is not None:
            raise secondary
