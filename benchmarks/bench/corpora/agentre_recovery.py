"""Fail-closed materialization of the pinned AgentRE-Bench Linux slice.

This module only retrieves and verifies upstream files. It has no compiler,
process launch, import, or sample execution path.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import uuid
from collections.abc import Callable, Iterable
from urllib.request import Request, urlopen

from ..agentre_provenance import (
    OFFICIAL_LINUX_SLICE,
    AgentRETaskSelection,
    PinnedArtifact,
    parse_linux_task_selection,
)

_THIS = pathlib.Path(__file__).resolve()
_BENCH_ROOT = _THIS.parents[2]
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 30

ArtifactFetcher = Callable[[PinnedArtifact], bytes]


class AgentREMaterializationError(RuntimeError):
    """The pinned corpus could not be proven complete and immutable."""


def _safe_relative_path(raw: str) -> pathlib.PurePosixPath:
    relative = pathlib.PurePosixPath(raw)
    if not raw or relative.is_absolute() or relative.parts in {(), (".",)}:
        raise AgentREMaterializationError(
            f"AgentRE artifact path must be repository-relative: {raw!r}"
        )
    if (
        relative.as_posix() != raw
        or ".." in relative.parts
        or any(part in {"", "."} for part in relative.parts)
    ):
        raise AgentREMaterializationError(
            f"AgentRE artifact path escapes its corpus root: {raw!r}"
        )
    return relative


def _expected_inventory(
    artifacts: Iterable[PinnedArtifact],
) -> tuple[dict[str, PinnedArtifact], set[str]]:
    files: dict[str, PinnedArtifact] = {}
    directories: set[str] = set()
    for artifact in artifacts:
        relative = _safe_relative_path(artifact.path)
        normalized = relative.as_posix()
        if normalized in files:
            raise AgentREMaterializationError(
                f"duplicate AgentRE artifact path in provenance: {normalized}"
            )
        files[normalized] = artifact
        parent = relative.parent
        while parent != pathlib.PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    if not files:
        raise AgentREMaterializationError("AgentRE provenance contains no artifacts")
    return files, directories


def _fetch_pinned_artifact(artifact: PinnedArtifact) -> bytes:
    request = Request(artifact.raw_url, headers={"User-Agent": "keyhog-benchmark"})
    try:
        with urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            final_url = response.geturl()
            if final_url != artifact.raw_url:
                raise AgentREMaterializationError(
                    f"AgentRE artifact redirected away from its pinned URL: "
                    f"{artifact.path}: {final_url}"
                )
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > MAX_ARTIFACT_BYTES:
                raise AgentREMaterializationError(
                    f"AgentRE artifact exceeds {MAX_ARTIFACT_BYTES} bytes: "
                    f"{artifact.path}"
                )
            payload = response.read(MAX_ARTIFACT_BYTES + 1)
    except AgentREMaterializationError:
        raise
    except (OSError, ValueError) as exc:
        raise AgentREMaterializationError(
            f"could not fetch pinned AgentRE artifact {artifact.path}: {exc}"
        ) from exc
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise AgentREMaterializationError(
            f"AgentRE artifact exceeds {MAX_ARTIFACT_BYTES} bytes: {artifact.path}"
        )
    return payload


def _write_new_file(path: pathlib.Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _make_removable(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    for current, dirnames, _filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = pathlib.Path(current)
        current_path.chmod(0o700)
        for name in list(dirnames):
            child = current_path / name
            if child.is_symlink():
                dirnames.remove(name)
            else:
                child.chmod(0o700)


def _stable_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


class AgentRERecoveryMaterializer:
    """Own the verified on-disk copy of the official Linux recovery slice."""

    def __init__(
        self,
        corpus_dir: str | pathlib.Path | None = None,
        *,
        _artifacts: Iterable[PinnedArtifact] | None = None,
    ):
        self.root = (
            pathlib.Path(corpus_dir)
            if corpus_dir is not None
            else _BENCH_ROOT / "corpora" / "agentre-recovery"
        )
        self._artifacts = tuple(
            OFFICIAL_LINUX_SLICE if _artifacts is None else _artifacts
        )
        self._expected_files, self._expected_directories = _expected_inventory(
            self._artifacts
        )

    def _open_pinned_artifact(
        self, relative: pathlib.PurePosixPath
    ) -> tuple[int, pathlib.Path]:
        path = self.root.joinpath(*relative.parts)
        read_flags = os.O_RDONLY
        directory_flags = os.O_RDONLY
        for flag_name in ("O_CLOEXEC", "O_NOFOLLOW"):
            flag = getattr(os, flag_name, 0)
            read_flags |= flag
            directory_flags |= flag
        directory_flags |= getattr(os, "O_DIRECTORY", 0)

        descriptors: list[int] = []
        descriptor = -1
        try:
            if os.open in os.supports_dir_fd:
                current = os.open(self.root, directory_flags)
                descriptors.append(current)
                opened_root = os.fstat(current)
                if not stat.S_ISDIR(opened_root.st_mode) or opened_root.st_mode & 0o222:
                    raise AgentREMaterializationError(
                        f"AgentRE corpus root is not a sealed directory: {self.root}"
                    )
                for part in relative.parts[:-1]:
                    current = os.open(part, directory_flags, dir_fd=current)
                    descriptors.append(current)
                    opened_directory = os.fstat(current)
                    if (
                        not stat.S_ISDIR(opened_directory.st_mode)
                        or opened_directory.st_mode & 0o222
                    ):
                        raise AgentREMaterializationError(
                            "AgentRE artifact parent is not a sealed directory: "
                            f"{path.parent}"
                        )
                descriptor = os.open(relative.parts[-1], read_flags, dir_fd=current)
            else:
                descriptor = os.open(path, read_flags)
        except OSError as exc:
            raise AgentREMaterializationError(
                f"could not safely open pinned AgentRE artifact {path}: {exc}"
            ) from exc
        finally:
            for directory_descriptor in reversed(descriptors):
                os.close(directory_descriptor)
        return descriptor, path

    def _read_pinned_bytes(
        self, relative: pathlib.PurePosixPath, artifact: PinnedArtifact
    ) -> tuple[pathlib.Path, bytes]:
        descriptor, path = self._open_pinned_artifact(relative)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o333:
                raise AgentREMaterializationError(
                    f"AgentRE artifact is not a sealed regular file: {path}"
                )
            if opened.st_size > MAX_ARTIFACT_BYTES:
                raise AgentREMaterializationError(
                    f"AgentRE artifact exceeds the size limit: {path}"
                )

            chunks: list[bytes] = []
            remaining = MAX_ARTIFACT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            closed_over = os.fstat(descriptor)
            try:
                current = path.lstat()
            except OSError as exc:
                raise AgentREMaterializationError(
                    f"pinned AgentRE artifact disappeared while it was being read: {path}"
                ) from exc
            if _stable_file_identity(opened) != _stable_file_identity(
                closed_over
            ) or not os.path.samestat(closed_over, current):
                raise AgentREMaterializationError(
                    f"pinned AgentRE artifact was replaced while it was being read: {path}"
                )
        except OSError as exc:
            raise AgentREMaterializationError(
                f"could not read pinned AgentRE artifact {path}: {exc}"
            ) from exc
        finally:
            os.close(descriptor)

        if len(payload) > MAX_ARTIFACT_BYTES:
            raise AgentREMaterializationError(
                f"AgentRE artifact exceeds the size limit: {path}"
            )
        try:
            artifact.verify(payload)
        except ValueError as exc:
            raise AgentREMaterializationError(str(exc)) from exc
        return path, payload

    def read_pinned_texts(
        self, raw_paths: Iterable[str]
    ) -> list[tuple[pathlib.Path, str]]:
        """Validate once, then safely read pinned UTF-8 artifacts in order."""

        requested: list[tuple[pathlib.PurePosixPath, PinnedArtifact]] = []
        for raw_path in raw_paths:
            relative = _safe_relative_path(raw_path)
            artifact = self._expected_files.get(relative.as_posix())
            if artifact is None:
                raise AgentREMaterializationError(
                    f"validated AgentRE corpus does not pin {raw_path}"
                )
            requested.append((relative, artifact))
        self.validate()
        output: list[tuple[pathlib.Path, str]] = []
        for relative, artifact in requested:
            path, payload = self._read_pinned_bytes(relative, artifact)
            try:
                output.append((path, payload.decode("utf-8")))
            except UnicodeDecodeError as exc:
                raise AgentREMaterializationError(
                    f"AgentRE artifact is not valid UTF-8 at {path}: {exc}"
                ) from exc
        return output

    def read_pinned_text(self, raw_path: str) -> tuple[pathlib.Path, str]:
        """Validate the full corpus, then read one pinned UTF-8 artifact safely."""

        return self.read_pinned_texts((raw_path,))[0]

    def task_selection(self) -> AgentRETaskSelection:
        """Derive the reviewed Linux task slice from validated tasks.json bytes."""

        path, raw = self.read_pinned_text("tasks.json")
        try:
            return parse_linux_task_selection(raw)
        except ValueError as exc:
            raise AgentREMaterializationError(
                f"validated AgentRE tasks manifest is incompatible at {path}: {exc}"
            ) from exc

    def validate(self) -> None:
        """Prove exact inventory, file type, mode, and content identity."""

        try:
            root_stat = self.root.lstat()
        except FileNotFoundError as exc:
            raise AgentREMaterializationError(
                f"AgentRE corpus is absent at {self.root}; materialize it first"
            ) from exc
        if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
            raise AgentREMaterializationError(
                f"AgentRE corpus root must be a real directory, not a link: {self.root}"
            )
        if root_stat.st_mode & 0o222:
            raise AgentREMaterializationError(
                f"AgentRE corpus root is writable and therefore unsealed: {self.root}"
            )

        observed_files: set[str] = set()
        observed_directories: set[str] = set()
        for current, dirnames, filenames in os.walk(
            self.root, topdown=True, followlinks=False
        ):
            current_path = pathlib.Path(current)
            for name in list(dirnames):
                child = current_path / name
                relative = child.relative_to(self.root).as_posix()
                child_stat = child.lstat()
                if stat.S_ISLNK(child_stat.st_mode):
                    raise AgentREMaterializationError(
                        f"AgentRE corpus contains a directory symlink: {relative}"
                    )
                if not stat.S_ISDIR(child_stat.st_mode):
                    raise AgentREMaterializationError(
                        f"AgentRE corpus contains a non-directory entry: {relative}"
                    )
                if child_stat.st_mode & 0o222:
                    raise AgentREMaterializationError(
                        f"AgentRE corpus directory is writable: {relative}"
                    )
                observed_directories.add(relative)
            for name in filenames:
                child = current_path / name
                relative = child.relative_to(self.root).as_posix()
                child_stat = child.lstat()
                if stat.S_ISLNK(child_stat.st_mode):
                    raise AgentREMaterializationError(
                        f"AgentRE corpus contains a file symlink: {relative}"
                    )
                if not stat.S_ISREG(child_stat.st_mode):
                    raise AgentREMaterializationError(
                        f"AgentRE corpus contains a special file: {relative}"
                    )
                if child_stat.st_mode & 0o333:
                    raise AgentREMaterializationError(
                        f"AgentRE corpus file is writable or executable: {relative}"
                    )
                observed_files.add(relative)

        if observed_directories != self._expected_directories:
            missing = sorted(self._expected_directories - observed_directories)
            unexpected = sorted(observed_directories - self._expected_directories)
            raise AgentREMaterializationError(
                "AgentRE corpus directory inventory mismatch: "
                f"missing={missing}, unexpected={unexpected}"
            )
        if observed_files != self._expected_files.keys():
            missing = sorted(self._expected_files.keys() - observed_files)
            unexpected = sorted(observed_files - self._expected_files.keys())
            raise AgentREMaterializationError(
                "AgentRE corpus file inventory mismatch: "
                f"missing={missing}, unexpected={unexpected}"
            )
        for relative, artifact in self._expected_files.items():
            self._read_pinned_bytes(pathlib.PurePosixPath(relative), artifact)

    def materialize(self, fetcher: ArtifactFetcher | None = None) -> pathlib.Path:
        """Publish a complete verified tree or leave the destination absent."""

        if self.root.exists() or self.root.is_symlink():
            self.validate()
            return self.root

        self.root.parent.mkdir(parents=True, exist_ok=True)
        staging = self.root.parent / f".{self.root.name}-{uuid.uuid4().hex}.staging"
        staging.mkdir(mode=0o700)
        fetch = _fetch_pinned_artifact if fetcher is None else fetcher
        try:
            for artifact in self._artifacts:
                relative = _safe_relative_path(artifact.path)
                destination = staging.joinpath(*relative.parts)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                payload = fetch(artifact)
                if not isinstance(payload, bytes):
                    raise AgentREMaterializationError(
                        f"fetcher returned non-bytes for AgentRE artifact {artifact.path}"
                    )
                if len(payload) > MAX_ARTIFACT_BYTES:
                    raise AgentREMaterializationError(
                        f"AgentRE artifact exceeds {MAX_ARTIFACT_BYTES} bytes: "
                        f"{artifact.path}"
                    )
                try:
                    artifact.verify(payload)
                except ValueError as exc:
                    raise AgentREMaterializationError(str(exc)) from exc
                _write_new_file(destination, payload)

            for path in staging.rglob("*"):
                if path.is_file():
                    path.chmod(0o400)
            directories = [path for path in staging.rglob("*") if path.is_dir()]
            for path in sorted(
                directories, key=lambda item: len(item.parts), reverse=True
            ):
                path.chmod(0o500)
            staging.chmod(0o500)

            original_root = self.root
            self.root = staging
            try:
                self.validate()
            finally:
                self.root = original_root
            if self.root.exists() or self.root.is_symlink():
                raise AgentREMaterializationError(
                    f"AgentRE corpus destination appeared during materialization: {self.root}"
                )
            staging.rename(self.root)
            return self.root
        except BaseException:
            _make_removable(staging)
            shutil.rmtree(staging, ignore_errors=True)
            raise
