"""Corpus contract: a labeled (or perf-only) set of on-disk fixtures.

A :class:`Corpus` exposes three things the runner needs:

* ``root``, the single directory handed to a scanner; it recurses and pays
  one cold-start over the whole tree (the 257x amortisation score.py
  documents).
* ``records()``, the ground truth as :class:`LabeledRecord` objects. Empty
  for a perf-only corpus (kernel).
* ``info()``, fixture count / labeled-positive count / total bytes for the
  result header.

One record == one labeled credential candidate. A file may carry several
records (CredData has multiple secrets per file); the scorer groups by file
so multi-secret attribution is correct, while the single-record-per-file
mirror still scores identically.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import unicodedata
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass

from ..schema import CorpusInfo


@dataclass(frozen=True)
class LabeledRecord:
    """One ground-truth credential candidate.

    ``label`` follows the SecretBench convention: ``True`` = confirmed real
    secret (a positive the scanner MUST surface), ``False`` = confirmed
    non-secret (a negative the scanner must NOT fire on). ``ignore=True``
    marks a candidate that scores neither way (CredData's ``Template`` /
    ``X`` rows, placeholders), findings overlapping it are dropped, and it
    never contributes a false negative.
    """

    id: str
    secret: str
    label: bool
    category: str
    file_path: str          # relative to the corpus file_root
    line_start: int = 0
    line_end: int = 0
    ignore: bool = False
    # ``overlap`` preserves the historical SecretBench scoring contract
    # (containment/escape/Base64 aliases). Recovery corpora use ``exact`` so
    # reporting an encoded representation cannot earn plaintext credit.
    match_mode: str = "overlap"

    def __post_init__(self) -> None:
        if self.match_mode not in {"overlap", "exact"}:
            raise ValueError(
                f"record {self.id!r} has unsupported match_mode "
                f"{self.match_mode!r}; expected 'overlap' or 'exact'"
            )


@dataclass(frozen=True)
class WorkloadSnapshot:
    """Immutable identity for one fully validated scan-tree snapshot."""

    bytes: int
    file_count: int
    sha256: str


class Corpus(ABC):
    """Adapter from an on-disk dataset to (root, records, info)."""

    #: short stable identifier used in result filenames + reports
    name: str = ""

    @property
    @abstractmethod
    def root(self) -> pathlib.Path:
        """Directory a scanner is pointed at (recurses)."""

    @property
    def file_root(self) -> pathlib.Path:
        """Prefix under which a record's ``file_path`` resolves. Defaults to
        ``root``; CredData overrides it (manifest dir != data dir)."""
        return self.root

    @property
    def scan_root(self) -> pathlib.Path:
        """The path a scanner is actually pointed at, the fixture tree with
        the ground-truth manifest/answer-key EXCLUDED. Defaults to ``root``;
        corpora whose manifest lives inside ``root`` override this to the
        manifest-free subtree (e.g. ``root/fixtures``).

        This is the fairness boundary: a scanner that reads the manifest
        would "find" every labeled secret in plaintext, measured on the 15k
        mirror, betterleaks fires 9392 spurious matches on ``manifest.jsonl``
        and kingfisher 7581. No scanner is ever shown the answer key, so the
        comparison reflects detection skill, not whether a tool happens to
        skip a data file keyhog already ignores."""
        return self.root

    @abstractmethod
    def _load_records(self) -> list[LabeledRecord]:
        """Parse the ground truth from disk. Empty list for a perf-only corpus.
        Called at most once per instance: :meth:`records` memoizes it."""

    def records(self) -> list[LabeledRecord]:
        """Ground-truth records, parsed once and cached on the instance.

        ``build_result`` -> ``info()`` -> ``records()`` plus ``score()`` and the
        ``__main__`` calibrate/analyze paths all ask for the same records several
        times per run; for CredData that is ~11k files re-opened and re-sliced.
        Memoising here parses each meta CSV exactly once."""
        cached = self.__dict__.get("_records_cache")
        if cached is None:
            cached = self._load_records()
            self._records_cache = cached
        return cached

    def is_labeled(self) -> bool:
        return bool(self.records())

    def workload_snapshot(self) -> WorkloadSnapshot:
        """Hash a fresh, fail-closed view of the answer key and scan tree."""
        total_bytes, file_count, sha256 = self._workload_metrics(self.records())
        return WorkloadSnapshot(total_bytes, file_count, sha256)

    def assert_workload_unchanged(self, expected: WorkloadSnapshot) -> None:
        """Fail if the live workload differs from a prior snapshot."""
        actual = self.workload_snapshot()
        if actual != expected:
            raise RuntimeError(
                "benchmark workload changed after it was snapshotted: "
                f"expected {expected.sha256}, got {actual.sha256}"
            )

    def info(self) -> CorpusInfo:
        # Deliberately do not cache this. Hosted evidence takes a pre-run
        # identity and the result builder asks again after scanning; a cached
        # CorpusInfo would let byte or label mutation silently reuse the old
        # digest.
        recs = self.records()
        positives = sum(1 for r in recs if r.label and not r.ignore)
        snapshot = self.workload_snapshot()
        return CorpusInfo(
            name=self.name,
            fixture_count=len(recs) if recs else snapshot.file_count,
            labeled_positives=positives,
            bytes=snapshot.bytes,
            workload_sha256=snapshot.sha256,
        )

    # ── exact workload identity ───────────────────────────────────────

    @staticmethod
    def _hash_part(digest: "hashlib._Hash", payload: bytes) -> None:
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)

    @staticmethod
    def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )

    @classmethod
    def _scan_workload_files(
        cls, root: pathlib.Path
    ) -> list[tuple[pathlib.Path, str, tuple[int, ...]]]:
        """Enumerate only regular, non-symlink files under ``root``."""
        try:
            root_stat = root.lstat()
        except FileNotFoundError as error:
            raise FileNotFoundError(f"benchmark scan root does not exist: {root}") from error
        if stat.S_ISLNK(root_stat.st_mode):
            raise ValueError(f"benchmark scan root must not be a symlink: {root}")

        files: list[tuple[pathlib.Path, str, tuple[int, ...]]] = []
        normalized_paths: set[str] = set()

        def add_file(path: pathlib.Path, relative: str, value: os.stat_result) -> None:
            normalized = unicodedata.normalize("NFC", relative)
            if normalized in normalized_paths:
                raise ValueError(
                    "benchmark scan tree has duplicate normalized path "
                    f"{normalized!r}"
                )
            normalized_paths.add(normalized)
            files.append((path, relative, cls._stat_identity(value)))

        def visit(directory: pathlib.Path, prefix: pathlib.PurePosixPath) -> None:
            try:
                with os.scandir(directory) as stream:
                    entries = sorted(stream, key=lambda entry: entry.name)
            except OSError as error:
                raise OSError(
                    f"cannot enumerate benchmark scan directory {directory}: {error}"
                ) from error
            for entry in entries:
                relative_path = prefix / entry.name
                relative = relative_path.as_posix()
                try:
                    value = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise OSError(
                        f"cannot stat benchmark workload path {entry.path}: {error}"
                    ) from error
                mode = value.st_mode
                if stat.S_ISLNK(mode):
                    raise ValueError(
                        f"benchmark scan tree must not contain symlinks: {entry.path}"
                    )
                if stat.S_ISDIR(mode):
                    visit(pathlib.Path(entry.path), relative_path)
                elif stat.S_ISREG(mode):
                    add_file(pathlib.Path(entry.path), relative, value)
                else:
                    raise ValueError(
                        "benchmark scan tree must contain only regular files and "
                        f"directories: {entry.path}"
                    )

        if stat.S_ISREG(root_stat.st_mode):
            add_file(root, root.name, root_stat)
        elif stat.S_ISDIR(root_stat.st_mode):
            visit(root, pathlib.PurePosixPath())
        else:
            raise ValueError(
                f"benchmark scan root must be a regular file or directory: {root}"
            )
        return files

    def _workload_metrics(
        self, records: list[LabeledRecord]
    ) -> tuple[int, int, str]:
        """Return bytes, file count, and a validated answer-key + tree hash."""
        digest = hashlib.sha256()
        self._hash_part(digest, b"keyhog-workload-v1")
        self._hash_part(digest, self.name.encode("utf-8"))
        for record in records:
            encoded = json.dumps(
                {
                    "id": record.id,
                    "secret": record.secret,
                    "label": record.label,
                    "category": record.category,
                    "file_path": record.file_path,
                    "line_start": record.line_start,
                    "line_end": record.line_end,
                    "ignore": record.ignore,
                    "match_mode": record.match_mode,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            self._hash_part(digest, encoded)

        root = self.scan_root
        paths = self._scan_workload_files(root)
        total = 0
        for path, relative, expected_identity in paths:
            self._hash_part(digest, relative.encode("utf-8"))
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags)
            except OSError as error:
                raise OSError(f"cannot open benchmark workload file {path}: {error}") from error
            with os.fdopen(descriptor, "rb") as source:
                before = os.fstat(source.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError(
                        f"benchmark workload path is not a regular file: {path}"
                    )
                if self._stat_identity(before) != expected_identity:
                    raise RuntimeError(
                        f"benchmark workload changed while being snapshotted: {path}"
                    )
                size = before.st_size
                self._hash_part(digest, size.to_bytes(8, "big"))
                read_bytes = 0
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    read_bytes += len(chunk)
                after = os.fstat(source.fileno())
            try:
                current = path.lstat()
            except FileNotFoundError as error:
                raise RuntimeError(
                    f"benchmark workload changed while being snapshotted: {path}"
                ) from error
            if (
                read_bytes != size
                or self._stat_identity(after) != expected_identity
                or self._stat_identity(current) != expected_identity
            ):
                raise RuntimeError(
                    f"benchmark workload changed while being snapshotted: {path}"
                )
            total += size

        if self._scan_workload_files(root) != paths:
            raise RuntimeError(
                "benchmark scan tree changed while being snapshotted"
            )
        return total, len(paths), digest.hexdigest()


def _strict_type(value: object, expected: type | tuple[type, ...]) -> bool:
    allowed = expected if isinstance(expected, tuple) else (expected,)
    return type(value) in allowed


def _validate_manifest_file(
    file_root: pathlib.Path, relative_text: str, *, record_id: str
) -> str:
    relative = pathlib.PurePosixPath(relative_text)
    if (
        not relative_text
        or "\\" in relative_text
        or relative.is_absolute()
        or relative_text != relative.as_posix()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(
            f"manifest record {record_id!r} has unsafe path {relative_text!r}"
        )

    try:
        root_stat = file_root.lstat()
    except FileNotFoundError as error:
        raise ValueError(f"manifest file root does not exist: {file_root}") from error
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise ValueError(
            f"manifest file root must be a regular non-symlink directory: {file_root}"
        )

    current = file_root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            value = current.lstat()
        except FileNotFoundError as error:
            raise ValueError(
                f"manifest fixture missing for record {record_id!r}: {relative_text}"
            ) from error
        if stat.S_ISLNK(value.st_mode):
            raise ValueError(
                f"manifest fixture must not traverse a symlink for record "
                f"{record_id!r}: {relative_text}"
            )
        final = index == len(relative.parts) - 1
        if final and not stat.S_ISREG(value.st_mode):
            raise ValueError(
                f"manifest fixture must be a regular file for record "
                f"{record_id!r}: {relative_text}"
            )
        if not final and not stat.S_ISDIR(value.st_mode):
            raise ValueError(
                f"manifest fixture path is not a directory for record "
                f"{record_id!r}: {relative_text}"
            )
    return relative.as_posix()


def load_jsonl_manifest(
    path: pathlib.Path,
    *,
    file_root: pathlib.Path,
    schema: Mapping[str, type | tuple[type, ...]],
    required_fields: frozenset[str],
    allow_duplicate_file_paths: bool = False,
) -> list[LabeledRecord]:
    """Strictly load a typed JSONL manifest and validate every scanned file."""
    if not required_fields <= schema.keys():
        raise ValueError("manifest required fields must be declared in its schema")
    out: list[LabeledRecord] = []
    ids: set[str] = set()
    file_paths: set[str] = set()
    try:
        manifest_stat = path.lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(manifest_stat.st_mode) or not stat.S_ISREG(manifest_stat.st_mode):
        raise ValueError(f"manifest must be a regular non-symlink file: {path}")

    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"{path} line {line_number} is invalid JSON: {error}"
                ) from error
            if not isinstance(row, dict):
                raise ValueError(f"{path} line {line_number} must be a JSON object")
            unknown = row.keys() - schema.keys()
            missing = required_fields - row.keys()
            if unknown:
                raise ValueError(
                    f"{path} line {line_number} has unknown fields: "
                    + ", ".join(sorted(unknown))
                )
            if missing:
                raise ValueError(
                    f"{path} line {line_number} is missing required fields: "
                    + ", ".join(sorted(missing))
                )
            for field, value in row.items():
                if not _strict_type(value, schema[field]):
                    expected = schema[field]
                    raise ValueError(
                        f"{path} line {line_number} field {field!r} has type "
                        f"{type(value).__name__}; expected {expected}"
                    )

            record_id = row["id"]
            if not record_id:
                raise ValueError(f"{path} line {line_number} has an empty id")
            if record_id in ids:
                raise ValueError(f"{path} contains duplicate record id {record_id!r}")
            ids.add(record_id)
            relative = _validate_manifest_file(
                file_root, row["on_disk_path"], record_id=record_id
            )
            normalized = unicodedata.normalize("NFC", relative)
            if not allow_duplicate_file_paths and normalized in file_paths:
                raise ValueError(
                    f"{path} contains duplicate fixture path {relative!r}"
                )
            file_paths.add(normalized)

            line_start = row.get("start_line", 0)
            line_end = row.get("end_line", 0)
            if line_start < 0 or line_end < 0:
                raise ValueError(
                    f"{path} line {line_number} has negative line coordinates"
                )
            if line_end and line_start and line_end < line_start:
                raise ValueError(
                    f"{path} line {line_number} has end_line before start_line"
                )
            out.append(
                LabeledRecord(
                    id=record_id,
                    secret=row["secret"],
                    label=row["label"],
                    category=row["category"],
                    file_path=relative,
                    line_start=line_start,
                    line_end=line_end,
                    match_mode=row.get("match_mode", "overlap"),
                )
            )
    return out


def resolve_corpus(name: str, **kw) -> Corpus:
    """Factory: map a corpus name to its adapter. Kept here (not in each
    module) so the runner/report import one symbol and new corpora register
    by adding a branch. Imports are lazy so a missing optional dep in one
    adapter never breaks the others."""
    name = name.lower()
    if name == "mirror":
        from .mirror import MirrorCorpus
        return MirrorCorpus(**kw)
    if name in ("ioc-recovery", "ioc_recovery"):
        from .ioc_recovery import IocRecoveryCorpus
        return IocRecoveryCorpus(**kw)
    if name in ("homefield-betterleaks", "homefield_betterleaks", "betterleaks-homefield"):
        from .homefield import HomefieldCorpus
        return HomefieldCorpus(turf="betterleaks", **kw)
    if name in ("homefield-kingfisher", "homefield_kingfisher", "kingfisher-homefield"):
        from .homefield import HomefieldCorpus
        return HomefieldCorpus(turf="kingfisher", **kw)
    if name == "creddata":
        from .creddata import CredDataCorpus
        return CredDataCorpus(**kw)
    if name == "kernel":
        from .perf_corpus import KernelCorpus
        return KernelCorpus(**kw)
    if name in ("daemon-file", "daemon_file"):
        from .perf_corpus import DaemonFileCorpus
        return DaemonFileCorpus(**kw)
    raise SystemExit(
        f"unknown corpus {name!r}; known: mirror, ioc-recovery, "
        f"homefield-betterleaks, homefield-kingfisher, creddata, kernel, daemon-file"
    )
