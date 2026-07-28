"""Samsung/CredData corpus adapter.

CredData (https://github.com/Samsung/CredData, Apache-2.0) is a
human-reviewed credential-detection benchmark: ~11k labeled files across
~300 repositories. The repository ships *metadata only* (``meta/*.csv``,
one CSV per repo) plus ``download_data.py``, which fetches the actual source
files from their origin repos at pinned commits into ``data/<RepoID>/...``.

We do NOT vendor the data (mixed upstream licenses, ~GB scale): only a
pinned CredData commit is committed (:data:`CREDDATA_PIN`); ``make creddata``
clones that commit and runs its downloader. The clone + ``data/`` are
gitignored.

This adapter loads CredData two ways, in priority order:

1. **Pre-built manifest**: if a ``manifest.{jsonl,csv,parquet}`` is present
   under the corpus root, load it directly (lets a CredData export be dropped
   in without the native download). Optional Parquet support stays lazy.
2. **Native CredData layout**: otherwise parse ``meta/*.csv`` and slice each
   positive's literal secret out of the on-disk file at its ``LineStart`` /
   ``ValueStart..ValueEnd`` span, so the value-overlap scorer works unchanged.

**Labeling** (CredData's own convention, README "Properties"):
``GroundTruth`` is ``T`` (real credential → positive) or ``F``/``X`` (false
positive / placeholder/test/example → negative). We follow that exactly so
the numbers are comparable to CredSweeper's published CredData scores, this
intentionally diverges from the planning note's "X=ignore"; firing on a
CredData placeholder is a false positive in CredData's own scoring, and
keyhog is already run with ``--no-suppress-test-fixtures`` to keep the
comparison apples-to-apples. Override with ``treat_x="ignore"``.

Native CSV columns (in order): Id, FileID, Domain, RepoName, FilePath,
LineStart, LineEnd, GroundTruth, ValueStart, ValueEnd, CryptographyKey,
PredefinedPattern, Category. Lines are 1-indexed; ValueStart/ValueEnd are
0-indexed character offsets on the line (ValueEnd = index just past the
value); ``-1``/empty means the corresponding offset is unbounded.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

from .base import Corpus, LabeledRecord, _strict_type, _validate_manifest_file

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DEFAULT_ROOT = _BENCH_ROOT / "corpora" / "creddata" / "CredData"

# Pinned CredData commit, bump deliberately, never float to a branch, so a
# CredData score is always reproducible against an exact dataset revision.
CREDDATA_REPO = "https://github.com/Samsung/CredData.git"
CREDDATA_PIN = "f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee"  # 2026-05-26


# ── generic manifest fast-path (jsonl / csv / parquet export) ─────────


_MANIFEST_SCHEMA: dict[str, type] = {
    "id": str,
    "secret": str,
    "label": bool,
    "category": str,
    "on_disk_path": str,
    "start_line": int,
    "end_line": int,
    "ignore": bool,
}
_REQUIRED_MANIFEST_FIELDS = frozenset(_MANIFEST_SCHEMA) - {"ignore"}
_NATIVE_COLUMNS = (
    "Id",
    "FileID",
    "Domain",
    "RepoName",
    "FilePath",
    "LineStart",
    "LineEnd",
    "GroundTruth",
    "ValueStart",
    "ValueEnd",
    "CryptographyKey",
    "PredefinedPattern",
    "Category",
)
_REQUIRED_NATIVE_VALUES = frozenset(
    {
        "Id",
        "FileID",
        "Domain",
        "RepoName",
        "FilePath",
        "LineStart",
        "LineEnd",
        "GroundTruth",
        "Category",
    }
)
_CANONICAL_UNSIGNED_INTEGER = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def _require_regular_file(path: pathlib.Path, *, kind: str) -> None:
    try:
        value = path.lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(value.st_mode) or not stat.S_ISREG(value.st_mode):
        raise ValueError(f"{kind} must be a regular non-symlink file: {path}")


def _validate_manifest_row(
    row: object,
    *,
    source: str,
    file_root: pathlib.Path,
    ids: set[str],
) -> LabeledRecord:
    if not isinstance(row, dict):
        raise ValueError(f"{source} must be an object")
    unknown = row.keys() - _MANIFEST_SCHEMA.keys()
    missing = _REQUIRED_MANIFEST_FIELDS - row.keys()
    if unknown:
        raise ValueError(
            f"{source} has unknown fields: " + ", ".join(sorted(unknown))
        )
    if missing:
        raise ValueError(
            f"{source} is missing required fields: " + ", ".join(sorted(missing))
        )
    for field, value in row.items():
        expected = _MANIFEST_SCHEMA[field]
        if not _strict_type(value, expected):
            raise ValueError(
                f"{source} field {field!r} has type {type(value).__name__}; "
                f"expected {expected}"
            )

    record_id = row["id"]
    if not record_id:
        raise ValueError(f"{source} has an empty id")
    if record_id in ids:
        raise ValueError(f"{source} contains duplicate record id {record_id!r}")
    ids.add(record_id)
    relative = _validate_manifest_file(
        file_root, row["on_disk_path"], record_id=record_id
    )
    line_start = row["start_line"]
    line_end = row["end_line"]
    if line_start < 0 or line_end < 0:
        raise ValueError(f"{source} has negative line coordinates")
    if line_end and line_start and line_end < line_start:
        raise ValueError(f"{source} has end_line before start_line")
    if row.get("ignore", False) and row["label"]:
        raise ValueError(f"{source} cannot be both positive and ignored")
    return LabeledRecord(
        id=record_id,
        secret=row["secret"],
        label=row["label"],
        category=row["category"],
        file_path=relative,
        line_start=line_start,
        line_end=line_end,
        ignore=row.get("ignore", False),
    )


def _read_jsonl(path: pathlib.Path) -> list[tuple[str, object]]:
    rows: list[tuple[str, object]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"{path} line {line_number} is invalid JSON: {error}"
                ) from error
            rows.append((f"{path} line {line_number}", row))
    return rows


def _decode_csv_field(path: pathlib.Path, line_number: int, field: str, value: str):
    expected = _MANIFEST_SCHEMA[field]
    if expected is str:
        return value
    if expected is bool:
        if value == "true":
            return True
        if value == "false":
            return False
    elif expected is int and _CANONICAL_UNSIGNED_INTEGER.fullmatch(value):
        return int(value)
    raise ValueError(
        f"{path} line {line_number} field {field!r} has invalid "
        f"{expected.__name__} value {value!r}"
    )


def _read_csv(path: pathlib.Path) -> list[tuple[str, object]]:
    rows: list[tuple[str, object]] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        if fields is None:
            raise ValueError(f"{path} is missing a CSV header")
        if len(fields) != len(set(fields)):
            raise ValueError(f"{path} has duplicate CSV fields")
        unknown = set(fields) - _MANIFEST_SCHEMA.keys()
        missing = _REQUIRED_MANIFEST_FIELDS - set(fields)
        if unknown:
            raise ValueError(
                f"{path} has unknown fields: " + ", ".join(sorted(unknown))
            )
        if missing:
            raise ValueError(
                f"{path} is missing required fields: " + ", ".join(sorted(missing))
            )
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"{path} line {reader.line_num} is malformed")
            decoded = {
                field: _decode_csv_field(path, reader.line_num, field, value)
                for field, value in row.items()
            }
            rows.append((f"{path} line {reader.line_num}", decoded))
    return rows


def _read_parquet(path: pathlib.Path) -> list[tuple[str, object]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise SystemExit(
            "pyarrow is required for CredData Parquet exports; "
            "install benchmarks/requirements.txt"
        ) from exc
    table = pq.read_table(path)
    fields = table.column_names
    if len(fields) != len(set(fields)):
        raise ValueError(f"{path} has duplicate Parquet fields")
    unknown = set(fields) - _MANIFEST_SCHEMA.keys()
    missing = _REQUIRED_MANIFEST_FIELDS - set(fields)
    if unknown:
        raise ValueError(
            f"{path} has unknown fields: " + ", ".join(sorted(unknown))
        )
    if missing:
        raise ValueError(
            f"{path} is missing required fields: " + ", ".join(sorted(missing))
        )
    return [
        (f"{path} row {index}", row)
        for index, row in enumerate(table.to_pylist(), 1)
    ]


# ── native CredData meta/*.csv parsing ────────────────────────────────


def _native_int(
    row: dict[str, str],
    field: str,
    *,
    source: str,
    optional: bool = False,
) -> int:
    value = row[field]
    if optional and value in {"", "-1"}:
        return -1
    if not _CANONICAL_UNSIGNED_INTEGER.fullmatch(value):
        raise ValueError(
            f"{source} field {field!r} has invalid integer value {value!r}"
        )
    return int(value)


def _slice_value_from_lines(lines: list[str], line_start: int, line_end: int,
                            value_start: int, value_end: int) -> str:
    if line_start <= 0:
        return ""
    if line_start > len(lines):
        return ""
    # ValueStart == -1 marks a WHOLE-LINE span: the secret is the entire
    # line(s) with no sub-line offset. CredData uses this for multi-line
    # secrets: PEM/RSA private keys, service-account JSON, whose value has no
    # column offset. Clamp a negative start to the line beginning (a negative
    # end already falls through to len(line) in both branches below). Treating
    # value_start < 0 as "invalid → empty" silently dropped 1003 real private-key
    # positives from the ground truth, which both undercounted private-key/ssh
    # recall in the bench and starved the MoE retrain of PEM-key positives.
    if value_start < 0:
        value_start = 0
    if line_end <= 0:
        line_end = line_start
    if line_start == line_end:
        line = lines[line_start - 1]
        end = value_end if value_end >= 0 else len(line)
        return line[value_start:end]
    if line_end > len(lines):
        line_end = len(lines)
    first = lines[line_start - 1][value_start:]
    middle = lines[line_start:line_end - 1]
    last_line = lines[line_end - 1]
    last = last_line[:value_end] if value_end >= 0 else last_line
    return "\n".join([first, *middle, last])


class CredDataCorpus(Corpus):
    name = "creddata"

    def __init__(self, root: str | pathlib.Path | None = None,
                 treat_x: str = "negative"):
        self._root = pathlib.Path(
            root or os.environ.get("KEYHOG_BENCH_CREDDATA", _DEFAULT_ROOT))
        if treat_x not in ("negative", "ignore"):
            raise SystemExit("treat_x must be 'negative' or 'ignore'")
        self._treat_x = treat_x

    @property
    def root(self) -> pathlib.Path:
        # Scanner is pointed at the data tree when present (recurses); a
        # manifest-only export points the scanner at the export dir itself.
        if self._root.is_file():
            return self._root.parent
        data = self._root / "data"
        return data if data.is_dir() else self._root

    @property
    def file_root(self) -> pathlib.Path:
        # Native CSV FilePath is clone-relative (data/<RepoID>/...). A direct
        # manifest path resolves its fixtures beside that manifest.
        return self._root.parent if self._root.is_file() else self._root

    def meta_dir(self) -> pathlib.Path:
        return self._root / "meta"

    def _find_manifest(self) -> pathlib.Path | None:
        if self._root.is_file():
            return self._root
        for name in ("manifest.jsonl", "manifest.csv", "manifest.parquet"):
            cand = self._root / name
            if cand.exists():
                return cand
        return None

    def is_downloaded(self) -> bool:
        if self._find_manifest() is not None:
            return True
        data = self._root / "data"
        return self.meta_dir().is_dir() and data.is_dir() and any(data.iterdir())

    def _load_records(self) -> list[LabeledRecord]:
        manifest = self._find_manifest()
        if manifest is not None:
            _require_regular_file(manifest, kind="CredData manifest")
            if manifest.suffix == ".jsonl":
                rows = _read_jsonl(manifest)
            elif manifest.suffix == ".csv":
                rows = _read_csv(manifest)
            elif manifest.suffix == ".parquet":
                rows = _read_parquet(manifest)
            else:
                raise SystemExit(f"unsupported CredData manifest format: {manifest}")
            ids: set[str] = set()
            return [
                _validate_manifest_row(
                    row, source=source, file_root=self.file_root, ids=ids
                )
                for source, row in rows
            ]
        return self._records_from_meta()

    def _records_from_meta(self) -> list[LabeledRecord]:
        meta = self.meta_dir()
        try:
            meta_stat = meta.lstat()
        except FileNotFoundError:
            raise SystemExit(
                f"CredData metadata missing: {meta}\n"
                f"  download it with: make creddata"
            )
        if stat.S_ISLNK(meta_stat.st_mode) or not stat.S_ISDIR(meta_stat.st_mode):
            raise ValueError(
                f"CredData metadata must be a regular non-symlink directory: {meta}"
            )
        out: list[LabeledRecord] = []
        ids: set[str] = set()
        line_cache: dict[pathlib.Path, list[str]] = {}

        def cached_lines(path: pathlib.Path) -> list[str]:
            if path not in line_cache:
                try:
                    with open(path, "r", encoding="latin-1") as fh:
                        raw = fh.read()
                except OSError as error:
                    raise ValueError(
                        f"CredData fixture could not be read: {path}"
                    ) from error
                # CredData's coordinates count only '\n' boundaries. Using
                # splitlines() also splits NEL and Unicode separators.
                line_cache[path] = [
                    line[:-1] if line.endswith("\r") else line
                    for line in raw.split("\n")
                ]
            return line_cache[path]

        for csv_path in sorted(meta.glob("*.csv")):
            _require_regular_file(csv_path, kind="CredData metadata")
            with csv_path.open(newline="", encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                fields = reader.fieldnames
                if fields is None:
                    raise ValueError(f"{csv_path} is missing a CSV header")
                if tuple(fields) != _NATIVE_COLUMNS:
                    raise ValueError(
                        f"{csv_path} must have exactly the native CredData columns"
                    )
                for row in reader:
                    source = f"{csv_path} line {reader.line_num}"
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError(f"{source} is malformed")
                    missing_values = sorted(
                        field for field in _REQUIRED_NATIVE_VALUES if row[field] == ""
                    )
                    if missing_values:
                        raise ValueError(
                            f"{source} has empty required fields: "
                            + ", ".join(missing_values)
                        )
                    record_id = row["Id"]
                    if record_id in ids:
                        raise ValueError(
                            f"{source} contains duplicate record id {record_id!r}"
                        )
                    ids.add(record_id)

                    gt = row["GroundTruth"]
                    if gt == "T":
                        label, ignore = True, False
                    elif gt == "F":
                        label, ignore = False, False
                    elif gt == "X":
                        label = False
                        ignore = self._treat_x == "ignore"
                    else:
                        raise ValueError(
                            f"{source} field 'GroundTruth' must be exactly T, F, or X; "
                            f"got {gt!r}"
                        )

                    ls = _native_int(row, "LineStart", source=source)
                    le = _native_int(row, "LineEnd", source=source)
                    vs = _native_int(row, "ValueStart", source=source, optional=True)
                    ve = _native_int(row, "ValueEnd", source=source, optional=True)
                    if ls == 0 or le == 0:
                        raise ValueError(f"{source} has non-positive line coordinates")
                    if le < ls:
                        raise ValueError(f"{source} has LineEnd before LineStart")
                    if ls == le and vs >= 0 and ve >= 0 and ve < vs:
                        raise ValueError(f"{source} has ValueEnd before ValueStart")

                    rel = _validate_manifest_file(
                        self._root, row["FilePath"], record_id=record_id
                    )
                    secret = ""
                    if label:
                        secret = _slice_value_from_lines(
                            cached_lines(self._root / rel), ls, le, vs, ve
                        )
                        if not secret:
                            raise ValueError(
                                f"{source} positive has an empty or out-of-range value"
                            )
                    out.append(
                        LabeledRecord(
                            id=f"creddata-{record_id}-{ls}-{vs}",
                            secret=secret,
                            label=label,
                            category=row["Category"],
                            file_path=rel,
                            line_start=ls,
                            line_end=le,
                            ignore=ignore,
                        )
                    )
        return out

    # ── download (pinned clone + CredData's own downloader) ───────────

    def download(self) -> None:
        clone = self._root
        if not (clone / ".git").is_dir():
            clone.parent.mkdir(parents=True, exist_ok=True)
            print(f"cloning CredData -> {clone}", file=sys.stderr)
            subprocess.run(["git", "clone", CREDDATA_REPO, str(clone)], check=True)
        print(f"checking out pinned commit {CREDDATA_PIN[:12]}", file=sys.stderr)
        subprocess.run(["git", "-C", str(clone), "fetch", "--depth", "1",
                        "origin", CREDDATA_PIN], check=False)
        subprocess.run(["git", "-C", str(clone), "checkout", CREDDATA_PIN], check=True)
        req = clone / "requirements.txt"
        if req.exists():
            print("installing CredData requirements", file=sys.stderr)
            subprocess.run([sys.executable, "-m", "pip", "install", "-q",
                            "-r", str(req)], check=False)
        downloader = clone / "download_data.py"
        if not downloader.exists():
            raise SystemExit(f"CredData downloader not found: {downloader}")
        print("running download_data.py (fetches ~11k files; takes a while)",
              file=sys.stderr)
        subprocess.run([sys.executable, str(downloader), "--data_dir", "data"],
                       cwd=str(clone), check=True)
        print(f"CredData ready: {self.root}", file=sys.stderr)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CredData corpus management.")
    parser.add_argument("--download", action="store_true",
                        help="Clone pinned CredData + run its downloader.")
    parser.add_argument("--root", default=None)
    parser.add_argument("--treat-x", choices=("negative", "ignore"),
                        default="negative")
    args = parser.parse_args(argv)
    corpus = CredDataCorpus(root=args.root, treat_x=args.treat_x)
    if args.download:
        corpus.download()
    if corpus.is_downloaded():
        info = corpus.info()
        print(f"{corpus.name}: {info.fixture_count} records, "
              f"{info.labeled_positives} positives at {corpus.root}",
              file=sys.stderr)
    else:
        print(f"{corpus.name}: not downloaded (run: make creddata)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
