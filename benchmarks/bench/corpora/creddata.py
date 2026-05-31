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

1. **Pre-built manifest** — if a ``manifest.{jsonl,csv,parquet}`` is present
   under the corpus root, load it directly (lets a CredData export be dropped
   in without the native download). Optional Parquet support stays lazy.
2. **Native CredData layout** — otherwise parse ``meta/*.csv`` and slice each
   positive's literal secret out of the on-disk file at its ``LineStart`` /
   ``ValueStart..ValueEnd`` span, so the value-overlap scorer works unchanged.

**Labeling** (CredData's own convention, README "Properties"):
``GroundTruth`` is ``T`` (real credential → positive) or ``F``/``X`` (false
positive / placeholder/test/example → negative). We follow that exactly so
the numbers are comparable to CredSweeper's published CredData scores — this
intentionally diverges from the planning note's "X=ignore"; firing on a
CredData placeholder is a false positive in CredData's own scoring, and
keyhog is already run with ``--no-suppress-test-fixtures`` to keep the
comparison apples-to-apples. Override with ``treat_x="ignore"``.

Native CSV columns (in order): Id, FileID, Domain, RepoName, FilePath,
LineStart, LineEnd, GroundTruth, ValueStart, ValueEnd, CryptographyKey,
PredefinedPattern, Category. Lines are 1-indexed; ValueStart/ValueEnd are
0-indexed character offsets on the line (ValueEnd = index just past the
value); ``-1``/empty means whole-line markup (negatives only).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

from .base import Corpus, LabeledRecord

_BENCH_ROOT = pathlib.Path(__file__).resolve().parents[2]
_DEFAULT_ROOT = _BENCH_ROOT / "corpora" / "creddata" / "CredData"

# Pinned CredData commit — bump deliberately, never float to a branch, so a
# CredData score is always reproducible against an exact dataset revision.
CREDDATA_REPO = "https://github.com/Samsung/CredData.git"
CREDDATA_PIN = "f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee"  # 2026-05-26


# ── generic manifest fast-path (jsonl / csv / parquet export) ─────────


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    return text in {"1", "true", "t", "yes", "y", "positive", "secret", "valid"}


def _ignored(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text in {"ignore", "ignored", "template", "placeholder"}


def _secret(row: dict[str, Any]) -> str:
    for key in ("secret", "Secret", "value", "Value", "credential", "Credential"):
        if row.get(key):
            return str(row[key])
    return ""


def _file_path(row: dict[str, Any]) -> str:
    for key in ("on_disk_path", "file_path", "FilePath", "path", "Path", "filename"):
        if row.get(key):
            return str(row[key])
    return ""


def _manifest_label(row: dict[str, Any]) -> tuple[bool, bool]:
    for key in ("label", "Label", "GroundTruth", "verdict", "classification"):
        if key not in row:
            continue
        value = row.get(key)
        if _ignored(value):
            return False, True
        return _truthy(value), False
    return _truthy(row.get("is_secret") or row.get("positive")), False


def _manifest_record(row: dict[str, Any], index: int) -> LabeledRecord:
    label, ignore = _manifest_label(row)
    return LabeledRecord(
        id=str(row.get("id") or row.get("Id") or row.get("record_id") or index),
        secret=_secret(row),
        label=label,
        category=str(row.get("category") or row.get("Category") or "unknown"),
        file_path=_file_path(row),
        line_start=int(row.get("line_start") or row.get("start_line")
                       or row.get("LineStart") or row.get("line") or 0),
        line_end=int(row.get("line_end") or row.get("end_line")
                     or row.get("LineEnd") or row.get("line") or 0),
        ignore=ignore,
    )


def _read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _read_csv(path: pathlib.Path) -> list[dict[str, Any]]:
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _read_parquet(path: pathlib.Path) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise SystemExit(
            "pyarrow is required for CredData Parquet exports; "
            "install benchmarks/requirements.txt"
        ) from exc
    return pq.read_table(path).to_pylist()


# ── native CredData meta/*.csv parsing ────────────────────────────────


def _to_int(s: Any, default: int = -1) -> int:
    text = str(s or "").strip()
    if text in ("", "-1"):
        return default
    try:
        return int(text)
    except ValueError:
        return default


def _extract_value(file_path: pathlib.Path, line_start: int, line_end: int,
                   value_start: int, value_end: int) -> str:
    """Slice the literal secret from the file at the CredData span. Returns ""
    on any inconsistency (missing file, out-of-range, whole-line markup) — a
    positive whose value can't be anchored to a real on-disk byte range is
    dropped by the caller rather than guessed, keeping the corpus free of
    fabricated truth."""
    if line_start <= 0 or value_start < 0:
        return ""
    try:
        # latin-1: source files are arbitrary bytes; we only need a stable
        # byte-faithful substring for the containment overlap, not valid UTF-8.
        with open(file_path, "r", encoding="latin-1") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return ""
    if line_start > len(lines):
        return ""
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
        data = self._root / "data"
        return data if data.is_dir() else self._root

    @property
    def file_root(self) -> pathlib.Path:
        # Native CSV FilePath is clone-relative (data/<RepoID>/...), so
        # records resolve from the clone root.
        return self._root

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

    def records(self) -> list[LabeledRecord]:
        manifest = self._find_manifest()
        if manifest is not None:
            if manifest.suffix == ".jsonl":
                rows = _read_jsonl(manifest)
            elif manifest.suffix == ".csv":
                rows = _read_csv(manifest)
            elif manifest.suffix == ".parquet":
                rows = _read_parquet(manifest)
            else:
                raise SystemExit(f"unsupported CredData manifest format: {manifest}")
            return [_manifest_record(row, i) for i, row in enumerate(rows)]
        return self._records_from_meta()

    def _records_from_meta(self) -> list[LabeledRecord]:
        meta = self.meta_dir()
        if not meta.is_dir():
            raise SystemExit(
                f"CredData metadata missing: {meta}\n"
                f"  download it with: make creddata"
            )
        out: list[LabeledRecord] = []
        dropped_no_value = 0
        for csv_path in sorted(meta.glob("*.csv")):
            with open(csv_path, newline="") as fh:
                for row in csv.DictReader(fh):
                    gt = (row.get("GroundTruth") or "").strip().upper()
                    if gt == "T":
                        label, ignore = True, False
                    elif gt == "X" and self._treat_x == "ignore":
                        label, ignore = False, True
                    else:  # F, X (default), anything else -> negative
                        label, ignore = False, False
                    rel = (row.get("FilePath") or "").strip()
                    if not rel:
                        continue
                    ls = _to_int(row.get("LineStart"), 0)
                    le = _to_int(row.get("LineEnd"), 0)
                    vs = _to_int(row.get("ValueStart"), -1)
                    ve = _to_int(row.get("ValueEnd"), -1)
                    secret = ""
                    if label:
                        secret = _extract_value(self._root / rel, ls, le, vs, ve)
                        if not secret:
                            dropped_no_value += 1
                            continue
                    out.append(LabeledRecord(
                        id=f"creddata-{row.get('Id') or row.get('FileID')}-{ls}-{vs}",
                        secret=secret,
                        label=label,
                        category=(row.get("Category") or "unknown").strip() or "unknown",
                        file_path=rel,
                        line_start=ls,
                        line_end=le,
                        ignore=ignore,
                    ))
        if dropped_no_value:
            print(f"creddata: dropped {dropped_no_value} positives with "
                  f"unextractable on-disk values (file absent or span "
                  f"inconsistent)", file=sys.stderr)
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
