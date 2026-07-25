"""Canonical baseline inventory policy.

The ``benchmarks/baselines/`` directory is split into an active surface and an
archive boundary:

* ``baselines/canonical.toml`` declares one canonical current baseline per
  active corpus by relative path.
* ``baselines/archive/`` holds historical baseline versions. Active gates never
  load files from the archive, and the inventory is rejected if it points there.

The gate consumes baselines by declared identity (corpus -> path) instead of
scanning a directory and choosing the newest filename or most recent
``generated_at``.
"""

from __future__ import annotations

import json
import pathlib
import tomllib

from .schema import RunResult


BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINES_DIR = BENCH_ROOT / "baselines"
ARCHIVE_DIR = BASELINES_DIR / "archive"
CANONICAL_FILE = BASELINES_DIR / "canonical.toml"


class BaselineInventoryError(Exception):
    """The baseline inventory is missing, malformed, or selects an unusable anchor."""


def _baselines_dir(baselines_dir: pathlib.Path | None = None) -> pathlib.Path:
    return baselines_dir or BASELINES_DIR


def _canonical_path(
    canonical_path: pathlib.Path | None = None,
    baselines_dir: pathlib.Path | None = None,
) -> pathlib.Path:
    return canonical_path or (_baselines_dir(baselines_dir) / "canonical.toml")


def _archive_dir(baselines_dir: pathlib.Path | None = None) -> pathlib.Path:
    return _baselines_dir(baselines_dir) / "archive"


def read_inventory(
    *,
    canonical_path: pathlib.Path | None = None,
    baselines_dir: pathlib.Path | None = None,
) -> dict[str, str]:
    """Read ``canonical.toml`` and return a ``corpus -> relative path`` map.

    Rejects missing files, malformed TOML, non-table entries, paths that are
    not relative, and ambiguous paths that map to more than one corpus.
    """
    p = _canonical_path(canonical_path, baselines_dir)
    if not p.exists():
        raise BaselineInventoryError(f"missing canonical baseline inventory: {p}")
    try:
        data = tomllib.loads(p.read_text())
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BaselineInventoryError(
            f"cannot read canonical baseline inventory {p}: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise BaselineInventoryError(
            f"canonical baseline inventory {p} must be a top-level table"
        )

    inventory: dict[str, str] = {}
    for corpus, entry in data.items():
        if not isinstance(entry, dict):
            raise BaselineInventoryError(
                f"canonical baseline for corpus {corpus!r} must be a table"
            )
        rel = entry.get("path")
        if not isinstance(rel, str) or not rel:
            raise BaselineInventoryError(
                f"canonical baseline for corpus {corpus!r} must declare a non-empty string 'path'"
            )
        if rel.startswith("/") or ".." in rel.split("/"):
            raise BaselineInventoryError(
                f"canonical baseline path {rel!r} for corpus {corpus!r} must be a relative path without '..'"
            )
        inventory[corpus] = rel

    # Reject the same relative path being declared for multiple corpora.
    by_path: dict[str, list[str]] = {}
    for corpus, rel in inventory.items():
        by_path.setdefault(rel, []).append(corpus)
    for rel, corpora in by_path.items():
        if len(corpora) > 1:
            raise BaselineInventoryError(
                f"ambiguous canonical baseline: path {rel!r} is declared for multiple corpora: {', '.join(corpora)}"
            )

    return inventory


def resolve(
    corpus: str,
    *,
    inventory: dict[str, str] | None = None,
    baselines_dir: pathlib.Path | None = None,
    canonical_path: pathlib.Path | None = None,
) -> pathlib.Path:
    """Return the canonical baseline file path for ``corpus``.

    The returned path must sit inside the active surface (``baselines_dir``),
    not inside ``baselines_dir/archive/``, and must be an existing regular file.
    """
    if inventory is None:
        inventory = read_inventory(
            canonical_path=canonical_path, baselines_dir=baselines_dir
        )
    rel = inventory.get(corpus)
    if rel is None:
        raise BaselineInventoryError(
            f"no canonical baseline declared for corpus {corpus!r}"
        )

    root = _baselines_dir(baselines_dir).resolve()
    candidate = (root / rel).resolve()

    try:
        candidate.relative_to(root)
    except ValueError:
        raise BaselineInventoryError(
            f"canonical baseline path {rel!r} for corpus {corpus!r} escapes baselines directory"
        )

    archive = _archive_dir(baselines_dir).resolve()
    try:
        candidate.relative_to(archive)
    except ValueError:
        pass
    else:
        raise BaselineInventoryError(
            f"canonical baseline for corpus {corpus!r} points into the archive: {rel!r}"
        )

    if not candidate.exists():
        raise BaselineInventoryError(
            f"canonical baseline for corpus {corpus!r} does not exist: {candidate}"
        )
    if not candidate.is_file():
        raise BaselineInventoryError(
            f"canonical baseline for corpus {corpus!r} is not a file: {candidate}"
        )

    return candidate


def load_canonical(
    corpus: str,
    *,
    inventory: dict[str, str] | None = None,
    baselines_dir: pathlib.Path | None = None,
    canonical_path: pathlib.Path | None = None,
) -> RunResult:
    """Load and validate the canonical baseline RunResult for ``corpus``.

    The file must be a valid ``RunResult``, must be available, must be a keyhog
    measurement, and its embedded ``corpus.name`` must match the requested
    corpus.
    """
    p = resolve(
        corpus,
        inventory=inventory,
        baselines_dir=baselines_dir,
        canonical_path=canonical_path,
    )
    try:
        data = json.loads(p.read_text())
        run = RunResult.from_json(data, source=str(p))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise BaselineInventoryError(
            f"canonical baseline {p} is not a valid RunResult: {exc}"
        ) from exc

    if not run.available:
        raise BaselineInventoryError(
            f"canonical baseline {p} is marked unavailable: {run.error}"
        )
    if run.scanner.name != "keyhog":
        raise BaselineInventoryError(
            f"canonical baseline {p} is not a keyhog result (scanner={run.scanner.name!r})"
        )
    if run.corpus.name != corpus:
        raise BaselineInventoryError(
            f"canonical baseline for corpus {corpus!r} has corpus.name={run.corpus.name!r} in {p}"
        )
    return run
