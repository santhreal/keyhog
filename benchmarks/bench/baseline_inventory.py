"""Inventory current baseline coverage without hiding duplicate or stale evidence."""

from __future__ import annotations

import argparse
import json
import pathlib
import tomllib

from .baseline_capture import BaselineCaptureError, validate_baseline_payload
from .schema import RunResult
from .target_matrix import load_target_matrix
from .workload_catalog import load_workload_catalog

BENCH_ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINES_DIR = BENCH_ROOT / "baselines"
ARCHIVE_DIR = BASELINES_DIR / "archive"
CANONICAL_FILE = BASELINES_DIR / "canonical.toml"


class BaselineInventoryError(RuntimeError):
    """Baseline artifacts cannot prove one unambiguous workload inventory."""


def _baselines_dir(baselines_dir: pathlib.Path | None = None) -> pathlib.Path:
    """Return the resolved baselines directory path."""
    return baselines_dir or BASELINES_DIR


def _canonical_path(
    canonical_path: pathlib.Path | None = None,
    baselines_dir: pathlib.Path | None = None,
) -> pathlib.Path:
    """Return the resolved canonical baselines manifest path."""
    return canonical_path or (_baselines_dir(baselines_dir) / "canonical.toml")


def _archive_dir(baselines_dir: pathlib.Path | None = None) -> pathlib.Path:
    """Return the resolved archive directory path under baselines."""
    return _baselines_dir(baselines_dir) / "archive"


def read_inventory(
    *,
    canonical_path: pathlib.Path | None = None,
    baselines_dir: pathlib.Path | None = None,
) -> dict[str, str]:
    """Read the explicit corpus-to-baseline inventory."""
    path = _canonical_path(canonical_path, baselines_dir)
    if not path.exists():
        raise BaselineInventoryError(
            f"missing canonical baseline inventory: {path}"
        )
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BaselineInventoryError(
            f"cannot read canonical baseline inventory {path}: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise BaselineInventoryError(
            f"canonical baseline inventory {path} must be a top-level table"
        )

    inventory: dict[str, str] = {}
    for corpus, entry in data.items():
        if not isinstance(entry, dict):
            raise BaselineInventoryError(
                f"canonical baseline for corpus {corpus!r} must be a table"
            )
        relative = entry.get("path")
        if not isinstance(relative, str) or not relative:
            raise BaselineInventoryError(
                f"canonical baseline for corpus {corpus!r} must declare "
                "a non-empty string 'path'"
            )
        if relative.startswith("/") or ".." in relative.split("/"):
            raise BaselineInventoryError(
                f"canonical baseline path {relative!r} for corpus {corpus!r} "
                "must be a relative path without '..'"
            )
        inventory[corpus] = relative

    by_path: dict[str, list[str]] = {}
    for corpus, relative in inventory.items():
        by_path.setdefault(relative, []).append(corpus)
    for relative, corpora in by_path.items():
        if len(corpora) > 1:
            raise BaselineInventoryError(
                f"ambiguous canonical baseline: path {relative!r} is declared "
                f"for multiple corpora: {', '.join(corpora)}"
            )
    return inventory


def resolve(
    corpus: str,
    *,
    inventory: dict[str, str] | None = None,
    baselines_dir: pathlib.Path | None = None,
    canonical_path: pathlib.Path | None = None,
) -> pathlib.Path:
    """Resolve one canonical baseline inside the active baseline directory."""
    if inventory is None:
        inventory = read_inventory(
            canonical_path=canonical_path,
            baselines_dir=baselines_dir,
        )
    relative = inventory.get(corpus)
    if relative is None:
        raise BaselineInventoryError(
            f"no canonical baseline declared for corpus {corpus!r}"
        )

    root = _baselines_dir(baselines_dir).resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise BaselineInventoryError(
            f"canonical baseline path {relative!r} for corpus {corpus!r} "
            "escapes baselines directory"
        ) from exc

    archive = _archive_dir(baselines_dir).resolve()
    try:
        candidate.relative_to(archive)
    except ValueError:
        pass
    else:
        raise BaselineInventoryError(
            f"canonical baseline for corpus {corpus!r} points into the archive: "
            f"{relative!r}"
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
    """Load and validate the declared KeyHog baseline for one corpus."""
    path = resolve(
        corpus,
        inventory=inventory,
        baselines_dir=baselines_dir,
        canonical_path=canonical_path,
    )
    try:
        run = RunResult.from_json(
            json.loads(path.read_text(encoding="utf-8")),
            source=str(path),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise BaselineInventoryError(
            f"canonical baseline {path} is not a valid RunResult: {exc}"
        ) from exc
    if not run.available:
        raise BaselineInventoryError(
            f"canonical baseline {path} is marked unavailable: {run.error}"
        )
    if run.scanner.name != "keyhog":
        raise BaselineInventoryError(
            f"canonical baseline {path} is not a keyhog result "
            f"(scanner={run.scanner.name!r})"
        )
    if run.corpus.name != corpus:
        raise BaselineInventoryError(
            f"canonical baseline for corpus {corpus!r} has "
            f"corpus.name={run.corpus.name!r} in {path}"
        )
    return run


def inventory_baselines(
    baseline_dir: pathlib.Path,
    *,
    catalog_path: pathlib.Path,
    fixture_lock_path: pathlib.Path,
    target_matrix_path: pathlib.Path,
    backends: tuple[str, ...] = ("cpu", "simd"),
    require_complete: bool = False,
) -> dict[str, object]:
    """Validate authoritative artifacts and report exact coverage and parity gaps."""
    catalog = load_workload_catalog(catalog_path)
    catalog_ids = {workload.workload_id for workload in catalog.workloads}
    workspace_version = load_target_matrix(
        target_matrix_path
    ).software.workspace_version
    result: dict[str, object] = {"catalog_workloads": len(catalog_ids), "backends": {}}
    generation_binaries: set[str] = set()
    for backend in backends:
        rows: dict[str, tuple[pathlib.Path, dict[str, object]]] = {}
        binaries: set[str] = set()
        artifacts: list[str] = []
        pattern = f"current-v{workspace_version}-linux-{backend}-*.json"
        for path in sorted(baseline_dir.glob(pattern)):
            if "-part" in path.stem:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                validate_baseline_payload(
                    payload,
                    catalog_path=catalog_path,
                    fixture_lock_path=fixture_lock_path,
                    target_matrix_path=target_matrix_path,
                )
            except (OSError, json.JSONDecodeError, BaselineCaptureError) as exc:
                raise BaselineInventoryError(
                    f"invalid baseline artifact {path}: {exc}"
                ) from exc
            if payload["backend"] != backend:
                raise BaselineInventoryError(
                    f"artifact {path} names {backend} but records {payload['backend']!r}"
                )
            artifacts.append(path.name)
            binaries.add(str(payload["binary_sha256"]))
            for row in payload["workloads"]:
                workload_id = str(row["workload_id"])
                previous = rows.get(workload_id)
                if previous is not None:
                    raise BaselineInventoryError(
                        f"duplicate {backend} workload {workload_id!r} in "
                        f"{previous[0].name} and {path.name}"
                    )
                rows[workload_id] = (path, row)
        if len(binaries) > 1:
            raise BaselineInventoryError(
                f"{backend} baseline generation mixes executable identities: "
                f"{sorted(binaries)}"
            )
        generation_binaries.update(binaries)
        covered = set(rows)
        missing = catalog_ids - covered
        if require_complete and missing:
            raise BaselineInventoryError(
                f"{backend} baseline generation is incomplete: "
                f"missing={sorted(missing)}"
            )
        result["backends"][backend] = {
            "artifacts": artifacts,
            "binary_sha256s": sorted(binaries),
            "covered": sorted(covered),
            "missing": sorted(missing),
            "parity_failures": sorted(
                workload_id for workload_id, (_path, row) in rows.items()
                if row["parity_ok"] is not True
            ),
        }
    if len(generation_binaries) > 1:
        raise BaselineInventoryError(
            "baseline generation mixes executable identities across backends: "
            f"{sorted(generation_binaries)}"
        )
    result["binary_sha256"] = next(iter(generation_binaries), None)
    return result


def _main() -> int:
    """Execute CLI entry point for baseline inventory validation."""
    parser = argparse.ArgumentParser(description="Validate current baseline inventory")
    parser.add_argument("--baselines", default="baselines")
    parser.add_argument("--catalog", default="workload-catalog.toml")
    parser.add_argument("--fixture-lock", default="workload-fixtures.lock.json")
    parser.add_argument("--target-matrix", default="target-matrix.toml")
    parser.add_argument("--out")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    inventory = inventory_baselines(
        pathlib.Path(args.baselines),
        catalog_path=pathlib.Path(args.catalog),
        fixture_lock_path=pathlib.Path(args.fixture_lock),
        target_matrix_path=pathlib.Path(args.target_matrix),
        require_complete=args.require_complete,
    )
    encoded = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if args.out:
        pathlib.Path(args.out).write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
