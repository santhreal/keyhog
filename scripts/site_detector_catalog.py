#!/usr/bin/env python3
"""Generate and check the website detector catalog from detector TOMLs."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]


def detector_record_from_toml(path: pathlib.Path) -> dict[str, Any]:
    parsed = tomllib.loads(path.read_text())
    detector = parsed["detector"]
    return {
        "id": detector["id"],
        "name": detector["name"],
        "service": detector.get("service", ""),
        "severity": detector["severity"],
        "keywords": detector.get("keywords", []),
    }


def detector_records_from_toml(repo: pathlib.Path = REPO) -> list[dict[str, Any]]:
    records = [
        detector_record_from_toml(path)
        for path in sorted((repo / "detectors").glob("*.toml"))
    ]
    return sorted(records, key=lambda item: item["id"])


def detector_records_from_site_json(repo: pathlib.Path = REPO) -> list[dict[str, Any]]:
    data = json.loads((repo / "site/data/detectors.json").read_text())
    if not isinstance(data, list):
        raise ValueError("site/data/detectors.json must be a JSON array")
    records: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("site/data/detectors.json entries must be JSON objects")
        records.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "service": item.get("service", ""),
                "severity": item.get("severity"),
                "keywords": item.get("keywords", []),
            }
        )
    return sorted(records, key=lambda item: str(item["id"]))


def detector_catalog_drift(repo: pathlib.Path = REPO) -> list[str]:
    expected = detector_records_from_toml(repo)
    actual = detector_records_from_site_json(repo)
    issues: list[str] = []
    if len(actual) != len(expected):
        issues.append(
            f"site/data/detectors.json has {len(actual)} records; detectors/*.toml has {len(expected)}"
        )
    expected_by_id = {item["id"]: item for item in expected}
    actual_by_id = {item["id"]: item for item in actual}
    missing = sorted(set(expected_by_id) - set(actual_by_id))
    extra = sorted(set(actual_by_id) - set(expected_by_id))
    if missing:
        issues.append(f"missing detector ids in site JSON: {', '.join(missing[:20])}")
    if extra:
        issues.append(f"extra detector ids in site JSON: {', '.join(extra[:20])}")
    changed = [
        detector_id
        for detector_id in sorted(set(expected_by_id) & set(actual_by_id))
        if expected_by_id[detector_id] != actual_by_id[detector_id]
    ]
    if changed:
        issues.append(f"stale detector metadata in site JSON: {', '.join(changed[:20])}")
    return issues


def write_site_json(repo: pathlib.Path = REPO) -> int:
    records = detector_records_from_toml(repo)
    (repo / "site/data/detectors.json").write_text(
        json.dumps(records, indent=2, sort_keys=False) + "\n"
    )
    return len(records)


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        issues = detector_catalog_drift()
        if issues:
            for issue in issues:
                print(issue, file=sys.stderr)
            return 1
        print("site detector catalog is current")
        return 0
    if argv not in ([], ["--write"]):
        print("usage: scripts/site_detector_catalog.py [--write|--check]", file=sys.stderr)
        return 2
    count = write_site_json()
    print(f"wrote site/data/detectors.json with {count} detectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
