#!/usr/bin/env python3
"""Verify that GitHub Action reference documentation matches action.yml."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOT_ACTION = REPO / "action.yml"
NESTED_ACTION = REPO / ".github/actions/keyhog/action.yml"
ACTION_DOCS = (
    REPO / "docs/src/workflows/github-action.md",
    REPO / ".github/actions/keyhog/README.md",
)

_TABLE_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|")


class ContractError(ValueError):
    """Raised when the documented Action interface differs from its manifest."""


def load_manifest(path: Path) -> tuple[dict[str, str], tuple[str, ...]]:
    """Read the public interface without requiring a third-party YAML package."""
    inputs: dict[str, str | None] = {}
    outputs: list[str] = []
    section: str | None = None
    current_input: str | None = None
    member = re.compile(r"^  ([a-z0-9][a-z0-9-]*):\s*$")
    default = re.compile(r"^    default:\s*(.*?)\s*$")

    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if line and not line[0].isspace():
            section = line[:-1] if line in {"inputs:", "outputs:"} else None
            current_input = None
            continue
        if section is None:
            continue
        if match := member.match(line):
            name = match.group(1)
            current_input = name if section == "inputs" else None
            if section == "inputs":
                if name in inputs:
                    raise ContractError(
                        f"{path}:{line_number}: duplicate input {name!r}"
                    )
                inputs[name] = None
            else:
                if name in outputs:
                    raise ContractError(
                        f"{path}:{line_number}: duplicate output {name!r}"
                    )
                outputs.append(name)
            continue
        if section == "inputs" and current_input and (match := default.match(line)):
            value = match.group(1)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            inputs[current_input] = value

    if not inputs or not outputs:
        raise ContractError(f"{path}: manifest must define inputs and outputs")
    missing_defaults = [name for name, value in inputs.items() if value is None]
    if missing_defaults:
        raise ContractError(f"{path}: inputs lack defaults: {missing_defaults!r}")
    return {name: value for name, value in inputs.items() if value is not None}, tuple(
        outputs
    )


def markdown_table(text: str, heading: str) -> list[tuple[str, str]]:
    """Extract first and second columns from the table owned by one H2 heading."""
    marker = f"## {heading}\n"
    start = text.find(marker)
    if start < 0:
        raise ContractError(f"missing {marker.strip()!r} section")
    section = text[start + len(marker) :]
    next_heading = section.find("\n## ")
    if next_heading >= 0:
        section = section[:next_heading]
    rows = [
        match.groups()
        for line in section.splitlines()
        if (match := _TABLE_ROW.match(line))
    ]
    if not rows:
        raise ContractError(f"{heading!r} section has no interface table")
    names = [name for name, _ in rows]
    if len(names) != len(set(names)):
        raise ContractError(f"{heading!r} table contains duplicate names")
    return rows


def documented_inputs(text: str) -> dict[str, str]:
    """Return documented input defaults, normalized to action.yml scalar text."""
    values: dict[str, str] = {}
    for name, rendered_default in markdown_table(text, "Inputs"):
        value = rendered_default.strip()
        if value == "empty":
            value = ""
        elif len(value) >= 2 and value[0] == "`" and value[-1] == "`":
            value = value[1:-1]
        if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
            value = value[1:-1]
        values[name] = value
    return values


def documented_outputs(text: str) -> tuple[str, ...]:
    """Return documented output names in table order."""
    return tuple(name for name, _ in markdown_table(text, "Outputs"))


def verify_contract(
    root_manifest_path: Path,
    nested_manifest_path: Path,
    documentation_paths: tuple[Path, ...],
) -> None:
    """Verify manifest parity and the exact documented public interface."""
    root_interface = load_manifest(root_manifest_path)
    nested_interface = load_manifest(nested_manifest_path)
    if nested_interface != root_interface:
        raise ContractError("root and nested Action public interfaces differ")

    expected_inputs, expected_outputs = root_interface
    for path in documentation_paths:
        text = path.read_text(encoding="utf-8")
        actual_inputs = documented_inputs(text)
        actual_outputs = documented_outputs(text)
        if actual_inputs != expected_inputs:
            raise ContractError(
                f"{path}: input names/defaults differ: expected {expected_inputs!r}, "
                f"found {actual_inputs!r}"
            )
        if actual_outputs != expected_outputs:
            raise ContractError(
                f"{path}: output names/order differ: expected {expected_outputs!r}, "
                f"found {actual_outputs!r}"
            )


def check_repo() -> int:
    """Run the repository Action documentation contract gate."""
    try:
        verify_contract(ROOT_ACTION, NESTED_ACTION, ACTION_DOCS)
    except (ContractError, OSError) as error:
        print(f"FAIL - GitHub Action documentation contract: {error}", file=sys.stderr)
        return 1
    print("OK - GitHub Action manifests and reference tables expose one interface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(check_repo())
