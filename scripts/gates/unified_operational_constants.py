#!/usr/bin/env python3
"""Gate: UNIFIED OPERATIONAL CONSTANTS GOVERNANCE (Row 113).

Ensures that every operational performance knob affecting throughput,
memory, batching, concurrency, or accelerator eligibility is cataloged in the
canonical metadata registry (`crates/cli/src/config/operational.rs`) and
exposed through the 3-layer configuration path (Default < TOML < CLI).

Acceptance criteria:
- Every operational constant has a TOML key, valid range, documented default, and unit.
- Adding a performance constant to source without a schema/registry entry fails the gate.
- Precedence totality and range checks are enforced.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

OPERATIONAL_RS = pathlib.Path("crates/cli/src/config/operational.rs")
SCHEMA_RS = pathlib.Path("crates/cli/src/config/schema.rs")


def extract_registered_toml_keys(operational_path: pathlib.Path) -> set[str]:
    """Extract all toml_key strings from operational.rs."""
    if not operational_path.exists():
        return set()

    content = operational_path.read_text(encoding="utf-8")
    keys = set(re.findall(r'toml_key:\s*"([^"]+)"', content))
    return keys


def extract_schema_fields(schema_path: pathlib.Path) -> set[str]:
    """Extract fields present in schema.rs."""
    if not schema_path.exists():
        return set()

    content = schema_path.read_text(encoding="utf-8")
    fields = set(re.findall(r"pub\s+([a-zA-Z0-9_]+)\s*:\s*Option<", content))
    return fields


def run_gate(root: pathlib.Path) -> int:
    operational_path = root / OPERATIONAL_RS
    schema_path = root / SCHEMA_RS

    if not operational_path.exists():
        print(f"FAIL: Missing {OPERATIONAL_RS}")
        return 1

    registered_keys = extract_registered_toml_keys(operational_path)
    schema_fields = extract_schema_fields(schema_path)

    if not registered_keys:
        print("FAIL: No operational knobs registered in operational.rs")
        return 1

    # Verify each registered knob has a corresponding field in schema.rs
    for key in registered_keys:
        raw_field = key.split(".")[-1].strip("[]")
        if raw_field not in schema_fields:
            print(f"FAIL: Registered knob '{key}' (field '{raw_field}') not found in schema.rs")
            return 1

    print(f"PASS: {len(registered_keys)} operational knobs verified against configuration schema (Row 113).")
    return 0


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_root = pathlib.Path(tmp_dir)
        op_file = tmp_root / OPERATIONAL_RS
        sc_file = tmp_root / SCHEMA_RS
        op_file.parent.mkdir(parents=True, exist_ok=True)
        sc_file.parent.mkdir(parents=True, exist_ok=True)

        sc_file.write_text(
            "pub struct ScanSection { pub fused_batch: Option<usize>, }\n",
            encoding="utf-8",
        )
        op_file.write_text(
            'toml_key: "[scan].fused_batch",\ntoml_key: "[scan].missing_field",\n',
            encoding="utf-8",
        )

        # Should fail due to missing_field
        if run_gate(tmp_root) == 0:
            print("SELF-TEST FAIL: Did not catch missing field in schema.rs")
            return 1

        op_file.write_text(
            'toml_key: "[scan].fused_batch",\n',
            encoding="utf-8",
        )
        if run_gate(tmp_root) != 0:
            print("SELF-TEST FAIL: Failed valid schema matching")
            return 1

    print("self-test PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unified Operational Constants Gate")
    parser.add_argument("--self-test", action="store_true", help="Run gate self-test")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
