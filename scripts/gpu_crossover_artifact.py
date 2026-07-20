#!/usr/bin/env python3
"""Validate release-grade 8 MiB GPU crossover evidence."""

from __future__ import annotations

import argparse
import math
import pathlib
import sys
import tomllib


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=pathlib.Path)
    parser.add_argument("--git-hash", required=True)
    args = parser.parse_args()

    try:
        artifact = tomllib.loads(args.artifact.read_text())
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"cannot read GPU crossover artifact {args.artifact}: {error}", file=sys.stderr)
        return 1

    failures: list[str] = []
    require(artifact.get("schema_version") == 8, "schema_version must be 8", failures)
    require(artifact.get("git_hash") == args.git_hash, "git_hash must match the candidate source", failures)
    require(artifact.get("build_source_tree_state") == "clean", "benchmark binary must be built from a clean tree", failures)
    require(artifact.get("source_tree_state") == "clean", "source tree must remain clean through measurement", failures)
    require(artifact.get("diagnostic") is False, "diagnostic evidence is not release evidence", failures)
    require(artifact.get("production_comparable") is True, "production_comparable must be true", failures)
    require(artifact.get("crossover_passed") is True, "crossover_passed must be true", failures)
    require(artifact.get("source_bytes") == 8 * 1024 * 1024, "source_bytes must be exactly 8 MiB", failures)
    require(artifact.get("held_out_pairs", 0) >= 100, "at least 100 held-out pairs are required", failures)
    require(artifact.get("selection_rounds", 0) >= 20, "at least 20 selection rounds are required", failures)
    require(artifact.get("full_result_parity") is True, "full finding parity must pass", failures)
    require(artifact.get("gpu_degraded") is False, "GPU execution must not be degraded", failures)

    ratio = artifact.get("ratio_ci95_high")
    require(isinstance(ratio, float) and math.isfinite(ratio) and ratio < 1.0, "GPU/Hyperscan 95% ratio upper bound must be finite and below 1.0", failures)
    require(str(artifact.get("fastest_hyperscan_backend", "")).startswith("simd"), "fastest Hyperscan route identity is missing", failures)
    require(str(artifact.get("selected_gpu_backend", "")).startswith("gpu-"), "selected GPU route identity is missing", failures)
    for field in ("selected_gpu_driver", "selected_gpu_driver_version", "selected_gpu_device", "selected_gpu_runtime"):
        require(bool(artifact.get(field)), f"{field} is missing", failures)
    require(artifact.get("compiled_features") == "simd=true,gpu=true,decode=true,entropy=true", "release benchmark must include the production scanner features", failures)
    require(str(artifact.get("resolved_tuning", "")).startswith("ResolvedScannerTuningConfig {"), "resolved scanner tuning identity is missing", failures)
    require(len(str(artifact.get("binary_sha256", ""))) == 64, "benchmark binary SHA-256 is missing", failures)
    require(len(str(artifact.get("detector_spec_blake3", ""))) == 64, "detector specification BLAKE3 is missing", failures)
    require(len(str(artifact.get("scanner_detector_digest", ""))) == 16, "compiled scanner detector digest is missing", failures)

    if failures:
        for failure in failures:
            print(f"GPU crossover evidence rejected: {failure}", file=sys.stderr)
        return 1
    print(f"GPU crossover evidence accepted: {args.artifact}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
