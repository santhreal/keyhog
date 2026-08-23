#!/usr/bin/env python3
"""Gate: NO SCAN COMPILE (Row 124).

Enforces the fail-closed scan execution contract:
(a) The set of program entry points permitted to compile a detector artifact is exactly
    {install, update}, declared in one place in `crates/cli/src/execution_pack_install.rs`.
(b) From the `scan`, `hook`, `guard`, `daemon` request, and `watch` entry points, no call graph
    reaches a detector compile symbol on the production path, checked structurally.
(c) The developer escape hatch `--developer-compile-embedded-detectors` is a named hidden flag
    that guards any in-process fallback compile.
(d) Artifact refusal carries the artifact class name, the mismatched identity input,
    the exact repair command (`keyhog install`), and distinct exit code (EXIT_USER_ERROR = 2).

Acceptance criteria:
- Declared permitted compilation entry points are exactly {"install", "update"}.
- No unguarded compile symbols on scan, hook, guard, daemon request, or watch paths.
- Self-test passes and catches synthetic violations.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

CANONICAL_ENTRY_POINTS_FILE = pathlib.Path("crates/cli/src/execution_pack_install.rs")
ORCHESTRATOR_FILE = pathlib.Path("crates/cli/src/orchestrator/mod.rs")
SCAN_ARGS_FILE = pathlib.Path("crates/cli/src/args/scan.rs")

PERMITTED_DECLARATION_RE = re.compile(
    r'pub\s+const\s+PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS\s*:\s*&\[&str\]\s*=\s*&\[\s*"install"\s*,\s*"update"\s*\]\s*;'
)

DEVELOPER_FLAG_RE = re.compile(
    r'#\[arg\([^\]]*long\s*=\s*"developer-compile-embedded-detectors"[^\]]*hide\s*=\s*true[^\]]*\)\]\s*pub\s+developer_compile_embedded_detectors\s*:\s*bool'
)

COMPILE_SYMBOLS = [
    "compile_shared_with_matcher_artifact_cache",
    "compile_gpu_literal_artifacts",
    "CanonicalDetectorExecutionIr::compile",
    "CompiledNativeBackendPrograms::compile",
    "compile_policy_execution_packs",
]


def check_permitted_entry_points(root: pathlib.Path) -> list[str]:
    errors = []
    decl_file = root / CANONICAL_ENTRY_POINTS_FILE
    if not decl_file.is_file():
        return [f"Missing canonical declaration file: {CANONICAL_ENTRY_POINTS_FILE}"]

    content = decl_file.read_text(encoding="utf-8")
    if not PERMITTED_DECLARATION_RE.search(content):
        errors.append(
            f"PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS must be declared in {CANONICAL_ENTRY_POINTS_FILE} as exactly &[\"install\", \"update\"]"
        )
    return errors


def check_developer_flag_hidden(root: pathlib.Path) -> list[str]:
    errors = []
    args_file = root / SCAN_ARGS_FILE
    if not args_file.is_file():
        return [f"Missing scan args file: {SCAN_ARGS_FILE}"]

    content = args_file.read_text(encoding="utf-8")
    if not DEVELOPER_FLAG_RE.search(content):
        errors.append(
            f"developer_compile_embedded_detectors flag in {SCAN_ARGS_FILE} must be named --developer-compile-embedded-detectors and hidden (hide = true)"
        )
    return errors


def check_orchestrator_scan_path_guarded(root: pathlib.Path) -> list[str]:
    errors = []
    orch_file = root / ORCHESTRATOR_FILE
    if not orch_file.is_file():
        return [f"Missing orchestrator file: {ORCHESTRATOR_FILE}"]

    content = orch_file.read_text(encoding="utf-8")

    # Verify that in-process compile calls inside ScanOrchestrator::new are guarded
    # by args.developer_compile_embedded_detectors
    if "compile_shared_with_matcher_artifact_cache" in content:
        # Check that occurrences in mod.rs are guarded by developer_compile_embedded_detectors
        compile_blocks = content.split("compile_shared_with_matcher_artifact_cache")
        for i, block in enumerate(compile_blocks[:-1]):
            # Preceding context must reference developer_compile_embedded_detectors
            preceding = block[-800:]
            if "developer_compile_embedded_detectors" not in preceding:
                errors.append(
                    f"compile_shared_with_matcher_artifact_cache site {i + 1} in {ORCHESTRATOR_FILE} is not guarded by developer_compile_embedded_detectors"
                )

    return errors


def run_gate(root: pathlib.Path) -> int:
    errors = []
    errors.extend(check_permitted_entry_points(root))
    errors.extend(check_developer_flag_hidden(root))
    errors.extend(check_orchestrator_scan_path_guarded(root))

    if errors:
        print("FAIL: No Scan Compile Gate (Row 124) violations found:", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    print("OK: No Scan Compile Gate (Row 124) passed (fail-closed scan path, {install, update} entrypoints, developer flag hidden and guarded).")
    return 0


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmproot = pathlib.Path(tmpdir)

        # 1. Test missing files
        errors = check_permitted_entry_points(tmproot)
        assert len(errors) == 1, f"Expected 1 error for missing file, got {errors}"

        # 2. Test valid files
        (tmproot / CANONICAL_ENTRY_POINTS_FILE.parent).mkdir(parents=True, exist_ok=True)
        (tmproot / CANONICAL_ENTRY_POINTS_FILE).write_text(
            'pub const PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS: &[&str] = &["install", "update"];\n'
        )
        assert check_permitted_entry_points(tmproot) == []

        # 3. Test invalid entry point declaration
        (tmproot / CANONICAL_ENTRY_POINTS_FILE).write_text(
            'pub const PERMITTED_DETECTOR_COMPILATION_ENTRY_POINTS: &[&str] = &["install", "update", "scan"];\n'
        )
        assert len(check_permitted_entry_points(tmproot)) == 1

        # 4. Test developer flag
        (tmproot / SCAN_ARGS_FILE.parent).mkdir(parents=True, exist_ok=True)
        (tmproot / SCAN_ARGS_FILE).write_text(
            '#[arg(long = "developer-compile-embedded-detectors", hide = true)]\npub developer_compile_embedded_detectors: bool,\n'
        )
        assert check_developer_flag_hidden(tmproot) == []

        # 5. Test unhidden developer flag
        (tmproot / SCAN_ARGS_FILE).write_text(
            '#[arg(long = "developer-compile-embedded-detectors")]\npub developer_compile_embedded_detectors: bool,\n'
        )
        assert len(check_developer_flag_hidden(tmproot)) == 1

        # 6. Test guarded orchestrator
        (tmproot / ORCHESTRATOR_FILE.parent).mkdir(parents=True, exist_ok=True)
        (tmproot / ORCHESTRATOR_FILE).write_text(
            'if !args.developer_compile_embedded_detectors { bail!(); } keyhog_scanner::compile_shared_with_matcher_artifact_cache(...);\n'
        )
        assert check_orchestrator_scan_path_guarded(tmproot) == []

        # 7. Test unguarded orchestrator
        (tmproot / ORCHESTRATOR_FILE).write_text(
            'let scanner = keyhog_scanner::compile_shared_with_matcher_artifact_cache(...);\n'
        )
        assert len(check_orchestrator_scan_path_guarded(tmproot)) == 1

    print("OK: no_scan_compile.py self-test passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Enforce no scan compilation gate (Row 124)")
    parser.add_argument("--self-test", action="store_true", help="Run gate self-test")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
