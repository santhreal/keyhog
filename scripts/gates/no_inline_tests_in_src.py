#!/usr/bin/env python3
"""Structural Gate: NO INLINE TESTS IN SRC (Row 149).

Enforces that production Rust source files across all workspace crates under
`crates/*/src/` do not host inline test modules (`#[cfg(test)] mod <name> { ... }`)
or inline test functions (`#[test]`, `#[tokio::test]`, `#[proptest]`).

Test code belongs under `tests/` or in compliant sibling test files referenced by
`#[cfg(test)] mod tests;` or `#[cfg(test)] #[path = "..."] mod ...;`.

ALLOWLIST:
An explicit, justified set of crate-private modules permitted to keep co-located
white-box tests or test facades whose migration would force exposing internals as
public API. Every entry is validated against disk reality and must still contain
co-located tests (anti-staleness check).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]

# Explicit, justified allowlist of crate-private files hosting co-located tests or test facades.
ALLOWED: dict[str, str] = {
    # crates/scanner (12 files)
    "crates/scanner/src/detector_catalog.rs": "bundled_detector_ids private corpus loader",
    "crates/scanner/src/engine/phase2/mark_stats.rs": "mark stats telemetry facade",
    "crates/scanner/src/engine/scan_postprocess/fragments.rs": "reassembly floor and reassembly_probe_data one-place guard",
    "crates/scanner/src/engine/windowed_support.rs": "white-box absolute_offset overflow and saturation arithmetic",
    "crates/scanner/src/entropy/isolated.rs": "isolated entropy floor dedup parity proof",
    "crates/scanner/src/hw_probe/mod.rs": "hardware-probe tests need crate-private backend override hook",
    "crates/scanner/src/suppression/api.rs": "suppression API private typed contexts",
    "crates/scanner/src/suppression/shape/path.rs": "white-box path segment shape predicate",
    "crates/scanner/src/suppression/shape/prose.rs": "white-box prose shape predicate",
    "crates/scanner/src/suppression/shape/public.rs": "white-box public artifact reference predicate",
    "crates/scanner/src/telemetry.rs": "keeps cfg(test) doc(hidden) pub mod testing facade for counters",
    "crates/scanner/src/testing.rs": "doc-hidden scanner test facade",

    # crates/cli (1 file)
    "crates/cli/src/orchestrator/dispatch/backend/store/persistence/contention.rs": "store persistence contention subprocess test runner",

    # crates/profile (1 file)
    "crates/profile/src/detail.rs": "measurement level and runtime arming tests",

    # crates/sources (12 files)
    "crates/sources/src/cloud/azure_blob.rs": "azure blob builder tests",
    "crates/sources/src/cloud/mod.rs": "cloud source builder tests",
    "crates/sources/src/filesystem/extract/archive/zip_scan.rs": "zip scan open safety tests",
    "crates/sources/src/filesystem/extract/archive.rs": "archive capacity hint tests",
    "crates/sources/src/filesystem/read/window.rs": "window sparse read tests",
    "crates/sources/src/gcs.rs": "gcs builder setter tests",
    "crates/sources/src/git/manifest.rs": "git manifest tests",
    "crates/sources/src/git/mod.rs": "git command isolation and child tests",
    "crates/sources/src/guard.rs": "guard tests",
    "crates/sources/src/magic.rs": "magic file header tests",
    "crates/sources/src/parallel_fetch.rs": "parallel fetch tests",
    "crates/sources/src/s3/mod.rs": "s3 builder setter tests",
}


def is_test_file(path: pathlib.Path) -> bool:
    """Return True if the file is an external/sibling test file rather than production source."""
    name = path.name
    if name == "tests.rs" or name.endswith("_tests.rs"):
        return True
    if "tests" in path.parts:
        return True
    return False


def is_test_function_attr(trimmed: str) -> bool:
    """Return True if line is a test function attribute."""
    if trimmed.startswith("#[test]") or trimmed.startswith("#[test "):
        after = trimmed[len("#[test]"):].lstrip() if trimmed.startswith("#[test]") else trimmed[len("#[test "):].lstrip()
        return not after or after.startswith("fn ") or after.startswith("async ") or after.startswith("pub ")
    return trimmed.startswith("#[tokio::test") or trimmed.startswith("#[proptest]")


def strip_test_cfg_attr(trimmed: str) -> str | None:
    """Return remainder after #[cfg(test)] or #[cfg(all(test, ...))]."""
    if not (
        trimmed.startswith("#[cfg(test)]")
        or trimmed.startswith("#[cfg(all(test,")
        or trimmed.startswith("#[cfg(all(test ")
    ):
        return None
    end = trimmed.find("]")
    if end == -1:
        return None
    return trimmed[end + 1:]


def is_block_comment_line(trimmed: str) -> bool:
    return trimmed.startswith("/*") or trimmed.startswith("*") or trimmed.startswith("*/")


def strip_keyword(trimmed: str, keyword: str) -> str | None:
    if not trimmed.startswith(keyword):
        return None
    rest = trimmed[len(keyword):]
    if rest and (rest[0].isspace() or rest[0] in "({"):
        return rest.lstrip()
    return None


def is_module_decl(trimmed: str) -> bool:
    """Check if line is a module declaration opening an inline body."""
    rest = strip_keyword(trimmed, "mod")
    if rest is None:
        if not trimmed.startswith("pub"):
            return False
        after_pub = trimmed[3:].lstrip()
        rest = strip_keyword(after_pub, "mod")
        if rest is None:
            if not after_pub.startswith("("):
                return False
            if ")" not in after_pub:
                return False
            _, after_vis = after_pub.split(")", 1)
            rest = strip_keyword(after_vis.lstrip(), "mod")
            if rest is None:
                return False
    return "{" in rest or ";" not in rest


def has_inline_test_module_or_function(content: str) -> bool:
    """Parse Rust source content for inline test modules or test functions."""
    saw_test_cfg = False
    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("//"):
            continue
        if is_block_comment_line(trimmed):
            continue
        if is_test_function_attr(trimmed):
            return True
        after_attr = strip_test_cfg_attr(trimmed)
        if after_attr is not None:
            if is_module_decl(after_attr.lstrip()):
                return True
            saw_test_cfg = True
            continue
        if saw_test_cfg and trimmed.startswith("#["):
            if trimmed.startswith("#[path"):
                saw_test_cfg = False
            continue
        if saw_test_cfg and is_module_decl(trimmed):
            return True
        saw_test_cfg = False
    return False


def validate_allowlist(root: pathlib.Path, allowed: dict[str, str] = ALLOWED) -> list[str]:
    """Validate that every allowlist entry exists on disk, has a written reason, and contains tests."""
    errors = []
    for rel_path, reason in allowed.items():
        file_path = root / rel_path
        if not file_path.exists():
            errors.append(f"Allowlist entry does not exist on disk: {rel_path}")
            continue
        if not file_path.is_file():
            errors.append(f"Allowlist entry is not a file: {rel_path}")
            continue
        if not reason or not reason.strip():
            errors.append(f"Allowlist entry has empty justification reason: {rel_path}")
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as err:
            errors.append(f"Cannot read allowlist entry {rel_path}: {err}")
            continue
        if not has_inline_test_module_or_function(content):
            errors.append(
                f"Stale allowlist entry (no inline tests found): {rel_path}. "
                "Delete this allowlist entry once tests have been migrated."
            )
    return errors


def check_workspace_sources(root: pathlib.Path, allowed: dict[str, str] = ALLOWED) -> list[str]:
    """Check all workspace crate source files for forbidden inline tests."""
    violations = []
    crates_dir = root / "crates"
    if not crates_dir.is_dir():
        return [f"Crates directory missing: {crates_dir}"]

    for crate_dir in sorted(crates_dir.glob("*")):
        src_dir = crate_dir / "src"
        if not src_dir.is_dir():
            continue

        for rs_file in sorted(src_dir.rglob("*.rs")):
            if "target" in rs_file.parts:
                continue
            if is_test_file(rs_file):
                continue
            rel_path = rs_file.relative_to(root).as_posix()
            if rel_path in allowed:
                continue

            try:
                content = rs_file.read_text(encoding="utf-8")
            except Exception as err:
                violations.append(f"Failed to read {rel_path}: {err}")
                continue

            if has_inline_test_module_or_function(content):
                violations.append(
                    f"Forbidden inline test in {rel_path}. "
                    "Move tests to `tests/` or compliant sibling `tests.rs` module."
                )

    return violations


def run_gate(root: pathlib.Path) -> int:
    """Run full gate check."""
    allowlist_errors = validate_allowlist(root)
    source_violations = check_workspace_sources(root)
    all_errors = allowlist_errors + source_violations

    if all_errors:
        print(f"FAIL - {len(all_errors)} inline test violation(s) found (Row 149):", file=sys.stderr)
        for err in all_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("OK - No forbidden inline tests in workspace production `src/` files.")
    return 0


def self_test() -> int:
    """Run comprehensive self-tests."""
    # 1. Real repository verification
    if run_gate(REPO) != 0:
        print("Self-test FAIL on live repo", file=sys.stderr)
        return 1

    # 2. Syntax recognition tests
    assert has_inline_test_module_or_function("#[test]\nfn test_foo() {}")
    assert has_inline_test_module_or_function("#[tokio::test]\nasync fn test_async() {}")
    assert has_inline_test_module_or_function("#[proptest]\nfn prop_test() {}")
    assert has_inline_test_module_or_function("#[cfg(test)]\nmod tests {\n}")
    assert has_inline_test_module_or_function("#[cfg(test)]\npub mod tests {\n}")
    assert has_inline_test_module_or_function("#[cfg(test)]\npub(crate) mod tests {\n}")
    assert has_inline_test_module_or_function("#[cfg(test)]\npub(in crate::sub) mod tests {\n}")
    assert has_inline_test_module_or_function("#[cfg(all(test, feature = \"x\"))]\nmod tests {\n}")
    assert has_inline_test_module_or_function("#[cfg(test)] mod inline_same_line {}")
    assert has_inline_test_module_or_function("#[cfg(test)]\nmod split_line\n{}")

    # 3. Compliant patterns NOT flagged
    assert not has_inline_test_module_or_function("#[cfg(test)]\nmod tests;\n")
    assert not has_inline_test_module_or_function("#[cfg(test)]\npub mod tests;\n")
    assert not has_inline_test_module_or_function('#[cfg(test)]\n#[path = "../tests/foo.rs"]\nmod foo;\n')
    assert not has_inline_test_module_or_function('// #[test]\nfn not_a_test() {}')
    assert not has_inline_test_module_or_function('/* #[test] */\nfn not_a_test() {}')
    assert not has_inline_test_module_or_function('const TEST_NAME: &str = "#[test]";')

    # 4. Stale allowlist detection
    stale_allowed = {"crates/core/src/lib.rs": "core lib has no inline tests"}
    stale_errors = validate_allowlist(REPO, stale_allowed)
    assert any("Stale allowlist entry" in e for e in stale_errors), "Expected stale allowlist detection"

    # 5. Missing allowlist detection
    missing_allowed = {"crates/scanner/src/non_existent_file_xyz.rs": "non-existent"}
    missing_errors = validate_allowlist(REPO, missing_allowed)
    assert any("does not exist on disk" in e for e in missing_errors), "Expected missing file detection"

    # 6. Empty justification reason detection
    empty_reason_allowed = {"crates/scanner/src/detector_catalog.rs": ""}
    empty_errors = validate_allowlist(REPO, empty_reason_allowed)
    assert any("empty justification reason" in e for e in empty_errors), "Expected empty reason detection"

    print("no_inline_tests_in_src.py --self-test passed.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run self-tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    return run_gate(REPO)


if __name__ == "__main__":
    sys.exit(main())
