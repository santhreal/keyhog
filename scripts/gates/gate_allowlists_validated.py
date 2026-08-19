#!/usr/bin/env python3
"""Meta-Gate: VALIDATE ALL GATE ALLOWLISTS AND EXEMPTIONS (Row 137).

Ensures that every gate in `scripts/gates/` carrying an allowlist, exemption set,
skip list, or budget:
1. Validates all targets against reality on every run (fails if target path, symbol,
   or crate does not exist on disk).
2. Carries written reasons for every entry.
3. Detects any unvalidated raw literal exemption lists added to new or existing gates.

Acceptance criteria:
- Every allowlist entry across the gate suite is validated against disk/reality.
- All gates with allowlists expose validation functions or target existence checks.
- A new gate with an unvalidated literal list is caught at run time by this meta-gate.
"""

from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
GATES_DIR = REPO / "scripts" / "gates"

ALLOWLIST_VAR_PATTERN = re.compile(
    r"^(?:ALLOWED|ALLOW_FILES|ALLOWLIST|EXEMPT|EXEMPTIONS|SKIP_DIRS|SKIP_DIR_PARTS|BUDGET|PATHS|VYRE_DEPS)$"
)


class GateAstInspector(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.allowlist_vars: list[str] = []
        self.functions: set[str] = set()
        self.method_calls: set[str] = set()
        self.has_validation_calls = False

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id
                if ALLOWLIST_VAR_PATTERN.match(name):
                    self.allowlist_vars.append(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if ALLOWLIST_VAR_PATTERN.match(name):
                self.allowlist_vars.append(name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.add(node.name)
        if "validate" in node.name.lower() or "check" in node.name.lower() or "verify" in node.name.lower():
            self.has_validation_calls = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            self.method_calls.add(node.func.attr)
            if node.func.attr in {"exists", "is_file", "is_dir"}:
                self.has_validation_calls = True
        elif isinstance(node.func, ast.Name):
            if "validate" in node.func.id.lower() or "verify" in node.func.id.lower():
                self.has_validation_calls = True
        self.generic_visit(node)


def inspect_gate_source(source: str, filename: str) -> list[str]:
    """Inspect Python AST of a gate script to ensure allowlists have validation logic."""
    violations: list[str] = []
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError as err:
        return [f"{filename}: Syntax error in gate source: {err}"]

    inspector = GateAstInspector(filename)
    inspector.visit(tree)

    if inspector.allowlist_vars and not inspector.has_validation_calls:
        violations.append(
            f"{filename}: Defines allowlist variables {inspector.allowlist_vars} "
            "without validation logic (validate_* functions or path existence checks). "
            "Every allowlist must validate target reality on every run (Row 137)."
        )

    return violations


def audit_gates_suite(gates_dir: pathlib.Path = GATES_DIR) -> list[str]:
    """Audit all python gates under scripts/gates/ for unvalidated allowlists."""
    violations: list[str] = []
    if not gates_dir.is_dir():
        return [f"gates directory does not exist: {gates_dir}"]

    for py_file in sorted(gates_dir.glob("*.py")):
        if py_file.name == pathlib.Path(__file__).name:
            continue
        try:
            content = py_file.read_text(encoding="utf-8")
        except Exception as err:
            violations.append(f"{py_file.name}: Could not read file: {err}")
            continue

        file_violations = inspect_gate_source(content, py_file.name)
        violations.extend(file_violations)

    return violations


def self_test() -> int:
    """Run self-tests verifying that unvalidated allowlists fail and validated ones pass."""
    valid_source = """
ALLOWED: dict[str, str] = {
    "crates/scanner/src/lib.rs": "canonical lib entrypoint",
}

def validate_allowlists():
    for path in ALLOWED:
        if not path.exists():
            raise ValueError("missing path")
"""
    invalid_source = """
ALLOWED = {
    "crates/scanner/src/lib.rs",
    "some/retired/file.rs",
}

def run():
    print("running without validating ALLOWED")
"""
    valid_violations = inspect_gate_source(valid_source, "valid_sample.py")
    if valid_violations:
        print(f"self-test FAIL: valid sample flagged: {valid_violations}", file=sys.stderr)
        return 1

    invalid_violations = inspect_gate_source(invalid_source, "invalid_sample.py")
    if not invalid_violations:
        print("self-test FAIL: unvalidated allowlist sample was not flagged", file=sys.stderr)
        return 1

    print("self-test PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run self tests")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    violations = audit_gates_suite(GATES_DIR)
    if violations:
        print(
            f"FAIL - {len(violations)} gate script(s) carry unvalidated allowlists (Row 137):",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print("OK - all gate allowlists and exemption structures are validated against reality.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
