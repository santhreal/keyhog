#!/usr/bin/env python3
"""Reject un-prefixed continue-on-error steps across all GitHub Workflows (Row 5).

WHY THIS GATE EXISTS:
A gate that cannot fail is not a gate: `continue-on-error: true` absorbs failures
and turns broken code or regressed tests into false-green CI runs.

RULE:
No workflow step running `cargo test`, `cargo clippy`, `cargo build`, or `scripts/gates/`
may carry `continue-on-error: true` unless its name explicitly begins with `informational:`.
Job-level `continue-on-error: true` on test or lint jobs is prohibited.

Usage:
  python3 -B scripts/gates/no_continue_on_error.py
  python3 -B scripts/gates/no_continue_on_error.py --self-test
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS_DIR = REPO / ".github/workflows"

TEST_OR_GATE_CMD = re.compile(
    r"\b(cargo\s+(?:test|clippy|build)|scripts/gates/[a-zA-Z0-9_\-]+\.(?:py|sh))\b"
)


def split_steps(workflow_text: str) -> list[dict[str, str]]:
    """Extract steps with their attributes from workflow YAML text."""
    lines = workflow_text.splitlines()
    steps = []
    current_step: dict[str, str] = {}
    in_steps = False

    for line in lines:
        stripped = line.strip()
        if stripped == "steps:":
            in_steps = True
            continue

        if in_steps and re.match(r"^\s*-\s+(?:name|uses|run|id):", line):
            if current_step:
                steps.append(current_step)
            current_step = {"text": line + "\n"}
            # Extract initial field
            if line.strip().startswith("- name:"):
                current_step["name"] = line.split("- name:", 1)[1].strip()
            elif line.strip().startswith("- id:"):
                current_step["id"] = line.split("- id:", 1)[1].strip()
            elif line.strip().startswith("- uses:"):
                current_step["uses"] = line.split("- uses:", 1)[1].strip()
        elif in_steps and current_step:
            current_step["text"] += line + "\n"
            if stripped.startswith("name:") and "name" not in current_step:
                current_step["name"] = stripped.split("name:", 1)[1].strip()
            if stripped.startswith("continue-on-error:"):
                current_step["continue-on-error"] = (
                    stripped.split("continue-on-error:", 1)[1].strip().lower()
                )

    if current_step:
        steps.append(current_step)

    return steps


def check_workflow_text(path_name: str, content: str) -> list[str]:
    """Check workflow content for unauthorized continue-on-error occurrences."""
    errors = []

    # Check for job-level continue-on-error on test/lint jobs
    lines = content.splitlines()
    current_job = ""
    for line in lines:
        match_job = re.match(r"^ {2}([a-zA-Z0-9_-]+):", line)
        if match_job and match_job.group(1) not in ("steps", "env", "jobs", "defaults"):
            current_job = match_job.group(1)
        if re.match(r"^ {4}continue-on-error:\s*true\b", line, re.IGNORECASE):
            # Check if this job runs cargo or gates
            errors.append(
                f"{path_name}: job '{current_job}' sets job-level continue-on-error: true. "
                "Job-level error absorption is prohibited for CI integrity."
            )

    # Check step-level continue-on-error
    steps = split_steps(content)
    for step in steps:
        coe = step.get("continue-on-error", "")
        if coe in ("true", "1"):
            name = step.get("name", "").strip("\"'")
            step_text = step.get("text", "")
            is_test_or_gate = bool(TEST_OR_GATE_CMD.search(step_text))

            if is_test_or_gate and not name.lower().startswith("informational:"):
                errors.append(
                    f"{path_name}: step '{name or '<unnamed>'}' carries continue-on-error: true "
                    "on a test or gate command without the required 'informational:' prefix."
                )

    return errors


def check_workflows(workflows_dir: pathlib.Path) -> list[str]:
    errors = []
    for yml_file in sorted(workflows_dir.glob("*.yml")):
        content = yml_file.read_text(encoding="utf-8")
        errors.extend(check_workflow_text(yml_file.name, content))
    return errors


def self_test() -> None:
    bad_workflow = """
name: test
jobs:
  runner:
    runs-on: ubuntu-latest
    steps:
      - name: Absorbed un-prefixed test
        continue-on-error: true
        run: cargo test -p keyhog-scanner
"""
    errs = check_workflow_text("bad.yml", bad_workflow)
    assert len(errs) == 1, f"Expected 1 error on bad fixture, got: {errs}"
    assert "informational:" in errs[0]

    good_workflow = """
name: test
jobs:
  runner:
    runs-on: ubuntu-latest
    steps:
      - name: informational: Track recall debt
        continue-on-error: true
        run: cargo test -p keyhog-scanner --test capability_target_spec
"""
    errs_good = check_workflow_text("good.yml", good_workflow)
    assert len(errs_good) == 0, f"Expected 0 errors on good fixture, got: {errs_good}"

    job_level_bad = """
name: test
jobs:
  lint:
    runs-on: ubuntu-latest
    continue-on-error: true
    steps:
      - run: cargo clippy
"""
    errs_job = check_workflow_text("job_bad.yml", job_level_bad)
    assert len(errs_job) == 1, f"Expected 1 error on job-level bad fixture, got: {errs_job}"

    print("self-test PASS")


def main() -> int:
    if "--self-test" in sys.argv:
        self_test()
        return 0

    errors = check_workflows(WORKFLOWS_DIR)
    if errors:
        print("ERROR: continue-on-error absorption violation(s) detected:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("OK - all workflow continue-on-error occurrences comply with Row 5 informational policy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
