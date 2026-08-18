#!/usr/bin/env python3
"""Gate #5: COMPLEXITY BUDGET (a ratchet that can only tighten).

The disease behind the silent fallbacks is sprawl: `walk -> match -> emit`
spread across phase-2 lanes and several divergent backends, each re-implementing
a slice of the same job, each free to drift and hide its own silent drop. Prose
("keep it simple") never stopped that growth. This gate makes any unaccounted
change a RED BUILD: every metric must equal its pinned current value. Growth
must be removed; simplification must lower the matching budget in the same
change, so a stale ceiling can never accumulate slack.

The budgets are exact, only-tightening RATCHETS. Every number is the CURRENT
measured value. Candidate measurements must equal them, and change-bearing CI
events also compare the literal dictionary against the immutable base commit:
equal or lower is valid; a raised or removed ratchet is rejected. Base source is
parsed as data and is never executed.

Run: python3 scripts/gates/complexity_budget.py   (exit 1 on breach)
"""
from __future__ import annotations

import argparse
import ast
import json
import os
from collections.abc import Callable, Mapping
import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
ENGINE = REPO / "crates" / "scanner" / "src" / "engine"
BACKEND_OWNER = REPO / "crates" / "scanner" / "src" / "hw_probe" / "mod.rs"
BUDGET_PATH = "scripts/gates/complexity_budget.py"
COMMIT_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")

# ── BUDGETS (ratchet, only ever DECREASE these) ──────────────────────
# Pinned to the measured state. Lower a value in the same change that reduces
# the corresponding metric. Equality is enforced below, so neither growth nor
# stale slack can be hidden by a generous ceiling.
BUDGET = {
    "phase2_lanes": 10,          # engine/phase2*.rs files
    "scan_backends": 5,          # ScanBackend:: variants
    "engine_files": 31,          # top-level *.rs coordination modules under engine/
    "engine_loc": 9906,          # non-blank LOC in those top-level modules
}


def count_phase2_lanes() -> int:
    return len(list(ENGINE.glob("phase2*.rs")))


def count_scan_backends_source(source: str) -> int:
    """Count variants in the defining enum source, not in use sites."""
    match = re.search(r"enum\s+ScanBackend\s*\{(.*?)\}", source, re.S)
    if not match:
        return 0
    return len(
        re.findall(
            r"^\s*([A-Z][A-Za-z0-9_]*)\s*(?:\([^)]*\)|\{[^}]*\})?\s*,",
            match.group(1),
            re.M,
        )
    )


def count_scan_backends(owner: pathlib.Path | None = None) -> int:
    source = owner or BACKEND_OWNER
    if not source.exists():
        return 0
    # The defining `ScanBackend` enum is the sole ratchet owner. Counting use
    # sites would let an unreferenced new variant evade the exact budget.
    return count_scan_backends_source(source.read_text(encoding="utf-8"))


def count_engine_loc() -> int:
    total = 0
    for f in ENGINE.glob("*.rs"):
        total += sum(1 for ln in f.read_text(errors="replace").splitlines() if ln.strip())
    return total


def count_engine_files() -> int:
    return len(list(ENGINE.glob("*.rs")))


def budget_drift(
    measured: dict[str, int], budget: dict[str, int]
) -> list[tuple[str, int | None, int | None]]:
    """Return every missing, added, grown, or slackened exact metric."""
    return [
        (name, measured.get(name), budget.get(name))
        for name in sorted(measured.keys() | budget.keys())
        if measured.get(name) != budget.get(name)
    ]


class BaseBudgetError(RuntimeError):
    """A trusted comparison budget could not be resolved or decoded."""


def parse_budget_source(source: str) -> dict[str, int]:
    """Read a literal BUDGET assignment without executing repository code."""
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise BaseBudgetError(f"base complexity source is invalid Python: {error}") from error

    values: list[object] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "BUDGET" for target in node.targets):
            try:
                values.append(ast.literal_eval(node.value))
            except (ValueError, TypeError) as error:
                raise BaseBudgetError(
                    "base BUDGET must be a literal dictionary"
                ) from error
    if len(values) != 1:
        raise BaseBudgetError("base complexity source must define BUDGET exactly once")

    value = values[0]
    if not isinstance(value, dict) or any(
        not isinstance(name, str)
        or not isinstance(budget, int)
        or isinstance(budget, bool)
        or budget < 0
        for name, budget in value.items()
    ):
        raise BaseBudgetError(
            "base BUDGET must map metric names to non-negative integer literals"
        )
    return value


def budget_increases(
    candidate: dict[str, int], base: dict[str, int]
) -> list[tuple[str, int | None, int]]:
    """Return raised or removed ratchets relative to the trusted base."""
    return [
        (name, candidate.get(name), base_budget)
        for name, base_budget in sorted(base.items())
        if name not in candidate or candidate[name] > base_budget
    ]


def validated_commit_sha(value: object, context: str) -> str:
    if not isinstance(value, str) or not COMMIT_SHA.fullmatch(value):
        raise BaseBudgetError(f"{context} is missing a full commit SHA")
    return value.lower()


def read_event_payload(env: Mapping[str, str]) -> dict[str, object]:
    path = env.get("GITHUB_EVENT_PATH")
    if not path:
        raise BaseBudgetError("GitHub Actions event path is missing")
    try:
        value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BaseBudgetError(f"cannot read GitHub Actions event payload: {error}") from error
    if not isinstance(value, dict):
        raise BaseBudgetError("GitHub Actions event payload must be an object")
    return value


def commit_parent(commit: str, repo: pathlib.Path = REPO) -> str | None:
    # A depth-1 checkout hides parents. Fetch depth 2 for the exact immutable
    # commit so a zero-before tag/branch push can compare with its first parent,
    # while a genuine repository root has an explicit no-base initial state.
    fetched = subprocess.run(
        [
            "git",
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            "--depth=2",
            "origin",
            commit,
        ],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if fetched.returncode != 0:
        diagnostic = fetched.stderr.strip() or "git fetch failed"
        raise BaseBudgetError(
            f"cannot fetch zero-before push commit {commit}: {diagnostic}"
        )
    result = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", commit],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    parts = result.stdout.split()
    if result.returncode != 0 or not parts or parts[0].lower() != commit:
        raise BaseBudgetError(f"cannot inspect parents of zero-before push commit {commit}")
    if len(parts) == 1:
        return None
    return validated_commit_sha(parts[1], "zero-before push first parent")


def resolve_ci_base(
    env: Mapping[str, str],
    event: dict[str, object] | None = None,
    parent_commit_lookup: Callable[[str], str | None] | None = None,
) -> tuple[str | None, str]:
    """Derive an immutable trusted base for change-bearing GitHub events."""
    if env.get("GITHUB_ACTIONS", "").casefold() != "true":
        return None, "local non-CI run"

    event_name = env.get("GITHUB_EVENT_NAME", "")
    payload = event if event is not None else read_event_payload(env)
    if event_name in {"pull_request", "pull_request_target"}:
        try:
            base_sha = payload["pull_request"]["base"]["sha"]  # type: ignore[index]
        except (KeyError, TypeError):
            base_sha = None
        return validated_commit_sha(base_sha, "pull-request base"), "pull-request base"

    if event_name == "push":
        before = validated_commit_sha(payload.get("before"), "push before")
        if set(before) == {"0"}:
            current = validated_commit_sha(env.get("GITHUB_SHA"), "zero-before push commit")
            parent_lookup = parent_commit_lookup or commit_parent
            parent = parent_lookup(current)
            if parent is None:
                return None, "initial repository root push"
            return validated_commit_sha(
                parent, "zero-before push first parent"
            ), "zero-before push first parent"
        return before, "push before"

    if (
        event_name in {"schedule", "workflow_dispatch"}
        and env.get("GITHUB_REF") == "refs/heads/main"
    ):
        return None, f"{event_name} on trusted main"

    raise BaseBudgetError(
        f"GitHub Actions event {event_name or '<missing>'} has no trusted complexity base"
    )


def read_base_budget(commit: str, repo: pathlib.Path = REPO) -> dict[str, int]:
    trusted_commit = validated_commit_sha(commit, "complexity base")

    def show_source() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "show", f"{trusted_commit}:{BUDGET_PATH}"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    result = show_source()
    if result.returncode != 0:
        # actions/checkout defaults to a one-commit shallow clone. Fetch only the
        # event-authenticated immutable object, never a mutable branch name.
        fetched = subprocess.run(
            [
                "git",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--depth=1",
                "origin",
                trusted_commit,
            ],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if fetched.returncode != 0:
            diagnostic = fetched.stderr.strip() or "git fetch failed"
            raise BaseBudgetError(
                f"cannot fetch trusted base complexity commit {trusted_commit}: {diagnostic}"
            )
        result = show_source()
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or "git show failed"
        raise BaseBudgetError(
            f"cannot read trusted base complexity budget at {trusted_commit}: {diagnostic}"
        )
    return parse_budget_source(result.stdout)


def read_base_measurements(
    commit: str, repo: pathlib.Path = REPO
) -> dict[str, int]:
    """Measure the trusted tree directly, without checking it out or executing it."""
    trusted_commit = validated_commit_sha(commit, "complexity base")
    engine_dir = "crates/scanner/src/engine"
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", trusted_commit, "--", engine_dir],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if listing.returncode != 0:
        diagnostic = listing.stderr.strip() or "git ls-tree failed"
        raise BaseBudgetError(
            f"cannot list trusted base engine at {trusted_commit}: {diagnostic}"
        )
    engine_files = sorted(
        path
        for path in listing.stdout.splitlines()
        if pathlib.PurePosixPath(path).parent.as_posix() == engine_dir
        and path.endswith(".rs")
    )
    if not engine_files:
        raise BaseBudgetError(
            f"trusted base {trusted_commit} has no measurable scan-engine files"
        )

    def show(path: str) -> str:
        result = subprocess.run(
            ["git", "show", f"{trusted_commit}:{path}"],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            diagnostic = result.stderr.strip() or "git show failed"
            raise BaseBudgetError(
                f"cannot read trusted base measurement source {path}: {diagnostic}"
            )
        return result.stdout

    engine_loc = sum(
        sum(1 for line in show(path).splitlines() if line.strip())
        for path in engine_files
    )
    backend_source = show("crates/scanner/src/hw_probe/mod.rs")
    scan_backends = count_scan_backends_source(backend_source)
    if scan_backends == 0:
        raise BaseBudgetError(
            f"trusted base {trusted_commit} has no defining ScanBackend variants"
        )
    return {
        "phase2_lanes": sum(
            pathlib.PurePosixPath(path).name.startswith("phase2")
            for path in engine_files
        ),
        "scan_backends": scan_backends,
        "engine_files": len(engine_files),
        "engine_loc": engine_loc,
    }


def effective_base_budget(
    budget: dict[str, int], measured: dict[str, int]
) -> dict[str, int]:
    """Eliminate historical ceiling slack before comparing candidate ratchets."""
    missing = sorted(budget.keys() - measured.keys())
    if missing:
        raise BaseBudgetError(
            "trusted base measurements are missing budget metrics: "
            + ", ".join(missing)
        )
    return {
        name: min(base_budget, measured[name])
        for name, base_budget in budget.items()
    }


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-commit",
        help="explicit immutable base commit; otherwise GitHub event identity is used",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = argument_parser().parse_args(argv)
    measured = {
        "phase2_lanes": count_phase2_lanes(),
        "scan_backends": count_scan_backends(),
        "engine_loc": count_engine_loc(),
        "engine_files": count_engine_files(),
    }
    drift = budget_drift(measured, BUDGET)
    print("complexity ratchet (measured / exact budget):")
    for name, expected in BUDGET.items():
        got = measured.get(name)
        flag = "OK   " if got == expected else "DRIFT"
        print(f"  [{flag}] {name:16} {got} / {expected}")

    if drift:
        print("\nFAIL, the scan-engine complexity ratchet drifted:", file=sys.stderr)
        for name, got, expected in drift:
            if got is None:
                reason = "metric is budgeted but no longer measured"
            elif expected is None:
                reason = "metric is measured but has no exact budget"
            elif got < expected:
                reason = (
                    f"measured {got} < budget {expected}; lower the budget to {got} "
                    "in this change"
                )
            else:
                reason = (
                    f"measured {got} > budget {expected}; remove the added "
                    "complexity (ratchet budgets must never rise)"
                )
            print(f"  {name}: {reason}", file=sys.stderr)
        return 1
    print("\nOK, scan-engine complexity matches every exact ratchet.")

    try:
        if args.base_commit:
            base_commit = validated_commit_sha(args.base_commit, "explicit base")
            base_reason = "explicit base"
        else:
            base_commit, base_reason = resolve_ci_base(os.environ)
        if base_commit is None:
            print(f"OK, no historical comparison required: {base_reason}.")
            return 0
        base_budget = effective_base_budget(
            read_base_budget(base_commit),
            read_base_measurements(base_commit),
        )
    except BaseBudgetError as error:
        print(f"\nFAIL, cannot establish trusted complexity base: {error}", file=sys.stderr)
        return 1

    increases = budget_increases(BUDGET, base_budget)
    if increases:
        print(
            f"\nFAIL, complexity budgets raised relative to {base_reason} {base_commit}:",
            file=sys.stderr,
        )
        for name, candidate, base in increases:
            if candidate is None:
                detail = f"ratchet removed (trusted base {base})"
            else:
                detail = f"{candidate} > trusted base {base}"
            print(f"  {name}: {detail}", file=sys.stderr)
        return 1
    print(f"OK, every complexity budget is equal to or below {base_reason} {base_commit}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
