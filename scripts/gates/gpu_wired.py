#!/usr/bin/env python3
"""Fail when the GPU path is present in the tree but unproved by CI.

WHY THIS GATE EXISTS

`cargo test -p keyhog-scanner --test gpu_parity --test gpu_ac_smoke
--test gpu_peer_backend_parity`, built WITHOUT `--features gpu`, reported
4 + 2 + 6 passed and 0 ignored on a host with no adapter policy. Twelve GPU
tests, all green, none of which touched a GPU. Three separate wiring defects
combined to produce that green:

  1. `runners-nightly.yml` ran the `gpu_*` targets with no `--features gpu`, so
     the adapter branch was never compiled in. The step comment asserted the
     files "compile to empty without it", which is false: they have no
     file-level `cfg(feature = "gpu")`, so they compile and run and pass.
  2. The same step carried `continue-on-error: true`, so even a real failure
     was absorbed.
  3. No lane, hosted or self-hosted, armed the require-GPU runtime policy, so
     `require_gpu_or_panic` returned at its first line in every run and the
     hard-fail assertions were inert.

This gate needs no GPU. It is a static contract over the workflow files and the
test tree, so it runs on hosted PR CI where there will never be an adapter, and
it fails when any of the three defects above reappears.

Hardware parity is NOT this gate's job. That belongs to the self-hosted release
lane in `scripts/ci_local.sh`, which this gate checks is armed (rule 4) but
cannot execute here.

Usage:
  python3 -B scripts/gates/gpu_wired.py
  python3 -B scripts/gates/gpu_wired.py --self-test
"""

from __future__ import annotations

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from tests_wired import logical_command_lines  # noqa: E402  (single owner of the joiner)

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github/workflows"
RELEASE_LANE = REPO / "scripts/ci_local.sh"

# Crates whose top-level GPU test files must be wired to a gpu-featured step.
GPU_TEST_DIRS = ("crates/scanner/tests", "crates/cli/tests")

TEST_FLAG = re.compile(r"--test[ =]+([A-Za-z0-9_]+)")
FEATURES_FLAG = re.compile(r"--features[ =]+([A-Za-z0-9_,\-/]+)")
STEP_START = re.compile(r"^\s*-\s+(?:name|uses|run|id):")

# The release lane must prove a real adapter before it runs a GPU test.
RELEASE_ARM = "KEYHOG_REQUIRE_GPU=1"
RELEASE_PREFLIGHT = "backend --self-test"

# GPU-named targets that legitimately run without the feature in one lane. Keep
# tiny and justified, and note that an entry here is NOT an exemption from the
# GPU path: `check_workflows` still requires the target to run under
# `--features gpu` somewhere, so the allowlist can only permit an ADDITIONAL
# feature-free run, never replace the featured one.
HARDWARE_FREE_BY_DESIGN: dict[str, str] = {
    "gpu_literal_artifact_writer": (
        "spawns the keyhog-scanner-artifacts binary and asserts manifest and "
        "blob emission. It exercises the artifact writer, not an adapter, so a "
        "ci-lean build is the correct coverage for that lane."
    ),
}


def is_gpu_target(stem: str) -> bool:
    """True for a test target that exercises the GPU path.

    Token match, not substring: `gpu_parity`, `e2e_gpu_autoroute_optin`,
    `regression_require_gpu_fails_closed` and `packed_gpu_vyre_artifact` all
    carry `gpu` as a path token, while an unrelated stem that merely contains
    the letters does not.
    """
    return "gpu" in stem.split("_")


def features_of(command: str) -> set[str]:
    features: set[str] = set()
    for match in FEATURES_FLAG.findall(command):
        features |= {part.strip() for part in match.split(",") if part.strip()}
    return features


def step_blocks(text: str) -> list[str]:
    """Split a workflow into per-step text blocks.

    A step owns its `continue-on-error`, so an absorbed GPU command has to be
    attributed to the step that absorbs it, not to the file.
    """
    blocks: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if STEP_START.match(line) and current:
            blocks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def fold_yaml_scalars(text: str) -> str:
    """Join a YAML folded scalar (`run: >`) into one physical line.

    `ci.yml` writes its long `cargo test` steps as `run: >` and relies on YAML
    folding rather than backslash continuation, so the `--test` flags land on
    lines that carry no `cargo test`. Reading those line by line hid
    `regression_require_gpu_fails_closed` from rule 1: the exact target whose
    exit-12 assertion is vacuous without `--features gpu`. A literal block
    (`run: |`) is left alone, because there each line really is its own command.
    """
    out: list[str] = []
    folding_indent: int | None = None
    for line in text.splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if folding_indent is not None:
            if stripped and indent > folding_indent:
                out[-1] += " " + stripped
                continue
            folding_indent = None
        if re.match(r"^\s*(?:-\s+)?run:\s*>-?\s*$", line):
            folding_indent = indent
            out.append(line.rstrip()[: line.rstrip().rindex(">")] + " ")
            continue
        out.append(line)
    return "\n".join(out)


def gpu_commands(block: str) -> list[tuple[str, list[str]]]:
    """Every `cargo test` command in a step that names at least one GPU target."""
    found: list[tuple[str, list[str]]] = []
    for command in logical_command_lines(fold_yaml_scalars(block)):
        if "cargo test" not in command:
            continue
        targets = [stem for stem in TEST_FLAG.findall(command) if is_gpu_target(stem)]
        if targets:
            found.append((command, targets))
    return found


def check_workflows(workflow_texts: dict[str, str]) -> list[str]:
    """Rules 1 and 2, per workflow step, plus the allowlist's own obligation."""
    failures: list[str] = []
    featured_somewhere: set[str] = set()
    excused_used: set[str] = set()
    for name, text in sorted(workflow_texts.items()):
        for block in step_blocks(text):
            absorbed = re.search(r"^\s*continue-on-error:\s*true\s*$", block, re.MULTILINE)
            for command, targets in gpu_commands(block):
                built_with_gpu = "gpu" in features_of(command)
                if built_with_gpu:
                    featured_somewhere |= set(targets)
                else:
                    excused = set(targets) & set(HARDWARE_FREE_BY_DESIGN)
                    excused_used |= excused
                    unexcused = sorted(set(targets) - excused)
                    if unexcused:
                        failures.append(
                            f"{name}: step runs GPU targets ({', '.join(unexcused)}) "
                            f"without `--features gpu`. Without the feature the "
                            f"adapter branch is not compiled and these tests pass "
                            f"on a CPU, reporting GPU coverage that does not exist."
                        )
                if absorbed:
                    failures.append(
                        f"{name}: step runs GPU targets ({', '.join(sorted(targets))}) "
                        f"under `continue-on-error: true`. A gate that cannot fail "
                        f"is not a gate, and its green result is read as coverage."
                    )

    # An allowlisted target may have an extra feature-free run, never only that.
    for stem in sorted(excused_used):
        if stem not in featured_somewhere:
            failures.append(
                f"{stem} is in HARDWARE_FREE_BY_DESIGN but no workflow step runs "
                f"it under `--features gpu`. The allowlist permits an ADDITIONAL "
                f"feature-free run, it does not replace the featured one."
            )
    return failures


def gpu_test_stems() -> dict[str, str]:
    """Every top-level GPU test file in the tree, stem to repo-relative path."""
    stems: dict[str, str] = {}
    for rel in GPU_TEST_DIRS:
        directory = REPO / rel
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.rs")):
            if is_gpu_target(path.stem):
                stems[path.stem] = f"{rel}/{path.name}"
    return stems


def check_orphans(workflow_texts: dict[str, str], stems: dict[str, str]) -> list[str]:
    """Rule 3: a GPU test file nobody runs is not coverage."""
    wired: set[str] = set()
    for text in workflow_texts.values():
        wired |= set(TEST_FLAG.findall(text))
    return [
        f"{path}: GPU test file is named by no workflow step. It never runs, so "
        f"it proves nothing. Wire it into a `--features gpu` step or delete it."
        for stem, path in sorted(stems.items())
        if stem not in wired
    ]


def check_release_lane(text: str) -> list[str]:
    """Rule 4: the self-hosted lane must demand a real adapter, before testing."""
    failures: list[str] = []
    commands = logical_command_lines(text)
    first_gpu_test = next(
        (
            index
            for index, command in enumerate(commands)
            if "cargo test" in command
            and any(is_gpu_target(stem) for stem in TEST_FLAG.findall(command))
        ),
        None,
    )
    if first_gpu_test is None:
        failures.append(
            "scripts/ci_local.sh: the release lane runs no GPU test target. The "
            "self-hosted runner is the only place finding parity can be proved."
        )
        return failures
    if RELEASE_ARM not in text:
        failures.append(
            f"scripts/ci_local.sh: does not set {RELEASE_ARM}. Without it the "
            f"require-GPU policy stays Auto, `require_gpu_or_panic` returns at "
            f"its first line, and every GPU parity test passes on a runner whose "
            f"driver is dead."
        )
    preflight = next(
        (index for index, command in enumerate(commands) if RELEASE_PREFLIGHT in command),
        None,
    )
    if preflight is None:
        failures.append(
            f"scripts/ci_local.sh: no `{RELEASE_PREFLIGHT}` preflight. The lane "
            f"must prove a usable adapter before it runs GPU tests, so an absent "
            f"GPU fails as a named driver error instead of a green test run."
        )
    elif preflight > first_gpu_test:
        failures.append(
            f"scripts/ci_local.sh: the `{RELEASE_PREFLIGHT}` preflight runs after "
            f"the first GPU test. A preflight that follows the tests proves "
            f"nothing about them."
        )
    return failures


def read_workflows() -> dict[str, str]:
    if not WORKFLOWS.is_dir():
        return {}
    return {path.name: path.read_text() for path in sorted(WORKFLOWS.glob("*.yml"))}


def self_test() -> int:
    ok = True

    def case(label: str, actual: bool, expected: bool) -> None:
        nonlocal ok
        if actual != expected:
            ok = False
            print(f"  FAIL self-test: {label}")
        else:
            print(f"  ok: {label}")

    unfeatured = {
        "x.yml": "      - name: gpu\n        run: |\n"
        "          cargo test -p keyhog-scanner \\\n            --test gpu_parity\n"
    }
    case(
        "rule 1 catches a GPU step with no --features gpu",
        bool(check_workflows(unfeatured)),
        True,
    )

    featured = {
        "x.yml": "      - name: gpu\n        run: |\n"
        "          cargo test -p keyhog-scanner --features gpu \\\n"
        "            --test gpu_parity\n"
    }
    case(
        "rule 1 accepts a GPU step built with the feature",
        bool(check_workflows(featured)),
        False,
    )

    folded_unfeatured = {
        "x.yml": "      - name: fail-closed\n        run: >\n"
        "          cargo test -p keyhog --no-fail-fast\n"
        "          --test regression_output_to_dev_null\n"
        "          --test regression_require_gpu_fails_closed\n"
    }
    case(
        "rule 1 sees GPU targets inside a YAML folded scalar (run: >)",
        bool(check_workflows(folded_unfeatured)),
        True,
    )

    folded_featured = {
        "x.yml": "      - name: fail-closed\n        run: >\n"
        "          cargo test -p keyhog --features gpu --no-fail-fast\n"
        "          --test regression_require_gpu_fails_closed\n"
    }
    case(
        "rule 1 accepts a folded scalar built with the feature",
        bool(check_workflows(folded_featured)),
        False,
    )

    absorbed = {
        "x.yml": "      - name: gpu\n        continue-on-error: true\n        run: |\n"
        "          cargo test -p keyhog-scanner --features gpu \\\n"
        "            --test gpu_parity\n"
    }
    case(
        "rule 2 catches an absorbed GPU step",
        bool(check_workflows(absorbed)),
        True,
    )

    neighbour_absorbs = {
        "x.yml": "      - name: flaky\n        continue-on-error: true\n"
        "        run: cargo test -p keyhog-scanner --test perf_floor\n"
        "      - name: gpu\n        run: |\n"
        "          cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
    }
    case(
        "rule 2 does not blame a GPU step for a neighbour's absorption",
        bool(check_workflows(neighbour_absorbs)),
        False,
    )

    case(
        "rule 3 catches an unwired GPU test file",
        bool(check_orphans(featured, {"gpu_new_thing": "crates/scanner/tests/gpu_new_thing.rs"})),
        True,
    )
    case(
        "rule 3 accepts a wired GPU test file",
        bool(check_orphans(featured, {"gpu_parity": "crates/scanner/tests/gpu_parity.rs"})),
        False,
    )

    armed_lane = (
        "export KEYHOG_REQUIRE_GPU=1\n"
        "keyhog backend --self-test --require-gpu\n"
        "cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
    )
    case("rule 4 accepts an armed release lane", bool(check_release_lane(armed_lane)), False)
    case(
        "rule 4 catches a release lane that never arms the policy",
        bool(
            check_release_lane(
                "keyhog backend --self-test --require-gpu\n"
                "cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
            )
        ),
        True,
    )
    case(
        "rule 4 catches a preflight that runs after the GPU tests",
        bool(
            check_release_lane(
                "export KEYHOG_REQUIRE_GPU=1\n"
                "cargo test -p keyhog-scanner --features gpu --test gpu_parity\n"
                "keyhog backend --self-test --require-gpu\n"
            )
        ),
        True,
    )
    case(
        "is_gpu_target matches on path tokens, not on stray letters",
        is_gpu_target("gpu_parity")
        and is_gpu_target("e2e_gpu_autoroute_optin")
        and is_gpu_target("regression_require_gpu_fails_closed")
        and not is_gpu_target("perf_floor"),
        True,
    )

    print("SELF-TEST PASS" if ok else "SELF-TEST FAIL")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()

    sources = read_workflows()
    if RELEASE_LANE.is_file():
        # The self-hosted release lane is where hardware parity actually runs, so
        # a target wired only there is wired, not orphaned. It is checked by the
        # same rules: it must build with the feature and must not be absorbed.
        sources["scripts/ci_local.sh"] = RELEASE_LANE.read_text()
    failures = check_workflows(sources)
    failures += check_orphans(sources, gpu_test_stems())
    if RELEASE_LANE.is_file():
        failures += check_release_lane(RELEASE_LANE.read_text())
    else:
        failures.append(f"{RELEASE_LANE} is missing: the release GPU lane has no owner.")

    if failures:
        print("GPU WIRING GATE FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("GPU wiring gate: GPU targets are feature-built, unabsorbed, wired, and armed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
