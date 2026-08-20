#!/usr/bin/env python3
"""Fail if any standalone test file in an enforced crate is a CI-orphan.

Each crate's CI runs specific test targets: `cargo test -p <crate> --test
all_tests` (+ a handful of explicit `--test <name>` steps and `--lib`). There is
NO `cargo test --workspace`/nextest all-target run. So a top-level
`crates/<crate>/tests/*.rs` compiles as its OWN separate integration-test target
that runs ONLY if it is reachable from the `all_tests` module tree (as a
`#[path]` include OR a plain `[pub] mod X;` sibling declaration in the crate-root
`all_tests.rs`: both wire a sibling `tests/X.rs`) or is named by a `--test`
step. Otherwise its `#[test]`s never run and the regression it guards can ship
silently.

This generalises `recall_locks_wired.py` (scanner-only, `regression_*` only) to
EVERY top-level `tests/*.rs` of the ENFORCED crates below, modelling all three
wiring mechanisms. Crates are added to `ENFORCED_CRATES` only once fully wired
(the verifier + core orphan sweeps); cli/sources still carry a large orphan
backlog and are enforced as each is swept.

A file `crates/<crate>/tests/<stem>.rs` is wired iff its stem is:
  * captured by a `#[path = "…/<stem>.rs"]` include in ANY `.rs` under the
    crate's tests tree, OR
  * declared as `[pub] mod <stem>;` in that crate's `tests/all_tests.rs`
    (the aggregator crate-root; a sibling `mod` there compiles the top-level
    file), OR
  * named by a `--test <stem>` flag in any .github/workflows/*.yml step, OR
  * covered by an ALL-TARGETS step for the crate's package, a `cargo test
    -p <pkg>` invocation with NO target-narrowing flag (`--test`/`--lib`/
    `--doc`/`--bin`/`--example`), which compiles and runs EVERY integration
    target (each top-level file as its own test binary). keyhog-sources uses
    this for its deliberately-standalone, process-global-skip-counter tests,
    which must run in their own process rather than the shared `all_tests`
    binary. When such a step exists, every top-level file of that crate is
    wired.
`all_tests.rs` itself is the aggregator root (run directly) and is excluded.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = REPO / ".github/workflows"

# Crates whose top-level test files are fully wired and must STAY wired. Add a
# crate here only after its orphan sweep lands (else this gate turns CI red).
ENFORCED_CRATES: list[str] = ["verifier", "core", "sources", "scanner", "cli"]

AGGREGATOR = "all_tests"

# {crate: {stem, ...}} intentionally-unaggregated files that run in CI by another
# explicit means. Keep tiny and justified.
ALLOWED: dict[str, set[str]] = {
    "cli": {"target_spec_org_contracts"},
}

# A `cargo test` step whose command contains any of these narrows to a subset of
# targets, so it does NOT prove every top-level integration file runs.
TARGET_NARROWING = ("--test ", "--test=", "--lib", "--doc", "--bin", "--example")

PATH_INCLUDE = re.compile(r'#\[path\s*=\s*"(?:[^"]*/)?([A-Za-z0-9_]+)\.rs"\]')
MOD_DECL = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z0-9_]+)\s*;", re.MULTILINE)
TEST_FLAG = re.compile(r"--test[ =]+([A-Za-z0-9_]+)")


def crate_pkg(crate: str) -> str:
    """Cargo package name for a crate directory (cli ships as `keyhog`)."""
    return "keyhog" if crate == "cli" else f"keyhog-{crate}"


BLOCK_SCALAR = re.compile(r"^(\s*)[A-Za-z0-9_.-]+:\s*(\||>)[-+]?\s*$")


def fold_block_scalars(text: str) -> list[str]:
    """Expand YAML block scalars so a folded step reads as ONE command.

    A folded (">") step joins its continuation lines into a single command,
    but the raw file still shows them as separate lines:

        run: >
          cargo test -p keyhog --profile ci-test
          --test regression_install_insecure_env_removed

    Read line by line, line one is a `cargo test -p keyhog` carrying no
    narrowing flag, which is exactly the all-targets shape. That made
    `runs_all_targets("keyhog")` true and short-circuited orphan detection for
    the WHOLE crate: the gate reported every cli test file wired while
    `lane5_cli_subcommand_surface_matrix`, `regression_cli_version_help`, and
    `release_attestation_contract` ran in no job at all, and two of them had
    been red for some time.

    ">" folds into one line and "|" keeps its lines separate, matching what
    the shell receives, so the fold honours the indicator instead of treating
    every block alike. A blank line inside a folded block is a paragraph break
    and starts a new command.
    """
    out: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = BLOCK_SCALAR.match(lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        header_indent, style = m.group(1), m.group(2)
        i += 1
        body: list[str] = []
        while i < len(lines):
            line = lines[i]
            if line.strip() and len(line) - len(line.lstrip()) <= len(header_indent):
                break
            body.append(line)
            i += 1
        if style == "|":
            out.extend(body)
            continue
        paragraph: list[str] = []
        for line in body:
            if line.strip():
                paragraph.append(line.strip())
            elif paragraph:
                out.append(" ".join(paragraph))
                paragraph = []
        if paragraph:
            out.append(" ".join(paragraph))
    return out


def logical_command_lines(text: str) -> list[str]:
    """Join a CI step's continuation lines into ONE logical command string.

    Two mechanisms split one command across lines, and both hide a narrowing
    flag from a line-by-line scan: a YAML block scalar (see
    `fold_block_scalars`) and a shell backslash continuation:

        cargo test -p keyhog-scanner --profile release-fast \\
          --test contracts_runner
          --test adversarial_explosion_runner

    The FIRST line carries no `--test`, so a naive check reads it as an
    all-targets run and vacuously wires every orphan. Fold both so the flags
    on later lines belong to the same command.
    """
    out: list[str] = []
    buf = ""
    for raw in fold_block_scalars(text):
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
        else:
            out.append(buf + raw)
            buf = ""
    if buf:
        out.append(buf)
    return out


def runs_all_targets(pkg: str) -> bool:
    """True iff a workflow runs `cargo test -p <pkg>` with no target filter.

    Such a step compiles + runs every integration target, each top-level
    `tests/*.rs` as its own binary (so it wires them all without aggregation).
    Continuation lines are folded first (`logical_command_lines`) so a
    multi-line command whose `--test` flags sit on later lines is correctly
    recognised as NARROWED, not all-targets.
    """
    pkg_ref = re.compile(rf"-p\s+{re.escape(pkg)}(?:\s|$)")
    for text in ci_entrypoints():
        for line in logical_command_lines(text):
            if "cargo test" not in line or not pkg_ref.search(line):
                continue
            if any(flag in line for flag in TARGET_NARROWING):
                continue
            return True
    return False


SCRIPT_REF = re.compile(r"\b(?:bash|sh)\s+(scripts/[A-Za-z0-9_./-]+\.sh)")


def ci_entrypoints() -> list[str]:
    """Every text a CI step ultimately executes: the workflows plus the shell
    scripts they invoke.

    A workflow step is often one line, `bash scripts/ci_local.sh`, with the real
    `cargo test --test ...` battery inside the script. Reading only
    `.github/workflows/*.yml` therefore reports a test as running nowhere while
    it runs on every release: `ci_local.sh` is the ONLY lane that proves GPU
    finding parity, and all twelve of its GPU targets looked like orphans.
    Follow the reference one level, which is the depth CI actually uses.
    """
    texts: list[str] = []
    if not WORKFLOWS.is_dir():
        return texts
    seen: set[str] = set()
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        text = wf.read_text()
        texts.append(text)
        for rel in SCRIPT_REF.findall(text):
            if rel in seen:
                continue
            seen.add(rel)
            script = REPO / rel
            if script.is_file():
                texts.append(script.read_text())
    return texts


def workflow_test_flags() -> set[str]:
    stems: set[str] = set()
    for text in ci_entrypoints():
        stems |= set(TEST_FLAG.findall(text))
    return stems


def wired_stems(crate: str, workflow_flags: set[str]) -> set[str]:
    tests_dir = REPO / "crates" / crate / "tests"
    stems: set[str] = set(workflow_flags)
    if tests_dir.is_dir():
        for rs in tests_dir.rglob("*.rs"):
            stems |= set(PATH_INCLUDE.findall(rs.read_text()))
        aggregator = tests_dir / f"{AGGREGATOR}.rs"
        if aggregator.exists():
            # A `[pub] mod X;` in the aggregator crate-root compiles sibling
            # `tests/X.rs`. Directory-module names (adversarial, regression …)
            # also match but never collide with a top-level file stem.
            stems |= set(MOD_DECL.findall(aggregator.read_text()))
    return stems


def top_level_test_files(crate: str) -> list[str]:
    tests_rel = f"crates/{crate}/tests"
    try:
        listing = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z", f"{tests_rel}/*.rs"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        rels = [r for r in listing.split("\0") if r]
    except (OSError, subprocess.CalledProcessError):
        rels = [
            p.relative_to(REPO).as_posix()
            for p in (REPO / tests_rel).glob("*.rs")
        ]
    depth = tests_rel.count("/") + 1
    return sorted(
        stem
        for r in rels
        if r.count("/") == depth
        and r.endswith(".rs")
        and (REPO / r).is_file()
        for stem in [r.rsplit("/", 1)[-1][: -len(".rs")]]
        if stem != AGGREGATOR
    )


def crate_orphans(crate: str, workflow_flags: set[str]) -> list[str]:
    # An all-targets `cargo test -p <pkg>` step runs every integration file, so
    # nothing in the crate can be orphaned.
    if runs_all_targets(crate_pkg(crate)):
        return []
    wired = wired_stems(crate, workflow_flags)
    allowed = ALLOWED.get(crate, set())
    return [
        s
        for s in top_level_test_files(crate)
        if s not in wired and s not in allowed
    ]


def self_test() -> int:
    ok = True
    # #[path] sibling AND `../`-prefixed forms → bare stem.
    if PATH_INCLUDE.findall('#[path = "regression_sigv4_known_answer.rs"]') != [
        "regression_sigv4_known_answer"
    ]:
        print("self-test: sibling PATH_INCLUDE broken", file=sys.stderr)
        ok = False
    if PATH_INCLUDE.findall('#[path = "../regression_oob_fail_closed.rs"]') != [
        "regression_oob_fail_closed"
    ]:
        print("self-test: parent PATH_INCLUDE broken", file=sys.stderr)
        ok = False
    # `pub mod X;` and `mod X;` sibling declarations.
    if MOD_DECL.findall("pub mod detector_corpus_integrity;\nmod wave9_edge;") != [
        "detector_corpus_integrity",
        "wave9_edge",
    ]:
        print("self-test: MOD_DECL broken", file=sys.stderr)
        ok = False
    if TEST_FLAG.findall("cargo test -p keyhog-verifier --test break_it x") != [
        "break_it"
    ]:
        print("self-test: TEST_FLAG broken", file=sys.stderr)
        ok = False
    # `--test-threads=1` (a test-binary arg) must NOT be read as a `--test` target
    # and must NOT count as target-narrowing.
    if TEST_FLAG.findall("cargo test -p x -- --test-threads=1"):
        print("self-test: TEST_FLAG mis-parses --test-threads", file=sys.stderr)
        ok = False
    if any(f in "cargo test -p x -- --test-threads=1" for f in TARGET_NARROWING):
        print("self-test: --test-threads mis-flagged as narrowing", file=sys.stderr)
        ok = False
    if not any(f in "cargo test -p x --test all_tests" for f in TARGET_NARROWING):
        print("self-test: --test not flagged as narrowing", file=sys.stderr)
        ok = False
    # Backslash continuations fold into one logical line, so a multi-line
    # `cargo test -p x \\ --test y` reads as NARROWED (its --test is on line 2),
    # not as an all-targets run, the bug that would vacuously wire every orphan
    # the moment scanner (whose strict-runner step is exactly this shape) joins
    # ENFORCED_CRATES.
    folded = logical_command_lines("cargo test -p keyhog-scanner \\\n  --test contracts_runner\nplain")
    if not any("cargo test" in ln and "--test " in ln for ln in folded):
        print("self-test: continuation not folded into one command", file=sys.stderr)
        ok = False
    if "plain" not in folded:
        print("self-test: folding dropped a non-continued line", file=sys.stderr)
        ok = False
    # A YAML FOLDED (">") step is one command: its `--test` flags sit on later
    # lines, so line-by-line the first line is a bare `cargo test -p keyhog`,
    # the all-targets shape that short-circuits orphan detection for the whole
    # crate. This is the bug that hid 89 cli and 19 scanner orphans.
    folded_yaml = fold_block_scalars(
        "      - name: x\n"
        "        run: >\n"
        "          cargo test -p keyhog --profile ci-test\n"
        "          --test regression_cli_version_help\n"
        "      - name: y\n"
    )
    joined = [ln for ln in folded_yaml if "cargo test" in ln]
    if len(joined) != 1 or "--test regression_cli_version_help" not in joined[0]:
        print(f"self-test: folded scalar not joined: {joined}", file=sys.stderr)
        ok = False
    if not any("- name: y" in ln for ln in folded_yaml):
        print("self-test: folding swallowed the next step", file=sys.stderr)
        ok = False
    # A LITERAL ("|") block keeps its lines separate, matching the shell: two
    # commands must not merge into one, or a narrowing flag from the second
    # would silently narrow the first.
    literal = fold_block_scalars(
        "        run: |\n"
        "          cargo test -p keyhog-core\n"
        "          cargo test -p keyhog-scanner --test all_tests\n"
    )
    cmds = [ln.strip() for ln in literal if "cargo test" in ln]
    if cmds != ["cargo test -p keyhog-core", "cargo test -p keyhog-scanner --test all_tests"]:
        print(f"self-test: literal block merged commands: {cmds}", file=sys.stderr)
        ok = False
    # A workflow step that only invokes a script must be followed into that
    # script, or every target the script runs looks like an orphan.
    if SCRIPT_REF.findall("        run: bash scripts/ci_local.sh") != [
        "scripts/ci_local.sh"
    ]:
        print("self-test: SCRIPT_REF broken", file=sys.stderr)
        ok = False
    # crate -> cargo package name (cli ships as `keyhog`).
    if (crate_pkg("cli"), crate_pkg("core")) != ("keyhog", "keyhog-core"):
        print("self-test: crate_pkg broken", file=sys.stderr)
        ok = False
    # `-p keyhog` must NOT match a `-p keyhog-sources` line (word boundary).
    boundary = re.compile(r"-p\s+keyhog(?:\s|$)")
    if boundary.search("cargo test -p keyhog-sources --lib"):
        print("self-test: pkg boundary matched a longer name", file=sys.stderr)
        ok = False
    if not boundary.search("cargo test -p keyhog --test all_tests"):
        print("self-test: pkg boundary missed exact name", file=sys.stderr)
        ok = False
    # orphan set math: a file wired by ANY mechanism is not an orphan.
    wired = {"a", "c"}
    got = [s for s in ["a", "b", "c", "d"] if s not in wired and s not in set()]
    if got != ["b", "d"]:
        print(f"self-test: orphan math broken got={got}", file=sys.stderr)
        ok = False
    print("self-test PASS" if ok else "self-test FAIL", file=sys.stderr)
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    workflow_flags = workflow_test_flags()
    failed = False
    total = 0
    for crate in ENFORCED_CRATES:
        files = top_level_test_files(crate)
        total += len(files)
        orphans = crate_orphans(crate, workflow_flags)
        if orphans:
            failed = True
            print(
                f"FAIL - {len(orphans)} CI-orphan test file(s) in `{crate}` that never run in CI:",
                file=sys.stderr,
            )
            for stem in orphans:
                print(f"  crates/{crate}/tests/{stem}.rs", file=sys.stderr)
    if failed:
        print(
            "\nWire each into its crate's tests/all_tests.rs with a "
            "`pub mod <name>;` (sibling) or `#[path] pub mod <name>;` line (the "
            "aggregated target CI runs), or add an explicit `--test <name>` "
            "workflow step. An orphan test's assertions are dead weight and the "
            "regression it guards can ship silently.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK - all {total} top-level test files across {ENFORCED_CRATES} are CI-wired."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
