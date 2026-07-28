"""Produce a source- and run-bound CPU/SIMD Unicode parity receipt.

The wrapper builds and hashes the exact test executable, runs both parity tests,
and issues a receipt only when the checked-out source, detector corpus, release
binary, reviewed policy and hosted context stay unchanged around the test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Mapping, Sequence

from .executable_snapshot import sha256_file
from .hosted_cpu_gate import (
    CONTEXT_SCHEMA,
    PARITY_SCHEMA,
    HostedCpuInputError,
    load_policy,
    policy_sha256,
)
from .keyhog_version import (
    KeyhogVersionError,
    assert_workspace_tracked_tree_clean,
    workspace_detector_corpus_sha256,
    workspace_git_hash,
)

_SUMMARY_RE = re.compile(
    r"(?m)^backend parity: ([0-9]+) detector examples; "
    r"CPU == SIMD on all ASCII inputs; 0 unicode-input divergences$"
)
_BUILD_COMMAND = (
    "cargo", "test", "--locked", "--no-run", "--message-format=json",
    "-p", "keyhog-scanner", "--test", "detector_corpus_backend_parity",
)
_SOURCE = pathlib.Path("crates/scanner/tests/detector_corpus_backend_parity.rs")


def parse_summary(output: str, *, expected_examples: int) -> tuple[int, int]:
    """Require one exact explicit-zero line and the policy-pinned vector count."""
    matches = _SUMMARY_RE.findall(output)
    if len(matches) != 1:
        raise HostedCpuInputError(
            "CPU/SIMD detector parity emitted no unique explicit-zero summary"
        )
    examples = int(matches[0])
    if examples != expected_examples:
        raise HostedCpuInputError(
            f"CPU/SIMD parity covered {examples} examples, expected {expected_examples}"
        )
    return examples, 0


def _test_executable(build_stdout: str) -> pathlib.Path:
    candidates: list[pathlib.Path] = []
    for line in build_stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = event.get("target")
        if (
            event.get("reason") == "compiler-artifact"
            and isinstance(target, dict)
            and target.get("name") == "detector_corpus_backend_parity"
            and "test" in target.get("kind", [])
            and isinstance(event.get("executable"), str)
        ):
            candidates.append(pathlib.Path(event["executable"]))
    unique = list(dict.fromkeys(candidates))
    if len(unique) != 1:
        raise HostedCpuInputError(
            f"cargo did not identify one parity test executable: {unique}"
        )
    return unique[0].resolve(strict=True)


def _context_runner(context: Mapping[str, object]) -> Mapping[str, object]:
    runner = context.get("runner")
    if not isinstance(runner, dict):
        raise HostedCpuInputError("hosted context runner receipt is missing")
    required = (
        "repository", "workflow_ref", "workflow_sha", "run_id", "run_attempt", "job"
    )
    if any(not isinstance(runner.get(field), str) or not runner[field] for field in required):
        raise HostedCpuInputError("hosted context runner ownership is incomplete")
    return runner


def build_receipt(
    context: Mapping[str, object],
    command_output: str,
    *,
    expected_examples: int,
    context_sha256: str,
    release_executable_sha256: str,
    test_executable_sha256: str,
    parity_source_sha256: str,
    vector_sha256: str,
    command: Sequence[str],
    generated_at: str | None = None,
) -> dict[str, object]:
    """Build a complete receipt after all externally verified identities agree."""
    if context.get("schema_version") != CONTEXT_SCHEMA:
        raise HostedCpuInputError("Unicode parity requires a current hosted CPU context")
    for name, value in (
        ("context", context_sha256), ("release executable", release_executable_sha256),
        ("test executable", test_executable_sha256), ("parity source", parity_source_sha256),
        ("vector", vector_sha256),
    ):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise HostedCpuInputError(f"{name} SHA-256 is malformed")
    runner = _context_runner(context)
    examples, divergences = parse_summary(
        command_output, expected_examples=expected_examples
    )
    return {
        "schema_version": PARITY_SCHEMA,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "source_commit": context.get("source_commit"),
        "detector_corpus_sha256": context.get("detector_corpus_sha256"),
        "policy_sha256": context.get("policy_sha256"),
        "context_sha256": context_sha256,
        "repository": runner["repository"],
        "workflow_ref": runner["workflow_ref"],
        "workflow_sha": runner["workflow_sha"],
        "run_id": runner["run_id"],
        "run_attempt": runner["run_attempt"],
        "job": runner["job"],
        "release_executable_sha256": release_executable_sha256,
        "test_executable_sha256": test_executable_sha256,
        "parity_source_sha256": parity_source_sha256,
        "vector_sha256": vector_sha256,
        "detector_examples": examples,
        "unicode_divergences": divergences,
        "command": list(command),
    }


def run(
    context_path: pathlib.Path,
    policy_path: pathlib.Path,
    binary: pathlib.Path,
    output_path: pathlib.Path,
    *,
    repo_root: pathlib.Path,
) -> int:
    """Run parity and atomically publish only a fully bound passing receipt."""
    output_path.unlink(missing_ok=True)
    try:
        context_raw = context_path.read_bytes()
        context = json.loads(context_raw)
        if not isinstance(context, dict):
            raise HostedCpuInputError("hosted CPU context must be a JSON object")
        policy = load_policy(policy_path)
        runner = _context_runner(context)
        repo_root = repo_root.resolve(strict=True)
        source_path = (repo_root / _SOURCE).resolve(strict=True)
        before_commit = workspace_git_hash(repo_root)
        assert_workspace_tracked_tree_clean(repo_root)
        before_detector = workspace_detector_corpus_sha256(repo_root)
        before_binary = sha256_file(binary.resolve(strict=True))
        if context.get("source_commit") != before_commit or runner.get("workflow_sha") != before_commit:
            raise HostedCpuInputError("parity source commit differs from hosted context")
        if context.get("detector_corpus_sha256") != before_detector:
            raise HostedCpuInputError("parity detector corpus differs from hosted context")
        if context.get("executable_sha256") != before_binary:
            raise HostedCpuInputError("release executable differs from hosted context")
        if context.get("policy_sha256") != policy_sha256(policy_path):
            raise HostedCpuInputError("reviewed policy differs from hosted context")
        source_sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if source_sha != policy.parity_source_sha256:
            raise HostedCpuInputError("parity test source differs from reviewed policy")

        built = subprocess.run(
            _BUILD_COMMAND,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=1_800,
            check=False,
        )
        if built.returncode != 0:
            raise HostedCpuInputError(
                f"parity test build exited {built.returncode}: "
                f"{(built.stdout + built.stderr)[-2000:]}"
            )
        test_executable = _test_executable(built.stdout)
        test_sha = sha256_file(test_executable)
        command = (str(test_executable), "--nocapture")
        completed = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=1_800,
            check=False,
        )
        combined = completed.stdout + "\n" + completed.stderr
        if completed.returncode != 0:
            raise HostedCpuInputError(
                f"CPU/SIMD detector parity command exited {completed.returncode}: "
                f"{combined[-2000:]}"
            )

        after_commit = workspace_git_hash(repo_root)
        assert_workspace_tracked_tree_clean(repo_root)
        after_detector = workspace_detector_corpus_sha256(repo_root)
        after_binary = sha256_file(binary.resolve(strict=True))
        after_source = hashlib.sha256(source_path.read_bytes()).hexdigest()
        after_test = sha256_file(test_executable)
        if (after_commit, after_detector, after_binary, after_source, after_test) != (
            before_commit, before_detector, before_binary, source_sha, test_sha
        ):
            raise HostedCpuInputError("parity evidence inputs changed during execution")
        vector_sha = hashlib.sha256(
            source_path.read_bytes() + b"\0" + before_detector.encode("ascii")
        ).hexdigest()
        if vector_sha != policy.parity_vector_sha256:
            raise HostedCpuInputError("parity vector identity differs from reviewed policy")
        receipt = build_receipt(
            context,
            combined,
            expected_examples=policy.parity_detector_examples,
            context_sha256=hashlib.sha256(context_raw).hexdigest(),
            release_executable_sha256=before_binary,
            test_executable_sha256=test_sha,
            parity_source_sha256=source_sha,
            vector_sha256=vector_sha,
            command=command,
        )
    except (
        OSError, json.JSONDecodeError, subprocess.SubprocessError,
        HostedCpuInputError, KeyhogVersionError,
    ) as exc:
        print(f"UNICODE CPU/SIMD PARITY FAILED: {exc}", file=sys.stderr)
        return 1
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(
        f"Unicode CPU/SIMD parity passed across {receipt['detector_examples']} examples; "
        f"wrote {output_path}",
        file=sys.stderr,
    )
    return 0


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, type=pathlib.Path)
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--repo-root", default=pathlib.Path(".."), type=pathlib.Path)
    args = parser.parse_args(argv)
    return run(
        args.context, args.policy, args.binary, args.output, repo_root=args.repo_root
    )


if __name__ == "__main__":
    raise SystemExit(_main())
