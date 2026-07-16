# KeyHog AGENTS

## Execution Rules (local)

- Work on `main` unless the user explicitly asks for another branch.
- Read the code before edits. Don’t invent behavior from memory.
- Keep changes scoped; do not revert unrelated local edits.
- Never block productive work on a gate. Run independent tests, builds, and benchmarks in the background and advance another concrete lane while they run. A required gate may block the affected commit or release verdict, but it must never make the main thread wait, idle, repeatedly poll, or stop disjoint implementation and investigation.
- Do not use native Codex workers, `codex exec`, Cursor Agent, Gemini CLI, Kimi, OpenCode, Copilot audit, `codex-agents`, dispatch MCP, or any other subagent/worker for repository work.
- Keep repository work in the main thread. Do not use external worker, audit, or dispatch agents.
- Do not add unnecessary runtime overrides in source code. Prefer detector and data/config surfaces for behavior.
- Never log secrets in stdout/stderr.
- Keep existing module patterns unless a migration requires breaking design.
- If a previously started worker produced prose instead of an implementation diff, discard the prose and assign concrete edits.

## Paths and environments

- Work from the repository root.
- Keep the Cargo target directory OUTSIDE the source tree; set `CARGO_TARGET_DIR`
  to a path on a fast local disk. This keeps multi-gigabyte build artifacts out of
  the working copy and out of the dogfood self-scan.

## Simplicity rule

- OVERCOMPLEXITY IS CANCER. Secret scanning is insanely simple. Do not invent layers, indirection, or generic machinery where a direct, data-driven solution works. Every added abstraction is a maintenance tax; prefer deleting code to rewriting it.

## Scanner hard rules

- No credential values in logs.
- No destructive Git commands without explicit user approval.
- Preserve public APIs by migration, not by silent behavior drift.
- Update project changelog for user-visible scanner behavior and test surface changes.
- Prefer verification through real scanner workflow (`scan -> detect -> suppress -> confidence`) over isolated unit-only assertions.

## Autoroute hard rule

- Autoroute is a proof-backed selector over all eligible backends. It is not a fallback hierarchy, not "GPU primary with CPU fallback", not "CPU safe default", and not a threshold heuristic.
- GPU, Hyperscan/SIMD, scalar CPU, and any new backend are peers in the selector. The selected backend must be the fastest measured-correct backend for the exact workload class, detector digest, config digest, binary, OS/arch, CPU features, GPU/driver state, and accelerator availability.
- Install/recalibration must visibly probe eligible backends, prove finding parity, persist the decision table, and make normal scans use that table without runtime benchmarking.
- A missing, stale, invalid, or incomplete autoroute decision is an invalid autoroute state. Do not silently run SIMD/CPU/GPU as a substitute. Surface the state in the operator-visible result and exit/status semantics.
- `--backend` is a diagnostic and benchmark override only. It does not prove autoroute correctness.

## Documentation style

- Do not use the Unicode em dash character. Rewrite the sentence or use parentheses instead of mechanically substituting another separator.
- Keep README, specification, comments, commit messages, and user-facing text direct. Cut filler, hype, throat-clearing, and explanations that do not change operator understanding.
- Do not use vague quality superlatives in docs, comments, commits, identifiers, filenames, or agent output. Name the concrete standard, matrix, workflow, or depth instead.
