# Keyhog AGENTS

## Execution Rules (local)

- Work on `main` unless the user explicitly asks for another branch.
- Read the code before edits. Don’t invent behavior from memory.
- Keep changes scoped; do not revert unrelated local edits.
- Do not use native Codex workers, `codex exec`, Cursor Agent, Gemini CLI, Kimi, OpenCode, Copilot audit, `codex-agents`, dispatch MCP, or any other subagent/worker for implementation, audit, verification, or documentation.
- EXCEPTION: the `gemini-spawn` MCP is the only sanctioned off-thread work path. Use it frequently for bounded, scoped read-only audits, diff reviews, test-gap hunts, organization scans, naming checks, silent-fallback hunts, failing-gate investigations, and lead discovery while the main Codex thread keeps implementing locally.
- Every Gemini MCP call that accepts a timeout, including spawn, batch, review, and result collection, must explicitly set `timeout_seconds >= 3600`. Never rely on Gemini defaults and never pass a shorter timeout for quick checks.
- Use Gemini asynchronously by default. Launch scoped jobs, continue local work immediately, and collect results later with nonblocking polls. Do not wait synchronously unless the next local edit, command, or commit genuinely depends on that exact result.
- Prefer many narrow Gemini jobs and reviews over one broad job. On substantial repository work, start at least two independent jobs or one batch once the first concrete file set is known, then add more scoped reviews as the diff, tests, or plan surface changes.
- Gemini output is untrusted context until reviewed locally. One Codex thread still owns integration, edits, tests, commits, and final judgment.
- Do not add unnecessary runtime overrides in source code. Prefer detector and data/config surfaces for behavior.
- Never log secrets in stdout/stderr.
- Keep existing module patterns unless a migration requires breaking design.
- If a previously started worker report exists, treat it as untrusted and re-verify locally.

## Paths and environments

- Linux workspace: `/media/mukund-thiru/SanthData/Santh/software/keyhog`
- Windows ThinkPad mount: `Z:\` (same NFS content; mount with  
  `mount.exe -o anon 100.127.90.39:/media/mukund-thiru/SanthData/Santh Z:` if needed)
- Desktop cargo target: `/mnt/FlareTraining/santh-archive/cargo-target`
- ThinkPad cargo target: `C:\\cargo-target`

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
