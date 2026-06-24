# Keyhog AGENTS

## Execution Rules (local)

- Work on `main` unless the user explicitly asks for another branch.
- Read the code before edits. Don’t invent behavior from memory.
- Keep changes scoped; do not revert unrelated local edits.
- Do not use native Codex workers, `codex exec`, Cursor Agent, Gemini CLI, Kimi, OpenCode, Copilot audit, `codex-agents`, dispatch MCP, or any other subagent/worker for implementation, audit, verification, or documentation.
- EXCEPTION: the `gemini-spawn` MCP is the only sanctioned off-thread work path. Use it aggressively for bounded, scoped, small read-only audits, diff reviews, test-gap hunts, organization scans, naming checks, silent-fallback hunts, failing-gate investigations, and lead discovery while the main Codex thread keeps implementing locally.
- Gemini one-hour floor: every Gemini MCP call that accepts a timeout, including `gemini_spawn`, `gemini_spawn_batch`, `gemini_review`, and `gemini_result`, must explicitly set `timeout_seconds >= 3600`. This is a hard minimum for every spawn, review, batch, poll, quick check, result collection, retry, throwaway review, and small job. Never rely on defaults, never pass a shorter timeout, and do not call a Gemini tool if its timeout cannot be made explicit and at least one hour.
- Gemini spawn/review/result template: every wait-capable Gemini call is `timeout_seconds: 3600` or higher plus `wait: false` by default. This applies to initial spawns, batch jobs, reviews, status/result polls, retries, and follow-up checks. A "quick" Gemini job means narrow scope, not a short timeout or synchronous wait.
- Gemini spawn contract: every `gemini_spawn`, every `gemini_review`, and every job inside `gemini_spawn_batch` is a one-hour-minimum async job. "Small", "quick", "scoped", "cheap", "throwaway", or "review" describes scope only; it never permits `timeout_seconds < 3600`, omitted timeouts, blocking spawn calls, or synchronous result waits.
- Gemini async default: if the tool schema has `wait`, set `wait: false` unless the user explicitly orders a blocking wait and the main thread cannot make useful local progress without that exact result. `wait: true`, omitted timeouts, default timeouts, short quick-check timeouts, synchronous result polling, and spawn-time blocking are banned by default. Do not wait synchronously for Gemini just because a result would be convenient; keep working locally and poll later.
- Gemini no-sync rule: never turn a Gemini spawn, review, batch, or result poll into a synchronous gate for ordinary repo work. Spawn with `wait: false`, immediately continue local implementation or verification, and only read results through later nonblocking `gemini_result` polls with `timeout_seconds >= 3600`.
- Gemini fire-and-continue: launch Gemini jobs, continue local work immediately, and collect results later with nonblocking polls. Do not wait at spawn, review, or result time just because a job is small or a review seems quick. Block only when the next local edit, command, or commit genuinely depends on that exact scoped result.
- Gemini cadence: prefer many narrow independent Gemini jobs and reviews over one broad job. Use `gemini_spawn_batch` for multiple independent small jobs when available. Launch jobs near the start of each work batch, after meaningful local discoveries, before risky commits, and whenever a scoped review can run while local work continues. Re-spawn more scoped reviews as the diff changes instead of saving one large review for the end; keep at least one small useful Gemini audit running during substantial repository work whenever possible.
- Gemini fanout default: when there are several independent audit questions, use multiple small Gemini jobs or `gemini_spawn_batch` immediately; do not serialize them behind local implementation, tests, or another Gemini result. The main thread keeps working while those jobs run.
- Gemini minimum pattern: on substantial repository tasks, start at least two independent Gemini jobs or one batch as soon as the first concrete file set is known, then keep polling nonblocking while continuing local work. Add more small jobs whenever the scope widens, a risky diff appears, tests expose a new class of failure, or a commit is about to be made. If no Gemini job is running during substantial local repo work, either launch a small scoped job or have a concrete reason local progress would be harmed by doing so.
- Gemini review cadence: before substantial commits, launch or refresh at least one focused Gemini review/audit for the changed files and one adjacent-risk audit when the surrounding system is nontrivial. These reviews still use `timeout_seconds >= 3600`, `wait: false`, and nonblocking result collection; "quick review" is not an excuse for shorter timeouts or synchronous waiting. Prefer starting these reviews early enough that they run in parallel with local checks instead of blocking the commit path.
- Gemini small-job rule: small scoped jobs are preferred, but they are never short-timeout jobs. Every small audit, naming pass, fallback hunt, test-gap check, and diff review gets the same explicit one-hour-or-more timeout budget and runs asynchronously while local work continues.
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
