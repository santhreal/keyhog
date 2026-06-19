# Keyhog AGENTS

## Execution Rules (local)

- Work on `main` unless the user explicitly asks for another branch.
- Read the code before edits. Don’t invent behavior from memory.
- Keep changes scoped; do not revert unrelated local edits.
- Never use subagents, local workers, or “parallel assistant” workflows in this repo. One Codex thread owns implementation, audit, verification, and documentation.
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
