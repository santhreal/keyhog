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

## Scanner hard rules

- No credential values in logs.
- No destructive Git commands without explicit user approval.
- Preserve public APIs by migration, not by silent behavior drift.
- Update project changelog for user-visible scanner behavior and test surface changes.
- Prefer verification through real scanner workflow (`scan -> detect -> suppress -> confidence`) over isolated unit-only assertions.
