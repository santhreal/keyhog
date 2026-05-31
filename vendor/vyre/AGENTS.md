## VYRE Agent Rules

- No subagents or external agent workers are used in this repo. Codex handles implementation, audits, tests, and fixes in the main workflow.
- Read files before edits. Do not code from guesses.
- Keep work on `main`; use other branches only when a separate request explicitly requires it.
- Prefer existing patterns, structured APIs, and existing tests; avoid introducing unnecessary overrides/config flags when a detector or policy rule can carry the behavior.
- New tests belong in crate `tests/` directories unless an existing inline test must change to match a changed contract.
- Assume a GPU exists (`RTX 5090/4090` family and others are in-scope targets). `KEYHOG_REQUIRE_GPU=1` or equivalent feature flags are configuration failures, not silent success paths.
- Paths and workflow context to keep fixed:
  - Desktop Linux workspace: `/media/mukund-thiru/SanthData/Santh`
  - Windows ThinkPad share mount: `Z:\` (same NFS content)
  - Cargo target directory convention:
    - Desktop: `/mnt/FlareTraining/santh-archive/cargo-target`
    - ThinkPad: `C:\\cargo-target`
- No `git revert`, destructive `git reset`, destructive `git checkout`, or stash-drop without explicit user direction.
- Preserve dirty trees unless explicitly asked to clean; treat existing in-progress changes as active state unless the user directs otherwise.
