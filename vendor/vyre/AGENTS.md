## VYRE Agent Rules

- Do not use native Codex subagents for test generation, test-only patches, or audits.
- Use `codex-agents` workers such as Kimi/Cursor/Gemini for test fanout and critique.
- Native Codex subagents are reserved for bounded implementation work with disjoint file ownership.
- New tests belong in crate `tests/` directories unless an existing inline test must be updated to match a changed contract.
- Assume a GPU exists. Probe failures are configuration failures and must be reported loudly, not silently skipped.
