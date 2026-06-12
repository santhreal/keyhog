# 99 — Execution ledger

One line per landed item. Append-only. Format:
`YYYY-MM-DD · KH-L-NNNN/KH-G-NNNNN · commit · axes-moved · proving-test`

Axes (Scale Law): detection · perf · test-depth · dogfood · org/dedup · architecture.
A landed item names ≥1 axis and points at the proving test/PoC. Coverage notes
(what was covered, what's still unreached) go here, never to chat. "Clean/done"
is never written — only specific proven outcomes.

## Plan authored
- 2026-06-11 · plan · (docs/legendary) · org/architecture · 273 KH-L lane items + 3866 KH-G materialized items = 4139 concrete; materializer `scripts/materialize-backlog.sh` regenerates `99_BACKLOG.tsv` from the live registries.

## Pre-plan landings this session (engine refactor lineage)
- 2026-06-11 · (TUI) · 3de7a467,00f65606 · dogfood/test-depth · idle TUI ~0% CPU + feed==reporter-dedup.
- 2026-06-11 · KH-L-(homoglyph) · b5526b71 · detection/perf/test-depth · overlapping-AC + ASCII-skip default ON; parity+shadow gates in CI; ~13% faster, +14 mailgun recovered.
- 2026-06-11 · (determinism) · 80602457 · test-depth/architecture · push_match eviction order-independence pinned (RawMatch::Ord totality) + core file wired into CI.
- 2026-06-11 · KH-L-(stale-gates) · 8db8b347,dcc60edf · org/test-depth/architecture · megakernel inline-test allowlist (+stale guard) + 9 GPU contract gates re-pointed to the consolidated dispatch; behaviors verified preserved, not relaxed.

## Backlog burndown
- KH-G todo: 3866 / done: 0  (run `scripts/legendary-status.sh` once built — KH-L-0030)

## Execution log (newest last)
<!-- append landings below -->
- 2026-06-11 · KH-L-0001 · (root-cause, no code) · architecture · **vyre 0.6.2 release block = no single version source.** `[workspace.package]` (vyre/Cargo.toml:65) sets edition+rust-version but NOT `version`; 28 vyre crate manifests carry literal `version = "0.6.1"` (only other fields inherit via `.workspace`), `[workspace.dependencies]` re-pins each vyre-* to `"0.6.1"` (Cargo.toml:186-192), and `release/release-train.toml` independently hardcodes `[versions]`, all RC/final `[tags]`, 10 `required_release_note_tokens`, and `package_verify_passed`. Cutting 0.6.2 = lockstep-editing 28 manifests + the deps block + release-train + readiness, with `check_crate_metadata_normalized.sh`/`check_release_ready.sh` failing on any miss. CAVEAT: the workspace is multi-product — weir/vyrec/vyrec_train are at 0.1.0/0.1.0-beta, so the fix must convert ONLY the 28 vyre-0.6.1 crates, never blanket-inherit. NEXT: KH-L-0002 = add `[workspace.package] version`, convert the 28 vyre crates to `version.workspace = true`, bump deps+release-train to 0.6.2, coordinate keyhog's path override `=0.6.1`→`=0.6.2` (stays uncommitted until publish), prove BOTH trees build. KH-L-0006 (cargo publish) stays gated (irreversible + standing rule).
- 2026-06-11 · KH-L-0001 (empirical proof) · (ran vyre `xtask version-matrix`) · architecture · CORRECTION: vyre already HAS full release machinery (`xtask version-matrix`/`release-train`/`release-gate`/`release-evidence`/conformance+signed certs); the block is NOT a missing tool. `check_crate_metadata_normalized.sh` deliberately omits `version` from the inherit set (multi-product: weir/vyrec at 0.1.0), so `version.workspace=true` is the WRONG fix. Running `version-matrix` surfaces the real first blocker: **`release/release-train.toml` fails the tooling's schema** — "missing field `required_release_note_tokens`" (it sits under `[tags]` but the release_train deserializer expects it at another level). So KH-L-0002 starts by reading `xtask/src/release_train.rs` (the expected struct), fixing release-train.toml's schema, then a lockstep `bump-vyre 0.6.2` (28 vyre crates + workspace.deps + tokens/tags, weir/vyrec untouched), re-run version-matrix to zero blockers, prove vyre+keyhog build with keyhog's override flipped `=0.6.1`→`=0.6.2` (uncommitted). Publish stays gated.
