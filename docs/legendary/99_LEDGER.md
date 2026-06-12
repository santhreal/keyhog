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
