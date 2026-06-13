# keyhog backlog

Living backlog of flaws and improvements found by dogfooding the real tool and
auditing the codebase. The workflow takes these on; entries stay until closed.

> **Two planning trees, different jobs** (see [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)):
> this `backlog/` is the **flaw tracker** — concrete defects with `file:line`
> evidence and a fix recipe, grouped by theme. [`docs/legendary/`](../docs/legendary/)
> is the **structured perfection plan + execution ledger**;
> `docs/legendary/99_LEDGER.md` is the authoritative record of what has *landed*.
> File a found defect here; track planned/landed work there.

Each entry: `ID · severity · location · problem · fix`. Severity:
`crit` (data loss / security / wrong result), `high`, `med`, `low`.

## Files
- [`macro-coherence.md`](macro-coherence.md) — architecture-level coherence (configs, flag conventions, crate boundaries, dual sources of truth). **Primary focus — under-addressed by the May-30 audit.**
- [`cli-surface-bloat.md`](cli-surface-bloat.md) — 18 subcommands, 68 `scan` flags: overlap, redundancy, inconsistency.
- [`dogfood-realtool.md`](dogfood-realtool.md) — concrete issues found by running the built binary across its surfaces (NOT detection accuracy).
- [`detection.md`](detection.md) — scoring-pipeline flaws surfaced by the bench (non-monotonic floor, closure-round recall regression), with the proving data. Accuracy is measured ONLY by the SecretBench scorer.
- [`testing.md`](testing.md) — real-tool/integration test expansion + purging detection-decoration from `cargo test`.

## Status snapshot (2026-05-30, post config-pin)
- Config debloat unified the floor/decode/ml-weight defaults to ONE tuned profile across `ScanConfig` + `ScannerConfig` + CLI help + `.keyhog.toml.example`. Pinned: `min_confidence=0.40`, `decode_depth=10`, `decode_size_limit=512KB`, `ml_weight=0.5` (grid-sweep optimum, F1=0.8642).
- The pre→post-closure delta (0.8919→0.8453) was ~40% config (recovered by the pin) and ~60% a closure-round detection-logic regression (DET-09, ~132 lost TPs, open).
- `min_confidence` is non-monotonic in precision (DET-08) — the floor's biggest coherence bug; 0.40 is a tuned sweet-spot pending the real fix.
- The earlier "F1=0.80" scare was a stale-binary artifact — see macro-coherence MC-06 (no build provenance stamp).
