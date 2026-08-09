# keyhog-scanner SPEC

`keyhog-scanner` compiles detector specifications into executable matchers and scans text chunks for credential candidates. It combines literal prefiltering, regex fallback, entropy scoring, decode-through scanning, context scoring, and optional acceleration features.

## Guarantees

- Scanner input is bounded by configured chunk, decode, and match limits.
- Decode-through scanning tracks seen decoded payloads to prevent repeated expansion.
- Findings preserve detector identity, source location, severity, confidence, and credential hash.
- Optional acceleration backends must preserve the same match semantics as the default scanner path.

## Boundaries

This crate consumes `keyhog-core` types and does not enumerate files, git history, cloud sources, or verify live credentials.

## Accepted residuals (perf-3 / phase-2 hotpath)

Warm-daemon competitive bars (`one_long_line` ≤0.50, `one_large` ≤3.5, `many_small` ≤4.0 CPU-s) require an order-independent unique-line vocabulary fingerprint so overlapping windows of repetitive corpora can share empty-decode / clean proofs. An ordered or multiplicity-sensitive fingerprint misses those hits and regresses `one_large` past the bar (~5.94 CPU-s observed).

| Item | Severity | Decision | Mitigations |
| --- | --- | --- | --- |
| Vocab fingerprint ignores line order / multiplicity | YELLOW (Devin) | **Accepted residual** — keep unique-line fingerprint | Path-scoped keys (`vocab_path_class`); memo lookup/mark only for parent `filesystem/windowed` slices; no autoroute short-circuit on these proofs; detector + entropy-config digests in the key; capacity drops new keys instead of clearing unrelated stage proofs |

Do **not** "fix" this YELLOW by switching to ordered/multiplicity fingerprints: that trade loses the `one_large` residual win. Keep the mitigations above; treat the YELLOW as documented residual.

