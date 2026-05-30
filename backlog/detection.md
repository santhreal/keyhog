# Detection backlog

Accuracy is measured ONLY by the SecretBench mirror scorer
(`tools/secretbench/scoring/score.py`), never by `cargo test`. These items are
flaws in the detection/scoring pipeline surfaced by the bench, with the data
that proves them.

## Bench provenance (2026-05-30)
- Pre-closure binary (`keyhog-rebuilt-2b1d02b8`): F1=0.8919, P=0.986, R=0.814, TP=2443, FP=35, FN=557.
- Post-closure binary (`keyhog-closure-2b1d02b8`): F1=0.8453, P=0.923, R=0.779, TP=2338, FP=194, FN=662.
- Config grid-sweep on the post-closure binary (runtime flags, no rebuild):

  | min_confidence | decode | F1 | P | R | FP | FN |
  |---|---|---|---|---|---|---|
  | 0.30 | shallow 4/64KB | 0.8524 | 0.932 | 0.786 | 173 | 643 |
  | 0.40 | shallow 4/64KB | 0.8632 | 0.984 | 0.769 | 37 | 694 |
  | 0.50 | shallow 4/64KB | 0.7985 | 0.878 | 0.732 | 306 | 803 |
  | 0.30 | deep 10/512KB | 0.8544 | 0.932 | 0.789 | 174 | 633 |
  | **0.40** | **deep 10/512KB** | **0.8642** | **0.984** | 0.770 | **37** | 689 |
  | 0.50 | deep 10/512KB | 0.8452 | 0.984 | 0.741 | 37 | 777 |

- PINNED canonical profile (this change): `min_confidence=0.40`, `decode_depth=10`,
  `decode_size_limit=512KB`, `ml_weight=0.5`.
- **CORRECTION (verified on the fresh baked binary, no flags = the scorer's path):**
  the grid-sweep above was run with `--min-confidence`/`--decode-*` FLAGS, which
  resolve through a DIFFERENT path than the baked defaults. The scorer runs
  `keyhog scan` with NO flags. Re-benched the fresh binary both ways:
  - BAKED (no flags, scorer path): F1=**0.8455** P=0.982 R=0.742 (TP=2227 FP=41 FN=773).
  - FLAG (`--min-confidence 0.40 --decode-depth 10 --decode-size-limit 512KB`,
    identical values): F1=0.8035 P=0.877 R=0.741 (TP=2224 **FP=312** FN=776).
  So the sweep's 0.8642 was a FLAG-PATH artifact that does NOT ship. The real
  benched/shipped F1 with the 0.40 pin is **~0.845** - flat vs the closure 0.8453,
  but precision much improved (FP 194→~45). Recall (FN ~770) is the gap to 0.8919.
  LESSON: bench exactly how the scorer invokes the binary (no flags); flag-path
  tuning is meaningless for the shipped product until DET-10 is fixed.

## New bugs found while verifying the pin

- **DET-10 · HIGH · flag path ≠ baked path for IDENTICAL config values** — passing
  `--min-confidence 0.40 --decode-depth 10 --decode-size-limit 512KB` (the same
  values baked into `ScanConfig::default()`) yields FP=312, but NOT passing them
  (baked defaults) yields FP=41 - same binary, same nominal config, 270-FP gap.
  `build_scanner_config` produces an identical `ScannerConfig` for both, and the
  postprocess floor reads `args.min_confidence.unwrap_or(default)` = 0.40 either
  way. ISOLATED (2026-05-30): the culprit is the `--decode-*` flags, NOT
  `--min-confidence` (mc-only flag → FP=39 ≈ baked 41; decode-only flag → FP=313).
  Yet the resolved values are PROVABLY identical: depth 10 == 10 (sanitise only
  clamps >32), and `parse_byte_size("512KB")` = 512*1024 = 524288 == the baked
  `ScanConfig::default().max_decode_bytes`. So passing `--decode-*` has a side
  effect BEYOND its values. Two suspects found, neither fully explains it yet:
  (1) `orchestrator/mod.rs:132` caps `max_decode_bytes` to 256KB but only when
  `total_memory_mb < 4096` (not flag-gated; same on the 32GB bench box);
  (2) `orchestrator/mod.rs:137` calls `CompiledScanner::compile(detectors)` which
  uses `ScannerConfig::DEFAULT`, not the `scanner_config` built at line 126 -
  i.e. there are multiple config-application paths (the config sprawl). The real
  fix is to collapse to ONE applied config and make the `--decode-*` flag path
  and the baked path resolve through it identically. Until then, flag-path tuning
  is meaningless for the shipped product.

- **DET-12 · MED · the coherence oracle is dead code** — `render_effective_config`
  / `print_effective_config_if_requested` (orchestrator_config.rs:434) exist and
  the doc calls them "the coherence oracle... assert tuned == benched == shipped",
  but `print_effective_config_if_requested` is NEVER CALLED in the scan flow (no
  caller). The env var `KEYHOG_PRINT_EFFECTIVE_CONFIG=1` does nothing. Wire it in
  and add a dogfood test that diffs baked vs flag effective-config (would have
  caught DET-10). Also the doc references a `--print-effective-config` FLAG that
  does not exist (only the env var).

- **DET-13 · MED · low-RAM decode cap diverges from canonical** — `mod.rs:132`
  silently caps `max_decode_bytes` to 256KB when `total_memory_mb < 4096`, so the
  effective decode window on small machines (256KB) != the canonical/documented
  512KB. Either document the cap as a tier or fold it into a single resolved
  config that the effective-config oracle prints.

- **DET-11 · MED · detection is slightly non-deterministic** — two identical
  no-flag bench runs on the same binary: FP 41 vs 51, TP 2227 vs 2232, F1 0.8455
  vs 0.8450 (~±10 FP, ±0.0005 F1). Small, but a scanner should be deterministic.
  Likely parallel-chunk / dedup iteration order or a GPU race on borderline
  confidences. Make the finding set order-independent (sort before dedup floor).

## Open

- **DET-08 · HIGH · min_confidence is non-monotonic in FP** — raising the floor
  must monotonically reduce findings (FP can only fall). Measured FP went
  173 → 37 → 306 as the floor rose 0.30 → 0.40 → 0.50 (shallow); and 0.50-shallow
  (FP 306) vs 0.50-deep (FP 37) differ 8x. A clean post-filter cannot do this, so
  `min_confidence` is entangled in the scan-time generic gate
  (`engine/fallback_generic.rs`: `confidence < self.config.min_confidence`)
  and/or the ML confidence computation, NOT just the post-scan gate
  (`orchestrator/postprocess.rs:161`). Raising the scan-time floor likely drops
  candidates BEFORE a dedup/suppression step that keyed off them, paradoxically
  releasing more FPs. Fix: make the floor a single, orthogonal post-scan cutoff
  (or prove the scan-time gate is monotonic). Until fixed, 0.40 is a tuned
  sweet-spot, not a principled value. This is the highest-leverage coherence bug
  in the scoring path.

- **DET-09 · HIGH · closure-round recall regression (~132 FN)** — at MATCHED
  config (mc0.30, shallow ≈ pre-closure), the post-closure binary scores
  FN=643 / FP=173 vs pre-closure FN=557 / FP=35. Best achievable post-closure
  config (0.8642) is still below pre-closure 0.8919. So ~86-132 true positives
  were lost to closure-round CODE changes (detection logic), independent of the
  config floor, plus a precision regression (FP 35→37+ floor, but 173 at mc0.30).
  Bisect the 79-file closure round for the detection-logic edits that dropped
  TPs in: cloud-service-credential (-49), database-connection-string (-37),
  api-key (-11), webhook-url-token (-14). These are the categories whose findings
  the closure round demoted/dropped.

- **DET-01 · DONE · discord-bot-token dead detector** — TOML parse error at
  line 34 (single-quote in a single-quoted literal) dropped the detector silently
  (890/891 loaded). Fixed to a triple-quoted literal. Needs the rebuild to embed.
  → also testing T-04 / MC-16 (load-integrity must be a pre-push blocker).
