# Gemini ugliness sweep — triage

Eight Gemini-3.5-Flash audits (dispatch, scanner/engine, decode/structured,
sources/filesystem, confidence/adjudicate/suppression, orchestrator,
daemon, install.sh) surfaced ~240 raw findings. Gemini output is **untrusted**;
every item below is judged against this repo's actual contracts before action.

## Triage policy (why most "silent fallback" flags are NOT actionable)

- **Loud, recall-preserving fallbacks are ALLOWED** (Law 10): a `tracing::warn!`
  with a "recall preserved" annotation that keeps the strong path's recall is
  explicitly permitted. Gemini flagged ~60 of these as "silent" and asked for
  telemetry counters — that is gold-plating, not a Law-10 fix. Examples it
  mis-flagged: `phase2_anchor.rs` AC-build failures (warn + RegexSet path),
  `phase2_prefilter.rs` batch recompile (warn + ungated), `hot_patterns.rs`
  sieve unavailable (warn + standard scanner). These already warn loudly and
  preserve recall — no change.
- **`String::from_utf8(decoded).ok()` on decode candidates is by-design**, not
  recall loss: a base64/hex blob that does not decode to UTF-8 text is not a
  text credential the decode path would surface, and the ORIGINAL bytes are
  still scanned by the primary path. ~25 decode flags fall here — no change.
- **Single internal tuning scalars are not banned "hardcoded lists."** The
  Tier-B ban targets rule/wordlist/signature DATA, not a `const MIN_LEN: usize =
  6`. Gemini flagged ~90 such constants; moving them all to TOML widens scope
  and would violate the Screwdriver Principle. No change unless a constant is a
  real correctness/recall knob an operator must tune.
- **Deadline-expiry `return Vec::new()` is a typed coverage gap**, surfaced by
  the scan-metadata/coverage-gap panel (tasks #6/#7) and decode-truncation
  telemetry — not a silent drop. The engine reports "N findings" alongside the
  skip counts so it is never a false-clean.

## Genuine candidates — verified locally, all ALREADY ADDRESSED

The four items that survived the policy filter were read against the real code.
Every one turned out to be deliberate, documented, recall-preserving design —
prior hardening already covered them. The sweep found **no unaddressed genuine
Law-10 violation**.

1. **daemon `server.rs:122` `run`** — not a fallback; a thin `pub` wrapper that
   delegates to `run_with_backend_override(..., None)`. Marginal dead-wrapper at
   most, no recall/override semantics. Left as-is (removing a `pub` wrapper risks
   a test/library caller for zero correctness gain).
2. **`compiled_api.rs:350` SimdCpu→CpuFallback** — already carries an explicit
   Law-10 comment (lines 341-349): when the hw probe picks SimdCpu but THIS
   scanner built no Hyperscan prefilter (a no-anchorable-literal detector set),
   the AUTO path must resolve to a backend the scanner can run; the fail-closed
   abort is reserved for an EXPLICIT `--backend simd-regex`. Correct by design;
   a per-scan log here would be noise. No change.
3. **`fused.rs` `let _ = tx.send(...)` / `h.join()`** — all four sites already
   annotated `// LAW10: unused-binding marker; no runtime effect, not a
   fallback`. The sends/joins are shutdown-path bindings, not finding-dropping
   fallbacks. No change.
4. **`structured/parsers/yaml.rs:83` `let _ = structured_gap_is_real(...)`** —
   the helper's effect is the telemetry record; the boolean is advisory. Pure
   cosmetic; no recall/semantic loss. No change.

Outcome: the sweep's value was (a) CONFIRMING keyhog's fallback discipline is
already tight — loud, annotated, recall-preserving — and (b) this recorded
policy, so the 230+ allowed/by-design items are not re-flagged next sweep.

## Explicitly NOT actionable (recorded so they are not re-flagged)

- Every `tracing::warn!(... "recall preserved")` fallback in `engine/phase2*`,
  `engine/hot_patterns.rs`, `engine/scan_postprocess*`, `suppression/decode.rs`.
- Every `String::from_utf8(...).ok()` / `base64_decode(...).ok()` in `decode/*`.
- The `caesar.rs` source-code-path and credential-URL-line skips: documented FP
  controls, recall-by-design for those file/line classes.
- The `structured/mod.rs` `kind: Secret` / `docker-compose` substring gates:
  known fast-path format selectors with the generic scanner still running.
- All `const`-scalar "magic constant" flags that are internal tuning thresholds.

Net: the sweep's value is ~4 genuine items out of 240, plus a recorded policy
that prevents re-flagging the 230 allowed/by-design ones.
