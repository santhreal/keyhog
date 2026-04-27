# UX Sweep — confusing surfaces and how they were fixed

Closes #45 D.2 (confusing-to-user sweep).

This doc is a running log of UX footguns surfaced in audits, with
the concrete fix that shipped. Each entry is one grep-target for
"why did we change this" archaeology.

## Landed

| Area | Symptom | Fix shipped | Commit / audit |
|---|---|---|---|
| `BufferDecl::with_count(0)` | Silent accept of zero-count buffers, exploded at dispatch. | Panic at construction with a Fix: hint naming the positive-count or drop-the-call option. | FIX-REVIEW Finding #3 |
| `BufferDecl::workgroup(count=0)` | Same bug, different door. | Same rejection mirrored in the workgroup constructor. | THIRD-PASS Finding 08 |
| `fuse_programs([1,1,1])` workgroup | Silently collapsed any per-program workgroup size to 1×1×1. | Derive workgroup axis-wise max of the input programs. | FIX-REVIEW Finding #16 |
| `Expr::Cast` on `U64` | Generic "unsupported type" error. | Named error pointing at the missing vec2 emulation pass. | NAGA_DEEPER F53 |
| `emit_binop` on `U64` | **Silently wrong arithmetic** (no carry between words). | Reject with a Fix: naming the missing emulation pass; bitwise/equality remain allowed since those are componentwise-correct. | NAGA_DEEPER F59 |
| `emit_bool_from_handle` on `F32` | Callers had to manually insert `!= 0.0` comparison. | Accept F32 directly via the WGSL `f32 != 0.0` form. | NAGA_DEEPER F54 |
| `plan().to_wire()` | Emitted wire bytes for programs that hadn't been validated. | `plan()` calls `validate()` before `to_wire()`. | FIX-REVIEW Finding #17 |
| `dialect_lookup` conflicting-id install | Silent drop of the new provider; first-installed kept. | Panic with `Fix:` hint; reinstall with matching id is idempotent. | F-IR-33 / FIX-REVIEW #19 |
| `canonicalize` vs `to_wire` fingerprint | Programs differing only in buffer declaration order hashed to different fingerprints, fragmenting the pipeline cache. | Sort buffers by (binding, name) before `to_wire` in `canonical_wire`. | RUNTIME Finding 1 |
| `Diagnostic::to_json` | Unwrap would panic an LSP/CI annotator on a future non-serializable field. | Hand-rolled fallback JSON envelope naming the regression; callers always get valid JSON. | DRIVER Finding 1.1 |
| Surgec `scan` eprintln flood | A hostile target could flood stderr or block on a slow pipe. | Rate-limited `scan::diagnostics::skip_note` with per-category burst + summary stride. | THIRD-PASS Finding 05 |
| Surgec empty-fixture acceptance | Op with `test_inputs() -> vec![]` got a passing certificate with zero coverage. | Reject up front with "empty witness fixture" error. | CONFORM H4 |
| Surgec dup-named witnesses | Corpus hash collided but downstream indexes silently overwrote. | Sort + dup-check in `canonicalise_corpus`; new `DuplicateWitnessName` error. | CONFORM H5 |
| Surgec unauthenticated cert | Hash-chain verified but Ed25519 signature was never checked. | `verify_cert_signature_hex` helper; `#[must_use]` on return forces callers to inspect. | CONFORM C1 |
| `BackendFingerprint` delimiter injection | `\0` in backend/adapter fields let a hostile caller collide with a different config. | Length-prefixed canonical encoding; v2 domain tag distinguishes from legacy v1. | CONFORM M3 |
| `pocgen` exploit payloads | Unconditionally compiled into every downstream build (Soleno, Karyx) even when the consumer wanted only safe PoC rendering. | `dangerous-exploits` feature gate; disabled by default. | POCGEN Finding 1.1 |
| `pocgen` ExtractedPath template | Unescaped substitution let attacker-controlled values escape the URL path. | URL-encode the substituted value + origin-equality gate after `base.join`. | POCGEN Finding 2.1 |
| `polyglot` TOML binary signatures | `pattern = "PNG..."` silently UTF-8-encoded `` → `[0xC2, 0x89]` and broke every non-ASCII signature. | `pattern` now `Vec<u8>` with a custom visitor accepting `[0x89, 0x50, ...]` arrays. | POLYGLOT Finding 1 |
| `jsir` deep-nesting crash | `(((((1)))))` 100k deep blew the Rust stack. | Depth-capped visitor with sticky `depth_exceeded` flag. | JSIR Finding 1 |

## Open (tracked, not yet landed)

| Area | Symptom | Planned fix | Task |
|---|---|---|---|
| Tier-3 dialect imports | `vyre-libs::security::topology::match_order` pulled the security dialect into every non-security surgec compile. | Hoist to `vyre-libs::range_ordering` (done) + `check_4_cross_dialect_reachthrough` (done) + deprecate the security re-export (done). Full sweep is migrating every internal caller. | VISION V5 |
| `Match` vs `ByteRange` | Foundation-tier `Match.pattern_id` implies matching-dialect context. | `vyre_primitives::range::ByteRange` shipped; `vyre::ByteRange` re-export shipped; full Match deprecation after every caller migrates. | VISION V1 |

## Operating rule

Every session with user-facing-tool work runs `cargo xtask
list-ops` + reads BENCHMARK.md + rules out a new UX sweep target.
Confusing surfaces are first-class findings in the audit loop; they
don't need a separate "UX" audit to land.
