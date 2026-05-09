# Vyre primitive usage — audit & roadmap

Status snapshot of which vyre-libs primitives keyhog currently consumes,
what's available but unused, and a prioritised list of wires worth
making next. Updated 2026-05-08, against vendored vyre v0.6.0.

## What keyhog uses today

`keyhog-scanner` directly consumes:

| Vyre symbol                                          | Where keyhog uses it                                   |
| ---------------------------------------------------- | ------------------------------------------------------ |
| `vyre_libs::matching::GpuLiteralSet`                 | `engine/scan_gpu.rs::scan_coalesced_gpu` — primary GPU path |
| `vyre_libs::matching::RulePipeline`                  | `engine/scan_gpu.rs::scan_coalesced_megascan` — regex-NFA GPU path |
| `vyre_libs::matching::build_rule_pipeline_from_regex`| `engine/mod.rs::build_rule_pipeline` — MegaScan compile |
| `vyre_libs::matching::LiteralMatch`                  | Re-exported as `keyhog_scanner::LiteralMatch` for API stability |
| `vyre_libs::matching::dedup_regions_inplace`         | Per-pid match deduplication after both GPU dispatches  |
| `vyre_libs::matching::RegionTriple`                  | Same — input shape for the dedup primitive             |
| `vyre_libs::matching::cached_load_or_compile`        | On-disk cache for compiled GPU literal-set + rule pipelines |
| `vyre_driver_wgpu::WgpuBackend`                      | Persistent wgpu device handle held by `CompiledScanner` |
| `vyre_driver_wgpu::runtime::cached_device`           | Aliveness check before each GPU dispatch                |
| `vyre_libs::matching::nfa` (via RulePipeline)        | Indirectly — consumed by `build_rule_pipeline_from_regex` |

That's the entirety of vyre touch surface. Three files
(`engine/scan_gpu.rs`, `engine/mod.rs`, `engine/backend.rs`) hold every
consumer.

## What's available but unused

`vendor/vyre/vyre-libs/src/` exposes 16 top-level modules. Of those,
`matching` is the only one keyhog touches. The rest:

### High-leverage candidates (matching keyhog's existing concerns)

| Vyre module                         | What it offers                                | What keyhog has today                                | Why it could win                                              |
| ----------------------------------- | --------------------------------------------- | ---------------------------------------------------- | ------------------------------------------------------------- |
| `matching::cooperative_dfa`         | DFA scan kernel                               | Hyperscan + AC + GpuLiteralSet                       | DFA may beat NFA on dense literal sets — needs benchmark      |
| `matching::substring`               | substring search primitive                    | `aho_corasick` + custom `bigram_bloom`               | One unified GPU-aware path instead of two CPU paths           |
| `matching::classic_ac`              | Aho-Corasick on the vyre runtime              | `aho_corasick` crate (CPU only)                      | Same algorithm, but composable with vyre's GPU dispatches     |
| `decode::base64`, `decode::hex`     | byte-stream decoders                          | `crates/scanner/src/decode/{base64,hex}.rs` (CPU)    | Vyre version is GPU-aware via shared dispatch infra           |
| `decode::inflate`, `decode::ziftsieve` | DEFLATE + zstd over GPU buffers            | `ziftsieve` crate, called CPU-side                   | Decode-and-scan in one GPU dispatch on big compressed blobs   |
| `intern::perfect_hash`              | perfect-hash string interner                  | hand-rolled `ScanState::intern_credential` (`Arc<str>` HashMap) | Lookup is `O(1)` no-collision; lower memory on the 888-detector corpus |
| `hash::fnv1a32`, `hash::fnv1a64`    | GPU-IR FNV builders                           | thread-local FNV cache in `entropy_fast.rs` (CPU)    | Could feed into a GPU entropy-first prefilter pass            |
| `hash::blake3_compress`             | GPU-IR BLAKE3                                 | `blake3` crate (CPU) for merkle index                | Merkle index recompute on big repo could move to GPU          |
| `hash::crc32`                       | GPU CRC32                                     | per-detector custom checksums (`scanner/src/checksum/`) | Some checksum validators could share one CRC32 dispatch       |
| `nn::moe`, `nn::linear`, `nn::activation`, `nn::attention`, `nn::norm` | NN building blocks for compute shaders | Hand-rolled GPU MoE in `gpu.rs` + CPU MoE in `ml_scorer.rs` | Replace ~600 lines of bespoke MoE compute shader with composed primitives |
| `rule`                              | predicate engine (file_size_*, pattern_count_*, pattern_exists, literal_true/false) | Inline allowlist + suppression in `cli/src/inline_suppression.rs`, `cli/src/orchestrator.rs::filter_and_resolve` | Declarative filter rules + future user-defined gates          |
| `text::char_class`                  | byte-class predicates                         | `crates/scanner/src/alphabet_filter.rs`              | Centralised, GPU-shareable                                    |

### Lower-leverage / specialised

| Vyre module          | What it offers                          | Relevance to keyhog                                    |
| -------------------- | --------------------------------------- | ------------------------------------------------------ |
| `math::*`            | numeric kernels (broadcast, linalg, scan, succinct) | Useful only when more compute moves to GPU |
| `logical::*`         | and/or/xor/nand/nor over bitmaps        | Could compose post-process bitmap ops                   |
| `parsing::*`         | parser combinators on GPU               | Nothing in scanner needs this today                     |
| `security::*`        | static-analysis predicates (auth_check_dominates, bounded_by_comparison) | Different problem domain — not secret scanning |
| `graph::*`           | graph algorithms (reachability, dominators) | Nothing in scanner needs this today                  |
| `dataflow::*`        | taint-flow                              | Future "track this credential through this codebase" feature |
| `representation::*`  | IR helpers                              | Internal building blocks, not consumer-facing           |
| `compiler::*`        | program compiler                        | Used implicitly by every dispatch                       |
| `visual::*`          | viz helpers                             | Diagnostics only                                        |
| `signatures`, `contracts`, `tensor_ref`, `descriptor`, `harness`, `builder`, `buffer_names`, `range_ordering`, `region`, `test_migration` | API hygiene + plumbing | Indirectly used by everything above |

## Concrete next-wires (priority order)

Each of these is a self-contained scope of work whose payoff and risk
are estimable. Listed best-bang-for-buck first.

1. **`intern::perfect_hash` for credential interning.**
   The current `ScanState` builds an `Arc<str>` table per scan. Vyre's
   `perfect_hash` builds a static lookup at scanner-construction time
   for the detector ID / name / service strings (which are stable
   across the run). Wins: lower per-finding clone cost, lower steady-
   state memory. Risk: low — the existing API contract stays the same.
   Effort: ~half a day.

2. **`text::char_class` powering `alphabet_filter.rs`.**
   Both keyhog and vyre maintain their own byte-class predicates for
   the same patterns (alphanumeric, base64 alphabet, hex alphabet). One
   source of truth + the option to dispatch the alphabet check on GPU
   when running a coalesced batch. Risk: low — just an internal swap.

3. **`hash::fnv1a32` cache key for the entropy thread-local.**
   `entropy_fast.rs` carries a hand-rolled `fnv` table. Switching to
   vyre's primitive lets the same hash function feed both the CPU
   entropy fast-path AND any future GPU entropy prefilter pass.
   Risk: low.

4. **`matching::substring` instead of `aho_corasick` for the keyword
   pre-filter.**
   The fallback path in `pipeline.rs::has_secret_keyword_fast` and
   `has_generic_assignment_keyword` builds an AC matcher per scanner.
   Vyre's substring primitive is composable with the GPU dispatch and
   keeps everything on one engine. Needs a benchmark to confirm vyre
   matches the AC throughput on the typical 30-keyword set.

5. **`nn::moe` + `nn::linear` replacing `gpu.rs`'s hand-rolled MoE.**
   `gpu.rs` is ~620 lines of bespoke wgpu+WGSL for an MoE confidence
   scorer. Vyre's `nn::moe` is the same algorithm composed from
   `nn::linear` + `nn::activation` + `nn::norm`. Wins: ~600 lines
   deleted, automatic benefit from vyre kernel improvements, identical
   compute semantics. Risk: medium — would need parity tests against
   the current ML scorer outputs to confirm bit-equivalent results.
   Effort: ~3 days plus correctness validation.

6. **`rule` engine for inline-suppression / allowlist.**
   The current allowlist is hand-rolled string matching. Vyre's `rule`
   exposes typed predicates (`file_size_gt`, `pattern_count_gte`,
   `pattern_exists`, …) that compose into declarative rule trees.
   Wins: user-defined rules become trivial; a `.keyhogignore.toml`
   could express "suppress this finding when file_size > 10KiB AND
   pattern_count(test_keywords) >= 2" without code changes.

7. **`decode::inflate` + `decode::ziftsieve` GPU decode-then-scan.**
   The current path reads the compressed bytes, calls `ziftsieve` on
   the CPU to decompress, then hands the plaintext to `scan_coalesced`.
   Vyre's GPU decoders let us pipeline decompression and matching in
   the same dispatch. Big payoff on `.zst`-heavy corpora (npm, Docker
   image layers); meaningless on regular source trees. Effort: high.

## What blocks "max usage" right now

- **vyre's regex frontend `STATE_CAP = LANES × 32 = 1024` states.**
  The full 888-detector corpus compiles to an NFA larger than that
  (ballpark 25k states), so MegaScan currently auto-degrades to the
  literal-set path on the production corpus. Lifted upstream when
  vyre adds either (a) per-subgroup state batching or (b) a
  multi-pipeline dispatch that splits the regex set across multiple
  RulePipelines. keyhog can do (b) on its own side as a follow-up
  (compile detectors in groups, dispatch each group, merge triggers).

- **vyre's regex frontend MAX_REP cap.** The vendored v0.6.0 caps
  bounded repetitions at `{0,64}` / `{,64}`; upstream HEAD has this
  removed (the state-cap is the source of truth). A re-vendor against
  HEAD picks it up but currently breaks dep-version pinning across
  the workspace (rayon `=1.11` vs `=1.12`, smallvec `=1.14` vs `^1.15.1`,
  …). The vyre-side fix lands when an upstream tag releases with
  pin-relaxed dependency declarations.

- **Vyre is not on crates.io.** All path-deps in `vendor/vyre/`. This
  blocks `cargo publish` of `keyhog-scanner` and `keyhog` (the binary
  crate). Resolved when vyre publishes its workspace to crates.io.
