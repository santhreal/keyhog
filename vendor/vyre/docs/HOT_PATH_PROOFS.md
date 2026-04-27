# Hot-Path O(1) Proofs

Closes #27 A.3 hot-path O(1) proofs.

Every dispatch-time path that a scanner user hits millions of times
per second is annotated with a complexity contract + an asymptotic
proof. The proof is either:

1. An inline doc comment showing the loop bounds reduce to a
   constant given buffer sizes fixed at program-build time, or
2. A linked benchmark cell in `surgec/benches/` showing the
   measured operation is flat across a 1000× input-size sweep.

## The hot paths

| Surface | Claim | Proof |
|---|---|---|
| `PipelineFingerprint::of` | O(size of canonical wire) = O(program nodes). Program nodes are bounded by the compile budget (≤ 200 top-level nodes per op × op count), so on dispatch this is constant. | `canonical_wire` in pipeline_cache.rs: single to_wire + single blake3 over the result. |
| `InMemoryPipelineCache::get_arc` | O(1) amortised. Single HashMap lookup + Arc::clone (refcount bump). | Inspect: single `self.inner.lock().get().cloned()`. Lock contention tracked under RUNTIME Finding 5 (RwLock migration). |
| `WgpuBackend::dispatch` amortised | O(input bytes) for readback + O(1) + O(program nodes) for command build. Program node count bounded. | `megakernel_emit.rs` + `run_arbitrary.rs` both exercise the path; criterion cell locks steady-state wall time per byte. |
| `scan::diagnostics::skip_note` | O(1) per call. Atomic increment + one `eprintln` inside the burst window or a single stride comparison after. | Source inspection + `multithreaded_flood_is_safe` test shows 8 × 5000 = 40k calls complete under 5 seconds on the test host. |
| `Collector::scan_gpu_with_context` per file | O(file bytes) for scan + O(layers) for decode. Bounded by `MAX_FILE_BYTES = 128 MiB` and `MAX_SCAN_FILES = 1_000_000` (THIRD-PASS 03/04). | Constants land in `collector.rs`; tests exercise the cap paths. |
| `DialectLookup::lookup` | O(1). Hash-table lookup keyed by interned op id. | `dialect_lookup::intern_op` documents the interning + the frozen-index sub-ns reads. |
| `BufferDecl::with_count`, `::workgroup` | O(1). Single panic-guard + struct move. | Source + compile-time `const fn` where possible. |
| `ByteRange::{len, is_empty, contains, ends_before}` | O(1), `const fn`. | Source + layout-lock test pinning `size_of == 12`. |
| `Expr::u32`, `Expr::load`, `Expr::mul`, …constructors | O(1). Single small-vec allocation per expression frame. | Source; smallvec crate pinned in workspace. |

## How the proofs stay honest

- Every claim above is accompanied by either an inline doc comment
  on the function or a criterion cell whose wall time is flat
  across a 1000× size sweep. Changing the function body so the
  complexity grows breaks the benchmark cell and blocks merge.
- `cargo xtask bench-crossback` (existing xtask) runs a fixed-input
  regression on every release candidate to detect latent O(n²)
  regressions in the hot paths above.

## Anti-patterns explicitly hunted

- `Vec::contains` inside a hot loop (→ HashSet).
- `String::push_str` in a match-emit fast path (→ `write!`).
- `.clone()` + `.to_string()` chaining (→ Arc + Cow).
- Per-record mutex acquire (→ ThreadLocal or RwLock).

Each pattern is documented in CRITIQUE audits when found and
tracked in `docs/INNOVATION_SWEEP.md` for optimisation follow-ups.
