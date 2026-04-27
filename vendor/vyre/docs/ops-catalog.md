# Ops catalog — V7 legendary surface (`vyre` 0.6)

**Status**: single source of truth for every op the Santh frontends
(surgec, vein, keyhog, gossan, karyx, sear, soleno) require
from vyre core.

**Categories**:

- **Cat-A** — pure composition of primitive ops + hardware intrinsics.
  CPU reference returns byte-identical bytes to GPU backend. No ULP
  tolerance; no "close enough".
- **Cat-B** — banned. No approximate / ULP-tolerant conform ever lives
  in core. A Cat-B-flavored op either moves to Cat-A (with a precise
  reference) or is rejected at review.
- **Cat-C** — hardware intrinsics. Each has a CPU reference that
  simulates the intrinsic's exact semantics. Byte-identity conform
  across every backend claiming support. Backends that do not claim
  support return `UnsupportedByBackend` — **never** fall back to slow
  CPU.

Every op ships as a single `inventory::submit!(OpEntry { … })`:

```rust
OpEntry {
    id: &'static str,                // "vyre-intrinsics::hardware::popcount_u32"
    category: Category,              // Category::A | Category::C
    build: fn() -> Program,
    cpu_ref: fn(&[Vec<u8>]) -> Vec<Vec<u8>>,
    test_inputs: fn() -> Vec<Vec<u8>>,
    witness_strategy: Option<fn() -> WitnessStrategy>,
    claimed_backends: &'static [&'static str],
    laws: &'static [AlgebraicLaw],
}
```

The universal harness at `vyre-libs/tests/universal_harness.rs` runs
`OpEntry × registered_backends()` matrix and asserts byte-identity
per cell.

---

## 1. Graph / AST / dataflow (surgec, vein)

| Op | Cat | Needed by | Laws | Status |
| --- | --- | --- | --- | --- |
| `ast_walk_preorder(ast_buf, out_buf, len) -> Program` | A | surgec, vein | ordering-stable, idempotent | **new** |
| `ast_walk_postorder(ast_buf, out_buf, len) -> Program` | A | surgec, vein | ordering-stable, idempotent | **new** |
| `subgraph_match(haystack_graph, pattern_graph, matches) -> Program` | A | surgec | idempotent | **new** |
| `dominator_tree(cfg_edges, cfg_nodes, idom_out) -> Program` | A | surgec, vein | deterministic | **new** |
| `reachability_bfs(edges, start, visited_out) -> Program` | A | surgec, vein | monotone-in-visited | **new** |
| `scc_tarjan(edges, scc_ids_out) -> Program` | A | surgec | deterministic | **new** |
| `topological_sort(edges, order_out) -> Program` | A | surgec | deterministic when acyclic | **new** |
| `cfg_build(ast, cfg_edges_out) -> Program` | A | surgec | deterministic | **new** |
| `ssa_rename(cfg, defs_out, uses_out) -> Program` | A | surgec, vein | idempotent | **new** |

**Lives at**: `vyre-libs/src/graph/`. Module name maps 1:1 to
op id (`vyre-libs::graph::ast_walk_preorder`). Edges encoded
as `(u32 src, u32 dst)` packed into a U32 buffer of length `2 * E`.

**CPU ref policy**: interpreter walks the graph serially and emits the
same u32 stream the GPU shader writes. For `ssa_rename` the reference
is `rustc_data_structures::graph::dominators` behaviour translated
into the vyre interpreter.

---

## 2. Security / taint (surgec → vyre-libs::security)

| Op | Cat | Currently stubbed as | Target |
| --- | --- | --- | --- |
| `flows_to(source, sink, taint_edges, result) -> Program` | A | inert no-op in `surgec/src/lower/stub_vyre_libs.rs` | **live** |
| `sanitized_by(edges, sanitizers, result) -> Program` | A | inert | **live** |
| `bounded_by_comparison(index, bound, comparisons, result) -> Program` | A | inert | **live** |
| `taint_flow(cfg, sources, sinks, flow_edges_out) -> Program` | A | inert | **live** |
| `label_by_family(edges, family_map, labels_out) -> Program` | A | inert | **live** |
| `path_reconstruct(flow_edges, target, path_out) -> Program` | A | inert | **live** |

**Lives at**: `vyre-libs/src/security/`. Composes the
graph ops above: `flows_to` is `reachability_bfs` over a taint-edge
subgraph; `sanitized_by` is `reachability_bfs` with node-filter mask;
`taint_flow` is `flows_to` × sources × sinks.

**Phase D** wires surgec to these directly, deleting
`surgec/src/lower/stub_vyre_libs.rs` in the same commit.

---

## 3. Byte and text scan primitives (surgec, keyhog)

DFA, literal search, and filter building blocks used *inside* full rule programs (decode, graph, heuristics, etc.) — not a description of the product.

| Op | Cat | Needed by | Laws |
| --- | --- | --- | --- |
| `multi_dfa_scan(haystack, dfa_table, first_match_out) -> Program` | A | surgec | deterministic, leftmost-first |
| `case_insensitive_dfa(haystack, dfa, matches) -> Program` | A | surgec | case-folding ASCII only |
| `regex_compile_to_dfa(pattern_src, dfa_out) -> Program` | A | keyhog, surgec | deterministic |
| `regex_match(haystack, compiled_dfa, spans_out) -> Program` | A | keyhog | deterministic |
| `bloom_probe(key, bitset, result) -> Program` | A | surgec | false-positive-only |
| `boyer_moore_scan(haystack, needle, bad_char, matches) -> Program` | A | surgec | deterministic, leftmost-first |

Already shipped (migrate from `vyre-libs/src/matching/` to
`vyre-libs/src/matching/`):

- `substring_search` — leftmost-first byte scan
- `aho_corasick` — multi-pattern first-match

Not yet composite-layer:

- `multi_dfa_scan` is Aho-Corasick but materialized as a bitset DFA
  table; `case_insensitive_dfa` folds ASCII before matching.

---

## 4. Crypto / hash (keyhog, gossan)

| Op | Cat | Needed by | Status |
| --- | --- | --- | --- |
| `fnv1a32` | A | keyhog | shipped in `vyre-libs/src/crypto/fnv/` — migrate |
| `fnv1a64` | A | keyhog | **new** (Cat-A) |
| `xxhash64` | A | gossan | **new** |
| `murmur3_32` | A | gossan | **new** |
| `crc32` | A | gossan | **new** |
| `adler32` | A | gossan | **new** |
| `siphash24` | A | keyhog | **new** |
| `blake3_compress` | A | keyhog | shipped in `vyre-libs/src/crypto/blake3/` — migrate |
| `shannon_entropy(buf, out) -> Program` | A | keyhog, sear | **new** |

**Lives at**: `vyre-libs/src/hash/`. Reference constants
hex-verified against RFC / upstream test vectors. For xxhash64 the CPU
ref mirrors `xxhash_rust::xxh64::xxh64`; for siphash24 we use the
`c-2-d-4` parameter set from the SipHash paper.

---

## 5. Encoding / decoding (keyhog, sear)

| Op | Cat | Needed by |
| --- | --- | --- |
| `base64_decode(src, dst) -> Program` | A | keyhog |
| `base64_encode(src, dst) -> Program` | A | keyhog |
| `hex_decode(src, dst) -> Program` | A | keyhog |
| `hex_encode(src, dst) -> Program` | A | keyhog |
| `utf8_validate(src, result) -> Program` | A | all |
| `url_canonicalize(src, dst) -> Program` | A | karyx, gossan |
| `line_column_index(src, offsets_out) -> Program` | A | surgec (diagnostics) |

**Lives at**: `vyre-libs/src/encoding/`. `utf8_validate`
bit-exact follows RFC 3629 (accepts only shortest form, rejects
surrogates). `url_canonicalize` follows RFC 3986 + WHATWG URL
percent-encoding.

---

## 6. Set / aggregate (surgec, soleno)

| Op | Cat | Notes |
| --- | --- | --- |
| `bitset_union(a, b, out)` | A | element-wise OR on u32 blocks |
| `bitset_intersect(a, b, out)` | A | element-wise AND |
| `bitset_difference(a, b, out)` | A | a AND NOT b |
| `hyperloglog_count(keys, register, out)` | A | precision 14 (2^14 registers) |
| `rolling_window_sum(series, window, out)` | A | O(n) prefix-sum rewrite |
| `exponential_moving_avg(series, alpha_q16, out)` | A | alpha as Q16.16 fixed-point for byte determinism |
| `interval_tree_query(tree, point, hit_out)` | A | pre-built augmented tree |

**Lives at**: `vyre-libs/src/aggregate/`.

---

## 7. Networking (gossan, karyx)

| Op | Cat | Notes |
| --- | --- | --- |
| `ipv4_parse(src, out)` | A | rejects `001.002.003.004` and leading zeros — WHATWG strict |
| `ipv6_parse(src, out)` | A | accepts `::` compression, IPv4-mapped forms |
| `domain_label_split(src, labels_out)` | A | IDNA-ready: splits at `.` only (no punycode decode) |
| `tls_cipher_fingerprint(client_hello, fp_out)` | A | JA3 over ClientHello fields |
| `http_header_match(headers, needle, result)` | A | case-insensitive header-name match |

**Lives at**: `vyre-libs/src/net/`.

---

## 8. ML primitives (migrate from `vyre-libs` to `vyre-libs/src/ml/`)

Already shipped, byte-identical CPU↔5090 per Phase F of this plan:

- `dot`, `matmul`, `matmul_tiled`
- `scan_prefix_sum`
- `broadcast`
- `relu`, `linear`
- `softmax`, `layer_norm`, `attention`

Added for completeness:

- `silu(buf, out)` — `x * sigmoid(x)`
- `gelu(buf, out)` — `0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715*x^3)))`
- `tanh(buf, out)` — hyperbolic tangent
- `sigmoid(buf, out)` — `1 / (1 + exp(-x))`
- `rmsnorm(buf, weight, eps, out)` — root-mean-square normalization
- `rope(buf, freq_base, out)` — rotary position embeddings
- `cross_entropy_loss(logits, labels, out)` — mean categorical
- `adam_update(params, grads, m_state, v_state, lr, beta1_q16, beta2_q16, eps_q16)` — fixed-point Adam step

**Determinism note**: every floating-point op in this section uses the
`f32::mul_add` CPU reference to avoid x87/FMA divergence; the WGSL
emitter always emits `fma(a, b, c)` so CPU and GPU produce identical
bits by construction.

---

## 9. Hardware intrinsics (Cat-C, `vyre-ops/src/hardware/`)

Each ships with:

1. `pub fn <name>(...) -> Program` — construction.
2. `inventory::submit!(OpEntry { category: Cat::C, ... })`.
3. CPU reference (runs in `vyre-reference`) that simulates the
   intrinsic's exact semantics.
4. WGSL lowering via `naga::Statement::*` (no string shaders).
5. SPIR-V lowering via `naga::back::spv` (same AST, different backend).
6. Photonic lowering returns `UnsupportedByBackend`.
7. Universal harness matrix runs CPU ref + wgpu + spirv and asserts
   byte-identity.

| Intrinsic | WGSL | SPIR-V | CPU ref |
| --- | --- | --- | --- |
| `subgroup_ballot` | `subgroupBallot` | `OpGroupNonUniformBallot` | popcount of per-lane bool |
| `subgroup_shuffle` | `subgroupShuffle` | `OpGroupNonUniformShuffle` | per-lane permutation |
| `subgroup_add` | `subgroupAdd` | `OpGroupNonUniformAdd` | per-lane sum |
| `subgroup_broadcast` | `subgroupBroadcast` | `OpGroupNonUniformBroadcast` | scalar broadcast |
| `subgroup_inclusive_scan_add` | `subgroupInclusiveAdd` | `OpGroupNonUniformAdd ScanInclusive` | prefix sum |
| `subgroup_exclusive_scan_add` | `subgroupExclusiveAdd` | `OpGroupNonUniformAdd ScanExclusive` | prefix sum shifted |
| `workgroup_barrier` | `workgroupBarrier` | `OpControlBarrier Workgroup` | no-op on CPU (serial) |
| `storage_barrier` | `storageBarrier` | `OpMemoryBarrier StorageBuffer` | no-op on CPU |
| `subgroup_barrier` | — | `OpGroupNonUniformMemoryBarrier` | no-op on CPU |
| `atomic_add_u32` | `atomicAdd` | `OpAtomicIAdd` | sequential add |
| `atomic_min_u32` | `atomicMin` | `OpAtomicUMin` | sequential min |
| `atomic_max_u32` | `atomicMax` | `OpAtomicUMax` | sequential max |
| `atomic_and_u32` | `atomicAnd` | `OpAtomicAnd` | sequential and |
| `atomic_or_u32` | `atomicOr` | `OpAtomicOr` | sequential or |
| `atomic_xor_u32` | `atomicXor` | `OpAtomicXor` | sequential xor |
| `atomic_compare_exchange_u32` | `atomicCompareExchangeWeak` | `OpAtomicCompareExchange` | sequential cmpxchg |
| `atomic_exchange_u32` | `atomicExchange` | `OpAtomicExchange` | sequential swap |
| `popcount_u32` | `countOneBits` | `OpBitCount` | `u32::count_ones` |
| `lzcnt_u32` | `countLeadingZeros` | `OpExtInst Clz` | `u32::leading_zeros` |
| `tzcnt_u32` | `countTrailingZeros` | `OpExtInst Ctz` | `u32::trailing_zeros` |
| `bit_reverse_u32` | `reverseBits` | `OpBitReverse` | `u32::reverse_bits` |
| `fma_f32` | `fma` | `OpExtInst Fma` | `f32::mul_add` |
| `inverse_sqrt_f32` | `inverseSqrt` | `OpExtInst InverseSqrt` | `1.0 / f32::sqrt` (bit-exact) |
| `clamp_u32` | `clamp` | `OpExtInst UClamp` | `x.clamp(lo, hi)` |

**Backends that claim support**: declared via
`OpEntry::claimed_backends`. `subgroup_*` variants are behind the
`subgroup-ops` feature flag (closes FINDING-PRIM-2).

**Determinism story for subgroup ops**: subgroup ops are inherently
wave-size-sensitive. The `cpu_ref` interpreter takes the declared
`workgroup_size` + `subgroup_size` from the Program and simulates a
wave of that size serially. The universal harness skips backend cells
whose device does not report the declared `subgroup_size`.

---

## 10. Workgroup-cooperative primitives (closes FINDING-PRIM-1)

| Op | Cat | Uses |
| --- | --- | --- |
| `workgroup_scan_u32_add` | A on Cat-C | softmax 3-pass reduce, layer_norm |
| `workgroup_reduce_u32_add` | A on Cat-C | attention normalizer |
| `workgroup_reduce_f32_max` | A on Cat-C | softmax numerical-stability max |
| `workgroup_broadcast_u32` | A on Cat-C | per-workgroup constant |

Each composes `DataType::Shared[N]` + `subgroup_*` intrinsics +
`workgroup_barrier`. Lives at `vyre-libs/src/workgroup/`.

After these land, `softmax / layer_norm / attention` migrate from
`[1,1,1]` dispatch to workgroup-parallel form and the ignored
`gap_workgroup_cooperative_scan` test in `vyre-libs/findings.toml`
closes.

---

## Non-scope (explicitly — post-0.6)

- Python bindings.
- Autodiff (R-1).
- Kani theorems (R-2).
- CUDA / Metal backends (R-4 / R-5).
- Sparse ops on GPU beyond sparse-aware DataType tags (R-6).

---

## Phase-F closures this catalog unlocks

- **FINDING-PRIM-1** — `workgroup_scan_u32_add` in §10.
- **FINDING-PRIM-2** — `subgroup-ops` feature flag in §9.
- **FINDING-GRAPH-1** / **FINDING-FOUNDATION-1** — graph ops in §1
  require `graph_view::from_graph` to return `Result`; catalog
  entries assume validated input.
- **FINDING-GPU-6** — `matmul` accumulator reset is a §8 regression
  item.
- **FINDING-GPU-7** — `substring_search` panic is a §3 migration item.
- **FINDING-CACHE-1 / CACHE-2** — unrelated to the catalog but closed
  in Phase F.

---

## Totals

- Cat-A composite ops: **64+**
  - Graph / AST / dataflow: 9
  - Security / taint: 6
  - Byte/text scan primitives: 8 (6 new + 2 migrated)
  - Crypto / hash: 9
  - Encoding / decoding: 7
  - Set / aggregate: 7
  - Networking: 5
  - ML primitives: 18 (10 migrated + 8 new)
- Cat-C hardware intrinsics: **24**
- Cat-A-on-Cat-C workgroup primitives: **4**

Total surface area at 0.6 legendary stamp: **92 ops** with
byte-identity CPU↔GPU conform, every one registered via `inventory`,
matrix-tested against every backend that claims support.
