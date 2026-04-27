# V7 — Legendary stamp plan

> Superseded plan. Preserved for historical context and audit trail.
> The active release gate is
> [`../audits/LEGENDARY_GATE.md`](../audits/LEGENDARY_GATE.md); conflict
> resolution follows
> [`DOCUMENTATION_GOVERNANCE.md`](DOCUMENTATION_GOVERNANCE.md).

At the time this plan was active, it was the single load-bearing
document. Execution order was top-down; no item skipped, nothing
deferred. It no longer overrides the active release gate.

## Guiding rules

- **Cat-A** only: pure composition of primitive ops + hardware intrinsics.
- **Cat-B** banned. No ULP-tolerant conform. No "close enough".
- **Cat-C** = hardware intrinsics. Each has a CPU reference that simulates
  the intrinsic's exact semantics; byte-identity conform across every
  backend that claims to support it; backends that don't claim support
  return `UnsupportedByBackend` (never fall back to slow CPU).
- Every op registered via `inventory::submit!(OpEntry { … })` ships
  with: `build` fn, `cpu_ref` oracle, `test_inputs` generator,
  `witness_expansion` (proptest strategy), `category: Cat::A | Cat::C`,
  `claimed_backends: BitSet<BackendId>`. The universal harness
  matrix-tests every op × every available backend.

---

## Phase A — Ops catalog (`docs/ops-catalog.md`) ✴

Historical target catalog for what Santh frontends needed from core
during V7 planning. It categorized each op Cat-A or Cat-C, noted which
frontend needed it, and listed the claimed algebraic laws.

Catalog entries, grouped by domain:

### Graph / AST / dataflow (surgec, vein)

| Op | Category | Needed by | Laws |
| --- | --- | --- | --- |
| `ast_walk_preorder(ast_buf, out_buf, len) -> Program` | Cat-A | surgec, vein | ordering-stable |
| `ast_walk_postorder` | Cat-A | surgec, vein | ordering-stable |
| `subgraph_match(haystack_graph, pattern_graph, matches) -> Program` | Cat-A | surgec | idempotent |
| `dominator_tree(cfg_edges, cfg_nodes, idom_out) -> Program` | Cat-A | surgec, vein | deterministic |
| `reachability_bfs(edges, start, visited_out) -> Program` | Cat-A | surgec, vein | monotone-in-visited |
| `scc_tarjan(edges, scc_ids_out) -> Program` | Cat-A | surgec | deterministic |
| `topological_sort(edges, order_out) -> Program` | Cat-A | surgec | deterministic when acyclic |
| `cfg_build(ast, cfg_edges_out) -> Program` | Cat-A | surgec | deterministic |
| `ssa_rename(cfg, defs_out, uses_out) -> Program` | Cat-A | surgec, vein | idempotent |

### Security / taint (surgec → vyre-libs::security)

| Op | Category | Currently stubbed as |
| --- | --- | --- |
| `flows_to(source, sink, taint_edges, result) -> Program` | Cat-A | inert no-op |
| `sanitized_by(edges, sanitizers, result) -> Program` | Cat-A | inert |
| `bounded_by_comparison(index, bound, comparisons, result) -> Program` | Cat-A | inert |
| `taint_flow(cfg, sources, sinks, flow_edges_out) -> Program` | Cat-A | inert |
| `label_by_family(edges, family_map, labels_out) -> Program` | Cat-A | inert |
| `path_reconstruct(flow_edges, target, path_out) -> Program` | Cat-A | inert |

### Byte and text scan primitives (surgec, keyhog)

Low-level DFA / literal / filter ops used inside arbitrary rule programs — not the product category.

| Op | Category | Needed by |
| --- | --- | --- |
| `multi_dfa_scan(haystack, dfa_table, first_match_out) -> Program` | Cat-A | surgec |
| `case_insensitive_dfa(haystack, dfa, matches) -> Program` | Cat-A | surgec |
| `regex_compile_to_dfa(pattern_src, dfa_out) -> Program` | Cat-A | keyhog, surgec |
| `regex_match(haystack, compiled_dfa, spans_out) -> Program` | Cat-A | keyhog |
| `bloom_probe(key, bitset, result) -> Program` | Cat-A | surgec |
| `boyer_moore_scan(haystack, needle, bad_char, matches) -> Program` | Cat-A | surgec |

### Crypto / hash (keyhog, gossan)

| Op | Category | Needed by | Status |
| --- | --- | --- | --- |
| `fnv1a32` | Cat-A | keyhog | shipped in vyre-libs |
| `fnv1a64` | Cat-A | keyhog | add |
| `xxhash64` | Cat-A | gossan | add |
| `murmur3_32` | Cat-A | gossan | add |
| `crc32` | Cat-A | gossan | add |
| `adler32` | Cat-A | gossan | add |
| `siphash24` | Cat-A | keyhog | add |
| `blake3_compress` | Cat-A | keyhog | shipped in vyre-libs |
| `shannon_entropy(buf, out) -> Program` | Cat-A | keyhog, sear | add |

### Encoding / decoding (keyhog, sear)

| Op | Category | Needed by |
| --- | --- | --- |
| `base64_decode(src, dst) -> Program` | Cat-A | keyhog |
| `base64_encode` | Cat-A | keyhog |
| `hex_decode` | Cat-A | keyhog |
| `hex_encode` | Cat-A | keyhog |
| `utf8_validate(src, result) -> Program` | Cat-A | all |
| `url_canonicalize(src, dst) -> Program` | Cat-A | karyx, gossan |
| `line_column_index(src, offsets_out) -> Program` | Cat-A | surgec (for diagnostic locations) |

### Set / aggregate (surgec, soleno)

| Op | Category |
| --- | --- |
| `bitset_union`, `bitset_intersect`, `bitset_difference` | Cat-A |
| `hyperloglog_count(keys, out) -> Program` | Cat-A |
| `rolling_window_sum(series, window, out) -> Program` | Cat-A |
| `exponential_moving_avg(series, alpha_q16, out) -> Program` | Cat-A |
| `interval_tree_query(tree, point, hit_out) -> Program` | Cat-A |

### Networking (gossan, karyx)

| Op | Category |
| --- | --- |
| `ipv4_parse(src, out) -> Program` | Cat-A |
| `ipv6_parse(src, out) -> Program` | Cat-A |
| `domain_label_split(src, labels_out) -> Program` | Cat-A |
| `tls_cipher_fingerprint(client_hello, fp_out) -> Program` | Cat-A |
| `http_header_match(headers, needle, result) -> Program` | Cat-A |

### ML primitives (vyre-libs continues)

Already shipped: `dot`, `matmul`, `matmul_tiled`, `scan_prefix_sum`,
`broadcast`, `relu`, `linear`, `softmax`, `layer_norm`, `attention`.
All 10 byte-identical CPU↔5090 today.

Add for completeness:
- `silu`, `gelu`, `tanh`, `sigmoid` (activation variants)
- `rmsnorm`
- `rope` (rotary position embeddings)
- `cross_entropy_loss`
- `adam_update` (optimizer step, reference gradient descent)

### Hardware intrinsics (Cat-C, `vyre-ops/hardware/`)

The exact intrinsic table is owned by
[`ops-catalog.md`](ops-catalog.md#9-hardware-intrinsics-cat-c-vyre-opssrchardware).
This historical plan only depends on the invariant: every Cat-C
intrinsic has a CPU reference, and every backend that claims support must
byte-match that reference.

`hardware/` ships every intrinsic on wgpu first, spirv second, photonic
stub third. Conform matrix proves byte-identity.

### Workgroup-cooperative primitives (closes FINDING-PRIM-1)

| Op | Category | Uses |
| --- | --- | --- |
| `workgroup_scan_u32_add` | Cat-A on top of Cat-C | softmax 3-pass reduce, layer_norm |
| `workgroup_reduce_u32_add` | Cat-A on top of Cat-C | attention normalizer |
| `workgroup_reduce_f32_max` | Cat-A | softmax numerical-stability max |
| `workgroup_broadcast_u32` | Cat-A | per-workgroup constant |

Each composes `shared_memory[N]` + `subgroup_*` intrinsics + `workgroup_barrier`.

---

## Phase B — Empty `vyre-ops/hardware/` populated (Cat-C)

Each intrinsic:

1. Declares `pub fn <name>(...) -> Program` — construction only.
2. Ships with `inventory::submit!(OpEntry { … })` — category = Cat-C,
   cpu_ref = reference semantics, test_inputs, witness_expansion.
3. Lowering: wgsl via `naga::Statement::*` (existing naga emitter);
   spirv via `naga::back::spv`; photonic via `UnsupportedByBackend`.
4. Test: universal harness matrix runs CPU ref + wgpu + spirv (when
   shipped) and asserts byte-identity. Dedicated `cat_c_conform.rs`
   for cross-backend differential.

Deliverable: 24 Cat-C ops in `vyre-ops/hardware/`, each green on 5090.

---

## Phase C — Empty `vyre-ops/composite/` populated (Cat-A)

Each composite:

1. `pub fn <name>(...) -> Program` — Cat-A wrap over `hardware/` +
   primitives.
2. `inventory::submit!(OpEntry { … })` — category = Cat-A, cpu_ref
   returns byte-identical bytes, test_inputs covers edge cases.
3. Universal harness runs CPU ref + wgpu backend, byte-identity.

Deliverable: 30+ Cat-A ops covering graph, dataflow, encoding, set,
networking, ML activation variants, hash.

---

## Phase C2 — Critique audits (launched in parallel with Phase B+C op-build)

While the op-build waves are in flight, dispatch **5 critique audits in
parallel** across the whole vyre workspace. These are read-only deep
reviews — no code changes, no scope overlap with the writers. Each
audit produces a findings file that drops into the per-crate
`findings.toml` for Phase F's fix-all pass.

Every audit uses **kimi in read-only mode**. No other agent types —
Kimi is scope-locked per-audit, reads the whole tree, emits audit
TOML, never touches source. Five concurrent kimi reads is safe because
each writes to a distinct audit file.

| # | Audit | Output file | Scope |
| --- | --- | --- | --- |
| 1 | Performance | `audits/V7_perf.toml` | Every hot path — `fingerprint_of`, dispatch, lowering, region_inline, cache lookup. Propose structural wins. Identify unnecessary clones, O(n²) patterns, missing OnceCell caching, `Arc::clone` in tight loops. |
| 2 | Extensibility | `audits/V7_ext.toml` | Can a community crate add a new op / backend / dialect / op_family without editing core? Walk every `pub enum` and verify `#[non_exhaustive]`. Walk every trait and verify it accepts `Box<dyn T>` not concrete types. Check inventory::collect! registration paths actually work from outside the crate. |
| 3 | Correctness / spec | `audits/V7_correct.toml` | For every Cat-A op: is the CPU ref byte-identical to the spec the docstring claims? For every Cat-C: does the CPU ref exactly simulate the hardware intrinsic's contract? Proofread `docs/ir-semantics.md` against actual interpreter behavior. Find places the contract and the code disagree. |
| 4 | API surface | `audits/V7_api.toml` | `cargo public-api` every crate. Every public type: does it have docs? Does it carry `#[non_exhaustive]` where forward-compat matters? Is the module path where a consumer would expect it? Are there redundant re-exports? |
| 5 | Testing / harness | `audits/V7_test.toml` | Does every op's test suite cover: zero/one/MAX input, unicode, NaN/Inf, empty buffer, buffer-size boundary, workgroup-size boundary, panic-on-invalid-input contract? Does the universal harness execute every op × every registered backend? Are the adversarial tests designed to FAIL? |

Rules for every audit:
- `dispatch(agent="kimi", mode="read", workdir=<vyre>, prompt=<audit brief>)`.
- Output to the specified path. If the path exists, append a new
  `[[finding]]` block per issue.
- One finding per issue. Each finding: `id`, `severity`
  (critical|major|minor|nit), `file`, `line`, `why`, `proposed_fix`.
- No `[critical]` stays `open` past Phase F.

Audits run in parallel with Phase B+C op-build — writers own source
files, auditors emit audit TOML only, zero scope overlap. When Phase
B+C closes, all 5 audit outputs exist and Phase F has a concrete work
queue.

---

## Phase D — Surgec wiring

1. Replace every `stub_vyre_libs::*` with `use vyre_ops::composite::security::*`.
2. Delete `surgec/src/lower/stub_vyre_libs.rs`.
3. Surgec's AST → vyre IR emitter calls real functions.
4. Add end-to-end test: parse a surge rule source file → lower to
   vyre IR → dispatch on wgpu → assert findings byte-identity vs.
   CPU ref.

Deliverable: surgec executes its stubbed contract on real hardware.

---

## Phase E — Harness upgrade

Consolidate `vyre-libs/src/harness.rs` + `vyre-ops` into a single
universal op harness:

```rust
pub struct OpEntry {
    pub id: &'static str,
    pub category: Category,          // ::A | ::C
    pub build: fn() -> Program,
    pub cpu_ref: fn(&[Vec<u8>]) -> Vec<Vec<u8>>,
    pub test_inputs: fn() -> Vec<Vec<u8>>,
    pub witness_strategy: Option<fn() -> WitnessStrategy>,  // proptest
    pub claimed_backends: &'static [&'static str],          // which backends claim support
    pub laws: &'static [AlgebraicLaw],
}
```

Universal harness test runs `OpEntry × registered_backends()` matrix,
byte-identity per cell. Failing cells emit OCC deviation certificates
for diagnosis.

Delete `cat_a_gpu_differential.rs` — redundant once matrix harness
covers every op × every backend.

Deliverable: adding a new op = one `inventory::submit!` with oracle.

---

## Phase F — Close all open findings

1. `FINDING-PRIM-1` — workgroup-cooperative scan lands as Cat-A on
   top of new Cat-C subgroup_*. softmax/layer_norm/attention migrate
   to workgroup-parallel form. Close + regenerate fingerprints.
2. `FINDING-PRIM-2` — subgroup ops gated behind `subgroup-ops` feature
   in vyre-spec; backend arms gated identically; universal harness
   skips cells where backend doesn't claim support.
3. `FINDING-GRAPH-1` — graph_view `from_graph` returns
   `Result<Program, GraphValidateError>`. Malformed graphs return
   structured errors (Cycle, DanglingEdge, OrphanPhi).
4. Task #127 — wgpu `gap_transcendentals_parity` bind-group-index
   bug. Root cause, fix, reenable.

Deliverable: zero open findings in findings.toml.

---

## Phase G — Organization

1. Split findings: `vyre-libs/findings.toml` → Cat-A libs findings;
   `vyre-ops/findings.toml` → core op findings; `vyre-foundation/findings.toml`
   → IR findings; `vyre-driver-wgpu/findings.toml` → backend findings;
   `vyre-pipeline-cache/findings.toml` → cache findings. Each crate
   owns its own.
2. `STATUS.md` at workspace root — table of op × backend × state.
   Regenerated by `cargo xtask status`.
3. Rename `vyre-libs::harness` module → `vyre-libs::op_entry` (reserve
   the "harness" noun for the test driver, not the op registration).
4. `docs/categories.md` — Cat-A / Cat-C rules, what banned Cat-B means.
5. Consolidate GPU findings fixed this sweep into a single closed block.

Deliverable: workspace legible at a glance; a new contributor finds
the op catalog, the status board, and the category rules in under a
minute.

---

## Phase H — Final verification

- `cargo clippy --workspace --all-features --all-targets -- -D warnings` clean.
- `cargo test --workspace --all-features --no-fail-fast` — 0 failed,
  0 unlabeled ignored.
- `cargo test --workspace` on each backend combination (default,
  no-gpu, parity-testing, subgroup-ops).
- `cargo doc --workspace --all-features --no-deps` clean.
- `cargo xtask check-cat-a` green.
- `cargo xtask check-cat-c` green (new).
- `cargo xtask status` prints:
  - 64+ Cat-A ops, each green on CPU + wgpu
  - 24 Cat-C intrinsics, each green on CPU + wgpu (+ spirv when ready)
  - 0 open findings
  - conform certificate hash, reproducible across machines.
- bench suite on 5090 for every new op; RESULTS.md updated.

---

## Phase I — Region chain invariant

Without the region chain, a big Cat-A composition (e.g. a parser, a full
attention block) becomes forensically opaque by the time it reaches the
shader. This phase makes "show me the whole composition chain" a
first-class operation at every tier.

Deliverables:

1. `docs/region-chain.md` — spec of the invariant:
   - Every `Node::Region` MUST carry a stable `generator: Ident` and
     populate `source_region` when the body was itself built from
     another registered op. Anonymous bodies (inline Rust constructions)
     set `source_region = None`.
   - `transform::optimize::region_inline` gains a debug-preserve mode
     that flattens the IR but records a side-channel
     `flat_node_index → region_path` map on the Program. Release builds
     may drop the map; debug builds carry it through to readback.
   - Backends emit region path as comments: WGSL via `//
     vyre-region: <path>`, SPIR-V via `OpLine`, photonic via its log
     channel.
2. `vyre-ops::region` (promoted from `vyre-libs::region`) — helper
   shared by every composite op. `wrap_anonymous(name, body)` +
   `wrap_child(name, parent_ref, body)`.
3. Every existing composition file in `vyre-ops/src/composite/` and
   `vyre-libs/src/*` rewired to thread `source_region` through.
4. Naga emitter writes region comments in WGSL output.

Deliverable: given any Program, you can walk `Node::Region` tree from
root to leaf and read off the compositional chain from high-level op
down to hardware intrinsics.

---

## Phase J — Composition audit tool

`cargo xtask print-composition <op_id>` walks:

1. The `OpEntry` inventory for `<op_id>` — takes the registered
   `build: fn() -> Program`.
2. The constructed Program's `Node::Region` tree via Phase I's
   invariant.
3. Prints a tree visualization:

```
vyre-libs-nn::attention  [48 nodes]
├─ softmax                [14 nodes]
│  ├─ workgroup_reduce_f32_max     (vyre-ops::composite::workgroup::reduce_f32_max)
│  └─ workgroup_scan_u32_add       (vyre-ops::composite::workgroup::scan_u32_add)
│     └─ subgroup_add              (vyre-ops::hardware::subgroup_add)
├─ matmul_tiled            [22 nodes]
│  └─ fma_f32              (vyre-ops::hardware::fma_f32)
└─ layer_norm              [12 nodes]
   └─ inverse_sqrt_f32     (vyre-ops::hardware::inverse_sqrt_f32)
```

Deliverable: for any op, produce an auditable decomposition chain.
Used by Phase C2 audits to verify composition size caps and by
consumers to understand what an op actually compiles to.

---

## Phase K — Library tier decomposition

Before 0.7 publishes, split `vyre-libs` into domain crates and lock the
three-tier rule:

1. **`docs/library-tiers.md`** — the rule:
   - Tier 1: `vyre-foundation` / `vyre-spec` / `vyre-core` — IR model,
     wire format, no ops.
   - Tier 2: `vyre-ops` — frozen core surface: `hardware/` (Cat-C),
     `primitive/` (arithmetic, bitwise, compare), `composite/` (Cat-A
     stdlib ≤ 200 top-level Nodes per op).
   - Tier 3: `vyre-libs-<domain>` — one crate per domain, unbounded
     size. Initial split:
     - `vyre-libs-nn` — matmul, matmul_tiled, attention, softmax,
       layer_norm, relu, linear, scan_prefix_sum, broadcast
       (extracted from `vyre-libs/src/{nn,math}`).
     - `vyre-libs-crypto` — full BLAKE3 compression rounds, full
       SipHash-2-4, future SHA-2 (extracted from
       `vyre-libs/src/crypto/`).
     - `vyre-libs-regex` — DFA compiler, aho_corasick, regex_match,
       substring_search (extracted from `vyre-libs/src/matching/`).
     - `vyre-libs-parse` — placeholder for future grammar-as-Cat-A
       parsers (surgec backend ports here post-0.7).
   - Tier 4: community packs via `vyre-libs-extern` — external repos
     registering `ExternDialect` / `ExternOp` inventories.
2. **Op ID encodes tier**. `vyre-ops::...` (T2), `vyre-libs-nn::...`
   (T3), `<dialect>::...` (T4). A grep tells you where any op lives.
3. **Tier-3 depends on Tier-2; never reverse**.
   `vyre-libs-nn::attention` calls `vyre-ops::hardware::fma_f32`, not
   the other way. CI gate enforces the dependency direction.
4. **`vyre-libs`** dissolves. Its final form is a deprecation shim
   re-exporting from `vyre-libs-{nn,crypto,regex}` for one minor
   version, then goes away.
5. **Size-cap CI gate**. `cargo xtask check-composite-size` fails if
   any op under `vyre-ops/src/composite/` builds a Program with
   > 200 top-level Nodes. Forces unbounded compositions into Tier 3.

Deliverable: a contributor can add a new small Cat-A op to core (Tier
2) in one PR with one OpEntry; a contributor can add a whole neural-net
variant (Tier 3) to `vyre-libs-nn` without touching core; a community
member can publish `vyre-libs-my-domain` on crates.io and have it
register into the same universal harness (Tier 4). Every op, any tier,
has a Region chain and is audit-printable via Phase J.

---

## Non-scope (explicitly)

- Python bindings (post-0.6).
- Autodiff (R-1, roadmap).
- Kani theorems (R-2, roadmap).
- CUDA/Metal backends (R-4/R-5, roadmap).
- Sparse ops on GPU beyond sparse-aware DataType tags (R-6, roadmap).
- **Whole-language parsers as Cat-A ops** (C / Rust / Go / etc.) —
  see `docs/parsing-and-frontends.md`. Parsing stays on CPU via
  tree-sitter / libclang bindings that emit an AST buffer in vyre's
  packed layout; everything above parsing (AST walks, dataflow, taint,
  pattern match) runs on GPU via the V7 §1 + §2 ops. A full
  GPU-native C parser is a 6-12 month project and provides near-zero
  value over the CPU-side bindings; revisit only when profiling shows
  parsing is the bottleneck.
