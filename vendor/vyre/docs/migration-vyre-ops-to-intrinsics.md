# Migration — `vyre-ops` → `vyre-intrinsics` + library relocation

**Governing rule**: if an op can be written as `fn(...) -> Program`
using only `vyre::ir::*` types (no new Expr/Node variant, no dedicated
Naga emitter arm, no dedicated `vyre-reference` eval arm) — it belongs
in `vyre-libs` or a user package, NOT `vyre-intrinsics`.

**Intrinsic test** (both must be true):

1. The op's lowered form emits a dedicated hardware-intrinsic
   instruction that requires a dedicated match arm in
   `vyre-driver-wgpu/src/lowering/naga_emit/`.
2. OR the op uses an `Expr`/`Node` variant that `vyre-reference` has
   to evaluate with dedicated logic rather than recursively on
   existing primitives.

If either condition fails, the op is a library composition.

## Classification

### Category C — dedicated intrinsics with explicit Naga emission

| Op | IR variant used | Naga emission | vyre-reference handling |
| --- | --- | --- | --- |
| `subgroup_add` | `Expr::SubgroupAdd` | dedicated `subgroupAdd` (Naga 25+) | serial single-lane wave (added) |
| `subgroup_ballot` | `Expr::SubgroupBallot` | dedicated `subgroupBallot` | serial single-lane (added) |
| `subgroup_shuffle` | `Expr::SubgroupShuffle` | dedicated `subgroupShuffle` | serial single-lane (added) |
| `workgroup_barrier` | `Node::Barrier` | `workgroupBarrier` | no-op on serial CPU (existing) |
| `storage_barrier` | `Node::Barrier` | `storageBarrier` | no-op on serial CPU (existing) |
| `bit_reverse_u32` | `Expr::reverse_bits` (UnOp) | `reverseBits` | `u32::reverse_bits` |
| `popcount_u32` | `Expr::popcount` (UnOp) | `countOneBits` | `u32::count_ones` |
| `fma_f32` | `Expr::Fma` | `fma` | `f32::mul_add` |
| `inverse_sqrt_f32` | custom body via `Expr::f32_div(Expr::f32(1.0), Expr::f32_sqrt(x))` | currently composition; border-line intrinsic per the plan | dedicated `1.0 / f32::sqrt(x)` ref to match Naga's `inverseSqrt()` exactly when promoted to dedicated arm |

Rationale: every op above either constructs an `Expr` variant the
Naga emitter has (or will have) a dedicated arm for, OR uses the
shared `Node::Barrier` that the emitter lowers to a backend-specific
barrier instruction. `fma_f32` is the canonical example — consumers
expect bit-identity across backends because the Naga emitter produces
`fma()` and CPU refs use `f32::mul_add`; a plain `a * b + c` does not
give the same bits.

### Category B — library compositions that still require built-in Naga atomic emission

| Op | Destination | Reason |
| --- | --- | --- |
| `lzcnt_u32` | `vyre-libs/src/math/lzcnt_u32.rs` | Pure composition: cascading if-else + shifts in IR (or maps to `Expr::clz` which is already a UnOp primitive, not a dedicated intrinsic arm). |
| `tzcnt_u32` | `vyre-libs/src/math/tzcnt_u32.rs` | Same reasoning. |
| `clamp_u32` | `vyre-libs/src/math/clamp_u32.rs` | `min(max(x, lo), hi)` — pure IR composition over existing `BinOp::Min` / `BinOp::Max`. |
| `atomic_add_u32` | `vyre-libs/src/math/atomic/atomic_add.rs` | Library builder over `Expr::Atomic`, but correctness still depends on the backend's `AtomicOp::Add` Naga lowering. |
| `atomic_min_u32` | `vyre-libs/src/math/atomic/atomic_min.rs` | Library builder; backend must emit `AtomicOp::Min`. |
| `atomic_max_u32` | `vyre-libs/src/math/atomic/atomic_max.rs` | Library builder; backend must emit `AtomicOp::Max`. |
| `atomic_and_u32` | `vyre-libs/src/math/atomic/atomic_and.rs` | Library builder; backend must emit `AtomicOp::And`. |
| `atomic_or_u32` | `vyre-libs/src/math/atomic/atomic_or.rs` | Library builder; backend must emit `AtomicOp::Or`. |
| `atomic_xor_u32` | `vyre-libs/src/math/atomic/atomic_xor.rs` | Library builder; backend must emit `AtomicOp::Xor`. |
| `atomic_exchange_u32` | `vyre-libs/src/math/atomic/atomic_exchange.rs` | Library builder; backend must emit `AtomicOp::Exchange`. |
| `atomic_compare_exchange_u32` | `vyre-libs/src/math/atomic/atomic_compare_exchange.rs` | Library builder; backend must emit `AtomicOp::CompareExchange`. |
| `lru_update_u32` | `vyre-libs/src/math/atomic/atomic_lru_update.rs` | Library builder; backend must emit `AtomicOp::LruUpdate` via the atomic lowering path. |

**Note — atomic ops were planned for `vyre-ops/src/hardware/` but never
re-landed after the mystery deletion. They are not on disk. They will
be written directly into `vyre-libs/src/math/atomic/` under this
migration.**

### Category A — pure IR compositions with no dedicated Naga emitter arm

| Op | Destination | Reason |
| --- | --- | --- |
| `lzcnt_u32` | `vyre-libs/src/math/lzcnt_u32.rs` | Pure composition over existing IR / `UnOp::Clz`; no dedicated op-owned emitter arm. |
| `tzcnt_u32` | `vyre-libs/src/math/tzcnt_u32.rs` | Pure composition over existing IR / `UnOp::Ctz`; no dedicated op-owned emitter arm. |
| `clamp_u32` | `vyre-libs/src/math/clamp_u32.rs` | `min(max(x, lo), hi)` over existing IR; no dedicated op-owned emitter arm. |

### Planned Category A additions (not on disk today)

| Op | Destination | Reason |
| --- | --- | --- |
| `fnv1a64` | `vyre-libs/src/hash/fnv1a64.rs` | Pure serial composition. |
| `crc32` | `vyre-libs/src/hash/crc32.rs` | Pure serial composition. |
| `adler32` | `vyre-libs/src/hash/adler32.rs` | Pure serial composition. |

### DUPLICATE — delete the `vyre-ops` copy (`vyre-libs` already has these)

`vyre-ops/` restored from HEAD has these directories, but `vyre-libs/`
already holds canonical implementations. The `vyre-ops` copies are
legacy duplicates from an earlier refactor. Delete after the rename.

| Path | Keep at | Delete at |
| --- | --- | --- |
| `avg_floor` | `vyre-libs/src/math/avg_floor.rs` | `vyre-ops/src/math/avg_floor/` |
| `wrapping_neg` | `vyre-libs/src/math/wrapping_neg.rs` | `vyre-ops/src/math/wrapping_neg/` |
| `and`, `or`, `xor`, `nand`, `nor` | `vyre-libs/src/logical/*` | `vyre-ops/src/logical/*` |
| `file_size_*`, `literal_*`, `pattern_*` | `vyre-libs/src/rule/*` | `vyre-ops/src/rule/*` |

### CONSOLIDATE — `vyre-libs::crypto` → `vyre-libs::hash`

Existing `vyre-libs/src/crypto/` (fnv1a32 + blake3_compress) merges
into `vyre-libs/src/hash/` alongside the newly-moved fnv1a64 / crc32 /
adler32.

| Current | New |
| --- | --- |
| `vyre-libs/src/crypto/fnv/fnv1a.rs` | `vyre-libs/src/hash/fnv1a32.rs` |
| `vyre-libs/src/crypto/blake3/blake3.rs` | `vyre-libs/src/hash/blake3_compress.rs` |
| `vyre-libs/src/crypto/mod.rs` | delete (merge into `vyre-libs/src/hash/mod.rs`) |

Every op id updates: `vyre-libs::crypto::fnv1a32` → `vyre-libs::hash::fnv1a32`.
Fingerprint lock file regenerates.

### STAYS in `vyre-intrinsics` but is INFRASTRUCTURE (not an op)

| File | Reason |
| --- | --- |
| `harness.rs` | OpEntry registry for the intrinsic-differential test. |
| `region.rs` | Region wrap helper (per `docs/region-chain.md`). |
| `contracts.rs` | Op-contract presets (driver-facing metadata, not a Program builder). |
| `signatures.rs` | Type-signature constants used by intrinsic descriptors. |
| `test_migration.rs` | Pre-sweep shader-snapshot migration inventory. |

### DELETE outright

| File | Reason |
| --- | --- |
| `vyre-ops/src/primitive.rs` | Orphan — declares `pub mod subgroup_ballot` etc. but the target files don't exist and the module is not referenced from `lib.rs`. Dead code. |
| `vyre-ops/src/ast_manifest.rs` | Confirm unreferenced before deleting; if still wired, keep. (Verify during Migration 2.) |

`vyre-intrinsics/build.rs` is the static gate for this document: Category A
ops must have no dedicated emitter ownership, Category B ops must map to the
built-in atomic lowering path, and Category C ops must keep an explicit
intrinsic registration plus dedicated Naga emission.

## Post-migration `vyre-intrinsics` structure

```
vyre-intrinsics/                       (formerly vyre-ops/)
  Cargo.toml                           name = "vyre-intrinsics"
  README.md
  AUTHORING.md
  src/
    lib.rs                             only hardware/ + harness + region
    region.rs
    harness.rs
    contracts.rs
    signatures.rs
    test_migration.rs
    hardware/
      mod.rs
      subgroup_add/
      subgroup_ballot/
      subgroup_shuffle/
      storage_barrier/
      workgroup_barrier/
      bit_reverse_u32/
      popcount_u32/
      fma_f32/
      inverse_sqrt_f32/
  tests/
    hardware_conform.rs                9 ops × CPU ref + wgpu byte-identity
```

## Post-migration `vyre-libs` structure (relevant additions)

```
vyre-libs/
  src/
    lib.rs
    region.rs                          (existing)
    harness.rs                         (existing)
    builder.rs                         (existing)
    tensor_ref.rs                      (existing)
    math/
      avg_floor.rs                     (existing)
      broadcast/                       (existing)
      linalg/                          (existing)
      scan/                            (existing)
      wrapping_neg.rs                  (existing)
      clamp_u32.rs                     NEW (moved)
      lzcnt_u32.rs                     NEW (moved)
      tzcnt_u32.rs                     NEW (moved)
      atomic/                          NEW dir
        mod.rs
        atomic_add.rs                  NEW
        atomic_and.rs                  NEW
        atomic_compare_exchange.rs     NEW
        atomic_exchange.rs             NEW
        atomic_max.rs                  NEW
        atomic_min.rs                  NEW
        atomic_or.rs                   NEW
        atomic_xor.rs                  NEW
    hash/                              NEW dir (absorbs crypto/)
      mod.rs
      fnv1a32.rs                       (moved from crypto/fnv/)
      fnv1a64.rs                       NEW
      crc32.rs                         NEW
      adler32.rs                       NEW
      blake3_compress.rs               (moved from crypto/blake3/)
    matching/                          (existing)
    nn/                                (existing)
    logical/                           (existing)
    rule/                              (existing)
    text/                              NEW (Phase L1+)
    parsing/                           NEW (Phase L2-L4)
    security/                          NEW (Phase L5 — surgec stubs)
```

## Downstream changes (Migration 4)

Every `use vyre_ops::*` import becomes `use vyre_intrinsics::*`. Every
op-id string beginning `vyre-ops::hardware::<op>` becomes
`vyre-intrinsics::hardware::<op>`. Every op-id string beginning
`vyre-ops::composite::hash::<op>` or `vyre-libs::crypto::<op>` becomes
`vyre-libs::hash::<op>`.

Fingerprint lock files regenerate for any op whose id changed.

## Migration order

1. **Migration 2** — relocate non-intrinsic ops from `vyre-ops` to
   `vyre-libs`. Write the 3 u32 math ops, 8 atomics, 3 hashes in
   `vyre-libs/src/math/` and `vyre-libs/src/hash/`. Delete `vyre-ops`
   duplicates.
2. **Migration 3** — consolidate `vyre-libs::crypto` → `vyre-libs::hash`.
3. **Migration 4** — rename crate + update every import + regenerate
   fingerprints. This is the big churn commit.
4. **Migration 5** — `cargo fmt`, `cargo clippy -D warnings`,
   `cargo test --workspace --all-features` all green.

Only after Migration 5 is green do we dispatch the parallel agents to
build Phase B (9 intrinsics in `vyre-intrinsics`) and Phase L1-L5 (GPU
C parser in `vyre-libs`).
