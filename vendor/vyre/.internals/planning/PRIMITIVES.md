# Primitive Operation Inventory

This is the canonical enumeration of primitive ops shipped in vyre 0.4.0-alpha.2. The benchmark showcase, conform KAT corpus, and adversarial test matrix are all indexed off this list. Adding a new primitive = new row here + new file in `vyre-core/src/ops/primitive/<family>/<op>.rs` + new KAT file in `rules/kat/primitive/<op>.toml`. Everything else (bench, oracle, adversarial) is generated.

## Families

| Family        | Count | Category | Notes                                                              |
|---------------|-------|----------|--------------------------------------------------------------------|
| `math`        | 15    | A        | Integer arithmetic over `u32` (wrapping), plus saturating variants |
| `bitwise`     | 13    | A        | `u32` bit-level operations; cat C for count-leading-zeros variants |
| `compare`     | 7     | A        | Boolean comparison returning `u32` 0/1                             |
| `logical`     | 1     | A        | Short-circuiting boolean logic                                     |
| `float`       | 9     | A/C      | IEEE-754 `f32` arithmetic; transcendentals are cat C               |
| `aggregates`  | 2     | A        | `min`, `max` as standalone primitives                              |
| `ternary`     | 2     | A        | `clamp`, `select`                                                  |
| `structural`  | 1     | A        | `bitfield` (composite field access)                                |

**Total: 50 primitives.** (`neg.rs` and `negate.rs` are duplicates scheduled for consolidation in 0.4.0 — tracked in `audits/duplicate_neg.md`.)

## Full list

### `math` (family id `primitive.math`)

| Op id                       | File                               | Sig           | Category | Laws                                      |
|-----------------------------|------------------------------------|---------------|----------|-------------------------------------------|
| `primitive.math.add`        | `math/add.rs`                      | `(u32,u32)→u32` | A        | Commutative, Associative, Identity{0}     |
| `primitive.math.sub`        | `math/sub.rs`                      | `(u32,u32)→u32` | A        | Identity{right=0}                         |
| `primitive.math.mul`        | `math/mul.rs`                      | `(u32,u32)→u32` | A        | Commutative, Associative, Identity{1}, Annihilator{0} |
| `primitive.math.div`        | `math/div.rs`                      | `(u32,u32)→u32` | A        | Identity{right=1}; div-by-zero contract   |
| `primitive.math.mod`        | `math/mod_op.rs`                   | `(u32,u32)→u32` | A        | Idempotent; mod-by-zero contract          |
| `primitive.math.abs`        | `math/abs.rs`                      | `(u32)→u32`     | A        | Idempotent                                |
| `primitive.math.abs_diff`   | `math/abs_diff.rs`                 | `(u32,u32)→u32` | A        | Commutative                               |
| `primitive.math.neg`        | `math/neg.rs`                      | `(u32)→u32`     | A        | Involutive (two's-complement wrapping)    |
| `primitive.math.sign`       | `math/sign.rs`                     | `(u32)→u32`     | A        | Idempotent                                |
| `primitive.math.min`        | `min.rs`                           | `(u32,u32)→u32` | A        | Commutative, Associative, Idempotent      |
| `primitive.math.max`        | `max.rs`                           | `(u32,u32)→u32` | A        | Commutative, Associative, Idempotent      |
| `primitive.math.gcd`        | `math/gcd.rs`                      | `(u32,u32)→u32` | A        | Commutative, Associative, Identity{0}     |
| `primitive.math.lcm`        | `math/lcm.rs`                      | `(u32,u32)→u32` | A        | Commutative, Associative                  |
| `primitive.math.add_sat`    | `math/add_sat.rs`                  | `(u32,u32)→u32` | A        | Commutative, saturates at u32::MAX        |
| `primitive.math.sub_sat`    | `math/sub_sat.rs`                  | `(u32,u32)→u32` | A        | Saturates at 0                            |

### `bitwise` (family id `primitive.bitwise`)

| Op id                              | File                                 | Sig           | Category |
|------------------------------------|--------------------------------------|---------------|----------|
| `primitive.bitwise.and`            | `bitwise/and.rs`                     | `(u32,u32)→u32` | A        |
| `primitive.bitwise.or`             | `bitwise/or.rs`                      | `(u32,u32)→u32` | A        |
| `primitive.bitwise.xor`            | `bitwise/xor.rs`                     | `(u32,u32)→u32` | A        |
| `primitive.bitwise.not`            | `bitwise/not.rs`                     | `(u32)→u32`     | A        |
| `primitive.bitwise.shl`            | `bitwise/shl.rs`                     | `(u32,u32)→u32` | A        |
| `primitive.bitwise.shr`            | `bitwise/shr.rs`                     | `(u32,u32)→u32` | A        |
| `primitive.bitwise.rotl`           | `bitwise/rotl.rs`                    | `(u32,u32)→u32` | A        |
| `primitive.bitwise.rotr`           | `bitwise/rotr.rs`                    | `(u32,u32)→u32` | A        |
| `primitive.bitwise.popcount`       | `bitwise/popcount.rs`                | `(u32)→u32`     | C        |
| `primitive.bitwise.clz`            | `bitwise/clz.rs`                     | `(u32)→u32`     | C        |
| `primitive.bitwise.ctz`            | `bitwise/ctz.rs`                     | `(u32)→u32`     | C        |
| `primitive.bitwise.reverse_bits`   | `bitwise/reverse_bits.rs`            | `(u32)→u32`     | C        |
| `primitive.bitwise.extract_bits`   | `bitwise/extract_bits.rs`            | `(u32,u32,u32)→u32` | C    |
| `primitive.bitwise.insert_bits`    | `bitwise/insert_bits.rs`             | `(u32,u32,u32,u32)→u32` | C |

### `compare` (family id `primitive.compare`)

| Op id                        | File                           | Sig             | Category |
|------------------------------|--------------------------------|-----------------|----------|
| `primitive.compare.eq`       | `compare/eq.rs`                | `(u32,u32)→u32` | A        |
| `primitive.compare.ne`       | `compare/ne.rs`                | `(u32,u32)→u32` | A        |
| `primitive.compare.lt`       | `compare/lt.rs`                | `(u32,u32)→u32` | A        |
| `primitive.compare.le`       | `compare/le.rs`                | `(u32,u32)→u32` | A        |
| `primitive.compare.gt`       | `compare/gt.rs`                | `(u32,u32)→u32` | A        |
| `primitive.compare.ge`       | `compare/ge.rs`                | `(u32,u32)→u32` | A        |
| `primitive.compare.not`      | `compare/logical_not.rs`       | `(u32)→u32`     | A        |

### `logical`, `ternary`, `structural`

| Op id                    | File               | Sig                         | Category |
|--------------------------|--------------------|-----------------------------|----------|
| `primitive.logical`      | `logical.rs`       | `(u32,u32)→u32` (short-circ) | A        |
| `primitive.math.clamp`   | `clamp.rs`         | `(u32,u32,u32)→u32`         | A        |
| `primitive.select`       | `select_op.rs`     | `(u32,u32,u32)→u32`         | A        |
| `primitive.bitfield`     | `bitfield.rs`      | composite                   | A        |

### `float` (family id `primitive.float`)

| Op id                     | File                       | Sig           | Category |
|---------------------------|----------------------------|---------------|----------|
| `primitive.float.add`     | `float/f32_add.rs`         | `(f32,f32)→f32` | A        |
| `primitive.float.sub`     | `float/f32_sub.rs`         | `(f32,f32)→f32` | A        |
| `primitive.float.mul`     | `float/f32_mul.rs`         | `(f32,f32)→f32` | A        |
| `primitive.float.div`     | `float/f32_div.rs`         | `(f32,f32)→f32` | A        |
| `primitive.float.abs`     | `float/f32_abs.rs`         | `(f32)→f32`     | A        |
| `primitive.float.neg`     | `float/f32_neg.rs`         | `(f32)→f32`     | A        |
| `primitive.float.sqrt`    | `float/f32_sqrt.rs`        | `(f32)→f32`     | C        |
| `primitive.float.sin`     | `float/f32_sin.rs`         | `(f32)→f32`     | C        |
| `primitive.float.cos`     | `float/f32_cos.rs`         | `(f32)→f32`     | C        |

## Benchmark axes

Every row above is benched at **N = 1 024 / 10 240 / 102 400 / 1 048 576** elements. Output columns:

- CPU ns/elt (single-threaded, via `CpuOp::cpu`)
- GPU ns/elt, kernel only (excludes upload/download)
- GPU ns/elt, end-to-end (includes both transfers)
- Crossover N — smallest N where end-to-end GPU beats CPU

Results are written to `benches/RESULTS.md` and mirrored into the top-of-README and the `Benchmarks` book chapter.

## KAT corpus target

Minimum 3 KAT vectors per op (boundary low, boundary high, midrange), minimum 1 adversarial per op (empty or short input). Files live at `rules/kat/primitive/<op_name>.toml`. Schema: `rules/SCHEMA.md#kat`.
