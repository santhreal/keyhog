# V7 Agent A — plan (scaffolding + Cat-C hardware intrinsics)

You own `vyre-ops` scaffolding + all 20 Cat-C hardware intrinsic files
+ the three vyre-reference interpreter extensions. Agent B works in
parallel on `vyre-ops/src/composite/` — you will NOT touch that
directory.

**Workdir**: `/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre`.

## HARD RULES

1. **No destructive git operations.** Only `git add`, `git commit`,
   `git status`, `git diff`, `git log`. NEVER
   `git checkout <path>`, `git reset`, `git rm`, `git clean`, `git
   stash drop`, `git restore`. If a file you wrote is gone, it is
   gone — rewrite from your own memory, do not restore from git.
2. **Commit after EVERY file.** The environment intermittently
   deletes tracked vyre-ops files; frequent commits minimize the
   blast radius.
3. **No raw WGSL strings anywhere in `vyre-ops/`**. Every op is
   constructed from `vyre::ir::Expr`, `Node`, `BinOp`, `UnOp`,
   `AtomicOp`, `DataType`. CI gate `scripts/check_no_string_wgsl.sh`
   enforces.
4. **No Co-Authored-By or AI attribution in commit messages.**
5. **No push** — commits stay local.
6. **Every Cat-C op wraps its body in `Node::Region`** using
   `crate::region::wrap_anonymous("vyre-ops::hardware::<op_name>",
   body)`. This is the Region chain invariant from
   `docs/region-chain.md`.
7. **LAW 1 — no stubs.** Every op you register must fully execute
   on the CPU reference (byte-identical to the documented spec) and
   have unit tests that pass. No `todo!()`, no `unimplemented!()`,
   no inert bodies.

## Your scope (20 Cat-C intrinsic files + scaffolding)

Scaffolding (commit these FIRST, before any op files):

1. Add `"vyre-ops",` to `members = [ ... ]` in workspace root
   `/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/Cargo.toml`.
   Commit.
2. Write `vyre-ops/Cargo.toml` with feature gates for
   `hardware`, `composite` (depends on hardware), `subgroup-ops`
   (off by default), plus the existing `logical`, `math`, `primitive`,
   `rule` features. Use the Cargo.toml template at the end of this
   doc. Commit.
3. Write `vyre-ops/src/lib.rs` with declarations for `hardware`,
   `composite`, and the shared `region` + `harness` modules.
   Template at the end of this doc. Commit.
4. Write `vyre-ops/src/harness.rs` — the `OpEntry` registry.
   Template at the end of this doc. Commit.
5. Write `vyre-ops/src/region.rs` — the `wrap_anonymous` /
   `wrap_child` helpers. Template at the end of this doc. Commit.
6. Write `vyre-ops/src/hardware/mod.rs` with shared helpers
   (`unary_u32_program`, `ternary_f32_program`, `atomic_serial_program`,
   `atomic_compare_exchange_program`, `pack_u32`, `pack_f32`,
   `run_program`, `lcg_u32`, `lcg_f32`, `MAP_WORKGROUP`,
   `SERIAL_WORKGROUP`). Template at the end. Commit.
7. Write `vyre-ops/src/composite/mod.rs` as a stub so Agent B's
   `composite/` tree wires in. Content:
   ```rust
   //! Cat-A compositional ops (Tier-2 stdlib). Populated by Agent B.
   // Each subdir is owned by Agent B — Agent A does not modify.
   ```
   Commit.

After scaffolding commits land, write the 20 hardware intrinsic files
below, committing per file. Agent B starts working on `composite/`
as soon as your Cargo.toml + lib.rs + harness.rs + region.rs commits
exist.

### Atomic ops (8 files) — use `atomic_serial_program` / `atomic_compare_exchange_program`

Layout: `vyre-ops/src/hardware/<op>/{mod.rs,<op>.rs}` where `<op>` is
each of the names below. `mod.rs` is one line: `pub mod <op>; pub use
<op>::<op>;`.

- `atomic_add_u32` — `Expr::Atomic { op: AtomicOp::Add, ... }`. CPU
  ref: `state.wrapping_add(value)`; trace = pre-op state.
- `atomic_min_u32` — `AtomicOp::Min`. CPU ref: `state.min(value)`.
- `atomic_max_u32` — `AtomicOp::Max`. CPU ref: `state.max(value)`.
- `atomic_and_u32` — `AtomicOp::And`. CPU ref: `state & value`.
- `atomic_or_u32` — `AtomicOp::Or`. CPU ref: `state | value`.
- `atomic_xor_u32` — `AtomicOp::Xor`. CPU ref: `state ^ value`.
- `atomic_exchange_u32` — `AtomicOp::Exchange`. CPU ref: returns old
  state, stores new value.
- `atomic_compare_exchange_u32` — uses
  `atomic_compare_exchange_program`. Signature takes expected + desired
  buffers. CPU ref: if `state == expected[i]`, write `desired[i]` and
  emit old state; else leave state and emit old state.

Each file follows the template below, just swap the atomic op and the
CPU ref closure. Public fn signature:
`pub fn <name>(values: &str, state: &str, trace: &str, n: u32) -> Program`
except compare-exchange which is
`pub fn atomic_compare_exchange_u32(expected: &str, desired: &str, state: &str, trace: &str, n: u32) -> Program`.

### Bit ops (4 files) — use `unary_u32_program`

- `popcount_u32` — `Expr::popcount`. CPU ref: `u32::count_ones`.
- `lzcnt_u32` — `Expr::clz`. CPU ref: `u32::leading_zeros`.
- `tzcnt_u32` — `Expr::ctz`. CPU ref: `u32::trailing_zeros`.
- `bit_reverse_u32` — `Expr::reverse_bits`. CPU ref: `u32::reverse_bits`.

Public fn: `pub fn <name>(input: &str, out: &str, n: u32) -> Program`.

### Float intrinsics (2 files)

- `fma_f32` — uses `ternary_f32_program`. Public fn:
  `pub fn fma_f32(a: &str, b: &str, c: &str, out: &str, n: u32) -> Program`.
  CPU ref per lane: `a.mul_add(b, c)` (BYTE-IDENTICAL — never
  multiply-then-add).
- `inverse_sqrt_f32` — custom body using `Expr::f32_div(Expr::f32(1.0),
  Expr::f32_sqrt(...))`. Public fn: `pub fn inverse_sqrt_f32(input,
  out, n) -> Program`. CPU ref: `1.0 / x.sqrt()` bit-exact.

### Other (3 files)

- `clamp_u32` — `min(max(x, lo), hi)` via `Expr::min` / `Expr::max`
  (BinOp::Min/Max work on u32). Signature: `pub fn clamp_u32(input,
  lo, hi, out, n) -> Program`. CPU ref: `x.clamp(lo, hi)`.
- `workgroup_barrier` — per-lane identity store + `Node::barrier()`.
  Signature: `pub fn workgroup_barrier(input, out, n) -> Program`.
  CPU ref: identity. Op id distinguishes from storage_barrier.
- `storage_barrier` — same body, different op id. CPU ref: identity.

### Subgroup ops (3 files) — feature-gated behind `subgroup-ops`

Each file follows the hardware/ op template but the
`inventory::submit!` line is wrapped in
`#[cfg(feature = "subgroup-ops")]` and every `fn cpu_ref` / `fn
fixture_cases` / `fn test_inputs` / `fn expected_output` helper is
wrapped in `#[cfg(any(test, feature = "subgroup-ops"))]`.

- `subgroup_ballot` — `Expr::SubgroupBallot { cond: Box::new(...) }`.
  Signature: `pub fn subgroup_ballot(cond_input, out, n) -> Program`.
  CPU ref: `u32::from(cond == 1)` per lane (single-lane serial wave).
- `subgroup_shuffle` — `Expr::SubgroupShuffle { value, lane }`.
  Signature: `pub fn subgroup_shuffle(values, lanes, out, n) -> Program`.
  CPU ref: `if lane == 0 { value } else { 0 }`.
- `subgroup_add` — `Expr::SubgroupAdd { value }`. Signature:
  `pub fn subgroup_add(values, out, n) -> Program`. CPU ref:
  identity (single-lane reduction).

### vyre-reference interpreter extensions (2 files)

After hardware ops, extend the CPU interpreter so the subgroup ops
evaluate on single-lane serial mode:

1. `vyre-reference/src/eval_expr.rs` — in `linearize_expr`, add arms
   for `Expr::SubgroupBallot`, `Expr::SubgroupShuffle`, `Expr::SubgroupAdd`.
   Each pushes a new internal `OpCode` variant:
   - `OpCode::SubgroupBallot` — pops 1 value (cond), pushes
     `Value::U32(if cond.truthy() { 1 } else { 0 })`.
   - `OpCode::SubgroupShuffle` — pops lane (u32), value; pushes
     `if lane == 0 { value } else { Value::U32(0) }`.
   - `OpCode::SubgroupAdd` — no-op (value already on stack).
   Add these variants to the `OpCode` enum; handle them in
   `eval_flat_ops`.
2. `vyre-reference/src/hashmap_interp.rs` — add equivalent arms for
   the same three variants in the `eval_expr` match (returns `Value`).
   Place them next to `Expr::Opaque` arm; use the serial-wave
   semantics above.

### Test harness

Write `vyre-ops/tests/hardware_conform.rs`:

```rust
//! Cat-C hardware intrinsic differential harness — runs CPU ref
//! side by side with the registered OpEntry body and asserts the
//! readback bytes are byte-identical.

use vyre_ops::harness::{all_entries, OpEntry};
use vyre_reference::value::Value;

fn run_cpu(entry: &OpEntry, inputs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let program = (entry.build)();
    let values: Vec<Value> = inputs.iter().map(|b| Value::Bytes(b.clone().into())).collect();
    vyre_reference::run(&program, &values)
        .expect("hardware op must execute")
        .into_iter()
        .map(|v| v.to_bytes())
        .collect()
}

#[test]
fn hardware_entries_match_expected_output_on_cpu_ref() {
    let entries: Vec<_> = all_entries()
        .filter(|e| e.id.starts_with("vyre-ops::hardware::"))
        .collect();
    assert!(!entries.is_empty(), "no hardware entries registered — check feature gates");
    for entry in entries {
        let inputs = (entry.test_inputs.expect("test_inputs required"))();
        let expected = (entry.expected_output.expect("expected_output required"))();
        assert_eq!(inputs.len(), expected.len(), "{}: fixture count mismatch", entry.id);
        for (case_idx, (case_inputs, case_expected)) in inputs.iter().zip(expected.iter()).enumerate() {
            let got = run_cpu(entry, case_inputs);
            assert_eq!(&got, case_expected, "{} case {}: CPU ref drifted from expected_output", entry.id, case_idx);
        }
    }
}
```

### Final verification steps

After every op file + the two interpreter extensions + the test file
land:

```bash
cd /media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre
cargo fmt -p vyre-ops -- --check
cargo clippy -p vyre-ops --all-features --all-targets -- -D warnings
cargo test -p vyre-ops --lib --all-features
cargo test -p vyre-ops --test hardware_conform --all-features
```

All four must pass clean. If clippy complains about
`module_inception`, confirm `#![allow(clippy::module_inception)]` is
in `vyre-ops/src/lib.rs`.

### Coordination with Agent B

- Agent B works ONLY in `vyre-ops/src/composite/` and depends on your
  scaffolding commits (step 1-7 above). Your scaffolding includes
  `composite/mod.rs` stub so Agent B can immediately start adding
  subdirectories.
- If you need to edit a file outside `vyre-ops/src/hardware/`,
  `vyre-ops/src/composite/mod.rs` (stub only), `vyre-ops/Cargo.toml`,
  `vyre-ops/src/lib.rs`, `vyre-ops/src/harness.rs`,
  `vyre-ops/src/region.rs`, `vyre-ops/src/hardware/mod.rs`,
  `vyre-ops/tests/hardware_conform.rs`, or
  `vyre-reference/src/{eval_expr,hashmap_interp}.rs` — STOP and note
  it in a separate doc; do not touch Agent B's files.
- Rebases: if your work conflicts with Agent B's, resolve conflicts
  in YOUR commits only (never force-push or overwrite B's work).

---

## Scaffolding templates

### `vyre-ops/Cargo.toml`

```toml
[package]
name = "vyre-ops"
version = "0.6.0"
edition.workspace = true
rust-version.workspace = true
license.workspace = true
authors.workspace = true
repository.workspace = true
homepage.workspace = true
description = "Ops layer: Cat-C hardware intrinsics + Cat-A composite stdlib over the vyre IR."
readme = "README.md"
keywords = ["gpu", "stdlib", "dialect", "ir", "vyre"]
categories = ["algorithms", "compilers", "hardware-support"]
documentation = "https://docs.rs/vyre-ops"

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]

[dependencies]
vyre-foundation = { version = "0.6.0", path = "../vyre-foundation" }
vyre-driver = { version = "0.6.0", path = "../vyre-driver" }
vyre-spec.workspace = true
vyre-macros.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tracing.workspace = true
rustc-hash.workspace = true
smallvec.workspace = true
blake3.workspace = true
bytemuck.workspace = true
inventory.workspace = true
toml.workspace = true

[dev-dependencies]
vyre = { workspace = true }
vyre-reference = { version = "0.6.0", path = "../vyre-reference" }

[features]
default = ["all"]
all = ["composite", "hardware", "logical", "math", "primitive", "rule"]
composite = ["hardware"]
hardware = []
logical = []
math = []
primitive = []
rule = []
subgroup-ops = []

[lints]
workspace = true
```

### `vyre-ops/src/lib.rs`

```rust
#![allow(clippy::ptr_arg, clippy::should_implement_trait, clippy::module_inception)]
//! vyre-ops — the standard op library for vyre.
#![allow(missing_docs)]

pub mod contracts;
pub mod signatures;
pub use signatures::*;
pub mod test_migration;
pub mod region;

#[doc(hidden)]
pub mod harness;

pub use vyre_foundation::cpu_op::{self, structured_intrinsic_cpu, CategoryAOp, CpuOp};
pub use vyre_spec::{AlgebraicLaw, Backend, BackendId, CpuFn, IntrinsicDescriptor};

#[cfg(feature = "hardware")]
pub mod hardware;
#[cfg(feature = "composite")]
pub mod composite;
#[cfg(feature = "logical")]
pub mod logical;
#[cfg(feature = "math")]
pub mod math;
#[cfg(feature = "rule")]
pub mod rule;
```

### `vyre-ops/src/harness.rs`

```rust
//! Inventory-backed OpEntry registry for the differential harness.

use vyre_foundation::ir::Program;

pub type Fixture = Vec<Vec<u8>>;
pub type Fixtures = Vec<Fixture>;
pub type InputsFn = fn() -> Fixtures;
pub type ExpectedFn = fn() -> Fixtures;

#[non_exhaustive]
pub struct OpEntry {
    pub id: &'static str,
    pub build: fn() -> Program,
    pub test_inputs: Option<InputsFn>,
    pub expected_output: Option<ExpectedFn>,
}

inventory::collect!(OpEntry);

pub fn all_entries() -> impl Iterator<Item = &'static OpEntry> {
    inventory::iter::<OpEntry>()
}
```

### `vyre-ops/src/region.rs`

```rust
//! Region builder — mandatory wrap-every-body helper.
//! Spec: docs/region-chain.md.

use std::sync::Arc;
use vyre_foundation::ir::model::expr::{GeneratorRef, Ident};
use vyre_foundation::ir::Node;

#[must_use]
pub fn wrap(generator: &str, body: Vec<Node>, source_region: Option<GeneratorRef>) -> Node {
    Node::Region {
        generator: Ident::from(generator),
        source_region,
        body: Arc::new(body),
    }
}

#[must_use]
pub fn wrap_anonymous(generator: &str, body: Vec<Node>) -> Node {
    wrap(generator, body, None)
}

#[must_use]
pub fn wrap_child(generator: &str, parent: GeneratorRef, body: Vec<Node>) -> Node {
    wrap(generator, body, Some(parent))
}
```

### `vyre-ops/src/hardware/mod.rs`

See `docs/V7_AGENT_A_SHARED_HELPERS.md` (file you'll create next —
copy the full content below into it AND into `hardware/mod.rs`):

```rust
//! Cat-C hardware intrinsics. Each lowers to one hardware instruction.

use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

pub mod atomic_add_u32;
pub mod atomic_and_u32;
pub mod atomic_compare_exchange_u32;
pub mod atomic_exchange_u32;
pub mod atomic_max_u32;
pub mod atomic_min_u32;
pub mod atomic_or_u32;
pub mod atomic_xor_u32;
pub mod bit_reverse_u32;
pub mod clamp_u32;
pub mod fma_f32;
pub mod inverse_sqrt_f32;
pub mod lzcnt_u32;
pub mod popcount_u32;
pub mod storage_barrier;
pub mod subgroup_add;
pub mod subgroup_ballot;
pub mod subgroup_shuffle;
pub mod tzcnt_u32;
pub mod workgroup_barrier;

pub(crate) const SERIAL_WORKGROUP: [u32; 3] = [1, 1, 1];
pub(crate) const MAP_WORKGROUP: [u32; 3] = [64, 1, 1];

pub(crate) fn unary_u32_program<F>(input: &str, out: &str, n: u32, expr: F) -> Program
where
    F: Fn(Expr) -> Expr,
{
    let body = vec![crate::region::wrap_anonymous(
        "vyre-ops::hardware::unary_u32_map",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(out, Expr::var("idx"), expr(Expr::load(input, Expr::var("idx"))))],
            ),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(input, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::output(out, 1, DataType::U32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

pub(crate) fn ternary_f32_program(a: &str, b: &str, c: &str, out: &str, n: u32) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        "vyre-ops::hardware::ternary_f32_map",
        vec![
            Node::let_bind("idx", Expr::InvocationId { axis: 0 }),
            Node::if_then(
                Expr::lt(Expr::var("idx"), Expr::buf_len(out)),
                vec![Node::store(
                    out, Expr::var("idx"),
                    Expr::Fma {
                        a: Box::new(Expr::load(a, Expr::var("idx"))),
                        b: Box::new(Expr::load(b, Expr::var("idx"))),
                        c: Box::new(Expr::load(c, Expr::var("idx"))),
                    },
                )],
            ),
        ],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(a, 0, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(b, 1, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::storage(c, 2, BufferAccess::ReadOnly, DataType::F32).with_count(n),
            BufferDecl::output(out, 3, DataType::F32).with_count(n),
        ],
        MAP_WORKGROUP,
        body,
    )
}

pub(crate) fn atomic_serial_program<F>(
    values: &str, state: &str, trace: &str, n: u32, atomic_expr: F,
) -> Program
where
    F: Fn(Expr) -> Expr,
{
    let body = vec![crate::region::wrap_anonymous(
        "vyre-ops::hardware::atomic_serial",
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![Node::loop_for(
                "i", Expr::u32(0), Expr::buf_len(values),
                vec![
                    Node::let_bind("v", Expr::load(values, Expr::var("i"))),
                    Node::let_bind("old", atomic_expr(Expr::var("v"))),
                    Node::store(trace, Expr::var("i"), Expr::var("old")),
                ],
            )],
        )],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(values, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::read_write(state, 1, DataType::U32).with_count(1),
            BufferDecl::output(trace, 2, DataType::U32).with_count(n),
        ],
        SERIAL_WORKGROUP,
        body,
    )
}

pub(crate) fn atomic_compare_exchange_program(
    expected: &str, desired: &str, state: &str, trace: &str, n: u32,
) -> Program {
    let body = vec![crate::region::wrap_anonymous(
        "vyre-ops::hardware::atomic_compare_exchange_serial",
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![Node::loop_for(
                "i", Expr::u32(0), Expr::buf_len(expected),
                vec![
                    Node::let_bind(
                        "old",
                        Expr::Atomic {
                            op: vyre_foundation::ir::AtomicOp::CompareExchange,
                            buffer: state.into(),
                            index: Box::new(Expr::u32(0)),
                            expected: Some(Box::new(Expr::load(expected, Expr::var("i")))),
                            value: Box::new(Expr::load(desired, Expr::var("i"))),
                        },
                    ),
                    Node::store(trace, Expr::var("i"), Expr::var("old")),
                ],
            )],
        )],
    )];
    Program::wrapped(
        vec![
            BufferDecl::storage(expected, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(desired, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::read_write(state, 2, DataType::U32).with_count(1),
            BufferDecl::output(trace, 3, DataType::U32).with_count(n),
        ],
        SERIAL_WORKGROUP,
        body,
    )
}

pub(crate) fn pack_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}
pub(crate) fn pack_f32(values: &[f32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

#[cfg(test)]
pub(crate) fn run_program(program: &Program, inputs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    use vyre_reference::value::Value;
    let values: Vec<Value> = inputs.into_iter().map(|b| Value::Bytes(b.into())).collect();
    vyre_reference::run(program, &values)
        .expect("hardware op must execute")
        .into_iter()
        .map(|v| v.to_bytes())
        .collect()
}

#[cfg(test)]
pub(crate) fn lcg_u32(seed: u32, len: usize) -> Vec<u32> {
    let mut s = seed;
    (0..len).map(|_| { s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223); s }).collect()
}
#[cfg(test)]
pub(crate) fn lcg_f32(seed: u32, len: usize) -> Vec<f32> {
    lcg_u32(seed, len).into_iter().map(|w| f32::from_bits((w >> 9) | 0x3F00_0000) - 1.0).collect()
}
```

### Template for a typical Cat-C hardware op file

See `vyre-ops/src/hardware/popcount_u32/popcount_u32.rs` — your first
op after scaffolding. Every other op follows the same shape; only
the function body, op id, CPU ref closure, and fixture cases change.

```rust
//! Cat-C `<op_name>` — <one-line description>.
//! CPU reference: <exact Rust expression> bit-exact.

use vyre_foundation::ir::{Expr, Program};
use crate::hardware::{pack_u32, unary_u32_program};

#[must_use]
pub fn <op_name>(input: &str, out: &str, n: u32) -> Program {
    unary_u32_program(input, out, n, Expr::<intrinsic>)
}

fn cpu_ref(input: &[u32]) -> Vec<u8> {
    pack_u32(&input.iter().map(|v| v.<intrinsic>()).collect::<Vec<_>>())
}

fn test_inputs() -> Vec<Vec<Vec<u8>>> {
    let input = vec![0u32, 1, 0xFFFF_FFFF, 0x1234_5678];
    let len = input.len() * 4;
    vec![vec![pack_u32(&input), vec![0u8; len]]]
}

fn expected_output() -> Vec<Vec<Vec<u8>>> {
    let input = vec![0u32, 1, 0xFFFF_FFFF, 0x1234_5678];
    vec![vec![cpu_ref(&input)]]
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-ops::hardware::<op_name>",
        build: || <op_name>("input", "out", 4),
        test_inputs: Some(test_inputs),
        expected_output: Some(expected_output),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{lcg_u32, run_program};

    fn assert_case(input: &[u32]) {
        let n = input.len() as u32;
        let program = <op_name>("input", "out", n.max(1));
        let outputs = run_program(&program, vec![pack_u32(input), vec![0u8; (n.max(1) * 4) as usize]]);
        assert_eq!(outputs, vec![cpu_ref(input)]);
    }

    #[test] fn one_element() { assert_case(&[1]); }
    #[test] fn max_value() { assert_case(&[u32::MAX]); }
    #[test] fn random_sixty_four() {
        let input = lcg_u32(0xC0FF_EE11, 64);
        assert_case(&input);
    }
}
```

---

## Done = shipped when

- All 20 op files land with green unit tests + green conform test.
- `cargo clippy -p vyre-ops --all-features --all-targets -- -D warnings` is clean.
- `cargo test -p vyre-ops --all-features` reports ≥113 pass / 0 fail.
- vyre-reference subgroup handlers land and survive `cargo test -p vyre-reference`.
- Commits: one per scaffolding step (≥7), one per hardware op (20),
  one for vyre-reference eval_expr extension, one for hashmap_interp
  extension, one for hardware_conform test. ≈30 commits total.

**When done, STOP. Do not push. Do not touch `composite/`. Report back which commits landed.**
