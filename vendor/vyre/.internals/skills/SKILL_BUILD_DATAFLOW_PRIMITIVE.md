# SKILL: Build a vyre-libs dataflow primitive

This skill is the contract every agent (Codex Spark, Kimi, Cursor)
must follow when adding a new dataflow / security / bitset primitive
to vyre-libs. Failing the contract = the file is rejected at the
gate (`scripts/check_primitive_contract.sh`) and CI is red.

## Files you create

Exactly **one** file per primitive, at one of:

- `vyre-libs/src/dataflow/<name>.rs` — generic dataflow ops
  (reachability, escape, range, def-use, points-to, summary, etc.).
- `vyre-libs/src/security/<name>.rs` — taint / sanitization /
  flow-with-sink compositions on top of dataflow primitives.
- `vyre-primitives/src/bitset/<name>.rs` — pure-bitset substrate
  ops (and / or / not / and_not / xor + their `_into` variants).
- `vyre-primitives/src/graph/<name>.rs` — substrate graph queries
  (csr_traverse / scc_decompose / path_reconstruct).

**No multi-file primitives.** If your op needs >1 file, you have
two primitives — split them.

## Required structure

Every primitive file MUST contain, in this order:

1. **Module doc comment.** Three sections:
   - 1-line tagline ("set difference of taint nodes by sanitizer label").
   - Semantics block — show the math / pseudocode the op computes.
   - Soundness annotation: `Exact` / `MayOver` / `MustUnder` with
     justification (link the soundness marker impl below).
2. **`pub(crate) const OP_ID: &str`** — stable op id of the form
   `vyre-libs::<domain>::<name>` or `vyre-primitives::<domain>::<name>`.
3. **`pub fn <name>(...) -> Program`** — the GPU emitter. Returns
   one `Program::wrapped(...)` with one `Node::Region { generator:
   Ident::from(OP_ID), ... }` at the entry. Buffer declarations
   match the function signature exactly (one BufferDecl per `&str`
   buffer-name parameter, in declaration order).
4. **`pub fn cpu_ref(...) -> ...`** — the CPU oracle. Identical
   semantics to the GPU emitter; tested for byte-equality against
   GPU output by the conformance harness.
5. **`pub struct <Name>;` + `impl SoundnessTagged for <Name>`** —
   only required for `dataflow/` and `security/` primitives, not
   `bitset/` / `graph/` substrate ops.
6. **`#[cfg(test)] mod tests`** — minimum 4 unit tests exercising
   the CPU oracle:
   - empty input → expected zero / identity
   - full input → expected saturated result
   - partial input → known specific value
   - idempotency / monotonicity (whichever applies)
7. **`inventory::submit! { OpEntry { ... } }`** — only required for
   `dataflow/` and `security/` (the harness picks them up at link
   time).

## Forbidden patterns

- `Program::new(...)` — use `Program::wrapped(...)`. The plain
  constructor is reserved for wire decode.
- `vec![offset; bytes.len()]` — per-byte source maps allocate
  gigabytes on real inputs. Use bounded `Vec<u32>` and cap the
  input.
- `_ => panic!(...)` / `_ => todo!(...)` / `_ => 0xFFFF_FFFF` /
  `_ => Expr::eq(left, right)` — every catch-all on a non-exhaustive
  enum is a silent-fail bug. Make the match exhaustive and document
  the conservative default explicitly.
- `expect("never fails")` — if the contract guarantees the
  invariant, document why; if the contract doesn't, propagate the
  error.
- Cross-file dependencies between primitives. Each primitive owns
  its buffer-name contract. Composition happens at the surgec
  lowering layer, not at the primitive layer.

## Worked examples

Read these as templates before writing a new primitive:

- `vyre-primitives/src/bitset/and_not.rs` — substrate bitset op
  with CPU oracle and 4 unit tests.
- `vyre-libs/src/security/taint_kill.rs` — security primitive
  composing one bitset op, with `SoundnessTagged` impl.
- `vyre-libs/src/security/flows_to_to_sink.rs` — composite
  primitive fusing three sub-Programs via `fuse_programs(...)`.
- `vyre-libs/src/dataflow/def_use.rs` — host-side query primitive
  packed into a bitset for the GPU hot path.

## How surgec consumes your primitive

1. Add a SURGE predicate name to
   `surgec/src/compile/predicates/stub_predicates.rs`'s
   `register_stub_predicates!` table (one line: name, arity, doc).
2. Add a `match` arm to `surgec/src/lower/call.rs::lower_call`
   that calls your primitive's `pub fn` with the lowered argument
   buffer names and binds the result to `binding.name`.
3. Add a proving + adversarial test to
   `surgec/tests/audit_compile_2026_04_24.rs` that compiles a
   SURGE rule using your predicate, dumps the emitted Program, and
   asserts (a) it contains a Region with your `OP_ID`, (b) it
   distinguishes between two distinct argument tuples, (c) any
   adversarial input documented in your CPU-oracle test fires the
   right way.

A primitive without all three wiring steps is invisible to the
scanner. The gate script verifies (1) and (2); (3) is verified by
the existing `audit_compile_2026_04_24` test harness.

## Acceptance gate (auto-run by CI)

`scripts/check_primitive_contract.sh <path/to/primitive.rs>` exits
0 if the file:

- contains the seven required structural pieces above,
- references no forbidden patterns,
- has ≥4 `#[test]` items in its `tests` module,
- is ≤600 LOC,
- declares a `pub(crate) const OP_ID` matching the file's namespace.

CI runs the script over every changed file under `vyre-libs/src/`
and `vyre-primitives/src/`; any nonzero exit fails the PR.
