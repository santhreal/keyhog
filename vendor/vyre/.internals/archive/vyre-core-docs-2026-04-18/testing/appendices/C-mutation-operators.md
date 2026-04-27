# Appendix C — Mutation operator reference

The complete mutation catalog used by vyre's mutation gate.
Each entry is a specific transformation the gate applies to
source code to verify that tests catch the corresponding
class of bug.

The catalog is maintained in
`vyre-conform/src/mutations/`. This appendix is a
human-readable snapshot. The authoritative source is the
code; when they disagree, the code wins.

Mutation classes group related mutations. An op's
`mutation_sensitivity` declaration names which classes the
gate applies to the op's source. Tests for the op must
kill every mutation in the declared classes.

---

## ArithmeticMutations

Mutations that swap arithmetic operators or change
arithmetic constants.

- `+` ↔ `-`
- `*` ↔ `/`
- `*` ↔ `+`
- `wrapping_add` → `saturating_add`
- `wrapping_add` → `checked_add`
- `wrapping_sub` → `saturating_sub`
- `wrapping_mul` → `saturating_mul`
- `<<` ↔ `>>`
- Literal constant `0` → `1`
- Literal constant `1` → `0`
- Literal constant `N` → `N + 1`
- Literal constant `N` → `N - 1`
- Literal constant `u32::MAX` → `0`
- Literal constant `0` → `u32::MAX`

Ops sensitive: every primitive arithmetic op (`Add`, `Sub`,
`Mul`, `Shl`, `Shr`).

---

## ComparisonMutations

Mutations that alter comparison operators.

- `<` ↔ `<=`
- `>` ↔ `>=`
- `==` ↔ `!=`
- `<` ↔ `>`
- `<=` ↔ `>=`
- Boolean result negation

Ops sensitive: comparison ops (`Eq`, `Lt`, `Gt`), validators
that compare, conditional logic in lowering.

---

## BitwiseMutations

Mutations that alter bitwise operators.

- `&` ↔ `|`
- `^` ↔ `&`
- `^` ↔ `|`
- `!x` → `x`
- `x & mask` → `x` (mask removal)
- Constant mask `31u` → `32u`

Ops sensitive: `And`, `Or`, `Xor`, `Not`, `Popcount`, shift
masking in lowering.

---

## ControlFlowMutations

Mutations that alter control flow in source code.

- Delete `if` branch (take only the else)
- Delete `else` branch (take only the if)
- Invert condition (`cond` → `!cond`)
- Loop `0..n` → `0..n+1`
- Loop `0..n` → `0..n-1`
- Loop `0..n` → `1..n`
- `break` → `continue`
- `continue` → removed
- Early return removal

Ops sensitive: validators with branching logic, lowering
with conditional emission.

---

## BufferAccessMutations

Mutations that alter buffer indexing or access patterns.

- `buffer[i]` → `buffer[i - 1]`
- `buffer[i]` → `buffer[i + 1]`
- `buffer[i]` → `buffer[0]`
- `buffer[i]` → `buffer[len - 1]`
- Read vs write swap
- `BufferAccess::Storage` → `BufferAccess::Workgroup`
- `BufferAccess::Workgroup` → `BufferAccess::Storage`

Ops sensitive: buffer-accessing ops, lowering code for
buffer operations.

---

## OrderingMutations

Mutations that weaken atomic memory orderings.

- `Ordering::SeqCst` → `Ordering::AcqRel`
- `Ordering::AcqRel` → `Ordering::Acquire`
- `Ordering::Acquire` → `Ordering::Relaxed`
- `Ordering::Release` → `Ordering::Relaxed`

Ops sensitive: atomic ops (`AtomicAdd`, `AtomicCompareExchange`,
`AtomicMin`, `AtomicMax`).

---

## IrStructuralMutations

IR-level mutations that change op identities or types.

- `BinOp::Add` → `BinOp::Sub`
- `BinOp::Add` → `BinOp::Mul`
- `BinOp::Sub` → `BinOp::Add`
- `BinOp::Mul` → `BinOp::Add`
- `DataType::U32` → `DataType::I32`
- `DataType::U32` → `DataType::U64`
- Swap `reference_fn` with another op's reference_fn
- Delete an archetype from OpSpec
- Remove a validation rule from the validator

Ops sensitive: OpSpec registration, op metadata, validator
code.

---

## LawMutations

Mutations specifically targeting law declarations.

- `LawFalselyClaim { law, op }`: adds a falsely-claimed law
  to an op that does not satisfy it.
- `LawIdentityCorrupt { op, wrong_value }`: corrupts the
  identity element in an existing Identity law.
- `LawAbsorbingCorrupt { op, wrong_value }`: corrupts the
  absorbing element in an Absorbing law.
- `LawRemoveDeclaration { op, law }`: removes a declared
  law from an op.

Ops sensitive: every op with declared laws.

---

## LoweringMutations

Mutations that alter the lowering output.

- `LowerRemoveBoundsCheck`: removes a bounds-check guard
  from lowered buffer access.
- `LowerRemoveShiftMask`: removes the `& 31u` mask from
  lowered shifts.
- `LowerSwapOpEmission`: emits the wrong operator in the
  WGSL output (e.g., `+` instead of `-`).
- `LowerChangeWorkgroupSize`: modifies the workgroup_size
  declaration in the shader.
- `LowerDropBarrier`: removes a barrier emission.

Ops sensitive: lowering code, specifically
`src/lower/wgsl/*`.

---

## ConstantMutations

Mutations to literal constants beyond the arithmetic class.

- Integer literals: `N` → `N ± 1`, `N` → `0`, `N` → `N * 2`.
- String literals: change first character.
- Boolean literals: `true` ↔ `false`.
- Range literals: `0..N` → `1..N`, `0..N` → `0..N-1`.

Ops sensitive: anywhere constants appear in source.

---

## WireFormatConverterMutations

Mutations specific to the IR wire format → IR converter.

- `WireFormatConverterSwap { from, to }`: swaps the IR output
  for a specific wire tag.
- `WireFormatConverterSkip { tag }`: makes the converter
  skip a specific wire tag instead of decoding it.
- `WireFormatConverterDuplicate { tag }`: makes the
  converter decode the tag twice.

Sensitive code: `src/ir/wire/from_wire.rs` and related
modules.

---

## ValidationMutations

Mutations targeting the validator.

- `ValidationSkipRule { rule }`: removes a specific V-rule
  from the validator, so programs violating it are
  accepted.
- `ValidationWrongRule { from, to }`: makes the validator
  return a wrong rule ID for a violation.
- `ValidationMissingCheck { path }`: removes a specific
  check from a validation pass.

Sensitive code: `src/ir/validate/*`.

---

## What adding a mutation looks like

When a post-mortem reveals a new bug class, a new mutation
is added to the catalog:

1. A Rust definition of the mutation is added to
   `vyre-conform/src/mutations/<class>.rs`.
2. The `apply()` function for the class is extended to
   handle the new mutation.
3. The mutation is added to the relevant op's
   `mutation_sensitivity` if necessary.
4. A test is written that deliberately introduces the
   bug and verifies the gate catches it.

The catalog grows monotonically. Additions happen through
post-mortem PRs, not through casual expansions.

## Reference

The authoritative source is `vyre-conform/src/mutations/`.
This appendix reflects the state of the catalog at the
time of the book's last update. When implementing or
modifying the mutation gate, read the source; when
understanding the discipline, read this appendix.
