# Rule Condition Evaluation

## Status: Rebuilt as Category A compositions

The legacy eval engine (a GPU bytecode interpreter) has been removed.
It was a Category B violation — runtime interpretation on the GPU.

Rule condition evaluation is now implemented as **Category A
compositions** in `core/src/ops/rule/`. Each condition is a typed
operation that composes Layer 1 primitives:

- Boolean combinators: `Expr::and`, `Expr::or`, `Expr::not`
- Pattern predicates: `PatternExists`, `PatternCountGt`
- File predicates: `FileSizeLt`, `EntryCountGt`
- Positional predicates: `MatchOrder`, `MatchDistance`

Each rule's condition tree compiles to a single `ir::Program` via
`build_rule_program()`. The program is lowered through the standard
pipeline — no interpreter, no switch statement, no opcodes.

## How it works

A rule condition like "string A AND string B AND filesize > 1MB"
becomes:

```text
Program {
    entry: [
        let matched_a = Load(bitmaps, rule_id * words + string_a_word) & string_a_bit
        let matched_b = Load(bitmaps, rule_id * words + string_b_word) & string_b_bit
        let size_ok = Lt(LitU32(1048576), Load(file_context, 0))
        let result = And(And(matched_a, matched_b), size_ok)
        Store(output, rule_id, result)
    ]
}
```

One invocation per rule. No stack machine. No opcode dispatch. The
condition tree is flat IR that the lowering inlines completely.

## Why this is better

- **Category A.** The composition inlines at lowering time. The
  generated WGSL is identical to what a human would write.
- **Testable.** Each condition op has a CPU reference and can be
  verified by the conformance suite.
- **Composable.** Conditions compose with other ops via `Expr::Call`.
- **Retargetable.** The same condition works on WGSL, SPIR-V, PTX,
  Metal — any backend that lowers vyre IR.

## Historical reference

The deleted eval engine's bytecode format (102 opcodes, stack machine)
is documented in `bytecode/opcodes.md` for historical reference. The
opcode table is preserved so archived rule sets can be decoded, but
the GPU interpreter that executed them no longer exists.
