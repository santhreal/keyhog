# Compiler Product Boundary And Implementation Plan

This document defines how to grow a full C compiler on top of `vyre`
without distorting `vyre`'s vision, while preserving the lego-block
philosophy and leaving room for future compilers (Rust and beyond).

The governing rule is simple:

- `vyre` owns computations, runtime substrate, reusable passes,
reusable data contracts, and reusable domain-specific compiler
machinery.
- external product repos own packaging, CLI, project/build UX,
artifact layout, configuration discovery, diagnostics presentation,
and end-user workflow.

The boundary is not "generic vs domain-specific".
The boundary is "semantic computation surface vs packaging".

## Core Decision

The C compiler should be built mostly inside `vyre`, but the
user-facing packaged compiler should live outside `vyre`.

That means:

- C lexer / preprocessor / parser / semantic analysis / CFG / SSA /
dataflow / lowering / codegen machinery may live inside `vyre`
as long as they are real ops, passes, runtime services, or stable
reusable computation surfaces.
- the end-user compiler product should be a separate repo that wires
those surfaces together into a usable tool.

This is the same pattern as `VyreOffload`:

- substrate and domain-specific execution logic stay in `vyre`
- packaging and user-facing product concerns live outside `vyre`

## Recommended External Product Name

Recommended packaged repo name:

- `vyrec`

Why:

- short
- obvious: "vyre C compiler"
- scales well alongside future siblings like `vyrerust`
- product-like without claiming that `vyre` itself is the compiler

Recommended future family:

- `vyrec` for the packaged C compiler
- `vyrerust` for the packaged Rust compiler
- `vyrego` if a Go compiler product ever appears

Do not name the external product repo `vyre-c-compiler` unless you
want a purely descriptive temporary name. That is acceptable as an
internal spike repo, but `vyrec` is the better durable product name.

## Boundary Policy

Inside `vyre`

- runtime substrate
- megakernel
- queueing, scheduling, observability, fault protocol
- reusable packed AST / IR / graph contracts
- compiler passes with stable inputs and outputs
- parser stages
- preprocessor stages
- language-specific semantic passes
- generic compiler-core passes
- codegen-core surfaces
- target-specific execution/codegen machinery if it is a reusable
semantic surface rather than packaging glue

Outside `vyre`

- CLI
- project model
- build graph UX
- config discovery
- compile_commands / workspace ingestion
- file walking and source collection policy
- artifact naming and layout
- cache directory policy
- human diagnostics rendering
- progress UI
- editor/IDE/LSP integration
- distribution/release packaging

Not allowed to masquerade as ops

- "compile this project"
- "run all stages in order for product X"
- "find files, choose targets, write object files, print errors"
- giant monolithic orchestration wrappers with no reusable contract

## What Must Stay As Subfolders, Not Microcrates

The current decision is correct: do not split compiler domains into a
swarm of `vyre-libs-*` microcrates. Keep the architecture mostly as
subfolders/modules inside the existing main crates unless a split is
justified by a strong, stable boundary.

Use subfolder/module boundaries first.
Only split into crates when one of these becomes true:

- independent release cadence is necessary
- dependency isolation is necessary
- the API is frozen and broadly reusable
- the codebase becomes unmanageable inside the current crate

For now, the compiler roadmap should assume folder-level organization,
not crate proliferation.

## Target Folder Structure Inside `vyre`

This is the recommended target structure to grow toward.

### `vyre-runtime`

Purpose:

- universal persistent job runtime
- generic megakernel execution substrate

Target structure:

```text
vyre-runtime/
  src/
    megakernel/
      mod.rs
      protocol.rs
      builder.rs
      handlers.rs
      scheduler.rs
      descriptor.rs
      continuation.rs
      telemetry.rs
      fault.rs
      io/
        mod.rs
        queue.rs
        uring.rs
        dma.rs
```

### `vyre-foundation`

Purpose:

- stable IR/data contracts, validation, transforms, packed compiler
data structures

Target structure:

```text
vyre-foundation/
  src/
    ir/
    validation/
    transform/
    compiler/
      mod.rs
      packed_ast.rs
      packed_cfg.rs
      packed_ssa.rs
      packed_symbols.rs
      packed_types.rs
      spans.rs
      diagnostics.rs
```

### `vyre-libs`

Purpose:

- reusable compiler and parsing lego blocks
- domain-specific computation surfaces

Target structure:

```text
vyre-libs/
  src/
    parsing/
      mod.rs
      core/
        mod.rs
        token_stream.rs
        delimiter.rs
        statements.rs
        ast/
          mod.rs
          node.rs
          shunting.rs
          walk.rs
        grammar/
          mod.rs
          lr.rs
          recursive_descent.rs
      c/
        mod.rs
        lex/
          mod.rs
          lexer.rs
          keyword.rs
          tokens.rs
        preprocess/
          mod.rs
          include_graph.rs
          macros.rs
          conditionals.rs
          expansion.rs
          line_map.rs
        parse/
          mod.rs
          declarations.rs
          expressions.rs
          statements.rs
          structures.rs
          initializers.rs
          attributes.rs
          gnu_builtins.rs
          inline_asm.rs
        sema/
          mod.rs
          scopes.rs
          symbols.rs
          types.rs
          layout.rs
          const_eval.rs
          linkage.rs
        lower/
          mod.rs
          ast_to_cfg.rs
          cfg_to_ssa.rs
          abi.rs
          object.rs
        pipeline/
          mod.rs
          examples.rs
          stage_contracts.rs
    compiler/
      mod.rs
      cfg/
        mod.rs
        build.rs
        simplify.rs
      ssa/
        mod.rs
        build.rs
        phi.rs
      dataflow/
        mod.rs
        lattice.rs
        fixed_point.rs
        analyses.rs
      symbols/
        mod.rs
        interner.rs
        scopes.rs
        tables.rs
      types/
        mod.rs
        layout.rs
        unify.rs
      optimize/
        mod.rs
        cse.rs
        dce.rs
        fold.rs
      codegen/
        mod.rs
        regalloc.rs
        stack_layout.rs
        reloc.rs
        object_writer.rs
```

### `vyre-cc`

Purpose:

- C-specific high-level compiler surface inside `vyre`
- no packaging or CLI
- stable programmatic API used by the external packaged compiler

Target structure:

```text
vyre-cc/
  src/
    lib.rs
    api/
      mod.rs
      compile_unit.rs
      options.rs
      outputs.rs
      errors.rs
    frontend/
      mod.rs
      preprocess.rs
      lex.rs
      parse.rs
      sema.rs
    middle/
      mod.rs
      cfg.rs
      ssa.rs
      optimize.rs
    backend/
      mod.rs
      lower.rs
      abi.rs
      object.rs
    target/
      mod.rs
      x86_64.rs
    tests/
      mod.rs
```

The important point:

- `vyre-libs` owns reusable building blocks
- `vyre-cc` owns the C-language composition surface
- neither owns packaging

## External Product Repo Structure

Recommended packaged repo:

- `vyrec`

Target structure:

```text
vyrec/
  Cargo.toml
  README.md
  src/
    main.rs
    cli/
      mod.rs
      args.rs
      config.rs
    driver/
      mod.rs
      workspace.rs
      compile_commands.rs
      source_discovery.rs
      pipeline.rs
      cache.rs
      artifacts.rs
    diagnostics/
      mod.rs
      render.rs
      spans.rs
      pretty.rs
    integration/
      mod.rs
      linker.rs
      toolchain.rs
      sysroot.rs
  tests/
    smoke/
    corpus/
    linux/
```

This repo should depend on:

- `vyre`
- `vyre-foundation`
- `vyre-runtime`
- `vyre-libs`
- `vyre-cc`

It should not duplicate compiler semantics that belong inside `vyre`.

## What Needs To Move Or Be Reorganized Right Now

### Keep

Keep inside `vyre`:

- megakernel runtime
- slot protocol
- scheduler
- parser primitives
- bracket matching
- DFA lexer execution
- AST builders
- scope/type/layout/dataflow/codegen computations

### Reorganize

The biggest current structural issue is that parser/compiler orchestration
and reusable compiler stages are not cleanly separated.

Immediate reorganization targets:

- [vyre-libs/src/parsing/c11/pipeline.rs](/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/vyre-libs/src/parsing/c11/pipeline.rs:1)
- [vyre-libs/src/parsing/c11](/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/vyre-libs/src/parsing/c11/mod.rs:1)
- [vyre-libs/src/parsing/ast](/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/vyre-libs/src/parsing/ast/mod.rs:1)
- [vyre-libs/src/parsing](/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/vyre-libs/src/parsing/mod.rs:1)

Required change:

- split "stage ops" from "full product orchestration"
- demote giant orchestration demos into examples or explicit staged
composition docs
- move reusable passes into stable folders with stable contracts

### Do Not Keep As-Is

Do not keep giant end-to-end orchestration files pretending to be one
clean reusable op surface.

If a file is mostly:

- "call phase A"
- barrier
- "call phase B"
- barrier
- "call phase C"

then it is probably not a true reusable op. It is a stage runner or
example workflow and should be treated as such.

## Full C Compiler Roadmap

This roadmap assumes the long-term goal is eventually to support
Linux-kernel-class workloads, while also keeping the architecture
usable for future compilers.

### Phase 0: Architecture Cleanup

Goal:

- establish the boundaries before adding more compiler surface

Tasks:

- freeze the "inside `vyre` vs outside packaged repo" boundary
- adopt the folder structure above
- classify every current parser/compiler file into one of:
  - reusable op/pass
  - language-specific reusable computation surface
  - example/demo
  - packaging concern
- move orchestration demos out of the main reusable path

Done means:

- no ambiguity about where new compiler work lands
- no more giant pipeline files being added to reusable folders

### Phase 1: Megakernel Becomes Universal Job Runtime

Goal:

- make the runtime truly suitable for compiler-scale workloads

Tasks:

- separate runtime/transport opcodes from semantic work opcodes
- add descriptor-driven payloads instead of growing `arg0..argN`
- add continuation states:
  - `done`
  - `yield`
  - `wait_io`
  - `requeue`
  - `fault`
- add stronger scheduler semantics:
  - priority classes
  - starvation tracking
  - tenant quotas
  - fairness metrics
- add typed host submission and completion APIs
- harden observability:
  - metrics
  - trace records
  - structured faults

Done means:

- parser and compiler stages can run as normal megakernel jobs
- no parser-specific runtime is needed

### Phase 2: Parse-Core Foundation

Goal:

- build reusable parsing substrate that future languages can share

Tasks:

- token stream contract
- source span contract
- statement partitioning
- delimiter/bracket matching
- generic AST node and packed AST layout
- generic AST traversal ops
- parser stack/arena/interner helpers
- generic expression-tree builders where sensible

Done means:

- future `rust/`, `go/`, `python/` parsing code can reuse the same
substrate instead of copying C-specific logic

### Phase 3: C Lexer Completeness

Goal:

- exact lexical correctness for real C inputs

Tasks:

- identifiers and keywords
- numeric literals
- string/char literals
- comments and whitespace
- escapes
- digraphs/trigraphs if supported
- line splicing
- exact source span mapping
- token output contracts stable enough for downstream passes

Done means:

- large real C corpora lex correctly
- token spans and token kinds are trustworthy

### Phase 4: Preprocessor

Goal:

- real-world C preprocessing, not a placeholder

Tasks:

- include graph resolution
- header search policy surface
- object-like macros
- function-like macros
- macro argument substitution
- stringification
- token pasting
- conditional compilation
- predefined macros
- line/file remapping
- expansion diagnostics

Done means:

- preprocessed translation units match expected real-world behavior

This phase is mandatory before any serious "full C compiler" claim.

### Phase 5: Full C Parser

Goal:

- parse full C syntax used by real projects

Tasks:

- declarations
- declarators
- types/specifiers/qualifiers
- initializers
- expressions
- statements
- function definitions
- structs/unions/enums
- typedef-sensitive parsing
- attributes/extensions hooks

Done means:

- parser produces a stable AST or equivalent compiler graph for
nontrivial real C programs

### Phase 6: GNU And Linux Reality Layer

Goal:

- stop being "toy C" and become "real-world C"

Tasks:

- GNU attributes
- statement expressions
- `typeof`
- builtins
- inline asm capture
- designated initializer edge cases
- Linux- and Clang/GCC-style extension handling

Done means:

- nontrivial GNU C projects start parsing and surviving semantic phases

### Phase 7: Semantic Analysis

Goal:

- make the frontend semantically correct

Tasks:

- scope graph
- symbol tables
- typedef vs identifier disambiguation
- type checking
- integer conversion rules
- constant-expression evaluation
- layout/alignment rules
- linkage/storage duration semantics
- diagnostics and source mapping

Done means:

- frontend meaning is trustworthy, not just syntax

### Phase 8: Lowering Into Compiler IR

Goal:

- convert parsed/sema-checked C into a lower compiler representation

Tasks:

- AST to CFG lowering
- typed intermediate representation
- memory model representation
- explicit control flow
- explicit value and effect boundaries

Done means:

- optimization and codegen no longer depend on high-level syntax trees

### Phase 9: Mid-End

Goal:

- optimization and analysis pipeline suitable for serious code

Tasks:

- CFG building and cleanup
- SSA construction
- phi placement
- constant propagation
- dead code elimination
- CSE
- value simplification
- dataflow/fixed-point analyses
- legality and normalization passes

Done means:

- mid-end can support real codegen quality and future languages

### Phase 10: Backend And Object Emission

Goal:

- generate real target objects

Tasks:

- ABI lowering
- calling convention
- stack layout
- register allocation
- relocation emission
- object writer
- target-specific codegen support

Done means:

- compiler emits correct objects for real programs

### Phase 11: External Productization In `vyrec`

Goal:

- make it usable as a compiler product

Tasks:

- CLI
- project/build ingestion
- compilation database integration
- source discovery
- artifact management
- linker/toolchain integration
- cache and incremental policy
- pretty diagnostics

Done means:

- users can invoke the compiler like a real tool
- none of this packaging logic pollutes `vyre`

### Phase 12: Validation Ladder

Goal:

- earn the right to claim real compiler capability

Milestones:

1. tiny C programs
2. medium standalone C libraries
3. GNU-heavy projects
4. selected Linux translation units
5. selected Linux subsystems
6. broader kernel compilation targets

Done means:

- the compiler is validated against increasingly hostile real codebases

## How This Leaves Room For Rust And Other Future Compilers

Do not let C define the architecture.

The architecture should be:

- parse-core shared
- compiler-core shared
- runtime shared
- codegen-core shared
- language-specific frontends separate in folders

Future target shape:

```text
vyre-libs/
  src/
    parsing/
      core/
      c/
      rust/
      go/
      python/
    compiler/
      cfg/
      ssa/
      dataflow/
      symbols/
      types/
      codegen/

vyre-cc/
vyre-rust/
```

`vyre-rust` should appear only when the shared substrate is strong
enough that Rust-specific work can layer on top cleanly.

## Concrete Classification Checklist

When deciding whether something belongs inside `vyre`, ask:

1. Does it have a stable semantic contract?
2. Can it be named as a computation surface?
3. Does it have clear inputs, outputs, and invariants?
4. Is it more than packaging glue?
5. Could a future compiler reuse the execution pattern or data model?

If yes, it belongs inside `vyre`.

When deciding whether something belongs in `vyrec`, ask:

1. Is this about CLI or UX?
2. Is this about workspace or build-system integration?
3. Is this about artifact naming, layout, or caching policy?
4. Is this about human-facing diagnostics presentation?
5. Is this about end-user workflow rather than computation?

If yes, it belongs in `vyrec`.

## Immediate Action List

1. Adopt `vyrec` as the external packaged compiler repo name.
2. Freeze the boundary rule: semantic computation stays in `vyre`, packaging stays outside.
3. Reorganize `vyre-libs/src/parsing` into `core/` and `c/` subfolders.
4. Move giant orchestration demos out of the reusable op path.
5. Strengthen `vyre-runtime` megakernel into the one true compiler job runtime.
6. Build C preprocessor as real reusable staged computation, not product glue.
7. Grow `vyre-cc` as the programmatic C compiler surface inside `vyre`.
8. Build `vyrec` only once `vyre-cc` has enough stable surface to wrap cleanly.

## Final Recommendation

The correct end-state is:

- `vyre` becomes the home of reusable compiler computation, including
wildly domain-specific compiler machinery.
- `vyre-cc` becomes the internal C compiler surface within `vyre`.
- `vyrec` becomes the external packaged compiler product.
- future compilers follow the same pattern.

That preserves the lego-block vision, keeps `vyre` from becoming a
CLI/product shell, and still allows `vyre` to grow into the real
compiler substrate you want.