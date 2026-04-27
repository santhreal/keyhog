# Vision

> For the complete system architecture, see [ARCHITECTURE.md](../ARCHITECTURE.md).

## The Abstraction Thesis

Every complex system in computing history was built bottom-up through forced
abstraction layers.

The CPU path: transistor → logic gate → ALU → microcode → instruction set →
assembler → compiler → operating system → programming language → application.

Nobody chose to build ten layers of abstraction. The complexity of each layer
demanded the next one. A transistor cannot execute Python. Python cannot flip a
transistor. Both work perfectly because every intermediate layer is simple,
complete, tested, and invisible.

The critical property: **abstractions do not decrease performance.** C++
templates compile to the same machine code as hand-written C. Linux's VFS adds
zero overhead to a raw `read()` syscall. Rust's iterators compile to the same
loops as manual indexing. The abstraction exists at design time. It vanishes at
execution time. This is not an observation — it is a requirement. An abstraction
that costs performance at execution time is not an abstraction. It is overhead.

## Why GPU compute has failed to generalize

GPU compute has not followed the CPU's path.

When researchers and engineers see GPU hardware — thousands of parallel cores,
massive memory bandwidth — they recognize the parallel to CPUs. They have seen
the CPU's final form: compilers, databases, operating systems. They attempt to
reproduce it directly. They jump from CUDA threads to compilers, from shader
units to databases, from GPU cores to neural network frameworks.

They skip the intermediate layers because they already know what the end looks
like. They have seen the destination and try to teleport there.

This fails every time.

Not because GPUs are harder than CPUs. Because the abstraction layers between
"GPU core" and "GPU application" do not exist yet. A CPU compiler works because
it stands on an ISA, which stands on microcode, which stands on an ALU, which
stands on logic gates. Each layer is simple, tested, trusted, invisible. The
compiler author does not think about transistors. The transistor does not know
about compilers.

A GPU "compiler" built directly on CUDA or WGSL stands on nothing. It
reimplements every primitive from scratch — untested, uncomposable, unreusable.
When it breaks, there is no intermediate layer to debug. When it needs a new
capability, there is no primitive to compose. The complexity of the final
application is borne by a single layer, which is why it collapses.

Anthropic demonstrated this precisely: an estimated $500K and 16 AI agents for
two weeks built a C compiler from scratch. Every component reimplemented from
zero — lexing, parsing, SSA construction, dataflow analysis, register
allocation, instruction selection, code emission, linking. The result has bugs,
no optimizations, and helps nobody else. If composable, tested GPU primitives
existed — a DFA engine for lexing, a dataflow engine for analysis, a sort for
ordering — the compiler would have been a composition exercise, not a research
expedition.

The gap is not capability. The gap is substrate.

## What vyre is

vyre builds the missing abstraction layers for GPU compute.

vyre is a **GPU compute intermediate representation** — the same kind of thing
as LLVM IR, WebAssembly, or SQL.

- **LLVM IR** defines how CPU computation is expressed. Frontends (C, Rust,
  Swift) compile to it. Backends (x86, ARM, RISC-V) execute it.
- **WebAssembly** defines how portable computation is expressed. Any language
  compiles to it. Any runtime executes it.
- **SQL** defines how data queries are expressed. Any question compiles to
  relational algebra. Any engine executes it.
- **vyre** defines how GPU computation is expressed. Any workload compiles to
  vyre IR. Any GPU backend executes it.

The IR is the contract. Implementations come and go. The specification is
forever.

vyre ships as a library crate with a single public surface: `Program`,
`VyreBackend`, and the standard operation library. The IR lives in `vyre::ir`.
Backends implement `vyre::backend::VyreBackend`. Operations are declared in
co-located `spec.toml` files and discovered at build time by the module walker —
no central enum, no registry list, no manual registration. At launch, the
standard library contains 47 operations across primitives, buffer utilities,
string matching, compression, cryptography, graph algorithms, and security
detection. New ops are added by creating a directory and a `spec.toml`; the
build script absorbs them automatically.

## The Cat A / Cat B / Cat C discipline

This is the move that separates vyre from every other GPU framework.

**Category A — Compositional ops.** These are pure IR compositions. They derive
their semantics from primitive operations and cost nothing at runtime because
the lowering backend inlines them completely. Sort, scan, string search,
decode, hash: all Category A. If you can build it from existing primitives
without a performance penalty, it belongs here.

**Category C — Hardware intrinsics.** These map 1:1 to hardware capabilities
that cannot be matched by software composition. Tensor cores, subgroup
operations, async copy, ray-tracing units. Category C ops are strictly optional
per backend. If a backend lacks the hardware, it returns
`Error::UnsupportedByBackend`. There is no software fallback, no degraded path,
no silent performance loss.

**Category B — Forbidden.** Category B is the runtime abstraction layer:
interpreters, virtual machines, dynamic dispatch, fallback CPU paths. These are
banned from vyre entirely. They add overhead, introduce nondeterminism, and
create two execution paths where there should be one. If an op cannot be
expressed as Category A or Category C, it does not exist in vyre.

The discipline is harsh and it is the reason vyre works. Category A guarantees
zero-cost composition. Category C guarantees honest hardware mapping. Category
B's absence guarantees that what you see in the IR is exactly what executes on
the GPU.

## The 6 frozen trait contracts

Extensibility in vyre is not a social contract. It is six trait signatures that
are frozen at 1.0 and guaranteed for five years.

1. **`VyreBackend`** (`vyre/core`) — the dispatch contract. Every backend
   implements `id()` and `dispatch(program, inputs, config)`. Byte-identical
   output to the CPU reference on success; actionable `BackendError` on failure.

2. **`Finding`** (`vyre-conform/spec`) — the violation contract. Every gate,
   oracle, and verifier returns structured findings with a `fix_hint()` that
   starts with `Fix: `. Any finding anywhere means fail.

3. **`EnforceGate`** (`vyre-conform/enforce`) — the enforcement contract. Each
   gate has an `id()`, a `name()`, and a `run(ctx)` that returns a vector of
   findings. Empty vector means pass.

4. **`Oracle`** (`vyre-conform/proof`) — the truth contract. Oracles declare
   their kind, applicability, and a `verify()` method that produces a `Verdict`.
   The strongest applicable oracle wins.

5. **`Archetype`** (`vyre-conform/generate`) — the input-shape contract.
   Archetypes instantiate test inputs from op signatures. They declare what they
   apply to and generate the vectors that stress-test correctness.

6. **`MutationClass`** (`vyre-conform/adversarial`) — the adversarial contract.
   Each mutation class produces source-code mutations that must be caught by the
   test suite. A surviving mutant is a suite failure.

New methods may be added with default implementations. Existing method signatures
never change. Breaking a frozen trait requires a major version bump. This is the
contract that lets NVIDIA, AMD, Intel, and a hundred independent contributors
extend vyre without coordination: implement the trait, run the suite, ship the
backend.

## certify() — the binary verdict

`vyre_conform::certify(backend)` accepts a backend and returns exactly one of
two things:

- `Ok(Certificate)` — the backend is conformant.
- `Err(Violation)` — the backend failed, with a concrete counterexample and an
  actionable `Fix: ...` hint.

There is no "mostly passing." There is no "known limitations" document. There
is no human judgment. Pass or fail. Nothing else.

`certify` runs the full eight-gate pipeline: executable spec verification,
algebraic law inference, reference interpreter agreement, mutation testing,
adversarial gauntlet, stability enforcement, composition proof, and
feedback-loop validation. Beyond the core gates, it enforces coverage minimums,
the no-CPU-fallback rule, out-of-bounds behavior, atomic sequential consistency,
barrier correctness, wire-format round-trip identity, and the no-silent-wrong
invariant.

The `Certificate` is a durable, independently verifiable artifact. It contains a
cryptographic registry hash, backend identification, timestamp, exact coverage
metrics, per-op verdicts, and the achieved track. Downstream users do not trust
marketing slides. They trust the certificate.

## The zero-conflict architecture

vyre is built so that 100 contributors can each add a leaf file with zero merge
conflicts, zero `lib.rs` edits, and zero central registry edits. This is not
aspirational. It is enforced in CI.

The rules are simple and mechanical:

- **One top-level item per file.** Every `.rs` file contains exactly one struct,
  enum, trait, type, const, static, single `fn`, or one impl block with one
  associated item.
- **Max 5 entries per directory.** When a sixth item is needed, the directory
  splits.
- **No `mod.rs` files.** The build script owns the module tree.
- **`lib.rs` is frozen.** It contains only crate-level attributes and a single
  `include!()` for the build-script-generated module tree.
- **No central enums, no central lists.** Every catalog is a trait implemented
  by per-file types, collected at build time by `vyre-build-scan` or at link
  time via distributed slices.

`vyre-build-scan` walks the source tree at compile time, identifies trait
implementations, and emits static registration tables. Adding a new gate,
oracle, archetype, or op is a single-file drop. The filesystem is the registry.
The build script is the librarian. Contributors never touch a shared file.

The consequence: 100 contributors, 100 new ops, zero conflicts. The system only
ever grows by adding leaf files. That guarantee lets parallel waves of
contributors produce hundreds of operations in an afternoon without a single
rebase.

## Determinism via restriction, not by elimination

A recurring question: "you need floats for LLMs, graphics, physics, ML. But
GPU floats are nondeterministic. How does vyre reconcile this?"

The answer is the Rust pattern applied to floating-point.

Rust's memory safety isn't achieved by eliminating memory access. It's
achieved by forbidding the patterns that make memory access unsafe. Raw
pointers, data races, use-after-free, buffer overflows — these are specific
patterns the compiler refuses to emit from safe code. Safe Rust has
full memory access. It just can't access memory in the unsafe ways.

vyre applies the same pattern to floating-point. GPU floats aren't
nondeterministic because floats are inherently nondeterministic. They're
nondeterministic because backends are PERMITTED to:

- Fuse `mul+add` into hardware FMA (one rounding vs two)
- Reorder reductions ("addition is approximately associative")
- Flush subnormals to zero for speed
- Substitute vendor math libraries for transcendentals
- Use tensor core accumulators of lower precision than declared

**Each permission is a specific pattern vyre forbids.** The IR contains
only strict IEEE 754 operations. `FMul + FAdd` stays as two roundings —
the backend cannot fuse it. Reductions are ordered (sequential or canonical
binary tree). Subnormals are preserved. Transcendentals use CR-Math
correctly-rounded implementations. Tensor operations declare their
accumulator type explicitly.

The hardware is as nondeterministic as it was before. The IR is not.
A `FAdd(a, b)` in vyre produces bit-exact IEEE 754 round-to-nearest-even
on every conforming backend, because the backend is not allowed to emit
the hardware instructions that would produce different results.

This costs performance. Strict `sin()` via CR-Math is 20-50× slower than
`cuBLAS sinf()`. Strict reduction is slower than parallel unordered reduction.
FMA fusion is forbidden even though it's more accurate. The tradeoff is the
same as safe Rust: you pay runtime for a compile-time guarantee.

And like Rust's `unsafe` block, vyre has an explicit escape hatch:
approximate operations (`FReduceApprox`, `FSinApprox`) are a separate class
with declared ULP tolerance. Backends can use fast paths for approximate
ops. But approximate and strict never mix in the same certificate. You
choose per operation, in the IR, visibly.

**Permissions grow, determinism is preserved.** This is how vyre supports
LLMs, neural networks, physics, graphics, scientific computing — everything
real-valued — without giving up the proof system. The proof system extends:
integer ops have bit-exact proofs, float ops have bit-exact IEEE 754 proofs,
approximate ops have ULP-bounded proofs. Three proof classes, all provable,
all deterministic within their stated class.

## What vyre is not

vyre is a GPU compute IR, a standard operation library, and a conformance suite.
That is all.

vyre is not a runtime-interpretation engine, not an opcode or microcode virtual
machine, and not a stack-machine evaluator. The only binary form is the
lossless IR wire format, and bytes are decoded back into `ir::Program` before
they are lowered to a backend. There is no VM, no opcode interpreter, no
execution path that bypasses IR lowering.

Any file that adds runtime opcode dispatch on the GPU or CPU is a Category B
violation and must be rewritten as IR compositions. Category A compositions and
Category C hardware intrinsics are the only permitted execution paths. Category
C has no fallback interpreter; unsupported hardware reports an explicit
unsupported-backend error instead of running a slower semantic path.

Rule, policy, and pattern-matching evaluation live as composed operations in
`ops/rule/` and `ops/match_ops/`, built from Layer 1 primitives. They are never
interpreters hidden inside vyre. Downstream products import vyre domains as
libraries; vyre does not embed their product surfaces.

## Where vyre goes from here

vyre must become the standard for expressing GPU computation. Not by decree —
by being so correct, so composable, so well-tested that building a GPU project
without vyre is obviously more expensive than building with it.

The test: if NVIDIA wanted to add a CUDA backend tomorrow, could they? The
answer is: yes, trivially. An engineer reads the spec, implements `VyreBackend`,
runs `certify()`, gets a certificate. No communication with us needed. If AMD
wants to do the same independently, they can. Both backends produce identical
bytes for every input — not because they coordinated, but because the spec is
unambiguous and the conformance suite is the arbiter.

This is the Linux property. NVIDIA spends tens of millions per year on Linux
kernel engineers — not because they love open source, but because if their GPUs
don't work on Linux, they can't sell to data centers. The substrate has more
leverage than the vendor. The cost of not being on Linux is higher than the cost
of contributing to it.

vyre achieves this when the spec is the authority, the conformance is automatic,
the ecosystem compounds, and the alternative is worse. At 0.4.0, the foundation
is frozen: six traits, three categories, one binary verdict, and zero merge
conflicts. The next ten years are composition.
