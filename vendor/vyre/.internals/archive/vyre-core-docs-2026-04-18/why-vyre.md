# Why vyre

## The problem

GPU compute has not generalized.
Every GPU application today is bespoke.
CUDA kernels are handwritten and tied to NVIDIA.
Metal is tied to Apple.
WGSL has no op catalog to speak of.
Triton solved one problem — ML kernels on CUDA — and stopped there.
There is no LLVM for GPU compute.

The result is a wasteland of reinvention.
Every team that wants to run a DFA scan, a rolling hash, or a prefix sum on a GPU writes the shader from scratch.
They debug warp divergence, alignment, and barrier placement by hand.
The code works on one vendor, maybe one architecture, and rots when the hardware changes.
No layer below the application is stable enough to reuse.

This is not a hardware problem.
The hardware is extraordinary.
The problem is that the abstraction stack between the GPU core and the GPU application does not exist yet.
There is no small, stable, testable IR that frontends can target and backends can implement.
There is no standard library of proven GPU operations.
There is no way to know whether a backend is correct except to hope the output looks right.

When a CPU compiler author needs a loop, they use LLVM's loop passes.
When a database author needs a sort, they use a standard algorithm.
When a GPU author needs a scatter-gather, they open a blank shader file and start typing.
That gap is what vyre closes.

## The observation

CPUs are the way they are because of fifty years of strategic abstractions.
Transistors became gates.
Gates became ALUs.
ALUs became instruction sets.
Instruction sets became compilers.
Compilers became operating systems.
Operating systems became languages.
Languages became the applications we use every day.

At every step, the layer below is a black box for the layer above.
A Python developer calling `numpy.dot` does not know SIMD.
A user moving a brightness slider does not know Python.
The slider works because every layer is simple, complete, tested, and invisible.

The critical property is that abstractions do not decrease performance.
C++ templates compile to the same machine code as hand-written C.
Linux's virtual file system adds zero overhead to a raw `read()` syscall.
Rust's iterators compile to the same loops as manual indexing.
The abstraction exists at design time and vanishes at execution time.
This is not an observation — it is a requirement.
An abstraction that costs performance at execution time is not an abstraction.
It is overhead.

GPUs need the same stack.
vyre is one of those missing layers.

We did not get here because GPU researchers are less capable than CPU researchers.
We got here because everyone tried to jump straight from CUDA threads to compilers, from shader units to databases, from GPU cores to neural network frameworks.
They skipped the intermediate layers because they already knew what the end looked like.
They saw the destination and tried to teleport there.
That fails every time, not because GPUs are harder, but because the substrate underneath was never built.

vyre builds the substrate.

## The approach

Every op in vyre is a theorem.
Its signature says what it takes.
Its laws say what it must satisfy.
Its CPU reference says exactly what it computes.
Its GPU kernel says how to compute it fast.
All four must be consistent.

If the signature, the laws, the reference, and the kernel disagree, that is a bug in vyre — not a backend quirk, not a known limitation, not a hardware difference to paper over.
The CPU reference is the ground truth.
The GPU kernel is correct only when it produces byte-identical output for every input.
Not approximately.
Not usually.
Exactly.

This rigor makes vyre usable by systems that do not trust human judgment at scale.
A security scanner running on a billion documents cannot afford a "mostly correct" shader.
A compiler backend cannot afford a silent precision drift.
An internet-scale matching engine cannot afford an off-by-one in a bounds check that only triggers on malformed input.
vyre is built for workloads where a "low" bug corrupts billions of records.

The approach is enforced by a single rule: there is exactly one execution path.

Source becomes an `ir::Program`.
The program is validated.
It is optimized.
It is lowered to a target shader language such as WGSL, CUDA, or SPIR-V.
That shader is compiled and dispatched on the GPU.
There is no interpreted path.
There is no runtime opcode loop.
There is no CPU fallback hidden behind a feature flag.
What you see in the IR is exactly what executes on the hardware.

This restriction is intentional.
It makes the IR exhaustively validatable.
It makes the conformance suite complete.
It makes backend authors responsible for a single, well-defined contract rather than a matrix of execution modes.

## Cat A / Cat B / Cat C — vyre's distinguishing discipline

This is the part LLVM does not have, MLIR does not have, Triton does not have.

- **Cat A: compositional.**
  Your op is defined as a composition of simpler ops.
  When lowered, the composition is inlined.
  Zero overhead.
  Sort, scan, string search, decode, hash, graph traversal — all Cat A.
  If you can build it from existing primitives without a performance penalty, it belongs here.

  The power of Cat A is that vyre does not need an update when a new neural network architecture appears, when a new attention variant is published, or when a new compression scheme becomes fashionable.
  The primitives stay the same.
  The compositions change.
  Cat A is why vyre is a substrate, not a library.
  The substrate outlasts the algorithms built on it.

- **Cat B: forbidden.**
  Runtime trait-object routing, hidden registration, `TypeId` switches, virtual dispatch, fallback CPU paths, interpreted execution, and dynamic plugin loading are all banned.
  They break the black-box invariant.
  They add overhead.
  They create two execution paths where there should be one.
  They make conformance impossible because the behavior depends on runtime state that the test suite cannot see.

  If an op cannot be expressed as Cat A or Cat C, it does not exist in vyre.
  This is non-negotiable.
  It preserves the property that vyre abstractions compose to arbitrary depth without accumulating cost.

- **Cat C: hardware intrinsic.**
  Declared per-backend via `IntrinsicTable`.
  vyre knows which GPUs have `popcount`, subgroup shuffles, tensor cores, async copy, ray-tracing units — and uses them only where they exist.
  If the hardware is missing, the op is unavailable and the backend returns `UnsupportedByBackend`.
  There is no software fallback, no degraded path, no silent performance loss.

  Category C keeps performance cliffs visible.
  A tensor-core matrix multiply does not silently become a naive triple loop.
  It is either fast or absent.
  This honesty is what makes vyre suitable for systems that must reason about throughput and latency guarantees.

The discipline is harsh and it is the reason vyre works.
Cat A guarantees zero-cost composition.
Cat C guarantees honest hardware mapping.
Cat B's absence guarantees that what you see in the IR is exactly what executes on the GPU.

## certify() — the binary verdict

Every backend passes `certify()` or it doesn't.
Pass means Santh-worthy.
Fail means a concrete counterexample with a `Fix: ...` hint.
There is no "83% passing."
There is no "known limitations" document.
There is no human judgment call.

`certify(backend)` runs the full eight-gate pipeline:
executable spec verification,
algebraic law inference,
reference interpreter agreement,
mutation testing,
adversarial gauntlet,
stability enforcement,
composition proof,
and feedback-loop validation.
Any failure at any gate returns `Err(Violation)`.
A full pass returns `Ok(Certificate)`.

Beyond the core gates, the suite enforces coverage minimums, the no-CPU-fallback rule, out-of-bounds behavior, atomic sequential consistency, barrier correctness, wire-format round-trip identity, and the no-silent-wrong invariant.
Every op, every archetype, every declared law, and every mutation is exercised.
A backend that passes every test except one is not conformant.
A backend that produces correct output for 99.99% of inputs but fails on a single edge case is not conformant.

The `Certificate` is a durable, independently verifiable artifact.
It contains a cryptographic registry hash, backend identification, timestamp, exact coverage metrics, per-op verdicts, and the achieved track.
Downstream users do not trust marketing slides.
They trust the certificate.

The `Violation` contains at least one concrete counterexample and an actionable `Fix: ...` hint.
It tells you exactly which gate failed, which op triggered it, the exact input that produced the wrong output, and the expected output according to the oracle.
You read it, apply the fix, and rerun `certify`.
There is no ambiguity.
There are no flaky tests.
Wrong is wrong.

## How vyre is different from LLVM / MLIR / Triton / Halide

**LLVM** is a mature, general compiler IR for CPU and accelerator code generation.
It solves the problem of lowering language-level programs to machine code across a broad hardware matrix.
vyre solves a smaller, sharper problem: expressing deterministic GPU compute programs as an IR that lowers to shader languages and carries a standard operation library.
LLVM has no Cat A/C discipline, no GPU-native op catalog, and no binary conformance verdict.
If you are building a CPU language frontend, LLVM is the default answer.
If you are building a GPU compute backend, vyre is the contract you want to target.

**MLIR** is a framework for building many IRs under one roof through composable dialects.
It is excellent when a project needs several abstraction levels to coexist — tensor algebra, affine loops, GPU constructs, and CPU lowering all in one pipeline.
vyre makes the opposite tradeoff: one IR, one semantic model, no dialect proliferation.
A stored vyre wire blob does not need a dialect registry to recover semantics.
It decodes into one program type with one set of validation rules.
In vyre, the conformance suite plays the role that dialect-specific invariants often play in MLIR projects.

**Triton** solved ML kernels on CUDA and stopped there.
It is a Python DSL that compiles tile-level matrix operations to highly optimized NVIDIA kernels.
vyre is not a Python DSL, not limited to CUDA, and not limited to machine learning.
Triton does not have a retargetable IR that lowers to Metal or DirectX, a standard op library spanning security scanning and graph algorithms, or a cross-backend certification suite.
Triton is brilliant at what it does.
vyre does something broader.

**Halide** separates the algorithm from the schedule for image processing and dense array code.
It is brilliant for stencil pipelines and tensor layouts where schedule exploration matters.
vyre does not separate algorithm from schedule; it expresses the algorithm as a deterministic IR program and leaves schedule and tiling to the backend or a higher-level frontend.
Halide is not a general GPU compute substrate and does not ship with a conformance-gated op library.
If your problem is image-processing schedules, use Halide.
If your problem is portable GPU compute with proven semantics, use vyre.

For a deeper comparison with CPU code generators such as Cranelift, see the competitors chapter.

## Who this is for

- **Backend authors** writing a GPU compute runtime for new hardware.
  Implement `VyreBackend`, run `certify()`, get a certificate.
  No coordination with the vyre core team required.
  NVIDIA, AMD, Intel, Apple, or an embedded vendor — the contract is the same.

- **Security tool authors** who need GPU pattern matching at internet scale.
  DFA scans, rolling hashes, entropy calculations, and byte-string matching are already in the standard library, proven correct, and ready to lower.
  Santh, the engine that vyre was originally built for, is the canonical example.

- **Research compilers** that need a retargetable IR with proven op semantics.
  The IR is small enough to validate exhaustively and rich enough to express real workloads.
  A frontend can emit vyre IR and immediately gain access to every conforming backend.

- **Systems engineers** building databases, packet processors, or streaming analytics that need to offload compute to a GPU without rewriting kernels for every vendor.

**NOT for:** CPU compilers — vyre has no CPU execution path and does not emit x86 or ARM machine code.
ML framework authors who need automatic differentiation, kernel fusion heuristics, and dynamic graph rewriting — that is 0.6 territory.
And not for anyone who needs a WebGPU-only solution.
vyre targets more than wgpu; WebGPU is just the reference backend.

## The 5-year bet

vyre commits to a 5-year stability contract for its frozen traits and data types.
A test written in year 1 compiles and passes in year 6.
This is SQLite-scale longevity for a compiler framework.

The bet works like this:

1. **Spec entries are permanent.**
   Once an op, a type, or a trait signature is published, it is never removed.
   If a definition is discovered to be wrong, the fix is a new versioned definition plus a deprecation note on the old one.
   The old entry remains testable because deployed programs and certificates may depend on it.

2. **Golden samples enforce the freeze.**
   Every published op behavior is backed by frozen input/output pairs computed from the CPU reference at publication time.
   Once frozen, a golden sample is permanent.
   If a future change to the CPU reference produces different output for a frozen input, the build fails.
   This is how "what is published is permanent" becomes a mechanical guarantee rather than a social convention.

3. **The six core trait contracts** — `VyreBackend`, `Finding`, `EnforceGate`, `Oracle`, `Archetype`, and `MutationClass` — are frozen at 1.0.
   New methods may be added with default implementations.
   Existing method signatures never change.
   Breaking a frozen trait requires a major version bump.

The bet is that stable semantics plus a growing community catalog compounds over 5 years into something irreplaceable.
Backend authors invest once.
Frontend authors emit once.
Tooling authors parse once.
The substrate outlasts the algorithms built on it.

This is the Linux property applied to a compiler framework.
NVIDIA spends tens of millions per year on Linux kernel engineers not because they love open source, but because if their GPUs do not work on Linux, they cannot sell to data centers.
The substrate has more leverage than the vendor.
The cost of not being on the substrate is higher than the cost of contributing to it.

vyre achieves this when the spec is the authority, the conformance is automatic, the ecosystem compounds, and the alternative is worse.
At the current foundation, six traits, three categories, one binary verdict, and zero merge conflicts are frozen.
The next ten years are composition.

## Where to go next

- Read the [zero-conflict architecture](zero-conflict.md) chapter to understand how 100 contributors can add ops without a single merge conflict, a single `lib.rs` edit, or a single central registry edit.

- Read the book's [Part II on the IR](ir/overview.md) for the complete data model — `Program`, `Node`, `Expr`, `BufferDecl`, and the validation rules that make incorrect programs unrepresentable.

- Try the [getting-started tutorial](getting-started.md) to build, validate, lower, and dispatch your first program in under five minutes.

- Read [Adding Your First Op](tutorial-new-op.md) to create an operation from scratch with a `spec.toml`, a CPU reference, and a conformance test.

- For the deeper philosophy behind the abstraction thesis, the determinism-via-restriction argument, and the zero-conflict architecture, read the [vision](vision.md) chapter.
