# Universality — vyre treats all compute as eventually absorbable

## The commitment

**Every operation that runs on any compute hardware today, and every
operation that might run on any compute hardware tomorrow, should be
expressible as a vyre Program.** No exceptions. No permanent carve-outs.
No "this is CPU work, we'll never touch it."

This is a design commitment, not a technical claim about current
implementation. vyre's job is to accommodate whatever compute becomes
possible, whenever it becomes possible, without requiring a rewrite of
existing programs or a fork of the substrate.

## Why this matters

The line between "CPU work" and "GPU work" is not a natural law. It is
a performance frontier determined by:

1. **Parallelism latency of the workload** — how much independent work
   is available before dependencies force serial execution.
2. **Dispatch overhead of the hardware** — how long it takes to launch
   a kernel, submit work, and return results.
3. **Memory locality requirements** — how much data moves where, at what
   cost.

All three change over time. Parallel algorithms replace serial ones as
researchers find new ways to decompose problems. Dispatch overhead drops
as hardware evolves (CUDA graphs, persistent kernels, cooperative groups,
unified memory, direct memory access). Memory locality improves as
new memory architectures emerge (HBM, unified memory, compute-in-memory,
non-volatile RAM).

**A workload that is "CPU-only today" might be "GPU-optimal in 2030"** because
of changes in any of these three factors. vyre must not encode the
current frontier into its architecture. The IR should be able to
express event loops, interrupt handlers, and serial dependency chains
— not because these are efficient on GPUs today, but because they might
become efficient tomorrow, and when they do, the code written against
vyre today should continue to work.

## The universal absorption principle

Any CPU operation is a candidate for eventual GPU execution if:

- The operation can be decomposed into parallel work (even if today it
  is implemented serially), OR
- The hardware eventually provides fast enough single-thread execution
  to match CPU latency (via frequency, out-of-order execution, or
  specialized fast-path cores), OR
- The operation can be batched with enough similar operations that
  dispatch overhead amortizes to negligible per-request cost, OR
- The operation can be made event-driven on the GPU (persistent kernels
  with signal-based wakeup, co-dispatch with interrupt handlers)

vyre does not forbid any of these paths. The current execution model
(one-shot batch dispatch) is a starting point, not a ceiling. As new
dispatch models emerge, vyre extends to accommodate them as new Program
variants, new execution modes, or new runtime integrations.

## What we do NOT assume

To keep this commitment real, vyre's core architecture avoids assuming:

1. **"GPU is batch-only"** — we expect eventual persistent, streaming,
   and event-driven Program variants.
2. **"GPU dispatch latency is always high"** — we expect hardware and
   drivers to make dispatch latency drop by 10-100× over the next
   decade, potentially enabling interactive GPU use.
3. **"GPU has no fast serial cores"** — we expect heterogeneous GPUs
   with fast-serial cores for control flow alongside massive-parallel
   cores for data flow.
4. **"The compute hardware will always be silicon transistor GPUs"** —
   we expect optical compute (photonic tensor cores), near-memory
   compute, processing-in-memory, neuromorphic chips, and other
   accelerators to become real targets. vyre should be able to target
   them as backends without IR changes.
5. **"Memory is volatile DRAM"** — we expect non-volatile RAM (MRAM,
   ReRAM, PCM) to change buffer semantics, enabling persistent-by-
   default storage and in-memory compute.
6. **"Single-device execution is sufficient"** — we expect multi-device
   and distributed execution to become a first-class concern as models
   grow and workloads span physical hardware.

None of these are architectural changes to the IR today. They are
commitments to how we'll think about extensions when they become
necessary. The `#[non_exhaustive]` enums, the versioned conformance
tracks, the add-only semantics, the Category A+C classification — all
of these exist so that when a future extension is needed, it can be
added without breaking existing programs.

## The only permanent carve-out

There is one thing vyre will likely never absorb: **the absolute-
lowest-latency single-request serial dependency chain**, measured in
nanoseconds, when the chain has literally no parallelism and no
batching opportunity. A CPU core with 5 GHz clock, 10-stage pipeline,
and L1 cache hit will race through such a chain in the 10-100 ns range.
A GPU's dispatch overhead alone is 10-100 μs — three orders of
magnitude higher, structurally, because the GPU is paying the cost of
having 10,000 cores that are not being used.

This is not "GPUs are bad at something." It is "GPUs trade single-
thread latency for parallel throughput as a design choice." The trade
is what makes them useful for everything else. A GPU core that could
match a CPU core on single-thread latency would have to be as large as
a CPU core, which means fewer of them fit on the die, which defeats
the purpose.

Even this carve-out is not forever. Future heterogeneous designs (one
fast-serial core + thousands of parallel cores on the same chip) could
absorb the remaining CPU role. Light-based compute might achieve both
low latency and massive parallelism simultaneously by using wavelength
multiplexing for the serial path. We don't know what comes. We only
commit to being ready.

**What we commit to:** when a new compute paradigm absorbs a class of
workload that vyre doesn't currently handle, the work to add it is
"write a new backend" or "add a new Program variant" — not "redesign
the IR." The architecture is extensible by design, and we will never
accept an extension that requires breaking existing semantics or
existing programs.

## The discipline that enforces this

Five rules, forever:

1. **Never change existing semantics.** A `BinOp::Add` with wrapping
   u32 semantics means wrapping u32 semantics. That's the contract. A
   Program written today runs the same way in 20 years.

2. **Always prefer composition.** Before adding a primitive, verify it
   cannot be composed from existing primitives at zero cost. Most
   "new" things are compositions of old things.

3. **Hardware-specific ops are Category C with per-backend availability.**
   A backend that lacks the hardware returns
   `Error::UnsupportedByBackend` and refuses the program. No fallback
   path exists.

4. **All enums are `#[non_exhaustive]`.** Every DataType, BinOp, UnOp,
   Node, Expr, BufferAccess, Convention, AlgebraicLaw, ConformanceLevel
   in the public API is marked non-exhaustive. Adding a new variant is
   a minor version bump, not a breaking change.

5. **Every extension is proven by conformance before it enters the
   standard library.** A new op, a new data type, a new engine, a new
   backend — each comes with conformance rules that vyre-conform can
   verify. Nothing enters the spec without a proof path.

These five rules are what make the universality commitment real. Without
them, "we can extend" would be a claim without teeth — the extensions
would accumulate inconsistencies and eventually require a rewrite.
With them, extensions ratchet forward without ever moving sideways.

## The test

Whenever a new compute paradigm emerges — a new GPU architecture, a new
accelerator, a new algorithm class, a new memory technology — we ask:

- Can vyre express it as a composition of existing primitives? If yes,
  no IR change needed.
- Can vyre expose it as a new Category C intrinsic with a software
  fallback? If yes, add the intrinsic.
- Can vyre extend its execution model (new Program variant, new
  dispatch mode, new buffer access) to accommodate it? If yes, add the
  extension.
- Does it require fundamentally new IR semantics? If yes, version the
  spec, add the new semantics alongside the old, and commit to
  supporting both forever.

The first three cover >99% of foreseeable extensions. The fourth is for
truly novel compute paradigms and would be rare. None of them break
existing programs.

**vyre's value is not what it does today. It's what it will still do
in 2040 without having been rewritten.** The universality commitment is
what makes that possible.
