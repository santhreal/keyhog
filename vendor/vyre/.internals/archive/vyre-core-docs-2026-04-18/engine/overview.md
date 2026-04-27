# Engines — GPU compute workflows

## What an engine is

An op domain describes computation. An engine runs a complete GPU
compute workflow.

Engines are Layer 3 in vyre's hierarchy. They compose Layer 1
primitives and Layer 2 domain ops into end-user dispatch paths, then
manage the host-side resources required to run those paths: buffers,
bind groups, pipelines, queue submission, staging readback, sorting,
and typed result materialization.

That resource ownership is the distinction. A primitive answers a
small IR question such as `a XOR b`. A Layer 2 op domain answers a
domain question such as "produce a Program for base64 decoding" or
"produce a Program for graph reachability." An engine answers a
runtime question such as "dispatch this DFA against these bytes and
return deterministic match rows."

Engines are not an escape hatch around the IR contract. When an
engine uses a vyre op, the op remains a `Program` producer that is
validated and lowered through the normal pipeline. The engine is the
stateful host boundary around that program: it sizes buffers, prepares
runtime inputs, submits work, reads results back, and returns typed
outputs to downstream tools.

Stage 1 of engine composability adapts engines onto the same composition
surface as ordinary ops through `EngineOpSpec`. The legacy `EngineSpec`
invariant API remains intact, but every bridged engine now has an op-like
signature, CPU reference, semantic input wire format, semantic output wire
format, and migration stage. Direct composition requires both the `DataType`
and wire format to match; byte buffers with different engine schemas are
rejected before dispatch.

## The current engines

The `core/src/engine/` module currently exposes these host-side GPU
compute workflows:

| Engine | Workflow | Input | Output |
|--------|----------|-------|--------|
| [DFA](dfa.md) | Pattern matching over bytes | Byte buffer + compiled transition table | Match rows `(pattern_id, start, end)` |
| [Dataflow](dataflow.md) | Graph reachability | CSR graph + source nodes | Reached sink tuples `(source, sink, depth)` |
| Decode | Recursive byte decoding | Runtime bytes + TOML decode rules | Decoded byte regions |
| Decompress | Block decompression | Compressed payload + declared limits | Decompressed bytes |
Tokenization is currently exposed as Layer 2 string operations plus
host-side filtering helpers, not as a Layer 3 engine. If a tokenization
engine lands, it should follow the same boundary: compose
`ops::string` Programs, manage GPU resources, and return typed host
results without becoming an op domain.

Scatter is no longer a Layer 3 engine in `core/src/engine/`. Match
distribution belongs in the Layer 2 collection and match op domains,
where consumers can build ordinary IR Programs for their specific
rule state layout.

## Engine vs op domain

An **op domain** is pure IR surface area:

- It exposes typed operation specs and builders.
- It produces `ir::Program` values.
- It goes through `validate` and target lowering.
- It is registered in the op catalog when public and stable.
- It does not own a GPU device, queue, buffer, pipeline, or readback
  staging resource.

An **engine** is host-side runtime orchestration:

- It accepts runtime inputs such as bytes, graphs, compressed blocks,
  tables, limits, and rule thresholds.
- It may build one or more Programs through `ops::*`, then lower them
  for dispatch.
- It owns or borrows GPU resources such as storage buffers, uniform
  buffers, bind groups, compute pipelines, and staging buffers.
- It submits work to a queue, performs readback, restores deterministic
  ordering where atomics are involved, and returns typed host results.
- It is adapted as an op-compatible `EngineOpSpec` for conformance-time
  composition checks.
- It is not yet always a single `Program`; host resource orchestration remains
  part of the engine contract until typed request and response schemas replace
  serialized byte envelopes.

This split keeps vyre reusable while the migration happens. Downstream tools can
consume the op domains directly when they need pure IR composition, or use
engines when they want a ready-to-dispatch GPU workflow with resource management
included. New engine work must define its typed wire schema so future engine
outputs can feed downstream engines and ops without bespoke glue.

## Resource management

Engines own the resource decisions that are not part of IR semantics.
A DFA engine instance, for example, allocates transition table
buffers, accept-state buffers, match output buffers, atomic counters,
parameter buffers, and readback buffers. The dataflow engine allocates
CSR graph buffers, source buffers, finding buffers, and per-source
visited bitsets. Decode and decompression workflows allocate region,
descriptor, status, output, and staging buffers around format-specific
dispatches.

Resource reuse is critical for throughput. An engine should allocate
for a validated workload envelope and reuse compatible buffers across
dispatches. Inputs that exceed that envelope must return structured,
actionable errors. They must not panic, silently truncate, or rely on
out-of-bounds behavior.

The IR remains responsible for computation semantics. The engine is
responsible for host-side capacity checks, backend limits, dispatch
shape, readback materialization, and deterministic result presentation.

## Determinism

An engine is conforming only when its complete output is deterministic
for the same inputs. This is stricter than "the GPU kernel finished."
Several engine workflows use atomics for concurrent output, and atomic
emission order is not stable across invocations.

Engines restore determinism at the workflow boundary. The DFA engine
sorts captured matches before returning them. Dataflow findings are
materialized into typed tuples with a documented order. Decode and
decompression validate region and output sizes before exposing bytes
to callers.

If an engine's output differs between two runs on the same inputs,
either the engine has a bug or the caller has bypassed the documented
workflow boundary. The conformance suite should test repeatability at
the engine boundary and IR equivalence inside the op domains.
