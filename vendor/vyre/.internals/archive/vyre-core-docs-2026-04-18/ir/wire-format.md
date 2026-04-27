# IR wire format

The **IR wire format** is the compact, versioned, binary serialization of
`ir::Program` values. It is vyre's only binary representation of a
program. It is not a second program format, not a virtual machine, not a
separate semantic model, not a translation layer. It is a codec — one
direction encodes an `ir::Program` to bytes, the other direction decodes
bytes back to the same `ir::Program`.

## The one-semantic-model rule

vyre has **exactly one** semantic model: the IR. Every program that
executes on any vyre backend is an `ir::Program` that was lowered by the
backend. The wire format exists only to transport and store that program
between the authoring side and the lowering side.

```
Program::builder() ──build──> ir::Program ──to_wire──> bytes
                                                         │
                                                         ↓ (network, disk)
bytes ──from_wire──> ir::Program ──lower──> backend code ──> GPU dispatch
```

There is no wire-format interpreter. There is no opcode VM. There is no
execution path that receives wire-format bytes and runs them without
first decoding to IR and lowering to a backend. If you see code that
claims to execute wire-format bytes directly, it is a bug.

## The "bytecode" name is retired

Earlier versions of vyre shipped a `bytecode` module that was a separate
stack-machine VM with its own opcode semantics, its own interpreter, and
its own notion of what a program meant. That was Category B contraband —
it introduced a second semantic model and an interpreted execution path.
The module has been deleted. The word "bytecode" is retired from vyre's
vocabulary. When you see "bytecode" in older notes, commits, or external
tool descriptions, translate it as **IR wire format** and know that no
separate VM exists.

This is the LLVM/WebAssembly convention applied cleanly:

- LLVM has LLVM IR (in-memory / textual) and LLVM bitcode (binary). Both
  represent the same programs. Bitcode is not a VM.
- WebAssembly has `.wat` (text) and `.wasm` (binary). Both represent the
  same modules. `.wasm` is not a VM.
- vyre has `ir::Program` (in-memory) and the IR wire format (binary).
  Both represent the same programs. The wire format is not a VM.

## Lossless round-trip (invariant I4)

For every valid `p: ir::Program`:

```rust
assert_eq!(from_wire(to_wire(&p))?, p);
```

This is invariant **I4 — IR wire format round-trip identity**. Any
observable semantic difference between `p` and `from_wire(to_wire(&p))`
is a codec bug, not an accepted limitation. The codec cannot alter
semantics — it can only encode and decode them.

## Fields and versioning

The wire format is versioned at the envelope level. Every wire-format
blob starts with a magic number and a format version so older decoders
can refuse newer blobs structurally rather than by silent misdecoding.

Within a version, every IR node variant has a stable tag. New variants
are added with new tag values; removing or repurposing an existing tag
is forbidden by vyre's stability rule (see [stability.md](../stability.md)).
Decoders that encounter an unknown tag in a known format version return
a structured error — they do not guess, fall back, or skip.

The format is designed around four requirements:

1. **Bounded allocation.** Every count read from the wire has an
   enforced upper bound before a `Vec::with_capacity` is issued. A
   malformed blob cannot coerce the decoder into allocating an
   arbitrary amount of memory. This is invariant **I10 — bounded
   allocation**.
2. **Checked conversions.** Every length or count conversion uses
   `try_from`. A blob whose declared length would overflow `u32` or
   `usize` is a decode error, not a silent truncation.
3. **Exhaustive variant coverage.** Every IR node variant round-trips.
   Adding a new variant without adding its codec entry is a build-time
   error — the codec is derive-generated from the IR type definitions
   where possible, and the test suite enforces round-trip for every
   variant on random and hand-crafted inputs.
4. **No panic on malformed input.** Every decode error returns a
   structured `WireError` with an actionable `Fix:` message. The
   decoder never panics, even on adversarially malformed input. This
   is invariant **I11 — no panic**.

## API

```rust
// Encode an in-memory program to wire-format bytes.
impl ir::Program {
    pub fn to_wire(&self) -> Vec<u8>;
}

// Decode wire-format bytes back to an in-memory program.
impl ir::Program {
    pub fn from_wire(bytes: &[u8]) -> Result<Self, WireError>;
}
```

Both ends are total functions over their respective domains:
`to_wire` succeeds for every valid `ir::Program`, and `from_wire` succeeds
for every blob produced by `to_wire` in the same format version. Round-trip
is exact.

## Not a public opcode table

Earlier bytecode notes described a "stable opcode table" that external
tools could emit directly. That table is retired along with the VM. The
wire format is an internal concern between vyre's `to_wire` and
`from_wire` — it is not a user-level programming model. Frontends that
want to produce vyre programs should emit IR via `ir::ProgramBuilder` and
call `to_wire` at the transport boundary. They should not hand-assemble
wire-format bytes.

If a future external tool needs a stable, versioned, human-authorable
text form for vyre programs, the right answer is an IR text format
analogous to LLVM's `.ll` — not a re-introduction of the opcode table.
That is a separate workstream and is not part of this reconciliation.

## Related documents

- [Program](program.md) — the in-memory `ir::Program` structure
- [IR Overview](overview.md) — the IR's role as the contract
- [Stability](../stability.md) — additive-only evolution rules
- [The Promises](../testing/the-promises.md) — invariants I4, I10, I11
