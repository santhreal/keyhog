# external_ir_extension

A minimal worked example of extending vyre's IR from a third-party
crate — no fork, no patch, no internal access required. If you are a
consumer writing a new op, new dialect, or new analysis pass, this is
the starting template.

## What the example demonstrates

1. Building a vyre `Expr` that uses an opaque extension payload — the
   escape hatch for extensions whose semantics are not known to the
   core IR.
2. Registering an `OpDef` in the `DialectRegistry` via
   `OpDefRegistration` so validators, the wire decoder, and the
   backend dispatch machinery all learn about the new op at link
   time.
3. Keeping the extension crate decoupled: it depends only on
   `vyre-core` and `vyre-driver`, never on backend crates or
   downstream tooling.

Running the example:

```bash
cd libs/performance/matching/vyre/examples/external_ir_extension
cargo run
# → Successfully built external extension: Opaque(42, [1, 2, 3])
```

## Anatomy — how an external crate plugs into vyre

Every extension follows the same four-step recipe:

1. **Claim an op tag range.** Core vyre uses tags `0..0x7F`. External
   dialects claim a disjoint range (convention: `0x80..0xFF` for
   internal forks, `0x100..` for published dialects). A published
   `DIALECTS.md` index (in progress, tracked by `dialect-registry`)
   will arbitrate overlapping claims the same way IANA arbitrates
   ports.
2. **Define the `OpDef`.** Give each op a stable name, a `Category`
   (A, B, or C per the migration doc), algebraic laws it obeys, and
   a signature. See `vyre-spec` for the trait surface.
3. **Register at link time.** Use `inventory::submit!` with an
   `OpDefRegistration`. Do NOT call a setup function from `main`;
   registration runs automatically via the `inventory` runtime-init
   hooks so consumer tooling (surgec, pyrograph, warpscan) picks up
   your op without linking-order surprises.
4. **Provide backend emitters and CPU refs.** If your op is
   Category-A (pure composition), no backend work is needed — you
   build a `Program` from existing primitives. Category-B / -C
   require a CPU reference and a Naga emitter arm in each backend
   that claims to support your op.

## Why Opaque exists

Opaque extensions are the IR's extensibility primitive. Core vyre
does not interpret an opaque payload's bytes; it preserves them
byte-for-byte and routes them to the registered resolver for that
extension kind.

This means:

- New dialects do not require a core release.
- A consumer that links the owning extension crate gets byte-identical
  passthrough semantics for the opaque payload on `to_wire` /
  `from_wire`.
- A consumer that does **not** link the owning extension crate fails
  loudly at decode time with a `Fix:` error naming the missing
  resolver. Unknown opaque kinds are never dropped or silently
  reinterpreted.
- The wire format remains stable because adding a new opaque kind does
  not change how core `Expr` / `Node` variants are encoded.

## Boundaries

This example deliberately:

- Does NOT implement a real backend emitter. A real extension that
  needs GPU execution must ship emitter arms in
  `vyre-driver-wgpu` / `vyre-driver-spirv` (or a third-party
  backend).
- Does NOT implement a CPU reference. Category-B / -C extensions
  need `CpuOp` impls to participate in conformance.
- Does NOT register in `inventory` — the example's `main` just builds
  an opaque expression and prints it, to keep the surface area small.
  Production extensions MUST register and ship the matching opaque
  resolver so consumers decode the payload as passthrough instead of
  hitting the loud missing-resolver failure path.

## Next steps for a real extension

1. Read `docs/migration-vyre-ops-to-intrinsics.md` to decide which
   Category your op belongs to (A / B / C).
2. Read `docs/region-chain.md` — every composition must wrap in a
   region; the helper is exported from `vyre-intrinsics::region`.
3. Read `conform/README.md` (once published) for the conformance
   workflow; your extension must hold parity against the CPU
   reference on every registered backend.
4. File your dialect tag claim against the `dialect-registry` tracker
   before publishing so users don't hit overlapping tags.

See `src/main.rs` for the minimal call graph; grep the workspace for
`inventory::submit!` to see real registrations that ship today.
