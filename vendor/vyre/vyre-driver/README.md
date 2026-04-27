# vyre-driver

Substrate-agnostic backend machinery for the vyre GPU compiler.

`vyre-driver` is the second layer in vyre's four-layer model. It sits
between `vyre-foundation` (the IR + validator) and concrete backend
crates (`vyre-driver-wgpu`, `vyre-driver-spirv`, `vyre-reference`). It
owns the frozen contract every backend must implement, the registry
that routes a `Program` to the right backend, the pipeline-cache key
machinery, and the capability surface consumer tools use to decide
whether a backend can execute a given program.

```text
vyre-foundation (IR + validator)
   ↓
vyre-driver        ← you are here
   ↓
vyre-driver-wgpu / vyre-driver-spirv / vyre-reference
```

## Invariants

1. **Backend trait is frozen.** `VyreBackend` and `CompiledPipeline`
   signatures do not change within a major version. New capability
   flows through `BackendCapability` registration, never through trait
   mutation.
2. **Dispatch is deterministic per `(program, inputs, config)`.** Two
   calls with the same triple produce byte-identical outputs on every
   registered backend. Divergence is a backend bug, caught by the
   shadow pipeline in `shadow.rs`.
3. **Registration is side-effect-free at import.** Registering a
   backend inserts a `BackendRegistration` into the `inventory`-backed
   registry but does not initialise devices, allocate memory, or open
   adapters. Initialisation is deferred to the caller's first
   `dispatch` / `compile_native`.
4. **Precedence is stable.** `registered_backends_by_precedence()`
   returns backends in ascending `BackendPrecedence` order and this
   order is part of the public API; consumer tools rely on it to pick
   a default backend without inspecting internal state.
5. **Pipeline-cache keys hash the complete Program.** Fingerprints use
   blake3 over the canonical wire form, so two programs with identical
   IR share a cached pipeline regardless of how they were constructed.
6. **Errors carry a `Fix:` section.** Every `BackendError` variant's
   `Display` implementation ends in `Fix: <remediation>` so users do
   not need to guess at recovery.

## Boundaries

`vyre-driver` does:

- Define `VyreBackend`, `CompiledPipeline`, `PendingDispatch`,
  `DispatchConfig`, `BackendCapability`, and the sealed `Backend`
  marker trait.
- Host `backend::registry` (inventory-backed discovery), `pipeline`
  (compile/dispatch indirection), `shadow` (reference-diff
  instrumentation), `migration` (deprecation + semver registries),
  and `validation` (program-level preconditions).
- Expose `core_supported_ops()` so backend crates and consumer tools
  can ask "does this backend execute this Program?" without importing
  any concrete backend.

`vyre-driver` does NOT:

- Touch a GPU, open an adapter, or allocate device memory. Those are
  backend-crate responsibilities.
- Own the IR (`vyre-foundation`), the evaluator (`vyre-reference`),
  or intrinsics (`vyre-intrinsics`).
- Declare workload-specific primitives. Those live in `vyre-primitives`
  / `vyre-libs` and compose over `Program`.

## Three worked examples

### 1. Pick the best-available backend and dispatch

```rust
use vyre_driver::backend::{registered_backends_by_precedence, VyreBackend};
use vyre_driver::pipeline::compile;
use vyre_foundation::ir::Program;

fn run(program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
    let backend = registered_backends_by_precedence()
        .first()
        .expect("no backend registered")
        .instantiate()?;
    let pipeline = compile(backend.as_ref(), program)?;
    pipeline.dispatch(inputs, &Default::default())
}
```

### 2. Gate a feature on backend capability

```rust
use vyre_driver::backend::{registered_backends, core_supported_ops};
use vyre_foundation::ir::Program;

fn can_run(program: &Program) -> bool {
    let ops = core_supported_ops(program);
    registered_backends()
        .iter()
        .any(|reg| ops.iter().all(|op| reg.capability.supports(op)))
}
```

### 3. Instrument with the shadow pipeline

```rust
use vyre_driver::shadow::ShadowedPipeline;
use vyre_driver::pipeline::compile;

fn compile_with_shadow(
    primary: &dyn vyre_driver::VyreBackend,
    reference: &dyn vyre_driver::VyreBackend,
    program: &vyre_foundation::ir::Program,
) -> Result<ShadowedPipeline, vyre_driver::BackendError> {
    let main = compile(primary, program)?;
    let refp = compile(reference, program)?;
    Ok(ShadowedPipeline::new(main, refp))
}
```

## Extension guide — adding a new backend

1. Create a new crate (for example `vyre-driver-cuda`). Depend on
   `vyre-foundation` and `vyre-driver` only; never on `vyre-runtime`
   or the `vyre` meta-crate.
2. Implement `VyreBackend` for your backend struct. Include a
   `BackendCapability` describing the ops, memory model, subgroup
   size, and max workgroup extent your hardware supports.
3. Implement `CompiledPipeline` for your cached pipeline form. It
   MUST be bit-identical to the trait's `dispatch` path.
4. Register with `inventory::submit!` — the registry picks it up at
   link time. No `lazy_static`, no initializer function.
5. Add your backend to the conformance matrix under
   `conform/vyre-conform-runner` so parity against the reference
   interpreter is enforced on every CI run.
6. Expose a `BackendPrecedence` value so callers that want "the best
   available backend" pick yours when appropriate.

See `capability.rs`, `registry.rs`, and `shadow.rs` for the exact
contracts; see `conform/vyre-conform-runner/tests/parity_matrix.rs`
for a worked wiring that brings a third-party backend online.
