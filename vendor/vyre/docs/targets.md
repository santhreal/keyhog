# vyre Targets

A **target** is a substrate that can execute vyre IR. Each target lives in its own crate, implements the `VyreBackend` trait, and registers with the global backend registry via `inventory::submit!`.

## Target matrix

| Target | Crate | Status | Execution path |
|--------|-------|--------|----------------|
| `wgpu` | `vyre-wgpu` | Primary, production | vyre IR → naga Module → wgpu → Vulkan / DX12 / Metal / WebGPU |
| `spirv` | `backends/spirv` | In plan | vyre IR → naga Module → `naga::back::spv` → Vulkan direct |
| `photonic` | `backends/photonic` | Stub (forcing function) | registers, `supports_dispatch = false`, listed by `registered_backends()` |
| `cuda` | `backends/cuda` | Future | vyre IR → PTX emitter → CUDA Driver API |
| `metal` | `backends/metal` | Future | vyre IR → MSL emitter → Metal Shading Language |
| `cpu` | `vyre-reference` | Oracle | Pure-Rust structural interpreter — the conformance reference, not a production target |

## Capabilities

Each target reports `Capabilities`:

```rust
pub struct Capabilities {
    pub supports_dispatch: bool,
    pub supports_storage_buffers: bool,
    pub supports_uniform_buffers: bool,
    pub supports_push_constants: bool,
    pub supports_workgroup_atomics: bool,
    pub supports_subgroup_ops: bool,
    pub max_invocations_per_workgroup: u32,
    pub max_workgroup_size: [u32; 3],
    pub max_storage_buffer_bytes: u64,
    pub max_push_constant_bytes: u32,
    pub datatype_support: DatatypeSupport,
}
```

Frontends query capabilities before dispatch. Programs exceeding a target's limits return `BE_E200_CAPABILITY` at compile time, not a runtime panic.

## Registration

```rust
inventory::submit! {
    vyre::BackendRegistration {
        id: "wgpu",
        factory: || Box::new(WgpuBackend::new()?),
        supported_ops: vyre::core_supported_ops,
    }
}
```

`vyre::registered_backends()` returns the id list; `vyre::backend(id)` constructs an instance. No manual global registration, no init function. Link the crate; the backend is visible.

## The photonic forcing function

`backends/photonic/` is intentionally minimal. It registers, reports `supports_dispatch = false`, and every conform cycle confirms it's listed in `registered_backends()`. When real photonic hardware ships, the stub becomes a real backend. The abstraction does not move.

The stub exists so that **every IR extension, every new op, every new wire-format field must compile photonic without changes**. A CI test asserts this. If adding `Node::Speculate` breaks photonic, the IR extension story is broken — merge blocked.

## Adapter selection (wgpu target)

The `wgpu` backend exposes:

- `enumerate_adapters()` — returns every adapter the wgpu instance can see.
- `AdapterCriteria` — policy struct (vendor preference, discrete-vs-integrated, required limits, required features).
- `select_adapter(criteria)` — chooses one adapter.
- `init_device_for_adapter(adapter)` — produces a `Device + Queue` pair.
- `VYRE_ADAPTER_INDEX` env var — manual override for diagnostics.

The default dispatch path uses a cached singleton adapter chosen by `AdapterCriteria::default()`. Multi-GPU frontends construct their own adapter list and dispatch per adapter.

## Target cross-matrix (what the conform gate runs)

```
             wgpu   spirv   photonic   cpu (reference)
primitive       ✓      (planned)     ✓*        ✓
hash            ✓      (planned)     ✓*        ✓
decode          ✓      (planned)     ✓*        ✓
graph           ✓      (planned)     ✓*        ✓
…
* Photonic is the forcing function, not a real execution target.
  "✓" means "compiles, registers, passes the cert check that it can
  see the op declared"—not that it executes on hardware. When real
  photonic hardware lands, the cells become genuine parity passes.
```

Every op that lands in `vyre-core` must enter this matrix. The dialect-coverage CI script (`scripts/check_dialect_coverage.sh`) blocks merges that declare ops without at least one non-stub target lowering (`naga_wgsl | naga_spv | ptx | metal_ir`).

## Adding a new target

1. Create the crate: `backends/<name>/`.
2. Implement `VyreBackend`. Validate capabilities at compile time, not at dispatch time.
3. Register via `inventory::submit! { BackendRegistration { … } }`.
4. Run the conform suite: `cargo test -p vyre-conform-runner -- --backend <name>`. Every witness case must match the reference.
5. Emit a certificate. Two backends with byte-identical certificates (modulo backend-id field) are exchangeable.

No step in this flow touches `vyre-core`, `vyre-reference`, `vyre-conform-spec`, or any other existing target. That is the test of whether the design is right.
