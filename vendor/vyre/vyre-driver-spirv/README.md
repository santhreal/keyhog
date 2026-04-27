# vyre-driver-spirv

SPIR-V backend for [vyre](https://crates.io/crates/vyre), via
[naga](https://crates.io/crates/naga).

## What it does

Reuses the shared `naga::Module` builder family with `vyre-driver-wgpu` and emits
SPIR-V words via `naga::back::spv::write_vec`. That means the kernel body
is the same program across both backends — the only difference is the
back-end writer. This is the "substrate-neutral" claim of vyre 0.5.0 made
concrete: two real compute backends, same IR, same op ids, interchangeable
certificates.

## Using it

```rust,no_run
use vyre_driver_spirv::SpirvBackend;

// The caller passes the naga::Module produced by the shared VYRE lowering path.
let module: naga::Module = build_module_for_current_program();
let spirv_words: Vec<u32> = SpirvBackend::emit_spv(&module).expect("spv emit");
// hand `spirv_words` to your Vulkan dispatch stack.
# fn build_module_for_current_program() -> naga::Module { naga::Module::default() }
```

## Relationship to vyre-driver-wgpu

`vyre-driver-wgpu` owns a Vulkan/Metal/DirectX dispatch stack via `wgpu`. `vyre-driver-spirv`
does not — it emits a SPIR-V blob for consumers that own their own Vulkan
stack. The registered `VyreBackend::dispatch` returns a structured refusal
pointing the caller at the intended flow.

## License

MIT OR Apache-2.0.
