# vyre-wgpu

wgpu backend for vyre IR — implements `vyre::VyreBackend` on any wgpu-capable GPU (Vulkan, DX12, Metal, WebGPU).

```
cargo add vyre vyre-wgpu
```

## Example

```rust
use vyre::ir::Program;
use vyre::{DispatchConfig, VyreBackend};
use vyre_wgpu::WgpuBackend;

let backend = WgpuBackend::new()?;
let program: Program = my_program();
let inputs: Vec<Vec<u8>> = vec![b"input data".to_vec()];
let config = DispatchConfig::default();

let outputs: Vec<Vec<u8>> = backend.dispatch(&program, &inputs, &config)?;
```

## Features

- Pipeline cache — reuses compiled WGSL pipelines across dispatches by content hash.
- Buffer pool — reuses GPU buffer allocations across dispatches.
- Validation cache — skips repeated capability checks for already-validated programs.
- Lowering happens internally. Consumers never pass WGSL strings; the crate lowers `Program` through `lowering::lower_with_features`.

## Requirements

- A wgpu-capable GPU. This crate does NOT silently fall back to CPU. Absence of a GPU is surfaced as an error, not a degradation.
- `wgpu = 24.x`. Pinned — major wgpu version bumps are a vyre-wgpu major bump.

## MSRV

Rust 1.85.

## License

MIT OR Apache-2.0.
