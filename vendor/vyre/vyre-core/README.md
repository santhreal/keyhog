# vyre

GPU compute intermediate representation with a proven standard operation library.

## What this crate does

vyre is the compiler stack for GPU compute. Construct `ir::Program` values with
the IR builder, compose operations from the standard library, validate and lower
the result to WGSL, and dispatch the shader on a GPU backend.

## Install

```sh
cargo add vyre
```

## Quick example

The snippet below builds a small program, validates it, lowers it to WGSL, and
dispatches it on the GPU via `wgpu`. It also requires `bytemuck` and `wgpu` in
`Cargo.toml`.

```rust
use vyre::ir::*;
use vyre::runtime::{cached_device, compile_compute_pipeline, bg_entry};
use wgpu::util::DeviceExt;

let program = Program::wrapped(
    vec![
        BufferDecl::read("a", 0, DataType::U32),
        BufferDecl::read("b", 1, DataType::U32),
        BufferDecl::read_write("out", 2, DataType::U32),
    ],
    [64, 1, 1],
    vec![
        Node::let_bind("idx", Expr::gid_x()),
        Node::store(
            "out",
            Expr::var("idx"),
            Expr::bitxor(
                Expr::load("a", Expr::var("idx")),
                Expr::load("b", Expr::var("idx")),
            ),
        ),
    ],
);
assert!(vyre::validate(&program).is_empty());

let wgsl = vyre::lower::wgsl::lower(&program).unwrap();
let (device, queue) = cached_device().unwrap();
let pipeline = compile_compute_pipeline(device, "xor", &wgsl, "main").unwrap();

let a = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
    label: Some("a"), contents: bytemuck::cast_slice(&[0xAAAAAAAAu32; 64]), usage: wgpu::BufferUsages::STORAGE,
});
let b = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
    label: Some("b"), contents: bytemuck::cast_slice(&[0x55555555u32; 64]), usage: wgpu::BufferUsages::STORAGE,
});
let out = device.create_buffer(&wgpu::BufferDescriptor {
    label: Some("out"), size: 256, usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC, mapped_at_creation: false,
});

let bg = device.create_bind_group(&wgpu::BindGroupDescriptor {
    label: Some("bg"), layout: &pipeline.get_bind_group_layout(0), entries: &[bg_entry(0, &a), bg_entry(1, &b), bg_entry(2, &out)],
});
let mut enc = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("enc") });
{
    let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor { label: Some("pass"), timestamp_writes: None });
    pass.set_pipeline(&pipeline);
    pass.set_bind_group(0, &bg, &[]);
    pass.dispatch_workgroups(1, 1, 1);
}
queue.submit(std::iter::once(enc.finish()));
```

Buffer readback and a complete runnable version are in
`examples/02_xor_gpu_dispatch.rs`.

## Why vyre

- **Composable primitives (Cat A):** any algorithm is a composition of simpler
  ops with zero-cost lowering.
- **Hardware intrinsics (Cat C):** ops declare GPU instruction backing per-target;
  swap hardware, swap intrinsics.
- **Link-time registration:** dialect ops, backends, and optimizer passes register
  with `inventory::submit!`; consumers discover those registries through
  `inventory::iter` instead of generated build-scan files.
- **Forbidden patterns (Cat B):** no typetag, no trait-object execution routing,
  no CPU fallback dispatch. Closed-enum semantics throughout.

## Conformance

Pair vyre with `vyre-reference` and backend KAT parity tests for a binary
verdict on backend correctness.

## The book

Documentation and tutorials live in `core/docs/`. Read them locally or build the
mdbook when a rendered site is available.

## License

MIT OR Apache-2.0.
