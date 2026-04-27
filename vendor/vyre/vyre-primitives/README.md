# vyre-primitives

Marker types for compositional primitive operations dispatched by
[`vyre-reference`](../vyre-reference). Each primitive is a unit (or
near-unit) struct that implements `ReferenceEvaluator`; the evaluator
bodies live in `vyre-reference::src/primitives/`, the GPU shaders for
the same primitives live in `vyre-driver-wgpu::src/shaders/`.

Keeping the marker types in their own crate lets tools that walk
`inventory::iter` (coverage matrix, Python bindings, etc.) name a
primitive without pulling in the reference interpreter or any GPU
dependency.

## Crates that depend on this one

- `vyre-reference` — CPU oracle
- `vyre-driver-wgpu` — GPU shaders for the same primitives
