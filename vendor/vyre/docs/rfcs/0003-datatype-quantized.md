# RFC 0003 — DataType::Quantized

## Summary

Add a first-class quantization DataType:

```rust
DataType::Quantized {
    storage: Box<DataType>,          // underlying storage (I8 / I4 / U8 / U4)
    scale_kind: ScaleKind,           // PerTensor | PerChannel(u32) | PerGroup(u32)
    zero_point_kind: ZeroPointKind,  // Absent | PerTensor | PerChannel
}
```

## Motivation

Modern LLM serving uses int8 weight-only quantization as standard;
int4 is common. Activation quantization is emerging. Vyre today
routes all weights + activations as u32/f32 — inefficient for
every ML production workload.

Quantization also interacts with every other 0.7 RFC: autodiff in
quantized domain needs straight-through estimators; Region
compositions need scale-aware rewrites; megakernel bytecode needs
tagged storage for quantized tensors.

## Design

New DataType variant: `Quantized { storage, scale_kind, zero_point_kind }`.

`ScaleKind`:
- `PerTensor` — one f32 scale per buffer
- `PerChannel(axis: u32)` — one scale per slice along axis
- `PerGroup(group_size: u32)` — one scale per `group_size` contiguous elements (GPTQ-style)

`ZeroPointKind`:
- `Absent` — symmetric quant, zero point = 0
- `PerTensor` — one zero point per buffer
- `PerChannel(axis: u32)` — one per slice

Quantized buffers carry two-to-three backing buffers:
- `<name>_storage` — the quantized values (I8 / I4 / etc.)
- `<name>_scale` — f32 scale factors
- `<name>_zero_point` — (optional) zero points

New BinOps: `QuantizedMatMul`, `QuantizedAdd` — backends lower these
to hardware tensor-core / MMA instructions when available, scalar
dequant-op-requant otherwise.

## Wire format

Tag `0x16` reserved for `Quantized`. Payload:
- 1 byte storage DataType tag (restricted to I4/I8/I16/U4/U8/U16)
- 1 byte scale_kind discriminant + `u32` parameter for PerChannel/PerGroup
- 1 byte zero_point_kind discriminant + `u32` parameter

## Testing

- Round-trip: every `Quantized { ... }` combination round-trips
  through wire format
- Parity: dequantize → op → quantize path matches the pure-float
  reference within a declared ULP budget
- Gap: every Category A nn op (`vyre-libs::nn::linear`, etc.) has
  a quantized variant registered

## Alternatives considered

- **Opaque extension only.** Rejected: every ML consumer needs
  quantization; making it an extension prevents cross-crate
  ecosystem composition.
- **Only f16/bf16 (no int quant).** Rejected: int4 weight-only is
  now standard for LLM serving and we can't defer it past 0.7.
- **Separate `vyre-quant` crate.** Considered; rejected because
  DataType is the cross-cutting surface.

## Open questions

- Int4 storage layout: nibble-packed vs byte-aligned?
- Quantization-aware training support in 0.7 or 0.8?
