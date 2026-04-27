# Wire-format tag reservations — vyre 0.6 terminal allocation

This document is the terminal tag allocation table for the VIR0 wire format
as frozen in vyre 0.6. It supplements `docs/wire-format.md` (VIR0 structural
spec) with the byte-level byte-to-variant mapping for every enum that crosses
the wire.

After 0.6 no existing tag is renumbered. New variants append in the reserved
ranges below. Any variant added in 0.7+ that lands outside its reserved range
is a wire-format break and requires a major-version bump.

## Reserved ranges per enum

Every op enum follows the same range discipline:

- `0x00 .. 0x7F` — core variants. Append-only. Used by every 0.6 and 0.7+
  variant that ships in `vyre-spec` proper.
- `0x80` — `Opaque(ExtensionXxxId)`. Followed by `u32` little-endian
  extension id plus any variant-specific payload. Reserved per enum; never
  reused for a core variant.
- `0x81 .. 0xFF` — reserved. DO NOT ALLOCATE. Held in reserve for future
  extension-class escape hatches (e.g. "hardware-lowered opaque",
  "composite-lowered opaque") that might need a distinct tag namespace so
  decoders can distinguish without reading the extension id.

The core-variant range `0x00 .. 0x7F` is further partitioned by
*semantic class* so reading the tag table tells a reviewer at a glance what
layer a variant belongs to:

- `0x00 .. 0x3F` — primitive / logical / math / rule. The 0.6 shipping set.
- `0x40 .. 0x5F` — hardware-intrinsic variants (0.7). Reserved, empty in 0.6.
- `0x60 .. 0x6F` — composite-lowered variants (0.7). Reserved, empty in 0.6.
- `0x70 .. 0x7F` — reserved for future semantic classes. Unallocated.

When a 0.7 hardware op lands, it takes the next free tag in `0x40..0x5F`.
A 0.7 composite op takes `0x60..0x6F`. A 0.6 additive extension (appended to
an existing enum) takes the next free slot in its own enum's current range,
not the hardware/composite range.

## DataType

`vyre-spec/src/data_type.rs`. Source of truth for byte values:
`vyre-foundation/src/serial/wire/tags/data_type_tag.rs` and `data_type_from_tag.rs`.

| Tag | Variant | Shipped | Class |
| --- | --- | --- | --- |
| `0x00` | `U32` | 0.4 | primitive |
| `0x01` | `I32` | 0.4 | primitive |
| `0x02` | `U64` | 0.4 | primitive |
| `0x03` | `Vec2U32` | 0.4 | primitive |
| `0x04` | `Vec4U32` | 0.4 | primitive |
| `0x05` | `Bool` | 0.4 | primitive |
| `0x06` | `Bytes` | 0.4 | primitive |
| `0x07` | `F32` | 0.5 | primitive |
| `0x08` | `F16` | 0.5 | primitive |
| `0x09` | `BF16` | 0.5 | primitive |
| `0x0A` | `F64` | 0.5 | primitive |
| `0x0B` | `Tensor` | 0.5 | primitive |
| `0x0C` | `Array { element_size }` | 0.5 | primitive |
| `0x0D` | `U8` | **0.6 NEW** | primitive |
| `0x0E` | `U16` | **0.6 NEW** | primitive |
| `0x0F` | `I8` | **0.6 NEW** | primitive |
| `0x10` | `I16` | **0.6 NEW** | primitive |
| `0x11` | `I64` | **0.6 NEW** | primitive |
| `0x12` | `Handle(HandleKind)` | **0.6 NEW** | primitive |
| `0x13` | `Vec { element, count }` | **0.6 NEW** | primitive |
| `0x14` | `TensorShaped { element, shape }` | **0.6 NEW** | primitive |
| `0x15 .. 0x3F` | reserved, primitive class | — | primitive |
| `0x40 .. 0x5F` | reserved, hardware class (0.7) | — | hardware |
| `0x60 .. 0x6F` | reserved, composite class (0.7) | — | composite |
| `0x70 .. 0x7F` | reserved, future class | — | — |
| `0x80` | `Opaque(ExtensionDataTypeId)` | 0.5 | extension |

**Payload format** for the 0.6 additions:

- `U8`, `U16`, `I8`, `I16`, `I64` — tag only, zero payload bytes.
- `Handle` — tag + `u8 HandleKind` discriminant + optional variant payload.
  `HandleKind` tags: `0x00 Buffer`, `0x01 Texture`, `0x02 Sampler`,
  `0x03 Pipeline`, `0x04 BindGroup`. `0x05 .. 0x7F` reserved.
- `Vec` — tag + `u8 count` + recursive `DataType` of the element (cannot be
  `Vec`, `TensorShaped`, `Array`, `Bytes`, `Tensor`, or `Opaque` — enforce
  at encode time).
- `TensorShaped` — tag + recursive element `DataType` + `u8 rank` (bounded
  to 8) + `rank × u32` shape entries.

## BinOp

`vyre-spec/src/bin_op.rs`. Source of truth:
`vyre-foundation/src/serial/wire/tags/bin_op_tag.rs`.

| Tag | Variant | Shipped |
| --- | --- | --- |
| `0x00` | `Add` | 0.4 |
| `0x01` | `Sub` | 0.4 |
| `0x02` | `Mul` | 0.4 |
| `0x03` | `Div` | 0.4 |
| `0x04` | `Mod` | 0.4 |
| `0x05` | `BitAnd` | 0.4 |
| `0x06` | `BitOr` | 0.4 |
| `0x07` | `BitXor` | 0.4 |
| `0x08` | `Shl` | 0.4 |
| `0x09` | `Shr` | 0.4 |
| `0x0A` | `Eq` | 0.4 |
| `0x0B` | `Ne` | 0.4 |
| `0x0C` | `Lt` | 0.4 |
| `0x0D` | `Gt` | 0.4 |
| `0x0E` | `Le` | 0.4 |
| `0x0F` | `Ge` | 0.4 |
| `0x10` | `And` | 0.4 |
| `0x11` | `Or` | 0.4 |
| `0x12` | `AbsDiff` | 0.4 |
| `0x13` | `Min` | 0.5 |
| `0x14` | `Max` | 0.5 |
| `0x15` | `SaturatingAdd` | **0.6 NEW** |
| `0x16` | `SaturatingSub` | **0.6 NEW** |
| `0x17` | `SaturatingMul` | **0.6 NEW** |
| `0x18` | `Shuffle` | **0.6 NEW** |
| `0x19` | `Ballot` | **0.6 NEW** |
| `0x1A` | `WaveReduce` | **0.6 NEW** |
| `0x1B` | `WaveBroadcast` | **0.6 NEW** |
| `0x1C .. 0x3F` | reserved, primitive class | — |
| `0x40 .. 0x5F` | reserved, hardware class (0.7) | — |
| `0x60 .. 0x6F` | reserved, composite class (0.7) | — |
| `0x70 .. 0x7F` | reserved, future class | — |
| `0x80` | `Opaque(ExtensionBinOpId)` | 0.5 |

## UnOp

`vyre-spec/src/un_op.rs`. Source of truth:
`vyre-foundation/src/serial/wire/tags/un_op_tag.rs`.

| Tag | Variant | Shipped |
| --- | --- | --- |
| `0x00` | `Negate` | 0.4 |
| `0x01` | `BitNot` | 0.4 |
| `0x02` | `LogicalNot` | 0.4 |
| `0x03` | `Popcount` | 0.5 |
| `0x04` | `Clz` | 0.5 |
| `0x05` | `Ctz` | 0.5 |
| `0x06` | `ReverseBits` | 0.5 |
| `0x07` | `Sin` | 0.5 |
| `0x08` | `Cos` | 0.5 |
| `0x09` | `Abs` | 0.5 |
| `0x0A` | `Sqrt` | 0.5 |
| `0x0B` | `Floor` | 0.5 |
| `0x0C` | `Ceil` | 0.5 |
| `0x0D` | `Round` | 0.5 |
| `0x0E` | `Trunc` | 0.5 |
| `0x0F` | `Sign` | 0.5 |
| `0x10` | `IsNan` | 0.5 |
| `0x11` | `IsInf` | 0.5 |
| `0x12` | `IsFinite` | 0.5 |
| `0x13` | `Exp` | **0.6 NEW** |
| `0x14` | `Log` | **0.6 NEW** |
| `0x15` | `Exp2` | **0.6 NEW** |
| `0x16` | `Log2` | **0.6 NEW** |
| `0x17` | `Tan` | **0.6 NEW** |
| `0x18` | `Asin` | **0.6 NEW** |
| `0x19` | `Acos` | **0.6 NEW** |
| `0x1A` | `Atan` | **0.6 NEW** |
| `0x1B` | `Sinh` | **0.6 NEW** |
| `0x1C` | `Cosh` | **0.6 NEW** |
| `0x1D` | `Tanh` | **0.6 NEW** |
| `0x1E .. 0x3F` | reserved, primitive class | — |
| `0x40 .. 0x5F` | reserved, hardware class (0.7) | — |
| `0x60 .. 0x6F` | reserved, composite class (0.7) | — |
| `0x70 .. 0x7F` | reserved, future class | — |
| `0x80` | `Opaque(ExtensionUnOpId)` | 0.5 |

## AtomicOp

`vyre-spec/src/atomic_op.rs`. Source of truth:
`vyre-foundation/src/serial/wire/tags/atomic_op_tag.rs`.

| Tag | Variant | Shipped |
| --- | --- | --- |
| `0x00` | `Add` | 0.4 |
| `0x01` | `Or` | 0.4 |
| `0x02` | `And` | 0.4 |
| `0x03` | `Xor` | 0.4 |
| `0x04` | `Min` | 0.4 |
| `0x05` | `Max` | 0.4 |
| `0x06` | `Exchange` | 0.4 |
| `0x07` | `CompareExchange` | 0.4 |
| `0x08` | `CompareExchangeWeak` | **0.6 NEW** |
| `0x09` | `FetchNand` | **0.6 NEW** |
| `0x0A .. 0x3F` | reserved, primitive class | — |
| `0x40 .. 0x5F` | reserved, hardware class (0.7) | — |
| `0x60 .. 0x6F` | reserved, composite class (0.7) | — |
| `0x70 .. 0x7F` | reserved, future class | — |
| `0x80` | `Opaque(ExtensionAtomicOpId)` | 0.5 |

## TernaryOp (NEW in 0.6)

`vyre-spec/src/ternary_op.rs`. Source of truth:
`vyre-foundation/src/serial/wire/tags/ternary_op_tag.rs` (to be authored).

Introduced in 0.6 for signature-level metadata about fused-ternary ops. The IR
continues to represent Fma and Select as dedicated `Expr` variants; this enum
exists so `OpMetadata` / `OpSignature` can classify a ternary op by kind.

| Tag | Variant | Shipped |
| --- | --- | --- |
| `0x00` | `Fma` | **0.6 NEW** |
| `0x01` | `Select` | **0.6 NEW** |
| `0x02` | `Clamp` | **0.6 NEW** |
| `0x03 .. 0x3F` | reserved, primitive class | — |
| `0x40 .. 0x5F` | reserved, hardware class (0.7) | — |
| `0x60 .. 0x6F` | reserved, composite class (0.7) | — |
| `0x70 .. 0x7F` | reserved, future class | — |
| `0x80` | `Opaque(ExtensionTernaryOpId)` | **0.6 NEW** |

## RuleCondition

`vyre-spec/src/rule_condition.rs` (or wherever it lives after Codex-B's audit).

| Tag | Variant | Shipped |
| --- | --- | --- |
| `0x00 .. 0x??` | existing rule-condition variants (audit source for current tags) | 0.4–0.5 |
| **NEW 0.6** | `RegexMatch`, `SubstringMatch`, `PrefixMatch`, `SuffixMatch`, `RangeMatch`, `SetMembership` | **0.6 NEW** — append sequentially from the first free tag |
| `0x40 .. 0x5F` | reserved, hardware class (0.7) | — |
| `0x60 .. 0x6F` | reserved, composite class (0.7) | — |
| `0x70 .. 0x7F` | reserved, future class | — |
| `0x80` | `Opaque(ExtensionRuleConditionId)` | 0.5 |

## Invariants that the encoder enforces

Every `xxx_tag` encoder function in `vyre-foundation/src/serial/wire/tags/`:

- Returns `Err` for a variant whose tag is not in this document. Silent
  data loss on round-trip is a contract break.
- Never emits a tag in a reserved-but-unallocated range. Emitting `0x21` on
  `DataType` today is a bug; the variant must first be allocated here.
- Checks payload bounds before emitting. Truncation is a data-loss bug.

The decoder counterpart in `xxx_from_tag.rs`:

- Accepts every tag documented here.
- Returns a structured `UnknownDiscriminant { tag, enum: "DataType" }`
  error for any byte outside the allocated + reserved ranges. Opaque
  (`0x80`) is NEVER confused with "unknown."
- Never panics on unknown input.

## Policy

- **0.6 and later minor bumps** (`0.6.x → 0.7.0`): new variants append in
  the next free tag of the enum's primitive class (`0x00..0x3F`), or in
  `hardware` / `composite` / `future` ranges when the variant belongs to
  that class.
- **Patch bumps** (`0.6.0 → 0.6.1`): zero wire change.
- **Major bump** (`0.x → 1.0`): allowed to renumber, re-partition, remove
  variants, change the magic. A migration pass must translate 0.x programs.

See `docs/wire-format.md` for the structural (magic + version + header +
tree) specification; this document covers only the per-enum tag assignments.
