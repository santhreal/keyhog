# vyre Wire Format (VIR0)

> ⚠️ **Staleness warning (V7-CORR-001)**: the tag tables and the
> magic/version constants below predate the current encoder in
> `vyre-foundation/src/serial/wire/`. Where this doc and the code
> disagree, **the code is the truth**:
>
> - Magic + version: `vyre-foundation::serial::wire::framing` —
>   current magic is `b"VYRE"`, version is the `WIRE_FORMAT_VERSION`
>   u16 constant.
> - Expr tags: `serial::wire::tags::{expr_tag, expr_from_tag}`.
> - Node tags: `serial::wire::tags::{node_tag, node_from_tag}`.
> - Encode path: `serial/wire/encode/`.
> - Decode path: `serial/wire/decode/`.
>
> A full doc rewrite driven from the live tag tables is tracked in
> `audits/V7_STATUS.md` under V7-CORR-001/002/003.

This document specifies the binary serialization of a vyre `Program` — the "VIR0" format.

## Design axioms

1. **Deterministic.** Two encoders on the same program produce byte-identical output. Critical for content-addressed caching and cross-machine certificate comparison.
2. **Extensible.** Downstream crates can add new IR constructs without editing `vyre-core`. The format encodes extensions as `(extension_id: u32, payload: Vec<u8>)` pairs that unknown decoders preserve and report.
3. **Versioned.** Every encoded program carries a format version. Migrations land in `vyre-core::dialect::migration`.
4. **Round-trip complete.** Every program that passes `validate_program` round-trips through `to_wire → from_wire` byte-identically.

## Byte layout

```
+---------+---------+--------+-----------------------+-----------+--------------+
| "VIR0"  | version | flags  | metadata header       | node tree | expr arena   |
| 4 bytes |  u8     |  u16   | variable              | variable  | variable     |
+---------+---------+--------+-----------------------+-----------+--------------+
```

### Header

```
magic:          'V' 'I' 'R' '0'     (4 bytes)
version:        u8                  (currently 1)
flags:          u16 little-endian
metadata_len:   u32 little-endian
metadata:       metadata_len bytes
```

### Metadata header

The metadata header encodes program-level facts:

- `entry_op_id`: `Option<String>` — the op this program implements, if any.
- `workgroup_size`: `[u32; 3]`.
- `buffers`: `Vec<BufferDecl>` — each with name, binding, access, element type, count, output flag, optional output byte range, memory hints.
- `metadata`: a `String → Bytes` map for arbitrary attached data (provenance, hashes, certs).

Each field uses a one-byte discriminant followed by its payload. A discriminant in the `[0x00, 0x7F]` range is a core variant; `[0x80, 0xFF]` is an extension variant.

## Expr / Node tree

Nodes are serialized depth-first. Each `Node` / `Expr` begins with a one-byte tag:

### Expr tags

```
0x00  LitU32          u32 value
0x01  LitI32          i32 value
0x02  LitF32          f32 value (IEEE 754 little-endian)
0x03  LitBool         u8 (0 | 1)
0x04  Var             Ident
0x05  Load            Ident buffer, Expr index
0x06  BufLen          Ident buffer
0x07  InvocationId    u8 axis
0x08  WorkgroupId     u8 axis
0x09  LocalId         u8 axis
0x0A  BinOp           u8 op, Expr left, Expr right
0x0B  UnOp            u8 op, Expr operand
0x0C  Call            Ident op_id, u32 argc, Expr*argc
0x0D  Select          Expr cond, Expr true_val, Expr false_val
0x0E  Cast            DataType target, Expr value
0x0F  Fma             Expr a, Expr b, Expr c
0x10  Atomic          u8 op, Ident buffer, Expr index,
                      u8 has_expected, [Expr expected], Expr value
0x80  Opaque          u32 extension_id, u32 payload_len, bytes
```

Tags in `[0x11, 0x7F]` are reserved for future core variants.

### Node tags

```
0x00  Let             Ident name, Expr value
0x01  Assign          Ident name, Expr value
0x02  Store           Ident buffer, Expr index, Expr value
0x03  If              Expr cond, NodeList then, NodeList otherwise
0x04  For             Ident name, Expr start, Expr end, NodeList body
0x05  Loop            NodeList body
0x06  Block           NodeList body
0x07  Barrier
0x08  Return
0x09  IndirectDispatch   Ident buffer, Expr workgroups_offset_bytes
0x0A  AsyncLoad       (see async extension)
0x0B  AsyncWait       (see async extension)
0x80  Opaque          u32 extension_id, u32 payload_len, bytes
```

### BinOp / UnOp / AtomicOp sub-tags

Each u8 sub-tag encodes the operator variant. The table is append-only: new variants use the next free code. Adding a variant bumps the format version and requires a migration.

## DataType encoding

```
0x00  U32
0x01  I32
0x02  F32
0x03  Bool
0x04  Bytes
0x05  U64
0x06  F16
0x07  BF16
0x08  F64
0x09  Vec2U32
0x0A  Vec4U32
0x0B  Array        u32 length, DataType element
0x0C  Tensor
0x80  Opaque       u32 extension_id, u32 payload_len, bytes
```

## Ident encoding

Idents are length-prefixed UTF-8: `u32 length | bytes`. No null termination. No interior NUL bytes (validator rejects them).

## Extension extensibility

The `Opaque` tags (`0x80` on both Expr and Node) encode:

```
tag:            0x80           (1 byte)
extension_id:   u32 LE         stable extension namespace ID
payload_len:    u32 LE
payload:        payload_len bytes
```

Extension IDs are registered via `inventory::submit! { ExtensionRegistration { id, kind, decoder } }`. A decoder that does not know an extension returns `DecodeError::UnknownExtension { extension_id, kind }` with the ID preserved. The consumer installs an extension crate and re-decodes.

This is the forward-compatibility story: a new IR node lands as an `Opaque` extension in a downstream crate. Old decoders preserve it (round-trip round-preserves the extension bytes) but can't introspect. New decoders that link the extension crate decode it to its native form.

Extension IDs in the range `[0x0000_0000, 0x7FFF_FFFF]` are reserved for vendor-assigned core extensions. `[0x8000_0000, 0xFFFF_FFFF]` is community-assigned (registered at `https://vyre.dev/registry/extensions/` when that exists).

## Versioning policy

- Patch version bumps (`0.5.0 → 0.5.1`): no wire change.
- Minor version bumps (`0.5 → 0.6`): may append new discriminants. Old decoders return `DecodeError::UnknownDiscriminant`, not a crash.
- Major version bumps (`0.x → 1.x`): may change layout. A migration pass in `vyre-core::dialect::migration` translates old programs to the new format.

Every change to the discriminant tables above updates `crate::ir::serial::wire::CORE_WIRE_VERSION` and adds a migration entry.

## Round-trip invariant

For every program `p` that passes `validate_program`:

```
let bytes = to_wire(&p)?;
let p2 = from_wire(&bytes)?;
assert_eq!(p, p2);              // PartialEq
assert_eq!(to_wire(&p2)?, bytes); // stability under re-encoding
```

The `wire_roundtrip` test suite enforces this invariant on every KAT program and on fuzz-generated programs (proptest) with shrinking.

## Certificate compatibility

The conform certificate includes `wire_format_version` and a `blake3` of the program's canonical wire bytes. Two certificates with matching `wire_format_version + program_hash + witness_set_hash + backend_id` identify exchangeable artifacts.
