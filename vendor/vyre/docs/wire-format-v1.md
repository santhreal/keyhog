# VIR0 — vyre IR Wire Format Specification

**Version:** 1 (vyre 0.5.0)
**Status:** Stable
**Normative:** Yes
**Canonical reference:** [`docs/wire-format.md`](docs/wire-format.md)

## Scope

VIR0 is the external, language-agnostic binary serialization of a vyre IR `Program`.
Third-party tooling — including non-Rust bindings, cross-platform caches, and
conformance certificate pipelines — targets this format directly.

## Guarantees

- **Deterministic.** Two conformant encoders emit byte-identical output for the same `Program`.
- **Extensible.** Downstream crates add constructs via `(extension_id: u32, payload: Vec<u8>)` pairs without editing vyre-core. Tag range `[0x80, 0xFF]` is extension-reserved.
- **Versioned.** Every encoded program carries an 8-bit format version in its header. Migrations between versions ship as data transformations in `vyre-core::dialect::migration`.
- **Round-trip complete.** For every program that passes `validate_program`, `from_wire(to_wire(p)) == p` byte-identically.

## Header

```
magic:         "VIR0"  (4 bytes)
version:       u8      (this revision: 1)
flags:         u16 little-endian
metadata_len:  u32 little-endian
metadata:      metadata_len bytes
```

## Layers

1. **Header** — magic, version, flags, metadata.
2. **Metadata** — entry op id, workgroup size, buffer declarations, arbitrary k/v attachments.
3. **Expr / Node tree** — depth-first, tag-prefixed.
4. **Extension region** — `0x80..=0xFF` tags dispatched through `inventory::iter::<ExtensionRegistration>`.

## Full specification

See [`docs/wire-format.md`](docs/wire-format.md) for:
- exhaustive tag tables (Expr tags `0x00..0x7F`, Node tags, DataType tags)
- extension decoder protocol and `DecodeError::UnknownExtension { id }` semantics
- proof of determinism (canonical field ordering, canonical integer encoding)
- proof of round-trip equivalence (encoder ⊕ decoder form an isomorphism modulo
  the equivalence class defined by `validate_program`)

## Stability policy

- Tag assignments in `[0x00, 0x7F]` are **stable across the 0.5.x series**. Adding
  a new core tag bumps the `version` byte.
- Tags in `[0x80, 0xFF]` are **extension-reserved forever**. vyre-core never claims
  them; extension crates own the contract for their own ids.
- Wire format deprecations require a minor version bump and a migration in
  `vyre-core::dialect::migration`.

## Bindings

A conformant non-Rust binding MUST:
1. Parse the header and reject any version it does not support.
2. Preserve unknown extension payloads verbatim when re-encoding.
3. Surface unknown extensions as structured errors (not silent drops).
4. Produce byte-identical output when re-encoding a program it consumed.

## Reference implementation

- Rust encoder: `vyre-core/src/ir/serial/wire/encode/`
- Rust decoder: `vyre-core/src/ir/serial/wire/decode/`
- Round-trip tests: `vyre-wgpu/tests/ir/wire.rs`

## Licensing

This specification is published under MIT + Apache-2.0 dual license, matching
the vyre crate.
