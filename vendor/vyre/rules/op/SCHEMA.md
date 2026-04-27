# rules/op/ — Op Certificate Schema (v0.5.0)

One TOML file per op id. Emitted by `vyre-conform-runner` as the durable
artifact of "op X satisfies its declared laws on backend Y". Byte-identical
across backends (modulo `allowed_backends`) means the op is substrate-portable.

## Fields

| field                 | type          | required | meaning |
|-----------------------|---------------|----------|---------|
| `op_id`               | string        | yes      | Stable op identifier (e.g. `"primitive.bitwise.xor"`). |
| `cert_version`        | string        | yes      | Certificate format version (follows vyre minor). |
| `wire_format_version` | u32           | yes      | VIR0 wire format version the cert was produced against. |
| `signature_blake3`    | string        | yes      | `blake3(Signature::to_canonical_bytes())` (hex). Placeholder `"TBD"` permitted until runner lands. |
| `witness_set_blake3`  | string        | yes      | `blake3(sorted witness inputs)` (hex). Stable per witness set. |
| `program_blake3`      | string        | yes      | `blake3(program.to_wire())` (hex). Content-addressed program hash. |
| `allowed_backends`    | list<string>  | yes      | Backends for which the cert is valid (`"wgpu"`, `"spirv"`, `"photonic"`). |
| `laws`                | list<string>  | yes      | AlgebraicLaw variant names verified (e.g. `["Commutative", "Associative"]`). |
| `notes`               | string        | no       | Human-readable context. |

## Extension policy

New fields land under `[extensions.<name>]` tables. v0.5.x consumers ignore
unknown extension tables. Fields outside `[extensions]` are frozen per minor.

## Determinism

Two conformant runners producing a cert for the same op + backend MUST emit
byte-identical TOML output (field order, spacing, trailing newline). The
runner drives this by writing through a canonical serializer.

## Placeholder policy

`"TBD"` values are accepted during scaffolding. Before publishing a crate that
ships the cert, every `"TBD"` must resolve to a real blake3 digest.
