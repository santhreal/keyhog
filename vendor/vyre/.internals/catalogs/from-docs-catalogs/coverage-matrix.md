# dialect × backend coverage matrix

Generated from the live `DialectRegistry` + `BackendRegistration`
inventory. Regenerate via `VYRE_REGEN_COVERAGE=1 cargo test -p vyre
--test coverage_matrix`. Every cell transition from ✓ → - is a
coverage regression gated by CI.

| dialect | reference |
|---------|------|
| `buffer` | ✓ |
| `core` | ✓ |
| `decode` | ✓ |
| `encode` | ✓ |
| `hash` | ✓ |
| `io` | ✓ |
| `logical` | ✓ |
| `math` | ✓ |
| `security_detection` | ✓ |
| `stats` | ✓ |
| `string_matching` | ✓ |
| `string_similarity` | ✓ |
| `wgsl_byte_primitives` | ✓ |
| `workgroup` | ✓ |
