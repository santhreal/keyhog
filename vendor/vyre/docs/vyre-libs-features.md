# vyre-libs Feature Matrix

`vyre-libs` uses feature flags for footprint control, not for product
shape. The matrix has three layers:

| Layer | Features | Rule |
| --- | --- | --- |
| Defaults | `default` | Load-bearing consumer surface. CI must keep this compiling without parser WIP. |
| Aggregates | `math`, `nn`, `matching`, `crypto`, `parsing` | Compatibility rollups. Add new granular features here only when the aggregate contract should include them. |
| Granular dialects | `math-linalg`, `matching-nfa`, `c-parser`, etc. | Smallest selectable units. Benches/tests must declare `required-features` for any granular feature they need. |

Operational features:

| Feature | Use |
| --- | --- |
| `bench` | Benchmark-only helper APIs and layout introspection. Not part of normal consumer builds. |
| `rule` | Rule-builder surface. |
| `vyre_wgpu`, `vyre_driver_wgpu` | Compatibility aliases for optional wgpu integration. |

CI policy:

- Default `cargo check -p vyre-libs` covers the consumer surface.
- Parser tests must opt in with `c-parser`, `go-parser`, or `python-parser`.
- Bench targets must keep `required-features` in `vyre-libs/Cargo.toml`; do not rely on workspace-wide defaults.
- New granular features need one line in this table and one focused check command in the owning PR.
