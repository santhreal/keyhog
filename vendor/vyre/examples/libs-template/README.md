# {{crate_name}}

Community Category-A op dialect for
[`vyre-libs`](https://docs.rs/vyre-libs).

Generated from the `vyre-libs-template` scaffold. Ships a skeleton
`example_op` demonstrating the 5-step Cat-A authoring recipe (see
[AUTHORING.md](https://github.com/santhsecurity/vyre/blob/main/vyre-libs/AUTHORING.md)).

## Quickstart

```sh
cargo generate --git https://github.com/{{gh_org}}/vyre-libs-template \
    --name {{crate_name}}
cd {{crate_name}}
cargo test
```

## Layout

```
{{crate_name}}/
├── Cargo.toml
├── src/
│   └── lib.rs         # your op lives here
└── tests/
    └── cat_a_conform.rs  # byte-identity witness tests
```

## Contributing a second op

1. Add a new module under `src/` with your builder + free function.
2. Register an `OpEntry` so the universal harness picks it up.
3. Add a witness in `tests/cat_a_conform.rs`.
4. Run `cargo test --all-features`.

## Publishing

Community dialect crates ship on crates.io directly — no PR into
`vyre-libs` itself is needed. Use a `vyre-libs-` prefix in the crate
name so discovery is easy (e.g. `vyre-libs-quant`,
`vyre-libs-llm`). The extension-registry crate `vyre-libs-extern`
discovers them via inventory; link the extern crate as a dep so
callers see your ops through the unified surface.
