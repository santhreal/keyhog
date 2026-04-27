# Santh Rust Engineering Standard

Every Santh crate follows these rules.

## Module management

`explicit_mod_list!(pub "path")` handles module declarations in op category directories.
Drop a `.rs` file → it's discovered at compile time. No `mod.rs` edits.

`cargo fix --allow-dirty` after every structural change removes dead imports.

## One file per unit

- One op = one `.rs` file (struct + SPEC + kernel + laws + lowering marker)
- Categories = directories with `explicit_mod_list!` in their parent module
- No `impl_X.rs` split files — impl blocks live with the type
- No `const_X.rs` split files — constants live with their consumer

## Adding an operation

```bash
cp vyre-core/src/ops/template_op.rs vyre-core/src/ops/<category>/my_op.rs
# Edit: struct name, SPEC id, inputs/outputs, laws, program()
cargo check -p vyre  # automod discovers it
```

For conformance:
```bash
# Create vyre-conform/src/specs/<category>/my_op.rs with cpu_reference + golden samples
cargo test -p vyre-conform -- my_op
```

No mod.rs edits. No registry wiring. No multi-file dance.

## Quality gates

- `cargo check --workspace` → 0 errors
- `cargo clippy --workspace` → 0 warnings
- `cargo test --workspace` → all pass
- No `use super::*;` — explicit imports only
- No file > 500 LOC (use `splitrs` to split)

## Tools

| Tool | Purpose |
|------|---------|
| `automod` | auto-discover modules from .rs files |
| `automoduse` | auto-discover + re-export |
| `cargo fix` | remove dead imports |
| `splitrs` | split large files into modules |
| `cargo-modules` | visualize module tree |
