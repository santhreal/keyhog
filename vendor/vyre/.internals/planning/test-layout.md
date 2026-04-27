# Test layout convention

Tests in the vyre workspace live in exactly one of three places.

## Unit tests

Inside the source file they test, in a `#[cfg(test)] mod tests` block.
One module per file. Import `super::*`. No external crate deps.

```rust
// vyre-core/src/ir/validate/typecheck.rs
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn and_or_type_is_bool() { /* … */ }
}
```

Unit tests prove the **contract of a function**. They run fast, have no
setup, and assert the postcondition directly.

## Integration tests

Under `<crate>/tests/`. One file per feature area, mirroring the source
module tree. A top-level module file (`vyre-core/tests/ops.rs`) declares the
subtree via `mod ops { mod primitive { … } }`.

```
vyre-core/tests/ops.rs                       # mirror root for src/ops/
vyre-core/tests/ops/primitive/math/test_add.rs
```

Integration tests prove the **contract of a module from outside the
crate**. They exercise public APIs, they can touch the filesystem and the
GPU, and they encode golden-vector / KAT-style assertions.

## Adversarial / property / fuzz

- Adversarial (`tests/adversarial/…`): hand-written corner cases designed
  to fail the engine. Every op category ought to have one.
- Property (`proptest`): random inputs, invariants as assertions. Live
  alongside the unit/integration tests that own the function under test.
- Fuzz (`<crate>/fuzz/`): `cargo-fuzz` targets for wire-format and other
  attacker-controlled inputs. Separate crate per workspace member.

Bench files live under `<crate>/benches/` and are wired via `[[bench]]`
entries in that crate's `Cargo.toml`. Bench baselines are committed at
`<crate>/benches/baselines/<bench>.json` so CI can diff.

## What NOT to do

- Don't mix unit and integration tests in `tests/`. `tests/` is external.
- Don't invent new top-level test locations. If you need a new area, add
  a `mod` line to the existing mirror file (e.g. `vyre-core/tests/ops.rs`).
- Don't rely on `[[test]]` entries in `Cargo.toml` unless the test needs
  a bespoke entrypoint. The mirror-module approach keeps all
  discoverability in one place.

Covers ARCH-019 and NEW-TEST-001 scope expectations.
