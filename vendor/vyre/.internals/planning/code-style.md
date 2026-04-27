# vyre code style

Conventions this workspace follows. When an external contributor asks "what
is the style", this is the authoritative answer.

## Naming

### Modules

| Case                               | Convention      | Example                                   |
|------------------------------------|-----------------|-------------------------------------------|
| Module groups a category of peers  | **plural noun** | `enforcers/`, `passes/`, `witnesses/`     |
| Module is the single concept       | **singular**    | `optimizer`, `scheduler`, `validate`      |
| Module re-exports a trait family   | **singular**    | `backend`, `value`, `program`             |
| Module holds one op spec           | **op name**     | `sub_sat`, `f32_add`, `fnv1a`             |

Rule of thumb: if the file you're writing adds *one more of the same thing*
(one more enforcer, one more pass, one more witness), the module name is
plural. If the module defines *the* thing itself (the optimizer, the
scheduler, the validator), it is singular.

Crate-level naming (`vyre-wgpu`, `vyre-reference`, etc.) is singular by
convention — crates are products, not collections.

### Files

- One file = one concept (LAW 7). If you need `// --- section ---`
  separators to divide concerns in a file, split the file.
- File name is the concept name in `snake_case`. Don't prefix with the
  module name: `optimizer/rewrite.rs`, not `optimizer/optimizer_rewrite.rs`.
- Test files in `vyre-core/tests/` mirror the source tree. An integration test
  for `src/foo/bar.rs` lives at `tests/foo/bar.rs` and is wired via the
  mirror module in `tests/foo.rs`.

### Types and functions

- `CamelCase` for types/traits, `snake_case` for functions and methods.
- Avoid `fn get_x()` when `fn x()` is unambiguous.
- Return `Result<T, ConcreteError>` with `Fix: ...` prefixed error
  messages. Never return `String` for errors in new code.

### Pub visibility

- `pub(crate)` is the default for everything you don't explicitly expose.
- `pub` items in `lib.rs` are the crate's public contract — adding one
  bumps the minor version.
- `pub(super)` is a smell. It usually means the module boundary is wrong;
  consider moving the item up or making it `pub(crate)`.

## Comments

- Default to writing none. Only comment when the **why** is non-obvious.
- Never explain what the code does — the code already does. Explain
  constraints, prior incidents, subtle invariants, workarounds.
- Every `expect(...)` in non-test code must start with `"Fix: ..."`.
- No `TODO` / `FIXME` / `XXX` / `HACK` / `STUB` in shipped code (LAW 9).
  The `zero_stubs` enforcer catches evasions too (`T0DO`, `// TO DO`, etc.).

## Tests

- Unit tests (`#[cfg(test)] mod tests`) live next to the code.
- Integration tests (`vyre-core/tests/*.rs`) mirror the source tree.
- Tests are written to **fail** first — the assert is the spec. If a test
  passes without the engine, the test is wrong.
- Every module covered by `vyre-core/tests/` has adversarial and property
  coverage, not just happy path.

## Benchmarks

- Every perf-sensitive crate has `benches/*.rs` with Criterion.
- Bench baselines live in `benches/baselines/<bench-name>.json`.
- CI fails on a >5% regression against committed baseline (NEW-TEST-002).

## When the rule is wrong

This file is advisory for the cases it covers. When the existing code
consistently does something different, follow the surrounding code — a
local convention almost always beats a global one. Open an issue to
re-align the doc if the divergence is permanent.
