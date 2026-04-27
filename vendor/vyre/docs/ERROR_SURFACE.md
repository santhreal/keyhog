# Error Surface Contract

Closes #32 (A.8 Error surface — every error coded, fixable, documented).

Every error produced anywhere in the vyre + surgec workspace satisfies
three invariants. All three are machine-checkable and gated by CI.

## The three invariants

1. **Every error has a stable code.** A user who pastes the code
   into a search engine finds this doc. Codes are `PREFIX-NN` where
   `PREFIX` names the crate (e.g. `VYRE-IR-33`, `SURGEC-E012`,
   `SANTH-IO-PERM`, `KEYHOG-E001`).

2. **Every error message starts with `Fix:`** — the actionable
   hint a downstream developer follows to resolve it. No raw
   "parse error" or "internal error" text. The pattern is enforced
   in debug builds by `santh-error::SanthErrorBuilder` (typestate
   prevents constructing without a Fix:) and at runtime by the
   `debug_assert!(msg.starts_with("Fix:"))` in downstream wrappers.

3. **Every error has a documented fix path in this workspace.**
   The code is declared in `docs/error-codes.md` or the
   per-crate equivalent (`libs/tools/surgec/docs/error-codes.md`)
   with the named variant, the Fix: template, and a "common
   causes" bullet list.

## Where errors live

| Crate | Error type | Code prefix |
|---|---|---|
| `vyre-foundation` | `ir::IrError`, validator variants | `VYRE-IR-NN` |
| `vyre-driver` | `backend::BackendError`, dispatch errors | `VYRE-BE-NN` |
| `vyre-driver-wgpu` | `LoweringError`, `DispatchError` | `VYRE-WGPU-NN` |
| `vyre-runtime` | `PipelineError`, `ReplayLogError` | `VYRE-RT-NN` |
| `vyre-conform-runner` | `BundleCertError`, `ConformanceError` | `VYRE-CONF-NN` |
| `surgec` | `Error::{Parse, Compile, Io, …}` | `SURGEC-ENN` |
| `santh-error` | `SanthError` (ecosystem-wide) | `SANTH-*` (see `santh-error` docs) |
| `pocgen` | `PocError` | `POC-NN` |
| `jsir` | `JsirError` | `JSIR-NN` |
| `polyglot` | `PolyglotError` | `POLY-NN` |
| … each `libs/` crate declares its own. |

Every crate's `src/error.rs` is the single source of truth for that
crate's variants. A new variant must land together with its entry
in the crate's `docs/error-codes.md`.

## The Fix: hint pattern

```
"Fix: <what the caller did wrong in one sentence>. <the literal
command or code change that unblocks them>. <optional: where to
read more>."
```

Good example:

> `Fix: BufferDecl::with_count(0) is rejected. Drop the
> '.with_count(0)' call to declare a runtime-sized buffer, or pass
> a strictly positive count. Zero-length static buffers are a
> validation failure on every shipped backend.`

Bad example:

> `invalid argument`

## CI enforcement

- `cargo xtask gate1` includes an error-surface check that greps
  every `Display` / `Error::message` site for "Fix:" and fails the
  gate on any variant missing it.
- `docs/error-codes.md` is gated by a test in each crate that
  iterates every error variant and asserts an entry exists in the
  doc. Adding a new variant without the doc entry blocks merge.
- `santh-error` ships property tests that every constructed
  `SanthError` carries a Fix: prefix (already in the 0.6 test
  suite).

## User-facing surface

A user who sees an error like

```
SURGEC-E012: Fix: signal `sqli_sink` references an undeclared
buffer `user_input`. Declare the buffer in the rule's
`[[signal]] buffers = [...]` list, or rename the reference to an
existing buffer. Common causes: typo in buffer name; deleted a
buffer without updating every `{{buf}}` interpolation.
```

can:

- Grep the crate source for `SURGEC-E012` to find the exact variant
  and every place it fires.
- Open `libs/tools/surgec/docs/error-codes.md#SURGEC-E012` to read
  the full narrative.
- Read the `Fix:` sentence and act on it without reading the code.

## Open items

- The per-crate `docs/error-codes.md` registry is scaffolded for
  surgec; parity across every crate listed above is the follow-up
  sweep tracked under #33 A.9 docs.
- `santh-error::SanthErrorBuilder` already enforces the Fix: prefix
  via typestate; the per-crate `cargo xtask` grep check adds
  belt-and-braces coverage for crates not using the builder.
