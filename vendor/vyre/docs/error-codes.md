# vyre Error Codes

This document is the canonical registry of every stable error/warning code
in vyre-core. Codes are **append-only**: renames are semver-major events
handled as migrations in `vyre-core::dialect::migration`. Every new code
must appear here with a description and a `Fix:` template before it ships.

Every message emitted through [`Diagnostic`](../vyre-core/src/diagnostics.rs)
carries one of these codes. Tooling (LSP clients, CI annotators, editor
extensions) keys rules off the code, not the prose; prose is free to drift
across versions as long as the code stays stable.

## Code families

| Family | Severity | Source                                      |
|--------|----------|---------------------------------------------|
| `E-*`  | error    | General errors surfaced via `Diagnostic`    |
| `W-*`  | warning  | Deprecations, soft-failed invariants        |
| `V###` | error    | Program-validation rules (`validate_program`) |
| `B-*`  | error    | Backend dispatch / capability errors        |
| `C-*`  | error    | Conformance verdict failures                |

## V### — Validation codes

Emitted by `validate_program` when an IR invariant fails. Fields in every
message are prefixed `Fix:` per the frozen contract.

| Code | Invariant | Fix template |
|------|-----------|--------------|
| `V008` | Duplicate local binding (shadowing) | Choose a unique local name; shadowing is not allowed. |
| `V009` | Atomic on non-writable buffer | Declare the buffer with `BufferAccess::ReadWrite`. |
| `V010` | Barrier reached by only part of a workgroup (divergent barrier) | Move the barrier to uniform control flow. |
| `V011` | Assignment to loop variable | Loop variables are immutable — rename. |
| `V012` | Unsupported cast between two DataTypes | Use a supported casts.md conversion or rewrite the expression before validation. |
| `V013` | Bytes load/store on buffer without `bytes_extraction = true` | Use a typed buffer (U32/I32/F32/…), or declare the buffer with `.with_bytes_extraction(true)` when the op is a bytes-extraction op like `decode.base64`. |
| `V014` | Atomic on buffer with non-u32 element type | Atomics only support U32 elements — retype the buffer. |
| `V015` | Loop bound expression has wrong type (expected `u32`) | Ensure `from` and `to` are U32. |
| `V016` | Unknown op id in `Expr::Call` | Use a registered op id or add the op to core::ops::*. |
| `V017` | Call depth exceeds `DEFAULT_MAX_CALL_DEPTH` | Reduce call nesting or eliminate mutually recursive operations. |
| `V018` | Program nesting depth exceeds `DEFAULT_MAX_NESTING_DEPTH` | Flatten nested If/Loop/Block structures or split the program before lowering. |
| `V019` | Program has more than `DEFAULT_MAX_NODE_COUNT` nodes | Split the program into smaller kernels or run an optimization pass before lowering. |
| `V020` | Call to non-inlinable op | Lower this op through its dedicated backend path or rewrite the caller with explicit IR. |
| `V021` | Call argument count mismatches callee's ReadOnly/Uniform input count | Pass exactly one argument per input buffer in binding order. |
| `V022` | Program or callee declares too many outputs | Mark at most one result buffer with `BufferDecl::output(...)`. |
| `V023` | Cast to `Bytes` is unsupported in WGSL lowering | Use buffer load/store directly for byte data. |
| `V025` | Atomic on workgroup buffer not yet specified | Use a storage ReadWrite buffer for atomics, or wait for the workgroup-atomic memory model to land. |
| `V027` | Atomic index has wrong type (expected `u32`) | Cast the index to U32 before the atomic. |
| `V028` | Fma operand has wrong type (expected `f32`) | Cast the operand to F32 before Fma, or use the integer mul/add form explicitly. |
| `V029` | Select branches have mismatched types | Cast both branches to the same type before Select. |
| `V030` | Opaque Expr extension fails invariant (empty extension_kind/debug_identity/missing result_type/validate_extension failure) | Return a stable non-empty `extension_kind`, a human-readable `debug_identity`, and an explicit `result_type`, and pass `validate_extension`. |
| `V031` | Opaque Node extension fails invariant (empty extension_kind/debug_identity/validate_extension failure) | Return a stable non-empty `extension_kind`, a human-readable `debug_identity`, and pass `validate_extension`. |
| `V032` | Duplicate sibling `let` binding in the same region | Rename one binding, or move one declaration into an inner Block/Region/Loop if a new scope is intended. |
| `V033` | Expression nesting exceeds `DEFAULT_MAX_EXPR_DEPTH` | Split the expression into intermediate let-bindings before lowering. |
| `V034` | Backend does not support the requested cast target | Choose a target type the backend supports, or validate against a backend that advertises that cast support. |
| `V035` | Narrowing cast may truncate high bits | Use a non-narrowing target, or prove the source value fits before casting. |
| `V036` | Constant store index exceeds the declared buffer element count | Keep constant store indices inside the declared element range. |
| `V041` | Subgroup expressions used without backend subgroup support | Validate with `ValidationOptions::with_backend(backend)` where `backend.supports_subgroup_ops() == true`, or remove subgroup ops before lowering. |

Codes `V024`, `V026`, `V037`-`V040`, and any codes `>V041` are reserved for
future invariants and must be allocated via this registry first.

## E-* — General errors

| Code | Description | Fix template |
|------|-------------|--------------|
| `E-IR-001` | Decode of unknown Opaque extension id (wire format) | Link the crate that registers the extension id, then re-decode. |
| `E-IR-002` | Buffer zero-count with non-empty shape payload | Reject the non-canonical Program bytes. |
| `E-IR-003` | Diagnostic catalog carries a code not listed in `docs/error-codes.md` | Add the code to the registry before shipping. |

## W-* — Warnings

| Code | Description | Fix template |
|------|-------------|--------------|
| `W-DEPREC-001` | Deprecated op id in use | Migrate to the replacement op listed in the deprecation registry. |

## B-* — Backend codes

| Code | Description | Fix template |
|------|-------------|--------------|
| `B-CAP-001` | Backend does not support this op's capability class | Pick a backend that supports this op's capabilities, or use a different op. |
| `B-CAP-002` | Backend factory refused to construct (no GPU adapter, missing driver) | Fix the adapter issue per the error's `Fix:` prose, or skip this backend. |
| `B-CAP-003` | Unsupported feature (e.g. dispatch on the photonic stub) | Use a backend whose `supports_dispatch` returns true. |

## Backend ErrorCode stable ids

| Variant | code | description |
|---------|------|-------------|
| `DeviceOutOfMemory` | 1001 | Backend device reported insufficient memory during allocation, staging, or dispatch. |
| `UnsupportedFeature` | 1002 | The selected backend lacks a feature required by the program or dispatch policy. |
| `KernelCompileFailed` | 1003 | Kernel source compilation or validation failed for WGSL, SPIR-V, PTX, Metal IR, or another backend source format. |
| `DispatchFailed` | 1004 | Queue submission, command execution, readback, or dispatch completion failed. |
| `InvalidProgram` | 1005 | The submitted program violates backend constraints or the portable program contract. |
| `Unknown` | 1999 | Legacy or unclassified backend failure produced without a more specific machine-readable code. |

## P-* — Pipeline codes (`vyre-runtime::PipelineError`)

| Code | Variant | Description | Fix template |
|------|---------|-------------|--------------|
| `P-URING-001` | `IoUringSyscall { syscall, errno, fix }` | A raw `io_uring_setup` / `mmap` / `io_uring_enter` / `io_uring_register` syscall returned an errno. | Per-variant `fix:` string names the remediation; typical causes are kernel too old, missing CAP_SYS_ADMIN for SQPOLL on <5.13, or exhausted `max_map_count`. |
| `P-URING-002` | `QueueFull { queue, fix }` | The submission or completion queue rejected a request because it is full, out of bounds, or a slot is still in flight. | Drain completions with `AsyncUringStream::poll` or `GpuStream::poll`, then retry. For backpressure-triggered rejections on `publish_slot`, wait for the kernel to advance `control[DONE_COUNT]`. |
| `P-URING-003` | `NotLinux` | `io_uring` or `futex_waitv` was requested on a non-Linux host. | Run on Linux 5.16+ or use `Megakernel::dispatch` without a `GpuStream`. |
| `P-URING-004` | `NvmePassthroughDisabled` | `submit_nvme_passthrough` was called without the `uring-cmd-nvme` feature. | Add `features = ["uring-cmd-nvme"]` to `vyre-runtime` in your `Cargo.toml`; requires Linux 6.0+. |
| `P-BACKEND-001` | `Backend(msg)` | A backend error bubbled up from `Megakernel::bootstrap` or `Megakernel::dispatch`. | Inspect the wrapped message; usually a validation error on the IR or an OOM during pipeline creation. |

## C-* — Conformance codes

| Code | Description | Fix template |
|------|-------------|--------------|
| `C-LAW-001` | Backend output disagreed with reference on witnessed input | Fix the backend lowering or rewrite the op to honor the declared `AlgebraicLaw`. |
| `C-DET-001` | Backend produced non-deterministic output across seeds | Remove the non-deterministic code path; conform bans silent nondeterminism. |

## Adding a new code

1. Pick the next unused integer in the appropriate family.
2. Add a row to this document with the code, description, and `Fix:` template.
3. Emit the code via `Diagnostic` with the matching `code` field.
4. CI verifies every code emitted in source appears in this registry
   (see `scripts/check_error_codes_cataloged.sh`).

## Policy

- **Append-only.** Never reuse a retired code. Retiring a code leaves a
  row behind with a `Retired: v<X.Y.Z>` note.
- **Code is the stable key.** Prose may drift.
- **`Fix:` is mandatory.** Every variant carries actionable remediation.
- **No stringly-typed errors.** Every error-path surfaces a structured
  code; the prose is a formatting detail.


## Uncataloged Legacy / Auto-migrated Codes
| Code | Description | Fix template |
|------|-------------|--------------|
| `E-CSR` | Migrated code | See diagnostic output. |
| `E-DATAFLOW` | Migrated code | See diagnostic output. |
| `E-DECODE` | Migrated code | See diagnostic output. |
| `E-DECODE-CONFIG` | Migrated code | See diagnostic output. |
| `E-DECOMPRESS` | Migrated code | See diagnostic output. |
| `E-DFA` | Migrated code | See diagnostic output. |
| `E-GPU` | Migrated code | See diagnostic output. |
| `E-INLINE-ARG-COUNT` | Migrated code | See diagnostic output. |
| `E-INLINE-CYCLE` | Migrated code | See diagnostic output. |
| `E-INLINE-NON-INLINABLE` | Migrated code | See diagnostic output. |
| `E-INLINE-NO-OUTPUT` | Migrated code | See diagnostic output. |
| `E-INLINE-OUTPUT-COUNT` | Migrated code | See diagnostic output. |
| `E-INLINE-UNKNOWN-OP` | Migrated code | See diagnostic output. |
| `E-INTERP` | Migrated code | See diagnostic output. |
| `E-LOWERING` | Migrated code | See diagnostic output. |
| `E-PREFIX` | Migrated code | See diagnostic output. |
| `E-RULE-EVAL` | Migrated code | See diagnostic output. |
| `E-SERIALIZATION` | Migrated code | See diagnostic output. |
| `E-TEST` | Migrated code | See diagnostic output. |
| `E-TOML-PARSE` | Migrated code | See diagnostic output. |
| `E-UNKNOWN` | Migrated code | See diagnostic output. |
| `E-WIRE-UNKNOWN-DIALECT` | Migrated code | See diagnostic output. |
| `E-WIRE-UNKNOWN-OP` | Migrated code | See diagnostic output. |
| `E-WIRE-VALIDATION` | Migrated code | See diagnostic output. |
| `E-WIRE-VERSION` | Migrated code | See diagnostic output. |
| `E-X` | Migrated code | See diagnostic output. |
| `W-DEPRECATED` | Migrated code | See diagnostic output. |
| `W-OP-DEPRECATED` | Migrated code | See diagnostic output. |
| `W-TOML-BAD-OP-ID` | Migrated code | See diagnostic output. |
| `W-TOML-UNREADABLE` | Migrated code | See diagnostic output. |
