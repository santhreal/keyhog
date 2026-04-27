# Error Model

## Two Categories

Every input to a vyre backend falls into one of two categories:

### Valid inputs

A valid input is a `Program` that:
1. Passes `ir::validate()` with zero errors.
2. References buffer sizes that fit within the backend's resource limits.
3. Uses a `workgroup_size` supported by the backend's GPU hardware.

For valid inputs, the backend **MUST succeed**. It must produce output bytes
identical to the CPU reference. Returning an error for a valid input is a
**conformance violation**.

### Resource-exceeded inputs

A resource-exceeded input is a `Program` that passes validation but exceeds
the backend's hardware or resource limits:

| Limit | Example | Typical bound |
|-------|---------|---------------|
| Max buffer size | A buffer larger than GPU VRAM | 256MB - 2GB |
| Max buffer count | More bindings than the GPU supports | 8 - 16 |
| Max workgroup size | `workgroup_size` product exceeds HW limit | 256 - 1024 |
| Max dispatch size | Workgroup count exceeds HW limit | 65535 per axis |
| Total VRAM | Sum of all buffers exceeds available memory | varies |

For resource-exceeded inputs, the backend **MAY** return a structured error.
The error must:
- Identify which limit was exceeded.
- Include the requested value and the limit value.
- Be a proper error type, not a panic or crash.

Resource-exceeded errors are **NOT conformance violations**. Different GPUs have
different limits. A program that fits on a 24GB GPU may not fit on a 4GB GPU.
Both backends are conforming as long as they succeed on inputs within their
limits and return structured errors on inputs beyond their limits.

## Error Structure

Errors returned by a backend must contain:

1. **Category:** `Validation`, `ResourceExceeded`, or `BackendError`.
2. **Message:** Human-readable description with actionable fix guidance.
3. **Details:** For `ResourceExceeded`: which limit, requested value, limit
   value. For `Validation`: which rule was violated.

## What is NOT an error

- **Out-of-bounds access:** Not an error. Returns zero / no-op. See
  `out-of-bounds.md`.
- **Division by zero:** Not an error. Returns zero. See `binary-ops.md`.
- **Excess invocations:** Not an error. The Program handles them. See
  `invocation-model.md`.
- **Data races:** Not an error at the IR level. The output is indeterminate
  but the program does not fail. The conformance suite will catch the
  non-determinism.

## Backend Panics

A conforming backend **MUST NOT panic** on any input. Not valid inputs, not
invalid inputs, not resource-exceeded inputs, not malformed inputs. Every code
path must return a Result, never panic. A backend that panics on any input is
non-conforming regardless of whether it passes other tests.

## Validation Errors

`ir::validate()` errors are caught at Program construction time, before any GPU
work. They are not backend errors — they are IR errors. A Program with
validation errors should never reach a backend. If it does, the backend may
reject it with a `Validation` error.

Validation errors include:
- Duplicate buffer names or bindings.
- Zero workgroup_size component.
- Buffer reference to undeclared buffer.
- Store to non-ReadWrite buffer.
- Variable reference without prior binding.
- Invalid axis (> 2).

See `validation.md` for the complete enumerated list.

## Permanence

The two-category model (valid = must succeed, resource-exceeded = may fail) is
permanent. The prohibition on panics is permanent. The requirement for
structured errors is permanent.
