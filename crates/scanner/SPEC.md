# keyhog-scanner SPEC

`keyhog-scanner` compiles detector specifications into executable matchers and scans text chunks for credential candidates. It combines literal prefiltering, regex fallback, entropy scoring, decode-through scanning, context scoring, and optional acceleration features.

## Guarantees

- Scanner input is bounded by configured chunk, decode, and match limits.
- Decode-through scanning tracks seen decoded payloads to prevent repeated expansion.
- Findings preserve detector identity, source location, severity, confidence, and credential hash.
- Optional acceleration backends must preserve the same match semantics as the default scanner path.

## Boundaries

This crate consumes `keyhog-core` types and does not enumerate files, git history, cloud sources, or verify live credentials.

## Quantized confidence acceleration

The accelerator confidence ABI uses 55 signed Q7 features and a versioned
signed Q7 mixture-of-experts artifact. The embedded header authenticates the
feature schema, model dimensions, rounding mode, parameter count, and payload.
Generated model-card metadata binds the quantized artifact and schema digests.

CPU and SIMD routes evaluate eligible rows with the same fixed-point artifact.

On GPU routes, eligible candidates are scored after literal matching by one
asynchronous VYRE program. Bounded IR loops keep the complete model below
finite backend shader-size limits. This program does not fuse confidence
scoring into the resident literal kernel. Invalid UTF-8, empty, oversized, or
unquantizable candidates remain CPU-owned. Candidate order, confidence floors,
suppression, and final finding construction remain in the shared CPU finalizer.
Dispatch failure, malformed output, timeout, or device loss fails the selected
GPU route; the scanner does not silently rescore GPU-owned candidates on CPU.
