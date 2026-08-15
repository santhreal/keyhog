# keyhog-scanner SPEC

`keyhog-scanner` compiles detector specifications into executable matchers and scans text chunks for credential candidates. It combines literal prefiltering, regex fallback, entropy scoring, decode-through scanning, context scoring, and optional acceleration features.

## Guarantees

- Scanner input is bounded by configured chunk, decode, and match limits.
- Decode-through scanning tracks seen decoded payloads to prevent repeated expansion.
- Findings preserve detector identity, source location, severity, confidence, and credential hash.
- Optional acceleration backends must preserve the same match semantics as the default scanner path.
- Candidate generation retains the producer channel and exact canonical detector-pattern ordinal through shared adjudication. Generated homoglyph variants and packed backend routes keep the source ordinal. Public `RawMatch` ordering, identity, caps, and serialization remain unchanged.
- Detector TOML schema 5 binds synthetic positive and named hard-negative evidence to exact pattern ordinals. Every pattern receives an exact compiled-regex witness, while the production-path corpus ratchet remains detector-complete. A schema-5 enforcement-capable semantic policy additionally requires an indexed positive, a named direct hard negative, and a generated sibling-prefix negative for each pattern. Schema-4 policies retain their prior validity. Test evidence does not change scan behavior.
- Detector semantic policy is typed in corpus schema 4 as capture role, anchor role, allowed source roles, and required evidence. Omitted fields resolve to abstaining compatibility defaults and are omitted from serialization. Source compilation and execution-pack hydration preserve the policy exactly. Detector-plan schema version 3 rejects stale sections.
- Windowed absence memos bind to the exact ordered input bytes; reordered or repeated lines cannot inherit an earlier clean proof.

## Ordered GPU device routes

Multi-device GPU execution is an autoroute peer. Calibration enumerates one stable physical adapter set, rejects software, display-only, duplicate, or incompletely identified exposures, measures each device for the exact workload, proves complete-route finding parity, and persists the ordered identities, timings, integer weights, capacities, and resident budgets under an authenticated digest.

Normal scans validate the complete live census before and after all-or-nothing acquisition. Exact chunk shards are assigned as contiguous weighted ranges. Each device owns a bounded resident slot, devices execute concurrently, and retirement restores source order. A missing device, identity change, dispatch failure, recovery receipt, panic, or incomplete result invalidates the selected route; no sibling result is returned as a partial scan.

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
