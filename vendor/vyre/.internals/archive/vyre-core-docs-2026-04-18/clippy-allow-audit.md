# Clippy Allow Audit

Audited against `core/src` on 2026-04-12 without editing `core/src/lib.rs`.
The only explicit trigger site for the 13 crate-level allows is the allow list
itself at `core/src/lib.rs:5` through `core/src/lib.rs:17`; `rg` found no
secondary local allow, expect, or warn sites for these lint names under
`core/src`.

`cargo clippy --all-features -p vyre -- -D warnings` does not currently reach
these 13 allows as actionable blockers. It fails first on other pedantic lints
outside this edit window, including `missing_errors_doc`,
`cast_possible_truncation`, `too_many_lines`, `needless_pass_by_value`,
`too_many_arguments`, `unnecessary_lazy_evaluations`, `default_trait_access`,
`wildcard_imports`, and `semicolon_if_nothing_returned`.

| Allow | Trigger sites in `core/src` | Assessment | Recommendation |
| --- | --- | --- | --- |
| `clippy::duplicated_attributes` | `core/src/lib.rs:5` only | No active trigger found. | Remove in the next `lib.rs` edit window. |
| `clippy::type_complexity` | `core/src/lib.rs:6` only | No active trigger found by name scan; likely stale or masked by earlier clippy failures. | Probe with this allow removed, then remove if clean. |
| `clippy::cast_lossless` | `core/src/lib.rs:7`; workspace also allows it in `Cargo.toml:33` | Duplicated policy. Workspace already allows the lint. | Remove from `lib.rs`; keep or reassess workspace policy separately. |
| `clippy::must_use_candidate` | `core/src/lib.rs:8` only | Public APIs already use many targeted `#[must_use]` attributes; no active named trigger found. | Remove after a focused clippy probe. |
| `clippy::needless_raw_string_hashes` | `core/src/lib.rs:9` only | No active trigger found. | Remove. |
| `clippy::module_name_repetitions` | `core/src/lib.rs:10` only | Likely false positive risk for public module-qualified API names, but no active trigger found by name scan. | Probe, then keep only if public API churn would be worse than the lint. |
| `clippy::similar_names` | `core/src/lib.rs:11` only | Likely false positive risk in lowering and validation code where paired names are intentional. | Prefer targeted allows at real false positives; remove crate-level allow after focused cleanup. |
| `clippy::should_implement_trait` | `core/src/lib.rs:12` only | Builder helpers such as `Expr::add` and `Expr::sub` intentionally construct IR rather than implement arithmetic traits. | Replace crate-level allow with targeted allows only if clippy flags these constructors. |
| `clippy::match_same_arms` | `core/src/lib.rs:13` only | Match arms in IR lowering and typing may intentionally spell out stable enum semantics. | Probe; keep targeted allows only where explicit enum arms improve auditability. |
| `clippy::format_push_string` | `core/src/lib.rs:14` only | Round 1 perf audit identified string formatting in lowering and validation as real allocation debt. | Fix trigger sites and remove; do not keep as a false positive. |
| `clippy::unnecessary_wraps` | `core/src/lib.rs:15` only | Result-returning APIs are common at public boundaries; some may reserve future error states. | Probe; keep targeted allows only for stable public APIs where changing return type is breaking. |
| `clippy::unnested_or_patterns` | `core/src/lib.rs:16` only | No active trigger found. | Remove. |
| `clippy::doc_markdown` | `core/src/lib.rs:17` only | Documentation uses IR, WGSL, GPU, and crate-specific terms. Some findings may be false positives. | Prefer targeted backticks or targeted allows; remove crate-level allow after docs cleanup. |

Additional concrete clippy blockers observed during this audit:

| Lint | Trigger examples | Recommendation |
| --- | --- | --- |
| `clippy::missing_errors_doc` | `core/src/engine/decode.rs:27`, `core/src/runtime/shader.rs:9` | Add `# Errors` sections to public `Result` APIs. |
| `clippy::cast_possible_truncation` | `core/src/engine/decode/entropy.rs:16` | Use an explicit checked or documented conversion. |
| `clippy::too_many_lines` | `core/src/engine/decode/gpu.rs:45`, `core/src/engine/decompress/lz4.rs:10`, `core/src/lower/wgsl.rs:197` | Split functions by responsibility before enabling `-D warnings`. |
| `clippy::needless_pass_by_value` | `core/src/engine/decode/gpu.rs:195`, `core/src/engine/decode/gpu.rs:196`, `core/src/engine/decode/gpu.rs:197` | Take buffer references if ownership is not needed. |
| `clippy::too_many_arguments` | `core/src/engine/decode.rs:381`, `core/src/engine/decode.rs:412` | Introduce request/context structs. |
| `clippy::wildcard_imports` | `core/src/ir/wire.rs:4` | Replace wildcard import with explicit tag function imports when the wire file is unlocked. |
