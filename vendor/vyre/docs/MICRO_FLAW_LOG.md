# Micro-Flaw Log

Closes #44 D.1 micro-flaw sweep across every surface.

A running log of small-severity findings that land between major
audit cycles. Each entry is one grep target; landing one per
cycle is the minimum bar. This is the "keep the paper cuts off
the floor" surface, separate from the CRITIQUE_* critical /
structural findings.

## Landed

| Surface | Flaw | Fix | Commit |
|---|---|---|---|
| `hex32` in `bundle_cert.rs` | `let _ = write!(...)` silently discarded the Result. | Replaced with `hex::encode`; errors propagate instead of silently truncating. | CONFORM L2 |
| `santh-error::redact` | `Regex::new(...).unwrap()` on every secret pattern. | `compile(tag, src)` helper that panics with a named Fix: hint if any pattern ever becomes invalid. | SANTH-ERROR LOW |
| `Diagnostic::to_json` | `.unwrap()` panic path on serialisation. | Hand-rolled fallback JSON envelope naming the regression. | DRIVER 1.1 |
| `vyre-conform-runner` | `witness_count` declared but not validated on verify. | New `WitnessCountMismatch` error + guard. | CONFORM L1 |
| `vyre-conform-enforce` fixture gate | Required BOTH `test_inputs` and `expected_output` to be None. | Changed to OR so either missing half fails the gate. | CONFORM M7 |
| `BufferDecl::workgroup(count=0)` | Passed construction, crashed at dispatch. | Assert at construction with a Fix: hint matching `with_count(0)`. | FIX-REVIEW #3 / THIRD-PASS 08 |
| `BackendFingerprint` delimiter | `\0`-separated canonical allowed injection. | Length-prefixed canonical encoding. | CONFORM M3 |
| `scan::collector` per-clause `?` abort | A single bad plan killed the entire file scan. | Per-plan match arms logging + continuing; rate-limited via `scan::diagnostics`. | THIRD-PASS 02 |
| `scan` eprintln flood | Unbounded stderr on hostile corpus. | Rate-limited burst + summary stride. | THIRD-PASS 05 |
| `MAX_FILE_BYTES` at 512 MiB | Peaked ~2.63 GiB working set, OOMed 4 GiB CI. | Tighten to 128 MiB. | THIRD-PASS 04 |
| Streaming `scan_gpu_with_context` uncapped | Walker could accumulate unbounded `FileFinding`s. | `MAX_SCAN_FILES = 1_000_000` cap on the streaming path too. | THIRD-PASS 03 |
| DFA cache poison recovery | `poison.into_inner()` returned a potentially torn HashMap. | Replace with fresh empty HashMap on poison; drop torn map in controlled scope. | THIRD-PASS 01 |
| `PipelineFingerprint` buffer order | Two equivalent programs with different buffer order hashed differently, fragmenting the cache. | Sort by (binding, name) in `canonical_wire`. | RUNTIME F1 |

## Operating rule

Every session reads this log before starting work + appends a new
entry if a micro-flaw lands. No silent stash of small-severity
findings — if they're not worth landing, they're not findings.

## Categories hunted every session

- `.unwrap()` / `.expect()` outside test modules.
- `let _ = Result<…>` patterns.
- `to_string().to_string()` / `clone().clone()` chains.
- `Vec::contains` in hot loops (→ HashSet).
- `String::push_str` in emit fast paths (→ `write!`).
- Silent fallback arms on `#[non_exhaustive]` enums.
- `format!(...)` inside a tight loop (→ `write!` into reused buffer).
- Missing `#[must_use]` on fallible constructors.
- Error messages without `Fix:` prefix (see ERROR_SURFACE.md).
- Magic constants without named `const` + doc comment.
- `let .. = .unwrap_or(default_hiding_a_bug)` silent-default patterns.
- Re-exports that leak internal type layout (LAW 7 module boundary).
