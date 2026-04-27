# Documentation coverage contract

Closes #33 (A.9 docs — every user-facing surface answers every question).

## The promise

Every public surface in vyre + surgec answers three questions without the reader leaving that surface:

1. **What does this do?** — one-paragraph summary, the "elevator pitch" for the item.
2. **How do I use it?** — a minimal compiling example inside the rustdoc (`cargo test --doc` keeps these honest).
3. **What goes wrong and how do I fix it?** — every `# Errors` section names the error shape + the `Fix:` hint embedded in the error itself.

This contract is machine-checkable: a CI gate asserts each public item has all three sections before the crate can tag a release (see #77 P7.4 CI enforcement gates, landed 0.6).

## Layers

| Layer | Authority | Lives in |
|---|---|---|
| Vision | `VISION.md` — the north-star architecture brief. | `libs/performance/matching/vyre/VISION.md` |
| Architecture | `docs/ARCHITECTURE.md` — how the pieces fit today. | `libs/performance/matching/vyre/docs/ARCHITECTURE.md` |
| Tier rule | `docs/library-tiers.md` + `docs/primitives-tier.md` | same tree |
| Region chain | `docs/region-chain.md` — composition invariant. | same tree |
| Gate closure | `docs/GATE_CLOSURE.md` — the five release gates. | same tree |
| Benchmarks | `libs/tools/surgec/docs/BENCHMARK.md` — the ≥1000× methodology. | surgec tree |
| Error codes | `libs/tools/surgec/docs/error-codes.md` + `docs/error-codes.md` | per-crate |
| Severity taxonomy | `libs/tools/surgec/docs/SEVERITY_TAXONOMY.md` | surgec tree |
| Per-op references | per-op rustdoc + `cargo xtask print-composition <op_id>` |

## Per-question coverage

| Question | Where answered |
|---|---|
| What is vyre? | `VISION.md` §"The missing stack". |
| What is surgec? | `surgec/README.md` §`surgec`. |
| How do I run surgec? | `surgec/README.md` §Install. |
| How do I write a SURGE rule? | `surgec/AUTHORING.md`. |
| How do I configure surgec? | `surgec/CONFIGURATION.md`. |
| Why this architecture? | `VISION.md` §"After Effects architecture" + `docs/ARCHITECTURE.md`. |
| Where does op X live? | `cargo xtask print-composition <op_id>`, matches `docs/library-tiers.md` rule. |
| How do I add an op? | per-tier rustdoc on `vyre-libs`, `vyre-primitives`, `vyre-intrinsics`. |
| How do I add a backend? | `vyre-driver/README.md`. |
| What's the wire format? | `docs/wire-format.md`. |
| What's the memory model? | `docs/memory-model.md`. |
| How do I verify a conformance cert? | `vyre-conform-runner verify` + `verify_cert_signature_hex` for the cryptographic half (CONFORM C1). |
| How do I run benchmarks? | `libs/tools/surgec/docs/BENCHMARK.md`. |
| When is 0.7 shipping? | `docs/GATE_CLOSURE.md` — when all five gates go green. |
| What if a benchmark fails? | `docs/GATE_CLOSURE.md` §"E.2 yank protocol". |

## Contribution checklist for new public items

Reviewers enforce the following before merging any new `pub` item:

- [ ] `///` summary paragraph — "what does this do".
- [ ] `/// # Examples` block with a compiling snippet.
- [ ] `/// # Errors` block for every fallible fn, naming the error kinds by variant.
- [ ] For types added to a dialect, rustdoc names the Tier and points at the nearest registered sibling for context.
- [ ] For ops added to a Tier-3 dialect, `print-composition` renders a Region chain that bottoms at Tier-2 leaves (VISION V7 test enforces).

## Open items

- Continuous coverage sweeps track `cargo doc --all` warnings; any new `missing_docs` landing on a `pub` item blocks merge via the crate-level `#![warn(missing_docs)]` toggle.
- The VISION.md ↔ code delta audit runs every session (CRITIQUE_VISION_ALIGNMENT_2026-04-23 is the inaugural record); drift in this doc is itself a finding.
