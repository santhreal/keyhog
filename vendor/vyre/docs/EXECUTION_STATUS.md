# Vyre op plan — execution status

Companion to [`OP_MASTER_PLAN_BUILDING_BLOCKS_AND_QA.md`](OP_MASTER_PLAN_BUILDING_BLOCKS_AND_QA.md).
This tracks the Cat-A building-block plan only; release-gate precedence
is defined in [`DOCUMENTATION_GOVERNANCE.md`](DOCUMENTATION_GOVERNANCE.md).

## Phase 0 — Baseline inventory

| Item | Status | Notes |
| --- | --- | --- |
| Machine-readable op list | **Done** | `cargo run -p xtask --bin xtask -- list-ops` walks `vyre-libs`, `vyre-intrinsics`, `vyre-primitives` (with `inventory-registry`) |
| Committed snapshot | **Done** | [`generated/OP_INVENTORY.md`](generated/OP_INVENTORY.md) — regenerate after op adds/removals |
| Reconcile vs `ops-catalog.md` | **Ongoing** | Manual diff: catalog = aspirative full surface; inventory = what registers **today** |
| `findings.toml` triage | **Ongoing** | Single source: [`vyre-libs/findings.toml`](../vyre-libs/findings.toml) |

## Phase 1 — Conformance matrix

| Item | Status |
| --- | --- |
| `conform/*` runner | Exists — extend coverage per new backends |
| Universal harness (`vyre-libs`) | Exists — align `expected_output` with `FINDING-LIBS-1` closure in findings |

## Phase 2 — Adversarial

| Item | Status |
| --- | --- |
| vyre-libs: canonical `adversarial.rs` | **Done** (aggregator + pointer to split modules) |
| Per-crate `adversarial.rs` stubs for foundation/reference/driver | Backlog (large) |

## Phase 3+ — Property, gap, fuzz, Tier 2.5 promotion

Tracked in `findings.toml` and the Cat-A building-block plan §5–7.

## How to refresh inventory

The workspace may not install a global `cargo xtask` alias. Use:

```bash
cd libs/performance/matching/vyre
cargo run -p xtask --bin xtask -- list-ops --write docs/generated/OP_INVENTORY.md
```

Commit the updated `OP_INVENTORY.md` when the op set changes on `main`.

## Scope honesty

“End to end” for the **full** Cat-A building-block plan (every promotion, every finding closed,
full fuzz, every crate gaining four canonical test binaries) is **multi‑sprint** work.
This file tracks **completed** automation and **next** priorities; the authoritative
P0 list remains [`vyre-libs/findings.toml`](../vyre-libs/findings.toml).
