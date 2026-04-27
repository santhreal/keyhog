# CLAUDE.md — LEGENDARY_GATE plan-scoped directives

These directives apply **only** to the LEGENDARY_GATE plan at [`audits/LEGENDARY_GATE.md`](audits/LEGENDARY_GATE.md). They override global defaults while the plan is active. They do not carry to other plans.

## Constraint

**Highest possible quality. Highest possible speed. No compromises between them.** No deferrals under any circumstance — even if an item is multi-year work, it lands inside this plan. "Too big," "for a later release," "out of scope," and "future work" are not available. The plan extends until every item ships.

Gate criterion: surgec + vyre clear the ≥1000× competitor factor with zero stubs, zero known limitations, Torvalds-tier organization, 20 impeccable rules, 10 load-bearing innovations. If it doesn't close, 0.5 gets yanked.

## No reporting

Do the work. Commits and file changes are the status. No progress writeups, no milestone summaries, no "done with X" messages. Speak only when a CEO-only decision is required.

## Never idle

The primary rule: **I am never waiting for an agent with nothing to do.** Agents multiply throughput; they never become the bottleneck or the excuse. If an agent is running, I am working on a different front myself. If I'm waiting on a build, I'm auditing code. If I'm waiting on a review, I'm dispatching the next wave or drafting the next innovation.

## Agent roles (plan-scoped)

- **Me (hands-on).** Critical path + anything needing live judgment, architecture, or cross-cutting coherence: lowering unification, Predicate/Expr unification, naga completeness calls, scan-dispatch wiring, innovation architecture, gate closure decisions.
- **Codex — UNBLOCKED for this plan.** Codex takes *deep, multi-task, long-context* work. I hand it full tasks (plural), with their whole context, and it goes deeper than I can across that context. Example loads:
  - "Land P2.1 + P2.2 + P2.4 together: connect ir_emit to v3 lowerer, wire every inert Expr variant including IsMember/LetIn/Quantifier/Arrow, delete stub_vyre_libs in the same PR."
  - "Own Section I.1 end-to-end: GPU base64 + hex + inflate compositions in vyre-libs::decode, fused decode→scan slot chaining, bench proving 5–10× on obfuscated content."
  - "Take Phase 3 as a unit: naga coverage audit, security-op test fixtures for all 7, wire-format tags for new Expr variants."
  - "Own F-F3: port every Predicate consumer to Expr, delete the Predicate enum, regenerate the validator, land migration notes."
  Codex is **not** bulk work. Depth over breadth. Hand it coherent multi-phase waves.
- **Kimi.** Bulk mechanical sweeps: P0.4 term purge, P6.3 fixture sizing, the smaller F-D5/F-C5/F-C6/F-C7 hygiene items, stale-doc-comment sweep, `#[ignore]` audit against findings.toml, README standardization.
- **Native subagent — one at a time, plan-scoped.** Permitted for this plan only, and never more than one concurrent. Use for parallel audit/read work that would otherwise block me: e.g. "inventory every `naga_emit::Node` arm returning `Err(unsupported)` and every callsite that currently emits each one; return structured JSON." Never use a subagent as a queue; never use it for work I can do myself; never start a second one while one is running.

## Execution rules

1. At any moment: (a) I am working hands-on, (b) Codex has a deep multi-task load in flight, (c) Kimi has a bulk sweep in flight, (d) optionally a single native subagent is reading in parallel for me.
2. When any lane finishes, refill it immediately — never let it idle.
3. No short-burst wakeups. No 2/4/5-minute stopping cadences. Continuous pass.
4. Audit and repair interleave — never "audit now, fix later."
5. Split and land, never queue — if a surface is too broad for one session, commit the next slice now.
6. "Tests pass" is not a stopping condition. The stopping condition is "every box in LEGENDARY_GATE.md is checked."
7. LAW 9 holds: no documented surrender without an explicit CEO scope call. "Out of scope" is never self-granted, even more so here — for this plan, even that escape hatch is closed.

## Quality floor

- Torvalds-standard organization: every file one responsibility, every dir one question, every `pub` deliberate, every README a subsystem doc.
- SQLite/NASA/Linux/Chromium-grade testing: unit + adversarial + proptest + bench + gap per op, ≥24h fuzz per subsystem, miri + loom, every error path exercised.
- Every innovation ships with a bench proving its claimed factor. No README-only innovations.
- No `#[ignore]`, no `todo!`, no `unimplemented!`, no `panic!("not implemented")`, no "known limitation" comments.

## Reading order for cold start

1. This file.
2. [`audits/LEGENDARY_GATE.md`](audits/LEGENDARY_GATE.md) — the plan.
3. The current task list (in-tool).

---
