# Vyre × Santh — master plan: Cat‑A building blocks, op taxonomy, and quality program

**Status:** planning document (execution happens in phased PRs; do not treat as frozen spec).
**Authority:** not the release plan of record. The active release gate is
[`../audits/LEGENDARY_GATE.md`](../audits/LEGENDARY_GATE.md), and
cross-document precedence is defined in
[`DOCUMENTATION_GOVERNANCE.md`](DOCUMENTATION_GOVERNANCE.md).
**Execution tracker:** [`EXECUTION_STATUS.md`](EXECUTION_STATUS.md) (inventory snapshot, test layout, refresh commands).
**Audience:** engineers, agents, and subagents working on vyre, rule compilers, scanners, and GPU-accelerated security analysis across the Santh monorepo.

---

## 1. Why this plan exists

### 1.1 The thesis

- **Cat‑A ops** in vyre are not “end-user features.” They are **reusable, conform‑gated, byte‑identical `Program` building blocks** that will be **composed thousands of times** into higher-level detectors, pipelines, and tools.
- A small mistake in a primitive **multiplies** across every composition that embeds it. So **organization of primitives** and **testing depth** are first‑class, not late polish.
- Santh spans **web tooling, SAST/fuzz, secrets, detonation, scanner infra, intel, mobile, game‑theoretic RASP, offensive chains**, etc. Heterogeneous products still share a **finite set of computational patterns** (graphs, bytes, crypto, time series, ML-shaped kernels). This document maps that set and ties it to vyre’s tier model.

### 1.2 Tension to resolve

- **Today:** many `vyre-libs` ops are **scaffolds, placeholders, or thin demos** (especially C11 pipeline, security “stubs,” parts of `matching`). `vyre-libs/tests/SKILL.md` and `vyre-libs/findings.toml` track gaps explicitly.
- **Target:** a **pyramid of vetted blocks** (Tier 2.5 → Tier 3) where **new work defaults to composition**, not new inline IR, and every block has **adversarial + property + conform** coverage.

---

## 2. Organizational map — what already exists (vyre)

Use this as the **only** allowed mental model for “where an op lives.”

| Tier | Crate / surface | What it is | Count / notes |
| --- | --- | --- | --- |
| **1** | `vyre-foundation`, `vyre-spec`, `vyre-core` | IR, wire, validation, transforms. **No inventory ops** that execute domain logic. | — |
| **2 (Cat‑C)** | `vyre-intrinsics` | Hardware‑mapped intrinsics; dedicated interpreter + naga path. | ~9 in tree; more in catalog §9 of `ops-catalog.md` for future |
| **2.5** | `vyre-primitives` (feature flags per **domain** folder) | **Intended long‑lived atoms**: `text`, `matching` (bracket, etc.), `parsing` (CSE, structural hash…), `graph`, `bitset`, `label`, `predicate`, `fixpoint`, `hash`, `math`, `nn` (partial). | Grows as promotions from Tier 3 prove reuse (see `primitives-tier.md`) |
| **3** | `vyre-libs` (monolithic 0.6; Phase K may split) | Composed Cat‑A programs: `math/`, `nn/`, `matching/`, `hash/`, `security/`, `parsing/`, `compiler/`, `rule/`, … | `inventory::submit!` + `harness` |
| **4** | `vyre-libs-extern` | Foreign dialects registering into the same registry. | `adversarial_*.rs` tests |

**Cross‑cutting quality artifacts (already in repo):**

- `docs/ops-catalog.md` — target surface (~90+ op ids) for “legendary” stamp.
- `vyre-libs/findings.toml` — every `#[ignore]`, open gap, owner, fix plan (`LAW 9`).
- `.internals/skills/testing/` + per‑crate `tests/SKILL.md` — **six** test species: `adversarial`, `property`, `gap` (fails on purpose), `integration`, `bench`, `fuzz`.
- `conform/*` — parity, certificates, `vyre-conform-runner`.

**Key organizational rule for Cat‑A (building blocks for everything else):**

> New bytes‑processing or graph logic **default‑lands in `vyre-primitives`** *iff* it will be reused by ≥2 Tier‑3 modules or a Tier‑3 + `xtask`/conform. Otherwise it stays a **private helper** inside one Tier‑3 file until a second consumer exists (`lego-block-rule.md`, `primitives-tier.md`).

---

## 3. The building‑block architecture (1 → many operations)

This section is the **heart** of the plan: how a few **hundred** vetted primitives become **thousands** of public compositions.

### 3.1 Layers of composition

```text
                    [ Downstream: rule DSLs, surgec, karyx, keyhog, … ]
                                    │
                                    ▼
              Tier 3: named detectors, whole pipelines, "rule packs"
              (Node::Region chains, op ids, conform certs)
                                    │
            ┌───────────────────────┴───────────────────────┐
            ▼                                               ▼
   Tier 2.5: vyre-primitives                    Tier 2: intrinsics
   (hash step, bitset, graph walk,            (subgroup, atomics,
    UTF‑8 class, one DFA step…)               barriers, fma, …)
            │                                               │
            └───────────────────┬──────────────────────────┘
                                    ▼
                    Tier 1: Expr / Node / Program + validation
```

### 3.2 Naming and dependency discipline

- **One semantic → one `OpDef` id.** No `fnv1a32_v2` in parallel to `fnv1a32` without deprecation window.
- **Op ids encode tier** (`vyre-intrinsics::…`, `vyre-primitives::…`, `vyre-libs::…`) so `rg` and `print-composition` tell you audit depth.
- **No Tier‑3 importing another Tier‑3’s internals** — only public `vyre-primitives` / `vyre` APIs.
- **Region chain** on every registered op: `source_region` populated when composing children (`region-chain.md`).

### 3.3 What “thousands of operations” means (non‑hype)

- **Tier 2.5** might settle at **O(10²)** primitive ops over years (text, bitset, graph, hash steps, small parsers).
- **Tier 3** can register **O(10³–10⁴)** composed ops (detectors, language fragments, product‑specific rules) *without* new IR variants — they are **different `Program` trees built from the same block library**.
- **Santh** tools outside vyre (e.g. `secmatch`, Deviant, intel) can remain **CPU** for orchestration; they still benefit from a **shared vocabulary** of what “an op” is when/if lowered to vyre.

---

## 4. Cross‑Santh op families — the exhaustive taxonomy (planning)

Below: **families of computational ops** that *something* in Santh may need. Many already appear in `ops-catalog.md`. Status is **roadmap** unless an item is marked **shipped** in vyre `vyre-libs` / `vyre-primitives` / `vyre-intrinsics`.

### 4.1 Graph, CFG, and tree

- Walks: preorder, postorder, BFS, DFS, dominators, topological order, SCC (Tarjan), path reconstruct, betweenness (rare; expensive).
- Mutations: edge insert/delete (batch), subgraph extract, `PackedAst` navigation (per `parsing-and-frontends.md`).

**Santh consumers:** static analysis, rule engines, chain reasoning (e.g. Deviant `reachability` / taint), SurgeC‑style lowerings, Karyx when templates embed graph conditions.

### 4.2 Taint, IFDS‑shaped, security flows

- `flows_to`, `sanitized_by`, `bounded_by_comparison`, `taint_flow`, `label_by_family`, `path_reconstruct`, and future: **k‑limited** paths, field‑sensitive labels.

**Santh consumers:** any detector asking “data reaches sink.”

### 4.3 Bytes, text, patterns

- Substring, Aho–Corasick, multi‑DFA scan, Boyer–Moore, case folding (ASCII/Unicode policy per op), rolling hash (Rabin–Karp), **multi‑version regex → DFA** (compile once).

**Santh consumers:** `secmatch` (Aho+regex today on CPU; potential GPU for massive corpora), `keyhog`, karyx templates, corpus scanners.

### 4.4 Cryptographic and non‑crypto hashes

- FNV, CRC, Adler, BLAKE3 (compress rounds), SipHash, xxHash, Murmur, **keyed** vs **keyless** variants as separate op ids.
- HMAC as composition (document in catalog; may be one op id for conform simplicity).

**Santh consumers:** fingerprinting, dedup, `gossan`‑style artefact id, content addressing.

### 4.5 Encodings and formats

- base64, hex, percent‑decoding, UTF‑8 validate, leb128, protobuf‑length scan (not full parse), line/column index, **canonical URL** (already cataloged as aspirational per §5 `ops-catalog`).

**Santh consumers:** `sear` detonation, `keyhog`, any HTTP/URL tool.

### 4.6 Networks and protocol fingerprints

- IPv4/6 parse, host/label split, CIDR, JA3/JA4‑ish fingerprints from ordered fields, **HTTP header** tokenization and case‑insensitive name match (byte‑exact rules).

**Santh consumers:** `gossan`, karyx transport plugins, WAF work.

### 4.7 Time series, stats, and aggregates (scan telemetry)

- Rolling sum/window, EMA, HLL, quantile sketches (deterministic **approximation** only if we can define Cat‑A ref — else Tier 4 or CPU).

**Santh consumers:** `soleno`, timing detectors (e.g. Mann–Whitney in Deviant is CPU today; vyre may host batched stats at scale).

### 4.8 ML‑shaped kernels (deterministic f32)

- matmul, softmax, layer norm, attention, activations, optional training‑shaped **fixed‑point** Adam (catalog already names these).

**Santh consumers:** any ML‑assisted classification of payloads, embeddings produced offline then matched on GPU.

### 4.9 Parsing and compilation (front ends)

- **C11** (current tree): lex, preprocess subset, parse tables, `compiler/*` (CFG, regalloc sketch, ABI layout sketch).
- Future: Rust/Go/JSON/YAML *selective* extractors (not full general compiler — that’s a product claim). Prefer **table‑driven** ops + `PackedAst`.

**Santh consumers:** Surge, Venin, OpenAPI, any “scan source” tool.

### 4.10 Sandboxing, process, and I/O (mostly *not* Cat‑A in vyre)

- **Process isolation, eBPF, hypervisor hooks** — live in `procjail`, `ebpfsieve`, etc. Vyre is **computation**; these stay adjacent crates. Plan only **lists** them so we don’t pretend `vyre` runs containers.

**Santh consumers:** `detonation/pydet`, `jsdet`, `procjail`.

### 4.11 Adversarial / generative (attack strings)

- Grammar‑constrained string generation, mutation operators, **encoding** pipelines (for fuzzers).

**Santh consumers:** `attackstr`, `pocgen`, `soleno`, WAF smuggling research.

### 4.12 Intel, dedup, and document pipelines

- LSH, MinHash, SimHash, shingle compare, version‑aware diff of findings.

**Santh consumers:** `future_work/intel`, report dedup across scans.

### 4.13 Game‑theoretic / RASP (Invariant)

- Mostly **orchestration** + policy evaluation; vyre may host **tensor‑shaped** scoring if represented as fixed programs.

**Santh consumers:** `invariant/`.

### 4.14 MCP / protocol testing (`ai/mcpwn`)

- Pattern match on **JSON** tool traces, state machines over message sequences. Reuse **graph + string** families; *no* bespoke “MCP op” unless a second consumer justifies a primitive.

**Santh consumers:** `mcpwn`.

### 4.15 Mobile, OpenAPI, Yara (from `README` future work)

- **YARA** semantics overlap §4.3; implementation may stay CPU (`yara` crate) with optional GPU for massive corpora.
- **OpenAPI:** JSON pointer + schema subset validation → §4.5 + §4.1 tree walks.

---

## 5. Testing, review, and “designed to break” — mandatory program

*This is not optional for “low quality” remediation.* Work proceeds **in parallel** with new op work.

### 5.1 Phase 0 — Baseline inventory (1–2 weeks wall time, can parallelize)

| Task | Output |
| --- | --- |
| Enumerate all `OpEntry` / `inventory::submit!` across `vyre-libs`, `vyre-primitives`, `vyre-intrinsics` | machine‑readable list (xtask or script) |
| Reconcile with `ops-catalog.md` | diff: **cataloged but missing**, **exists but not cataloged** |
| Triage `vyre-libs/findings.toml` | P0 = blocks conform / misleads users, P1 = performance, P2 = cosmetic |
| Audit `tests/SKILL.md` gap lists per crate | single backlog linked to families in §4 |

**Subagent suggestion:** one subagent = inventory script + catalog diff; another = findings triage.

### 5.2 Phase 1 — Conformance and backend matrix

- Every op that claims a backend must appear in `vyre-conform-runner` (or the universal harness) with **CPU ref × backend** matrix.
- **Add:** SPIR‑V/photonic cells where claimed; mark `Unsupported` explicitly, never silent fallback.

**Subagent suggestion:** one subagent per backend (wgpu, spirv).

### 5.3 Phase 2 — Adversarial suite (must pass; designed to *not* crash)

Per **domain** (`math`, `matching`, `nn`, `hash`, `parsing`, `security`):

- Empty, max‑dim, all‑zero, all‑`0xFF`, unaligned length, `u32::MAX` where structurally rejected (not UB).
- Reference interpreter and GPU must **agree** on error vs zero‑work `Program` (define policy in validation).

**Files:** `tests/adversarial.rs` per skill contract.

### 5.4 Phase 3 — Property tests (proptest / laws)

- Algebraic laws already in `vyre-spec` where applicable; extend with **per‑op** mini‑laws (idempotence of walks, monotonicity of reachability, etc.).

**Subagent suggestion:** one subagent = graph ops, one = byte ops.

### 5.5 Phase 4 — Gap tests (“designed to break” until feature lands)

- **LAW** from `.internals/skills/testing/SKILL.md`: a gap test **fails** until the implementation is real; when fixed, **move** to property/adversarial, never delete the witness.

- Maintain **synchronized** `findings.toml` entries: no orphan ignores.

**Subagent suggestion:** dedicated “gap test sheriff” in CI to fail PRs that remove gap tests without finding closure.

### 5.6 Phase 5 — Fuzzing (untrusted input surfaces)

- `cargo-fuzz` (or `cargo xtask`) for: wire format decode, DFA table loaders, any host→GPU struct parser.

**Subagent:** LibAFL or cargo-fuzz harness per `fuzz/` directory.

### 5.7 Periodic review (quarterly)

- Random sample 10% of Tier‑3 ops → manual `print-composition` + compare to a **golden** `Program` hash where feasible.
- Security‑critical ops (taint, `flows_to`) — **red‑team** session: can two compositions disagree due to non‑determinism? If yes, **bug**.

---

## 6. Remediation: upgrading “low quality” ops

A Tier‑3 op is **low quality** if any apply:

1. **Placeholder** semantics (e.g. mock C11 lowering, inert taint).
2. **No** or **misleading** `expected_output` in `OpEntry` (see `FINDING-LIBS-1` pattern).
3. **FIXME** in hot path (e.g. substring byte compare: see `vyre-libs/tests/SKILL.md`).
4. **Gate 1** violation: huge inline body without `wrap_child` of smaller registered ops.
5. **Fuzz** finds divergence or OOM on small input.

**Definition of “upgraded”:**

- Semantics match docstring and **one** of: (a) reference implementation in `vyre-reference` path, (b) identical to named primitive composition with proof via `print-composition`.
- Conform + adversarial + property (where applicable) green.
- `findings.toml` entry closed with **date** and test name.

**Order of attack (recommended):**

1. `matching` (unblocks everything string‑shaped) → **promote** reusable steps to `vyre-primitives`.
2. `workgroup` / `subgroup` primitives (see `findings.toml` PRIM entries) before scaling `nn/`.
3. `security` stubs: replace with compositions over **real** graph primitives once graph ops are solid.
4. C11: either **narrow** claims in docs to “educational SIMT” or **invest** in spec‑aligned test vectors; avoid infinite half‑baked surface.

---

## 7. Execution: subagent‑friendly workstreams (parallel)

| ID | Workstream | Primary artifacts | Dependencies |
| --- | --- | --- | --- |
| **W1** | **Tier 2.5 expansion** from highest‑churn Tier‑3 inlines | `vyre-primitives` + promotions | inventory diff |
| **W2** | **Matching + hash** hardening (substring, DFA, FNV) | `vyre-libs`, new primitives | W1 partial |
| **W3** | **Graph + security** (real taint = graph reach in packed format) | `vyre-libs::security` | W1 `graph` |
| **W4** | **Conform matrix** and certificate automation | `conform/` | W2, W3 |
| **W5** | **Test system** (adversarial + gap sheriff CI) | `.internals/skills/testing`, GHA | none |
| **W6** | **Catalog alignment** (ops-catalog vs tree) | `docs/ops-catalog.md` | Phase 0 |
| **W7** (optional) | **Santh** bridge docs — *how* secmatch/karyx *would* call vyre (CPU boundary) | separate ADR, not in hot path | W2 |

Use **orchestrator rule:** no workstream edits another’s `OpEntry` ids without cross‑PR link ( semver / migration in `dialect` if ever needed).

---

## 8. Success metrics (6–12 months)

- **% Tier‑2.5** coverage of duplicated IR patterns (goal: >70% of node count in new Tier‑3 ops comes from `wrap_child` of primitives).
- **Zero** open P0 in `findings.toml` for ops shipped as default.
- **100%** of `inventory` ops in `vyre-libs` default feature set have **adversarial + at least one** property or conform witness.
- **Fuzz** 0 high‑severity crashes on wire + DFA loaders for 24h per release candidate.

---

## 9. Appendix: checklist — merge with `ops-catalog.md`

When updating `docs/ops-catalog.md`, use §4 of **this** document as the **pigeonhole** for new rows. If a new op does not fit §4, **add a sub‑§** here first, then the catalog. That keeps the **Santh-wide** and **vyre-legendary** views aligned.

**End of plan** — next step: execute **Phase 0 (inventory)** and assign W1–W5 owners or subagent prompts.
