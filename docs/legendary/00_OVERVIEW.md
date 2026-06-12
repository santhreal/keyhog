# keyhog → Legendary: the multi-year perfection plan

**Mandate.** Make keyhog Linux-kernel-level quality: perfection on every vector of
`~/.claude/CLAUDE.md`, massive innovation, zero shortcuts. Author this plan, then
execute it end-to-end, **hardest-first, never postponing**. The harder / more
research-heavy / multi-month an item is, the *earlier* it runs. No asking — this
runs autonomously.

This file is the spine. Item files live beside it (`10_*` … `90_*`). Every item
is grounded in a real read of the code or a real dogfood run, never a guess.

---

## The bar (what "legendary" means here)

1. **Detection truth.** Best-in-class recall AND precision on *real* corpora
   (CredData, not just the synthetic mirror), proven by differential benchmarks
   against every serious peer, with no silent recall loss anywhere (Law 10).
2. **Speed.** The fastest correct secret scanner in existence, measured before and
   after every change, on CPU (AVX-512 + Hyperscan) and GPU (CUDA + wgpu
   megakernel), with the bottleneck named at each layer.
3. **Soundness.** Every transform/decoder/suppressor preserves what the operator
   intended, proven by an oracle; fail closed when the oracle can't prove safety.
4. **Coherence.** Docs, `--help`, README claims, JSON/SARIF fields, exit codes,
   tests, and code agree at every commit — verified by gates, not by hope.
5. **Cross-OS.** Identical correctness on Linux (x86_64 + aarch64), macOS
   (arm64), and Windows; install + doctor + scan + TUI proven on each, every
   release.
6. **Legibility.** A new contributor can navigate any subsystem from a module map
   in < 5 minutes; no stray docs, no dead shims, one canonical primitive per job.

"Hardened / secure / clean / done" is never claimed. Only a passing proving test
or a reproduced PoC is evidence. Absence of a finding lowers *our coverage
estimate*, never raises a *safety* claim.

---

## Fleet (where dogfooding actually runs)

| Name | SSH | OS / arch | Role |
|---|---|---|---|
| work-linux (this box) | local | Linux x86_64, **RTX 5090**, AVX-512, Hyperscan | GPU host, source tree, default features |
| santhserver | `santhserver` | Linux x86_64, GPUs | portable build, 2nd Linux, `/mnt/santh-desktop` |
| macbook | `tt-macbook` | **Darwin arm64** | portable / Apple-Silicon wgpu path |
| windows-thinkpad | `windows-thinkpad` | Windows | portable, Windows-shippable |
| axiom-exec | `axiom-exec` | Linux x86_64 | extra runner |
| thamiya-desktop | `thamiya-desktop` | Linux | (was offline at plan time) |

`scripts/dogfood-all-os.sh` already drives `[cli] [tui] [install]` across
work-linux/santhserver/macbook/win and prints a loud PASS/FAIL/SKIP matrix.
**Extend it, never replace it.** Cross-OS dogfood is a release gate, not an
afterthought.

---

## Architecture snapshot (the audit, as of v0.5.40 @ dcc60edf)

Five crates, ~66k LOC src, one-way layering (domain logic never imports CLI/UI):

- **keyhog-core** (8.2k LOC / 34 files): `RawMatch`/dedup/report/SARIF, detector
  spec + registry, `.keyhogignore(.toml)` rule engine, merkle index, allowlist,
  calibration, the embedded 901-detector set + MoE ML model.
- **keyhog-scanner** (32.6k LOC / 142 files): the engine. `engine/` (44 files) is
  one `CompiledScanner` god-object split by impl-block, navigable from the
  `engine/mod.rs` pipeline map. Phase-1 trigger production (CPU Hyperscan /
  SIMD / GPU presence-bitmap / megakernel firings) → shared phase-2 tail
  (windowing → confirmed → fallback → generic → entropy → ML → suppression →
  dedup → confidence → decode → cross-chunk boundary). Sub-systems: checksum,
  confidence, context, decode (14 decoders + recursion pipeline), entropy,
  hw_probe, multiline, structured parsers, suppression.
- **keyhog-sources** (8.6k LOC / 33 files): filesystem, git history, git diff, S3,
  GitHub-org, Docker, HAR, **Ghidra binary**, web, slack, http, stdin, strings/
  sections/literals (binary), redact/sanitize, timeouts.
- **keyhog-verifier** (4.5k LOC / 18 files): live credential verification with
  SSRF/bogon/domain-allowlist/rate-limit guards, OOB, response cache.
- **keyhog-cli** (12.1k LOC / 49 files): 17 subcommands (scan, scan_system, daemon,
  watch, tui, doctor, calibrate, diff, explain, hook, repair, backend, update,
  uninstall, completion, detect), installer, orchestrator.

**vyre integration** (the perf substrate, pinned `=0.6.1` via live-source path
override): `vyre`/`vyre_libs` for regex→DFA lowering, NFA matching, CHD intern,
the declarative rule engine; optional `vyre-driver-wgpu`, **`vyre-driver-cuda`**
(doctor self-test ran the AC kernel on **CUDA**), and `vyre-runtime`
megakernel-batch. Utilization is partial — see `40_gpu_vyre.md`.

**GPU state.** 78046450 consolidated 13 `gpu_*.rs` files into
`backend_triggered.rs` + `megakernel_dispatch.rs` + `gpu_{forced,lazy,cache}.rs`.
Phase-1 is positionless (presence bitmap + `(file,detector)` firings); positions
come from CPU regex in phase-2. Stale gates from that consolidation are fixed
(8db8b347, dcc60edf). The refactor is `[LOCAL — DO NOT PUSH]` until vyre 0.6.2
publishes — finalizing it is a flagship lane (`40_gpu_vyre.md`).

### Seed dogfood findings (already real, v0.5.40, this box)
- **Install/PATH:** doctor flags a shadow — `~/.local/bin/keyhog` is ahead on PATH
  of a fresh build. The install/update/PATH UX needs hardening (`70_install_xos.md`).
- **GPU backend:** doctor self-test passes on **CUDA** (`backend=cuda`), while the
  wgpu integration test has no adapter in a headless shell — the CUDA vs wgpu
  split must be made explicit and both proven (`40_gpu_vyre.md`).
- **Self-scan:** `keyhog scan . --format json` on its own tree returns `[]`.
  Verify this is correct test-fixture suppression, not masking (`20_detection.md`).
- **Memory:** 1.5 GB peak RSS scanning its own source tree — a perf/memory item
  (`30_speed_mem.md`).

### Org/docs snapshot (legibility debt)
Core is well-mapped; the *root* is cluttered: 2 untracked audit reports
(`FP_AUDIT_REPORT.md` is referenced by a committed test + source yet uncommitted —
a real coherence bug), 5 stale session/program docs, `backlog/` + gitignored
`coordination/` trees. See `80_org_docs_dedup.md`.

---

## The vectors (every lens in CLAUDE.md becomes a column)

Each item is tagged with one or more vector IDs. Coverage of **all** of these is
the definition of "every vector of CLAUDE.md":

- **SCR** — Screwdriver Principle: deepen the one job, refuse scope creep, soundness over reach.
- **L1**…**L10** — the ten Laws (no-regrets · no-stubs · compat-by-contract · extend-architecture · modularity · test-truth · optimizations-are-fixes · GPU-exists · no-evasion · **no-silent-fallbacks**).
- **SCALE** — multi-axis progress: detection-truth · perf · test-depth · dogfood/UX · org/dedup · architecture.
- **VR1**…**VR12** — vulnerability-research discipline (targeted, oracle-backed, no overclaim, read+dynamic, no premature wrap-up) applied to keyhog-as-target AND to keyhog's own attack-surface hunts.
- **AV1**…**AV15** — Adversarial Review Vectors: speed · research · capability · innovation · insufficiency · generalization · dedup · architecture · wiring · coherence · utilization · testing · dogfooding · introspection · audit-hunts.
- **TC** — Testing Contract (positive/negative/adversarial/cross-file/CVE-replay/proptest-10k/differential/criterion/scale/e2e per surface).
- **ENG** — Engineering Standards (error-context, boundary-validation, fail-closed, no-secret-logging, layering).
- **CFG** — Two-tier TOML config (Tier-A knobs, Tier-B data files; hardcoded lists banned).
- **CRATE** — Crates-of-crates (CLI + lib + subcrate, modular, swappable boundary).
- **DEDUP** — one primitive / one schema / one parser / one constant source.

---

## Subsystems (the rows)

`CORE · ENGINE · DECODE · SUPPRESS · CONFIDENCE · ENTROPY · ML · MULTILINE ·
CONTEXT · CHECKSUM · STRUCTURED · VYRE · GPU · SOURCES · VERIFIER · CLI · DAEMON ·
TUI · INSTALL · DETECTORS · BENCH · DOCS · CI · SECURITY(keyhog-as-target)`

The plan files group items by area; the vector/subsystem tags make the matrix
queryable (`grep '\[AV9\]' docs/legendary/*.md` = every wiring item, etc.).

---

## Item files

| File | Area | Flagship hard lanes (run first) |
|---|---|---|
| `10_foundation.md` | vyre 0.6.2 publish+pin, repo landing, build/CI spine | RESEARCH: unblock the parked vyre release tooling |
| `20_detection.md` | recall/precision truth on real corpora | RESEARCH: close the CredData recall gap (5th/6) |
| `30_speed_mem.md` | speed + memory, every layer | RESEARCH: beat every peer on CredData wall-clock |
| `40_gpu_vyre.md` | GPU/megakernel finalize, CUDA+wgpu, vyre utilization | RESEARCH: GPU coverage of host_detectors; megakernel positions |
| `50_sources.md` | every source backend, hardened + complete | git-history scale, Ghidra, S3/web SSRF |
| `60_verifier.md` | live verification breadth + SSRF safety | provider matrix, OOB, constant-time |
| `70_install_xos.md` | install/update/uninstall, cross-OS, racing | XL: byte-identical correctness on 3 OSes |
| `80_org_docs_dedup.md` | legibility, dedup, doc hygiene, module maps | the stray-docs + dedup sweep |
| `90_security_audit.md` | keyhog-as-target: the audit hunts (AV15) | RESEARCH: fuzz every parser/decoder to a PoC or disk-kill |
| `95_testing_coherence.md` | Testing Contract + coherence gates per surface | TC across all 17 subcommands + every output format |

---

## Execution protocol (how the plan gets worked)

1. **Hardest-first.** Each turn, pick the highest-difficulty *unblocked* item
   (RESEARCH > XL > L > M > S). Difficulty is a reason to start, never to defer.
   "Postpone the hard part" is a session failure.
2. **One lane to ground.** Drive a lane to a proving test / PoC / committed fix /
   disk-documented kill before opening the next. No spray-and-pray.
3. **Dogfood is mandatory.** A fix isn't done until the *shipped binary* shows it
   (install the way a user would, run it cross-OS, race it, scale it).
4. **Encode every finding twice:** a failing regression test (asserts real values,
   never `!is_empty`) + a one-line ledger entry. A finding with no reproducing
   test does not count.
5. **No silent anything** (Law 10). Every degrade/fallback/skip is loud, recorded,
   and recall-preserving — or it fails closed.
6. **Never weaken a test to pass** (Law 6/9). A failing contract test is a finding.
7. **Multi-axis each push** (Scale Law): land ≥3 of {detection, perf, test-depth,
   dogfood, org/dedup, architecture} per ~10 commits; name them or you're tunneling.
8. **Branch `main` only; never push the vyre path override until 0.6.2 publishes;
   `.claude/` never committed; no AI attribution in commits.**
9. **Ledger, not chat.** Progress is recorded in `99_LEDGER.md` (one line per
   landed item: id · commit · the 3 axes moved · proving test). Coverage notes to
   disk, never to prose.

## Item numbering

`KH-L-NNNN` (Legendary), unique across files. Each line:
`KH-L-NNNN [VECTORS][SUBSYSTEM][EFFORT] one-sentence outcome — proving artifact.`
EFFORT ∈ {S, M, L, XL, RESEARCH}. RESEARCH/XL = multi-week/-month; these run FIRST.

Target: 1000+ items at authoring; the backlog grows as introspection (AV14) and
audit hunts (AV15) surface more. The plan is never "finished" by fiat — only the
*work* completes, item by item, proven on the ledger.
