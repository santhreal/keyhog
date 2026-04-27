# .internals — vyre development artifacts (not part of the public surface)

`.internals/` is the sediment layer of vyre: audits, plans, baselines, and
release scaffolding that stay out of the published crate surface. It is a
maintainer workspace, not the shipped source of truth. Documentation
precedence is defined in
[`../docs/DOCUMENTATION_GOVERNANCE.md`](../docs/DOCUMENTATION_GOVERNANCE.md).
Each top-level directory has exactly one purpose. When something doesn't fit,
propose a new directory — don't expand an existing one.

## Directory map

| Directory   | Purpose                                                                                                            |
|-------------|--------------------------------------------------------------------------------------------------------------------|
| `archive/`  | Frozen snapshots of superseded docs, plans, audits. Nothing here is load-bearing. Read-only reference.             |
| `audits/`   | Internal audit findings owned by open tasks. They are evidence/backlog, not release policy. When an audit closes, move the file into `archive/`. |
| `baselines/`| Reference timings, hardware fingerprints, conformance-cert baselines. Rebuild before any perf claim.               |
| `catalogs/` | Auto-generated inventories (op catalog, dialect surface, wire tags). Regenerate with `cargo xtask catalog`.        |
| `certs/`    | Signed conformance certificates produced by `vyre-conform prove`. One file per (adapter, program, timestamp).      |
| `perf/`     | Raw benchmark output (criterion JSON, flamegraphs). Fed by `cargo bench`; consumed by `baselines/`.                |
| `planning/` | In-progress design sketches and proposals. Each file names its owner + target date in the frontmatter.             |
| `plans/`    | Internal multi-phase execution notes. They become authoritative only when `../audits/LEGENDARY_GATE.md` delegates to them. Move to `archive/` on completion. |
| `public-api/`| `cargo public-api` snapshots, one per crate. Diff on every PR. Regression = intentional breaking change.          |
| `release/`  | Release-engineering scripts + checklists (publish dry-runs, tag provenance, yank ledger).                          |
| `scratch/`  | Short-lived notes, thought experiments, out-of-scope drafts. Age out after 30 days or move elsewhere.              |

## Housekeeping rules

- **Nothing in `.internals/` is a published API.** Anything consumed by
  external users belongs in the crate's public surface or in top-level docs.
- **Nothing in `.internals/` outranks the shipped docs.** If an internal
  audit or plan conflicts with `VISION.md`, `docs/THESIS.md`, `RELEASE.md`,
  or `audits/LEGENDARY_GATE.md`, the shipped document wins until the
  higher-precedence document is intentionally updated.
- **Archive aggressively.** A finished plan belongs in `archive/`, not
  `plans/`. A closed audit belongs in `archive/`, not `audits/`.
- **Don't invent directories.** If a new artifact doesn't fit, open a PR
  that explains why and updates this README in the same commit.
- **Keep `scratch/` under 20 files.** If it grows past that, promote the
  useful ones into `planning/` and delete the rest.

## Reading order for cold-start

1. `../docs/DOCUMENTATION_GOVERNANCE.md` (precedence)
2. `../audits/LEGENDARY_GATE.md` (active release gate)
3. `plans/` for delegated cross-cutting initiatives
4. `audits/` for internal findings
5. `archive/` only when tracing history
