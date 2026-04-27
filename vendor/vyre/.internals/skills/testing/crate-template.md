# Template: `<crate>/tests/SKILL.md`

Copy this file to every crate's `tests/SKILL.md` and fill in the
crate-specific sections. Agents writing tests read this file first
to understand what's load-bearing for this particular crate; then
they read the matching category skill at
`../../.internals/skills/testing/<category>.md` for the standard contract.

---

```markdown
# tests/SKILL.md — <crate-name>

## Purpose of this crate (one paragraph)

<What does this crate do? What's the public surface? Who consumes it?
  Who doesn't?>

## Critical invariants

The three or four invariants that, if violated, would make this
crate unusable. Every property test in `property.rs` maps to one of
these.

- **Invariant A**: <one sentence>
- **Invariant B**: <one sentence>
- **Invariant C**: <one sentence>

## Adversarial surface

What hostile inputs must this crate survive? Map each item to a
required test in `adversarial.rs`.

- <Input class 1> — test: `fn adversarial_<x>()`
- <Input class 2> — test: `fn adversarial_<y>()`

## Current gaps (drives `gap.rs`)

List every claim in README / ARCHITECTURE / VISION that the crate
does not yet satisfy. Each item is a failing test in `gap.rs`.

- <Gap 1> — source: `README.md §<section>` — test: `fn gap_<x>()`
- <Gap 2> — source: `<doc>` — test: `fn gap_<y>()`

## Cross-crate contracts (drives `integration.rs`)

Every trait this crate implements or defines, and every crate that
consumes / provides it. Map each to a test in `integration.rs`.

- `<trait>` declared in `<this-crate>`, implemented by
  `<consuming-crate>` → test: `fn integration_<trait>()`
- `<type>` exported by `<this-crate>`, round-tripped through
  `<consumer>` → test: `fn integration_<type>_round_trip()`

## Bench targets (drives `benches/`)

Every public function on the dispatch / decode / emit hot path.
Saved baseline name + regression budget per target.

- `<fn>` — bench `benches/<name>.rs::bench_<fn>()`, budget `5%`
  from `v0.6` baseline

## Fuzz targets (drives `fuzz/`)

Only for crates that decode / parse untrusted input. List every
fuzz target + seed corpus source.

- `decode` — `fuzz/fuzz_targets/decode.rs` — seeded from
  `<source-of-kats>` and all KATs under `<path>`

## What NOT to test here

Things that belong in some other crate's tests — preventing
responsibility drift.

- <Thing 1>: tested in `<other-crate>/tests/<file>`
- <Thing 2>: tested only inside the shared trait's consumer

## Running

```bash
cargo test -p <crate>
cargo test -p <crate> --test adversarial
cargo test -p <crate> --test property
cargo test -p <crate> --test gap       # expected to show failures
cargo test -p <crate> --test integration
cargo bench -p <crate>
cd <crate>/fuzz && cargo fuzz run <target>
```
```
