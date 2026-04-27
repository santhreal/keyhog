# Vyre testing skills — master guide

Every vyre crate implements the same testing contract. An agent writing
tests for any vyre crate reads this file first, then the matching
category skill in the same directory, then the crate's own
`tests/SKILL.md` which maps the general category contract onto the
specific invariants of that crate.

## The six categories

| File | Purpose | Designed to pass? |
| --- | --- | --- |
| [adversarial.md](adversarial.md) | hostile inputs, resource exhaustion, concurrent access | yes |
| [property.md](property.md) | invariants that must hold for every input (proptest) | yes |
| [gap.md](gap.md) | **failing-by-design** tests — a pass is a bug in the test | **no** |
| [integration.md](integration.md) | cross-crate contracts and API boundaries | yes |
| [bench.md](bench.md) | criterion perf + regression budgets | n/a (measures) |
| [fuzz.md](fuzz.md) | cargo-fuzz targets, corpus seeding | crashing = finding |

## The contract every crate honors

Every vyre crate has:

```
<crate>/
  tests/
    SKILL.md           # crate-specific mapping of these skills
    adversarial.rs     # one file per category = one cargo-test binary
    property.rs
    gap.rs
    integration.rs
  benches/             # criterion
  fuzz/                # optional; present for crates touching untrusted bytes
```

Cargo convention: every file directly under `tests/` is its own
compiled test binary. Subdirectories under `tests/` are not
auto-compiled — they are `mod`-included from the files above. Shared
helpers live at `tests/common/mod.rs` and are referenced via
`mod common;` in each test file.

## Writing standards — non-negotiable

1. **Every test asserts something meaningful.** `let _ = result;` is
   not a test. An assertion that cannot fail is not a test.
2. **Tests are higher-quality than the code they test.** A sloppy
   test creates false confidence and is worse than no test.
3. **Gap tests fail on purpose.** A gap test that passes means either
   the engine closed the gap (celebrate + move the test to property
   or adversarial) or the test is wrong (rewrite).
4. **No test swallows a panic**. A panic in the engine is a finding.
5. **Error messages include `Fix: ` when the test does diagnostic
   work**, matching the vyre-wide engineering standard.
6. **Adversarial tests never mutate shared state outside the test
   module** — concurrency tests use isolated fixtures so a failing
   test does not poison the next one.
7. **Determinism**. Every property and adversarial test has a fixed
   seed; every proptest regression is checked in. Non-determinism is
   a finding, not an excuse.

## Bar: measure against SQLite, NASA JPL, Linux kernel

- **SQLite**: 590× test-to-source ratio, branch coverage, OOM injection,
  IO error injection. Our adversarial tier aspires to this density.
- **NASA JPL**: contracts — pre/post-conditions + invariants. Our
  property tier covers the invariants.
- **Linux kernel**: kselftest + syzkaller + KASAN + lockdep. Our fuzz
  tier uses cargo-fuzz; concurrency tests use `loom` where present.
- **Chromium ClusterFuzz**: 24/7 fuzzing on every commit. Our fuzz
  tier runs on CI and on locally-scheduled cron.

If a test file passes every check in its category skill, it's
done. If any item is missing, it's incomplete.
