# fuzz.md — cargo-fuzz targets

## What goes here

Tests that **generate random bytes and look for crashes**. Fuzzing is
how serious runtime infrastructure finds security-relevant bugs
before the attacker does — Chromium's ClusterFuzz, OpenSSL's
oss-fuzz, every codec maintainer worth trusting.

## When a crate needs a fuzz target

A crate needs one or more fuzz targets when it:

- Decodes untrusted bytes (wire format, file format, network
  payload, env var)
- Parses untrusted strings (shader source, TOML config, DSL input)
- Accepts any input from a downstream crate that itself accepts
  untrusted input (transitive closure)
- Handles recovery from malformed state (cache corruption,
  truncated files, dropped connections)

A crate that only takes trusted in-process values probably doesn't
need fuzz — but property tests still cover it.

## Directory layout

```
<crate>/
  fuzz/
    Cargo.toml              # cargo-fuzz package
    fuzz_targets/
      decode.rs             # one target = one binary
      parse.rs
      round_trip.rs
    corpus/
      decode/               # seed inputs for each target
      parse/
      round_trip/
```

`cargo install cargo-fuzz` is required. `cargo fuzz init` generates
the scaffold — don't hand-roll it.

## Checklist — every fuzz suite covers

### Targets

- [ ] `decode` — raw bytes → attempt to decode → no panics allowed
- [ ] `parse` — raw bytes as UTF-8 → attempt to parse → no panics
- [ ] `round_trip` — raw bytes → decode → re-encode → assert bytes
  match on valid input (invalid input must return `Err`, not
  panic)
- [ ] Every public decoder / parser / state-machine has a target
- [ ] A `differential` target when two impls of the same contract
  exist (e.g. optimizer vs no-optimizer, CPU vs GPU) — feed same
  input, assert results match

### Corpus

- [ ] Seed the corpus from every KAT, every existing unit test
  input, every historical bug report payload, and the
  `cargo fuzz cmin` reduction of the above
- [ ] Corpus is checked into `fuzz/corpus/<target>/` so every
  reviewer starts from the same minimum coverage set
- [ ] Every crash found by the fuzzer is minimized via
  `cargo fuzz tmin` and the minimized input is checked in to
  `fuzz/artifacts/<target>/` with a test-case name referencing
  the issue or commit that fixed it

### Continuous fuzzing

- [ ] CI runs `cargo fuzz run <target> --runs=100000` on every PR
  that touches the crate's source
- [ ] A cron job runs `cargo fuzz run <target>` for hours on a
  dedicated machine and reports any new crashes
- [ ] Every crash surfaces as a GitHub issue with the minimized
  input and a stack trace

## Template target

```rust
//! Fuzz target: decode → re-encode round-trip.
//!
//! See `../../.internals/skills/testing/fuzz.md` for the category contract.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decode. Must never panic on arbitrary input.
    let Ok(program) = vyre_foundation::Program::from_wire(data) else {
        return;
    };
    // Valid decode → must re-encode to the same bytes (canonical
    // form) OR the encoder must round-trip stable: encoded bytes
    // decode back to an equal program.
    let Ok(encoded) = program.to_wire() else {
        // Decoded programs MUST encode. If not, that's a finding.
        panic!("decoded program failed to re-encode");
    };
    let redecoded = vyre_foundation::Program::from_wire(&encoded)
        .expect("re-encoded bytes must decode");
    assert_eq!(program, redecoded, "round-trip must stabilize");
});
```

## Crash triage

When a fuzz run finds a crash:

1. `cargo fuzz tmin fuzz/artifacts/<target>/<case>` — minimize to
   the shortest byte sequence that still crashes.
2. Check the minimized case in to `fuzz/artifacts/<target>/`
   with a filename naming the crash mode.
3. Open an issue referencing the minimized case.
4. Fix the engine so the input no longer crashes.
5. Add the minimized case to `fuzz/corpus/<target>/` so the fixed
   engine is regression-tested against it forever.
6. Run `cargo fuzz run <target> --runs=100000` again to confirm
   the fix doesn't reintroduce the crash or expose a new one.

## Anti-patterns

- **Fuzz targets that call `unwrap()`.** The whole point is no
  panic. If you need to bail on invalid input, `return` early.
- **Skipping corpus minimization.** An unminimized 2 KB crash input
  is useless to a human reviewer. Always minimize.
- **Running fuzz once locally, declaring "fuzzed".** Fuzzing is a
  continuous activity, not a checkbox. If the codebase has not
  been fuzzed in the last week, consider it unfuzzed.
- **No seed corpus.** An empty corpus means the fuzzer has to
  rediscover every valid input shape from scratch. Seed with
  every KAT and every valid-input test case.
- **Different impls in the same process during fuzz.** Differential
  fuzzing is powerful but requires the two impls to be clean-room
  in the same binary; otherwise a shared bug fools the diff.

## Santh fuzz pool

Santh's fuzz infrastructure (when ready) shares a corpus across
crates that consume the same wire format. Don't duplicate corpora —
link to the shared pool when it lands.
