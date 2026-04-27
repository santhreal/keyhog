# Differential fuzzing

## The bug-finding technique that scales

Most tests in vyre verify specific claims against specific
oracles. Specific-input tests check spec table rows. Property
tests check universal claims over generated inputs. Mutation
tests grade test strength by introducing deliberate bugs.
Each of these is a targeted technique.

Differential fuzzing is different in kind. It does not verify
a specific claim or grade a specific suite. It feeds a large
volume of inputs to two independent implementations of the
same semantics and reports any input where the implementations
disagree. The disagreement itself is the finding: if two
implementations of vyre's semantics disagree on any input,
at least one of them is wrong.

Differential fuzzing scales because the oracle is the other
implementation. There is no need to write expected values by
hand, no need to enumerate cases, no need to specify the bug
class in advance. The fuzzer generates inputs continuously and
the diff catches bugs automatically. In practice,
differential fuzzing is the single most productive bug-finding
technique for systems like vyre where correctness is
compositional.

This chapter is about how vyre uses differential fuzzing: what
the two implementations are, how to run the fuzzer, how to
interpret findings, and how to turn findings into regression
tests.

## The two implementations

Differential fuzzing requires two implementations that should
agree. vyre has several pairings:

- **The default backend vs the reference interpreter.** The
  wgpu backend lowers Programs to WGSL and dispatches them on
  the GPU. The reference interpreter runs Programs in pure
  Rust with obviously correct semantics. The two should
  produce byte-identical outputs for every Program. Any
  disagreement is a backend bug or a lowering bug.
- **Two backends against each other.** When vyre has multiple
  conformant backends (wgpu and, eventually, CUDA or Metal),
  each backend is diffed against the others. Any
  disagreement is a backend non-conformance finding.
- **vyre's validator vs vyre's lowering.** If the validator
  accepts a Program but the lowering panics or produces
  undefined behavior, invariant I5 (validation soundness) is
  violated. The "differential" here is between "passes
  validation" and "lowers safely"; the two should always
  agree.
- **vyre's encoder vs vyre's decoder.** If encoding a Program
  and decoding the result produces a different Program,
  invariant I4 (IR wire format round-trip identity) is violated.
  The differential is between the original and the round-tripped
  value.

Each pairing defines a specific differential test target.
Vyre's `fuzz/` directory contains these targets, each in its
own file.

## Fuzz targets

```
fuzz/
├── fuzz_targets/
│   ├── backend_vs_reference.rs
│   ├── cross_backend.rs
│   ├── validation_soundness.rs
│   ├── wire_format_roundtrip.rs
│   └── shader_compile.rs
├── corpus/
│   ├── backend_vs_reference/
│   ├── cross_backend/
│   └── ...
└── Cargo.toml
```

Each target is a small Rust file that uses `libfuzzer-sys` to
feed random bytes to a harness. The harness converts the bytes
into an input (via a structure-aware generator) and runs the
differential comparison.

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use vyre::ir::Program;
use vyre_conform::reference;

fuzz_target!(|data: &[u8]| {
    // Structure-aware generation: turn random bytes into a Program.
    let program = match Program::from_fuzz_input(data) {
        Ok(p) => p,
        Err(_) => return,  // invalid input, skip
    };

    // Only test validated Programs; invalid ones are the
    // validation target's job.
    if !vyre::ir::validate(&program).is_empty() {
        return;
    }

    // Run on both implementations.
    let backend_result = vyre::runtime::default_backend()
        .run(&program, &[]);
    let reference_result = reference::run(&program, &[]);

    // Diff. Any disagreement is a finding.
    match (backend_result, reference_result) {
        (Ok(b), Ok(r)) => {
            if b != r {
                panic!("backend and reference disagreed: backend={:?}, reference={:?}", b, r);
            }
        }
        (Err(_), Err(_)) => {
            // Both errored; acceptable.
        }
        _ => {
            // One succeeded and the other errored — finding.
            panic!("backend and reference disagreed on success/failure");
        }
    }
});
```

The harness is short. Most of the work is in
`Program::from_fuzz_input`, which is a structure-aware
conversion from raw bytes to a validated Program shape. The
conversion uses the same kind of logic as the proptest
generator but driven by the fuzzer's bytes rather than by a
seeded RNG.

The panic on disagreement is deliberate. libfuzzer detects
panics and records the failing input as a crash. The crash
becomes a finding: the maintainer minimizes the input, adds it
to the fuzz corpus, and investigates the bug.

## Running the fuzzer

```bash
cargo fuzz run backend_vs_reference
```

Starts the fuzzer on the `backend_vs_reference` target. The
fuzzer runs continuously, generating inputs and checking for
panics. The process is long-running: fuzzing is effective
because it has time to explore the input space, and "time"
here means hours or days, not seconds.

Vyre runs fuzz targets in dedicated CI jobs that are not part
of per-commit CI. The jobs run on schedule:

- **Continuous fuzzing** on a dedicated machine, 24/7. Any
  crashes are reported via a bug tracker issue and trigger a
  P1 notification.
- **Release gates** run fuzz targets for a fixed duration
  (typically 1 hour per target) before each release, to
  catch regressions introduced since the last release.
- **Nightly fuzzing** runs for 6-8 hours per target, covering
  the targets that are not under continuous fuzzing.

The separation is because fuzzing is expensive in CPU time
and the results are most valuable when the fuzzer has time to
explore.

## Corpus management

libfuzzer maintains a corpus of inputs it has tried. The
corpus grows as the fuzzer discovers new code paths, and it
is committed to the repository so that new fuzz runs start
from the existing corpus rather than from scratch. A large
corpus is a sign of fuzzing maturity.

The corpus is in `fuzz/corpus/<target>/` and is committed
like any other test fixture. Each file in the corpus is a
raw-bytes input that triggered a new code path at some point
during fuzzing. libfuzzer uses the corpus as a starting set
and generates mutations of the existing inputs to find new
code paths.

When a crash is found, the crashing input is added to the
corpus and to `tests/adversarial/fuzz_corpus.rs` as a
regression. The crash is fixed, the test continues to run on
every CI invocation, and the bug is caught permanently.

## Minimizing findings

A crash from the fuzzer is usually a large random input that
happens to trigger a bug. Minimization reduces it to the
smallest input that still triggers. libfuzzer has a built-in
minimizer:

```bash
cargo fuzz tmin backend_vs_reference crash-abc123
```

The minimizer produces a smaller version of the input. The
smaller version is what gets committed to the regression
corpus, not the original large input.

Minimization is essential because large crash inputs are
hard to debug. A minimized input — say, 20 bytes that trigger
a specific panic — is small enough to inspect by hand and
small enough to understand. The regression test built from
the minimized input is clear and focused.

## When findings are not bugs

Occasionally a fuzzer finding is not a bug. The input
discovered a case that was never considered, and the "crash"
is actually vyre correctly rejecting an input that should not
have been accepted in the first place. The triage:

- **Input passes validation but should not.** Validation has a
  gap. Add a V-rule that rejects the input. The fuzz finding
  becomes a V-rule test.
- **Input is legitimately different on the two backends
  because of a spec ambiguity.** The spec needs tightening.
  The tightening is a change to vyre's spec doc and
  potentially to the implementation. The fuzz finding becomes
  a spec clarification commit.
- **Input produces different error messages but the same
  behavior.** Not a bug; the comparison is over-strict. Relax
  the fuzz target's comparison to ignore error message text.

Each of these is a different kind of learning. The fuzz
finding is always informational; the action depends on what
the finding reveals.

## Structure-aware fuzzing

Fuzz targets that accept raw bytes have a quality problem:
most random bytes do not parse into valid Programs. The
fuzzer spends most of its time generating inputs that fail at
the parsing stage, which is wasted effort.

Structure-aware fuzzing generates inputs that are valid by
construction. The harness converts random bytes into a
Program using a guided process that respects the Program's
invariants:

```rust
impl Program {
    pub fn from_fuzz_input(data: &[u8]) -> Result<Self, InputError> {
        let mut reader = FuzzReader::new(data);
        let num_buffers = reader.u32()? % 4 + 1;  // bounded
        let buffers: Vec<_> = (0..num_buffers)
            .map(|i| BufferDecl::from_fuzz(&mut reader, i))
            .collect::<Result<_, _>>()?;
        let workgroup_size = reader.u32()? % 16 + 1;
        let entry = Node::from_fuzz(&mut reader, &buffers, 3)?;
        Ok(Program { buffers, workgroup_size, entry })
    }
}
```

The conversion pulls bounded values from the fuzz bytes,
which produces Programs within resource limits. The resulting
Program is almost always valid, which means the fuzzer's
effort is spent exploring real code paths instead of getting
rejected at the gate.

Structure-aware fuzzing is more code than raw-bytes fuzzing
but is much more productive. Every serious differential fuzz
target in vyre uses structure-aware input generation.

## Coverage-guided fuzzing

libfuzzer uses coverage feedback to prioritize inputs that
exercise new code paths. An input that hits a branch the
fuzzer has not seen before is saved to the corpus and used as
a seed for further mutation. Over time, the corpus accumulates
inputs that cover a large fraction of the codebase.

The coverage tracking is automatic when using `cargo fuzz`.
The maintainer does not have to configure it. The effect is
that fuzzing discovers bugs that only fire in specific code
paths, which are exactly the bugs the suite is most likely to
miss.

## Summary

Differential fuzzing runs large volumes of inputs through two
implementations and reports disagreements. vyre uses it for
backend-vs-reference, cross-backend, validation soundness,
and wire-format round-trip. Fuzz targets live in `fuzz/`, use
structure-aware input generation, run in dedicated CI jobs,
and feed findings back into the regression corpus. It is the
single most productive bug-finding technique for vyre, and
every invariant that can be cast as a differential should be
fuzz-tested.

Next: [Mutation testing at scale](mutation-at-scale.md).
