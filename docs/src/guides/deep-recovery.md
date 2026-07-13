# Deep recovery

Use `--deep` when recall matters more than routine scan cost:

```bash
keyhog scan . --deep
keyhog config --effective --deep
```

The second command prints the resolved policy. Record it with benchmark or
incident results.

## What changes

`--deep` is a bounded preset, not an unbounded evaluator.

| Setting | Default | Deep |
|---|---:|---:|
| Decode depth | 10 | 10 |
| Decode input ceiling | 512 KiB | 1 MiB |
| Source-file entropy | off | on |
| ML-only entropy veto | on | off |
| Comment confidence penalty | on | off |

ML remains enabled. Deep retains its score as evidence but does not let the
model alone discard an entropy candidate. Explicit compatible flags apply on
top of the preset, such as `--deep --decode-depth 3`.

## Recovery mechanisms

Deep runs the normal detector corpus and expands bounded recovery around it:

- recursive Base64, hex, URL, Unicode escape, and supported transport decoding;
- source-file entropy discovery for unknown opaque values;
- comment scanning without the normal comment penalty;
- static JavaScript recovery for recognized cyclic XOR expressions;
- static AES-256-CBC recovery when the key, IV, ciphertext, and bindings are
  literal and internally consistent.

Static program recovery does not execute JavaScript or invoke Node.js. It
accepts a small side-effect-free grammar and rejects dynamic operands. The
implementation lives in `crates/scanner/src/decode/javascript_static.rs` and
`crates/scanner/src/decode/javascript_static/aes.rs`.

The static evaluator caps source size, literal arrays, binding count, and
expression count. Decode recursion also enforces depth, output-size, expansion,
and total-work budgets. A rejected transform still leaves the original source
available to ordinary detection.

## Non-LLM recovery benchmark

The repository's `ioc-recovery` corpus contains 4,368 labeled fixtures across
13 JavaScript concealment phases. It has exact expected credentials and is
scored by the same benchmark runner used for other corpora.

Reproduce the checked benchmark matrix:

```bash
make -C benchmarks ioc-recovery-corpus
make -C benchmarks ioc-recovery
```

The committed deep target requires 4,368 true positives, zero false negatives,
and zero false positives for the pinned corpus and scanner identity. The fast
comparison reports 1,344 true positives and 3,024 false negatives. These are
corpus results, not a claim that every possible program transform is supported.

- [Executable deep target](../../../benchmarks/bench/tests/test_ioc_recovery_target_spec.py)
- [Corpus and scorer contract](../../../benchmarks/README.md#exact-secret-recovery-benchmark)

The reproduction commands write local artifacts under
`benchmarks/results-ioc-recovery/`. Those artifacts are intentionally ignored
because timings and hardware identity are host-specific. Each artifact records
the mode, backend, cache and daemon state, scanner version, corpus size, exact
detection totals, wall time, and peak RSS. Compare results only when those
identities match.
