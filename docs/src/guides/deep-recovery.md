# Deep recovery

Use `--deep` when recall matters more than routine scan cost:

```bash
keyhog scan . --deep
keyhog config --effective --deep
```

The second command prints the resolved policy. Record it with benchmark or
incident results.

When a report is written as `json-envelope`, `jsonl-envelope`, or `html`, its
metadata contains a `resolved_scan` manifest. The manifest records the selected
`preset`, every effective detection value, and the keys that differ from that
preset's base. This makes a deep run with compatible overrides directly
comparable to default, fast, and precision artifacts:

```json
{
  "schema_version": 1,
  "preset": "deep",
  "effective": {"max_decode_depth": "3", "entropy_enabled": "true"},
  "overrides": ["max_decode_depth"]
}
```

Values are strings by contract so the manifest remains stable as new typed
settings are added; maps are serialized in key order. It contains no paths,
credentials, or host-specific routing decisions. The benchmark runner should
store this object alongside timing and accuracy so results are never compared
across silently different detection policies.

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
  literal and internally consistent;
- static CryptoJS passphrase recovery for the exact immutable wrapper dialect,
  with strict OpenSSL `Salted__`, EVP_BytesToKey MD5, AES-256-CBC, PKCS#7, and
  UTF-8 validation.

Static program recovery does not execute JavaScript or invoke Node.js. It
accepts a small side-effect-free grammar and rejects dynamic operands. The
implementation lives in `crates/scanner/src/decode/javascript_static.rs` and
its `aes.rs` and `cryptojs.rs` submodules.

The static evaluator caps source size, literal arrays, binding count, and
expression count. Decode recursion also enforces depth, output-size, expansion,
and total-work budgets. A rejected transform still leaves the original source
available to ordinary detection.

## Non-LLM recovery benchmark

The repository's `ioc-recovery` corpus contains 4,368 labeled fixtures across
13 JavaScript concealment phases. It has exact expected credentials and is
scored by the same benchmark runner used for other corpora.

The paper authors publish 13 demonstration files in the pinned
[`llm-ioc-detection`](https://github.com/jaimemorales52/llm-ioc-detection/tree/91d45377cf482c1de6c36a0d33744665976a19b6/1.createdFiles)
repository. Their 336-program evaluation corpus is not present there. KeyHog's
4,368 fixtures are deterministic synthetic adaptations of the phase taxonomy,
not copies of the paper's evaluation files.

Reproduce the checked benchmark matrix:

```bash
make -C benchmarks ioc-recovery-corpus
make -C benchmarks ioc-recovery
```

The committed deep target requires 4,368 true positives, zero false negatives,
and zero false positives for the pinned corpus and scanner identity. The fast
comparison reports 1,344 true positives and 3,024 false negatives. These are
corpus results, not a claim that every possible program transform is supported.

- [Executable deep target](https://github.com/santhreal/keyhog/blob/main/benchmarks/bench/tests/test_ioc_recovery_target_spec.py)
- [Corpus and scorer contract](https://github.com/santhreal/keyhog/blob/main/benchmarks/README.md#exact-secret-recovery-benchmark)

The reproduction commands write local artifacts under
`benchmarks/results-ioc-recovery/`. Those artifacts are intentionally ignored
because timings and hardware identity are host-specific. Each artifact records
the mode, backend, cache and daemon state, scanner version, corpus size, exact
detection totals, wall time, and peak RSS. Compare results only when those
identities match.
