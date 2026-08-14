# Deep recovery

Git history keeps a credential after you delete it from the working tree. Scan
that history explicitly. A filesystem scan never includes it.

```bash
keyhog scan --git-history . --format json-envelope --output history.json
```

`--git-history` scans the lines added by commits reachable from the current
checkout, bounded by `--max-commits` and by the ancestry the clone contains.

A shallow clone reports the gap instead of a clean scan. `git clone --depth N`
records a graft boundary, and the parent commits named there were never
fetched, so their blobs cannot be scanned. Both `--git-history` and
`--git-blobs` count those absent parents, exit `13`, and report
`"scan_status":"partial"` with a `Git object unreadable` entry in
`coverage_gap_summary`. Read that as "this clone does not contain the history
you asked me to search", not as a scanner failure. The fix is on the checkout
side:

```bash
git fetch --unshallow && keyhog scan --git-history .
```

`actions/checkout` clones one commit by default, so set `fetch-depth: 0` on any
job that scans history. See
[failure modes](../workflows/ci.md#failure-modes-worth-knowing).

Choose the Git boundary before changing anything else:

| Boundary | Command | Covers | Does not cover |
|---|---|---|---|
| Added lines in reachable commits | `keyhog scan --git-history .` | Patch additions from the ancestry of the current checkout, with commit, author, and date on every finding. | Other branches, tags, stashes, notes, and objects no ref reaches. |
| Every reachable blob | `keyhog scan --git-blobs .` | Deduplicated blobs from every ref, including branches you have not checked out and refs that only exist in `packed-refs`, plus annotated tag messages, stashes, notes, and dangling objects that a rewrite or an amend left behind. Enumeration diffs each commit against its parents and keeps added, changed, and deleted blob sides, so a credential that was committed and later removed stays visible without rewalking every historical tree. Every ref tip under `refs/` plus HEAD is still fully walked once so `--max-commits` cannot hide untouched blobs on non-newest branches, custom ref namespaces, or detached CI checkouts. | Blobs that decode as binary, including committed archives. |
| Both | `keyhog scan --git-history . --git-blobs .` | The recursive recovery workflow. Use it for a release or incident review. | |

The two boundaries differ by more than cost. A credential committed on a
branch you never checked out, or left behind by `git commit --amend`, is
reachable through `--git-blobs` and invisible to `--git-history`.

A committed archive is a known gap in both. `--git-blobs` refuses a blob that
decodes as binary, so `bundles/payload.tar.gz` is reported as
`Git object unreadable` and the scan exits `13` rather than reporting the
archive clean. Scan the checked-out working tree as well when the repository
carries archives: the filesystem source does extract them.

Neither boundary reaches sibling repositories, provider organizations, cloud
buckets, or mounted filesystems. Run those boundaries as separate jobs and
preserve their reports and statuses.

Deep Git scans run in process. A warm daemon does not accelerate history or
blob traversal.

## Add the deep preset

Use `--deep` when recall matters more than routine scan cost, such as an
incident review or a release gate:

```bash
keyhog scan --deep --git-history . --git-blobs . --daemon=off \
  --format json-envelope --output deep-history.json
```

For a multi-backend installation, calibrate the deep policy before relying on
automatic routing:

```bash
keyhog calibrate-autoroute --policy deep
keyhog config --effective --deep
```

A normal installation already calibrates every preset. Re-run the first command
after changing the binary, host, driver, or routing-relevant configuration. The
second command prints the resolved policy. Record it with benchmark or incident
results.

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

The decode input ceiling is the row with teeth, because the default value sits
BELOW the 1 MiB window the reader hands to the scanner. A window larger than
`--decode-size-limit` is not decoded at all, so nothing Base64, hex, or
URL-encoded inside it is recovered.

Measured on release-fast v0.5.74, one Base64-wrapped AWS key pair at the end of
an otherwise plain text file, default preset:

| File size | Last window | Default | `--deep` |
|---:|---:|---|---|
| 400 KiB | 400 KiB | reports the credential | reports it |
| 510 KiB | 510 KiB | reports the credential | reports it |
| 520 KiB | 520 KiB | reports NOTHING | reports it |
| 600 KiB | 600 KiB | reports NOTHING | reports it |
| 1000 KiB | 1000 KiB | reports NOTHING | reports it |
| 1100 KiB | 204 KiB | reports the credential | reports it |
| 1500 KiB | 604 KiB | reports NOTHING | reports it |
| 2000 KiB | 208 KiB | reports the credential | reports it |

The result looks random in file size and is exact in WINDOW size: the payload
in that table sits at the end of the file, so it lands in the last window, and
it is recovered when that window fits under the limit. Windows are 1 MiB with
128 KiB of overlap, so the last window's size cycles as the file grows, which
is why 1100 KiB succeeds and 1500 KiB does not.

Position, not size, is what governs. Same 2000 KiB file, same bytes, only the
offset of the payload differs: at the end of the file the default preset
reports the credential, and in the middle of the file it reports nothing.
A full-size window is always over the default limit, so the tail is the only
place an encoded payload is reachable at all, and every size in that table is
really measuring how big the tail happened to be. Read the table as a
demonstration, not as a rule you can plan around, and write any regression
fixture with the payload mid-file, where the outcome is the same at every
size.

Two remedies, in order of preference:

```bash
keyhog scan . --decode-size-limit 4M
keyhog scan . --deep
```

Raise the limit when you want only this behavior; `--deep` raises it to 1 MiB
as part of a wider preset. Prefer the explicit flag when you are pinning a
policy, because it changes one setting instead of five.

Do not gate on the exit code here. The skip is reported as a coverage gap
naming `--decode-size-limit`, and that gap is the signal, whether or not the
run also reported findings. A run that reports findings AND the gap is telling
you the truth: some windows were expanded and others were not. See
[file shapes](file-shapes.md) for the same measurement from the
input-shape side.

## Backend routing

Deep is a detection preset. It does not select a backend. The default
`--backend auto` looks up evidence calibrated for the deep preset and the exact
resolved overrides:

```bash
keyhog scan . --deep
keyhog scan . --deep --decode-depth 3
```

Those two scans have different resolved configuration identities. If the second
scan reports an uncovered workload, measure that exact diagnostic shape once,
then return to normal automatic routing:

```bash
keyhog scan . --deep --decode-depth 3 \
  --autoroute-calibrate --autoroute-gpu
keyhog scan . --deep --decode-depth 3
```

Use an explicit backend only to isolate an engine problem:

```bash
keyhog scan . --deep --backend cpu
keyhog scan . --deep --backend simd
keyhog scan . --deep --backend gpu-cuda
keyhog scan . --deep --backend gpu-wgpu
```

An explicit backend bypasses autoroute evidence. It does not repair or calibrate
the deep route. It is a hard contract, so an unavailable SIMD runtime, GPU
driver, or selected GPU peer fails the scan. KeyHog does not silently continue
with another backend. Use `keyhog --version --full` for discovery and
`keyhog backend --self-test --require-gpu` to execute the GPU diagnostic paths.

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

The grammar reads spellings, not one canonical style. Within the XOR and
Node AES rules these are all the same program and all recover:

- `const`, `let`, or `var` for a binding;
- `String.fromCharCode` or `String.fromCodePoint`;
- `Buffer.from(literal, encoding)` or `new Buffer(literal, encoding)`;
- `'aes-256-cbc'` in any case, and `hex`, `base64`, `utf8`, or `utf-8` in any
  case, in single quotes, double quotes, or backticks;
- `.toString()` with no argument, which is Node's UTF-8 default;
- a plain string literal wherever a `[...].join('')` chain is accepted.

What still fails closed is anything the grammar cannot prove is constant: a
binding written to after its declaration, including through an index or a
mutating array method; a template literal containing `${...}` or a backslash
escape; `new Buffer(size)`; any algorithm other than AES-256-CBC; and any
operand that is not a literal. A refused program produces no plaintext, and
the original source stays in the ordinary scan path.

The CryptoJS rule is deliberately stricter and stays at `const` or `let`. It
resolves names through scope analysis rather than the whole-source occurrence
count the other rules use, and `var` hoisting could let a sibling-scope
binding win.

The static evaluator caps source size, literal arrays, binding count, and
expression count. Decode recursion also enforces depth, output-size, expansion,
and total-work budgets. A rejected transform still leaves the original source
available to ordinary detection.

## Read recovery receipts

Deep static recovery and backend recovery are separate. Inspect both from the
metadata-bearing report:

```bash
jq '{
  preset: .metadata.resolved_scan.preset,
  static_recovery: .metadata.static_recovery,
  scan_status,
  backend_recoveries: (.metadata.backend_recoveries // [])
}' deep.json
```

`static_recovery` counts supported, unsupported, and erroneous bounded program
transforms. These counters describe the JavaScript, AES, and CryptoJS evaluator.
They do not mean that a scan backend failed.

`backend_recoveries` records recovery after an authenticated automatic backend
faults. Each row names the failed backend, the backend that completed the stable
bytes, recovered range, chunk, and byte counts, a non-secret reason, and a
repair command. `scan_status: "complete_after_recovery"` means byte coverage is
complete, but the route still needs repair. Missing or invalid autoroute
evidence creates no recovery row; it leaves input unscanned and reports
`scan_status: "partial"`.

Use the receipt to remediate the route:

- Run `keyhog calibrate-autoroute --policy deep` for the standard deep ladder.
- Re-run an exact deep scan once with `--autoroute-calibrate --autoroute-gpu`
  when compatible overrides created an uncovered configuration.
- Run installer calibration for Git, Docker, or web source workloads.
- If a GPU backend faulted, run
  `keyhog backend --self-test --require-gpu`, repair the driver or runtime, and
  recalibrate. Inspect the quarantine with `keyhog backend --autoroute`.
- If SIMD faulted, confirm the running build and Hyperscan/Vectorscan runtime
  with `keyhog --version --full`, repair it, and recalibrate.

Do not replace these repairs with a permanent `--backend cpu` setting. That
would bypass the invalid autoroute state rather than restore measured routing.

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
