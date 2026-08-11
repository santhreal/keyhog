# Configuration

A verified-installer KeyHog release runs with **zero hand-written
configuration**: the installer calibrates every eligible backend, after which
`keyhog scan .` uses the canonical tuned defaults. A freshly built
multi-backend binary must first run `keyhog calibrate-autoroute`; a portable
single-backend build has no routing choice. Everything on this page is an
optional policy override, not a substitute for required autoroute evidence.

## Precedence

KeyHog first chooses the configuration-file layer:

1. `--no-config` skips file discovery and conflicts with `--config`.
2. `--config PATH` selects that file explicitly.
3. Otherwise, KeyHog walks from each scan root toward the filesystem root and
   uses the first `.keyhog.toml` found for that root.

A multi-root scan may use discovery only when every root resolves the same
configuration identity, or when every root resolves no file. Different
repository policies fail before scanning. Pass one `--config PATH`, split the
scan by repository, or use `--no-config`.

After the file layer is chosen, ordinary settings resolve from left to right:

```text
compiled typed default  →  selected .keyhog.toml  →  explicit CLI value
```

A CLI option that you do not pass does not erase the file value. With
`--no-config`, it falls through directly to the compiled default. There is no
system or user configuration-file tier.

Relative paths in `.keyhog.toml` resolve from the directory containing that
file. Relative CLI paths resolve from the caller's working directory. A
malformed `.keyhog.toml`, unknown table or key, invalid value, or unreadable
explicit path fails closed before any scan output is written.

Some detection settings compose rather than use simple replacement. Presets
seed a base before compatible explicit knobs apply. Detector confidence floors,
entropy bands, and BPE ceilings use the field-specific rules in
[How detection works](../detection.md#resolution-rules). The sections below
state the operator-layer precedence for each of those fields.

Detector policy also has explicit provenance. `keyhog explain <detector-id>`
prints fields from the loaded detector TOML. `keyhog config --effective` prints
the resolved scan policy, including whether the BPE ceiling is an explicit
`scan-override` or the compiled `scan-fallback`. During scanning, an eligible
detector's declared BPE ceiling wins over that fallback. An explicit `[scan]`
value wins over detector ceilings, and the CLI value wins over `[scan]`.

The effective view also prints report format, severity floor, dedup scope,
secret visibility, client-safe/test-fixture policy, lockdown, verification
enablement, timeout, concurrency, requests/second, TLS, OOB, and proxy policy.
Proxy URLs are never echoed: `http_proxy` is reported only as `unset`, `off`,
or `configured` so credentials embedded in a proxy URL cannot leak into logs.

## Core settings

This table maps each operator-facing knob to its TOML owner and CLI spelling.
Defaults come from the owning typed configuration (`ScanConfig::default()` for
scanner policy and the corresponding source/system policy type elsewhere).
A dash means that layer intentionally has no surface.

| Setting | Default | `.keyhog.toml` key | CLI flag | Effect |
|---|---|---|---|---|
| Detector corpus | discovered, else embedded | `detectors` | `--detectors` | Select a detector TOML directory. A config-relative path resolves from the config directory; a CLI path resolves from the caller's working directory. |
| Detector composition | replace | `detectors_mode` | `--detectors-mode` | Select one of the modes in the [detector composition table](../detectors.md#custom-detector-corpora). |
| Min confidence | **0.40** | `[scan].min_confidence` | `--min-confidence` | Drop findings scoring below this (0.0-1.0). Bench-tuned for max F1. |
| Decode depth | **10** | `[scan].decode_depth` | `--decode-depth` | Max recursive decode passes, e.g. `base64(hex(url(secret)))` (1-10). A zero value also disables bounded static JavaScript XOR/AES recovery. |
| Decode size limit | **512KB** | `decode_size_limit` | `--decode-size-limit` | Maximum prepared chunk admitted to decode-through. Large files are windowed, so this is not a whole-file limit. |
| Decoded payload validation | on | - | - | Validate decoded payloads (including UTF-8 validity) before recursive scanning. This engine safety policy is always included in `config --effective` and the autoroute identity; it has no public override. |
| Entropy enabled | on | `no_entropy = true` disables | `--no-entropy` | Shannon-entropy detection for novel high-entropy strings. |
| Entropy in source | off | `entropy_source_files` | `--entropy-source-files` | Run entropy inside `.py`/`.js`/`.go`/… (off by default to cut FPs). |
| Entropy threshold | **4.5** | `[scan].entropy_threshold` | `--entropy-threshold` | Scan-wide Shannon-entropy control in bits/byte. It is not a blanket replacement for detector `entropy_low`/`entropy_high`/`entropy_very_high`/length-bucket floors: each entropy detection path composes it with the owning detector's evidence band. For keyword-free admission the exact formula and margin are owned by that detector's TOML and shown by `keyhog explain`. Named-detector heuristic confidence uses this resolved value as its partial entropy tier and the scoring tier 1.3 bits above it as its full tier, so the setting can change confidence without changing regex matches. The byte-entropy domain is `[0.0, 8.0]`; non-finite and out-of-range requests fail closed. |
| BPE word-like bound | **2.2** | `[scan].entropy_bpe_max_bytes_per_token` | `--entropy-bpe-max-bytes-per-token` | With no explicit scan setting, detector TOML `bpe_max_bytes_per_token` wins over this compiled fallback. A `[scan]` value or the CLI flag becomes the visible Tier-A override for every BPE-enabled detector (CLI wins). Invalid, zero, negative, NaN, and infinite bounds fail closed. An eligible candidate above its resolved `cl100k_base` UTF-8 bytes-per-token ceiling is word-like and dropped; detector-owned canonical hex keys and encoded-text evidence bypass this language-likeness gate. Lower = higher precision/lower recall. Detectors for which token efficiency is inappropriate declare `bpe_enabled = false` and skip tokenization. `config --effective` reports `entropy_bpe_policy = scan-override` for explicit scan values and `scan-fallback` otherwise. |
| Entropy min length | **16** | `[scan].min_secret_len` | `--min-secret-len` | Minimum credential length for entropy-discovery candidates. Named detectors keep their own shape-specific length gates. |
| Keyword low-entropy | on | `generic_keyword_low_entropy` | `--no-keyword-low-entropy` | Admit credential-keyword-anchored values (`PASSWORD=`, `*_PASS=`, `secret:` …) on the `generic-keyword-secret` detector's lower floor. Shape/context policy and, when enabled, MoE scoring carry precision. Disabling restores the stricter `generic-secret` floor and can drop real low-randomness credentials. | <!-- keyhog:ignore detector=generic-password -->
| Entropy ML enable | on | - | `--no-entropy-ml-scoring` | Permit each entropy owner's compiled `ml.entropy_mode`. The scan switch can disable detector-owned ML but cannot choose authority. No effect when entropy or ML is disabled. This knob is CLI-only: there is no `.keyhog.toml` key for it, and writing one fails closed as an unknown key. |
| ML enabled | on | `no_ml = true` disables | `--no-ml` | Include the on-device MoE contribution in confidence policy. Disabling it changes which ambiguous candidates clear the resolved floor and makes entropy discovery use its non-ML scoring path. |
| ML weight override | detector policy | `ml_weight` | `--ml-weight` | Explicitly replace every detector TOML's ML scoring weight (`0.0..=1.0`) for diagnostics or controlled benchmarks. |
| Additional scan confidence floor | unset | `[scan].ml_threshold` | `--ml-threshold` | Despite its historical ML-oriented name, the live resolver composes this as `max(scan min_confidence, ml_threshold)`. It therefore tightens every finding that uses the global scan floor; a detector-specific floor still replaces that global floor. |
| Unicode norm | on | `no_unicode_norm = true` disables | `--no-unicode-norm` | Normalise homoglyphs before matching (anti-evasion). |
| Scan comments | off | - | `--scan-comments` | Treat secrets in code comments at full confidence (default downgrades them). |
| Threads | #cores | `[scan].threads` | `--threads` | Parallel scan workers. |
| Reader threads | scan-pool-derived | `[scan].reader_threads` | `--reader-threads` | Dedicated filesystem read workers. |
| Fused batch | `1024` | `[scan].fused_batch` | `--fused-batch` | Maximum chunks per fused filesystem batch; the 1 MiB byte ceiling usually cuts large-input batches first. |
| Fused depth | `0` (rendezvous) | `[scan].fused_depth` | `--fused-depth` | Queued fused filesystem batches. The default keeps no completed batch resident while another is scanned. |
| Per-chunk timeout | off | `[scan].per_chunk_timeout_ms` | `--per-chunk-timeout-ms` | Optional hard deadline per chunk scan in milliseconds. |
| Dedup scope | `credential` | `[scan].dedup` | `--dedup` | `credential` / `file` / `none`. |
| Credential verification | off | `verify` | `--verify` / `--no-verify` | The explicit CLI enable or disable wins over discovered configuration. The Action always passes one of these flags; its default `verify: 'false'` therefore prevents committed configuration from silently enabling credential egress. |
| HTTP verification timeout | `5` seconds | `timeout` | `--timeout` | Per-request verifier deadline; it does not bound scanning. Use `per_chunk_timeout_ms` for the optional scanner chunk deadline. | <!-- keyhog:ignore detector=entropy-token -->
| Verification concurrency | `5` per service | `verify_concurrency` | `--verify-concurrency` | Maximum in-flight verification requests per service; zero is rejected. Distinct from the requests/second limiter. |
| Verification request rate | `5.0` RPS per service | - | `--verify-rate` | Steady-state request-rate ceiling. `--verify-batch` additionally forces concurrency to one. |
| Max file size | 100 MiB | `max_file_size` | `--max-file-size` | Walker skips files larger than this. |
| GPU batch input limit | VRAM-adaptive (128 MiB to 1 GiB) | `[scan].gpu_batch_input_limit` | `--gpu-batch-input-limit` | Sets the CLI coalesced-batch and per-dispatch byte budget and is clamped to 128 MiB through 1 GiB. The pipeline can lower it further to keep its in-flight batches within host RAM headroom. A stricter backend ceiling still wins. Larger literal-presence requests shard between chunks and split an oversized chunk into overlap-preserving physical windows while retaining one logical result row. Retired MegaScan spellings are rejected. |
| Severity floor | (all) | `[scan].severity` | `--severity` | Minimum severity to report: info/client-safe/low/medium/high/critical. |
| Output format | `text` | `[scan].format` | `--format` | text/json/json-envelope/jsonl/jsonl-envelope/sarif/csv/github-annotations/gitlab-sast/html/junit. |
| Show secrets | off | `show_secrets` | `--show-secrets` | Print plaintext credentials. **Never enable in CI/logs.** |
| Incremental cache | off | `[scan].incremental` / `[scan].incremental_cache` | `--incremental` / `--incremental-cache` | BLAKE3 Merkle skip-cache. Trusted clean-file hits count as complete coverage. A run containing only unchanged files skips backend routing and scanner dispatch startup. |
| Hyperscan cache dir | platform cache dir | `[system].cache_dir` | `--cache-dir` | Compiled-database cache directory. Must be an absolute user-owned path under the home directory or per-user keyhog temp cache root. |
| Autoroute cache file | platform cache file | `[system].autoroute_cache` | `--autoroute-cache` | Persisted fastest-correct backend decisions. Use an absolute file path or `off` to disable persistence. Missing, stale, invalid, incomplete, or quarantined evidence selects no backend, leaves the affected batch unscanned, and returns incomplete coverage. |
| MatcherArtifact cache dir | platform cache dir | `[system].matcher_cache` | `--matcher-cache` | Persisted eager compiled matcher graph reused across process invocations. Distinct from Hyperscan `--cache-dir` `.db` shards. Default-on mirrors Hyperscan's local shard cache (unsigned, identity-bound). `--lockdown` disables it. Use an absolute directory or `off` to disable. Identity binds binary, features, detector digest, matcher-relevant config digest, pack generation, backend, and runtime identity; mismatches miss and rebuild. LazyRegex residency is not retained. |
| Bayesian calibration cache | off | `[system].calibration_cache` | `--calibration-cache` | Explicit per-detector confidence calibration file written by `keyhog calibrate`. Missing or damaged explicit files fail closed before scanning. |
| GPU runtime policy | `auto` | `[system].gpu` | `--no-gpu` / `--require-gpu` | `auto` probes when routing can use GPU, `off` skips GPU init, and `required` fails closed when no usable GPU stack is available. Printed by `keyhog config --effective` and included in autoroute scan identity. |
| Low-level calibration GPU control | off | `[system].autoroute_gpu` | `--autoroute-gpu` / `--no-autoroute-gpu` | Applies only to direct `scan --autoroute-calibrate` diagnostics. The canonical `keyhog calibrate-autoroute` command always measures every eligible backend, including GPU. Normal scans only consume persisted evidence. |
| Coalesced batch pipeline | off | `[system].batch_pipeline` | `--batch-pipeline` / `--no-batch-pipeline` | Diagnostic/calibration route that bypasses the fused filesystem pipeline. Printed by `keyhog config --effective` and included in autoroute scan identity. |
| AWS canary issuer extensions | embedded baseline | `[aws].canary_accounts` / `[aws].knockoff_accounts` | - | Extra 12-digit AWS account IDs treated as canary-token issuers during offline access-key metadata classification and verification suppression. |
| Scanner tuning | compiled scanner defaults | `[tuning]` | - | Detection/recall route gates that affect engine work selection. These are explicit config so autoroute calibration identity includes them; ambient `KEYHOG_*` tuning env vars are ignored. |
| Confidence prefixes | embedded scanner set | `known_prefixes` | - | Replace the scan-wide list of credential prefixes that raise confidence. Empty entries fail closed. Prefer detector TOML shape/keyword policy for one secret type. |
| Secret-context keywords | embedded scanner set | `secret_keywords` | - | Replace the scan-wide positive context words used by generic confidence scoring. Empty entries fail closed. |
| Test-context keywords | embedded scanner set | `test_keywords` | - | Replace the scan-wide test/mock context words used by confidence policy. Empty entries fail closed. |
| Placeholder keywords | embedded scanner set | `placeholder_keywords` | - | Replace the scan-wide placeholder markers used by confidence policy. Empty entries fail closed. |
| Backend | `auto` | - | `--backend <BACKEND>` | `auto`, `cpu` (`cpu-fallback`), `simd` (`simd-regex`), `gpu-cuda` (`gpu-cuda-region-presence`), `gpu-metal` (`gpu-metal-region-presence`), or `gpu-wgpu` (`gpu-wgpu-region-presence`). Aliases are accepted spellings of the same backend, not extra routing candidates. CUDA, Metal, and WGPU remain separate measured candidates with distinct route labels and timing evidence. Auto uses a persisted fastest-correct decision for the exact workload bucket; missing, stale, incomplete, or runtime-quarantined state leaves the affected batch unscanned and forces non-success status. |

The scan worker pool is process-global. Repeated in-process scans may reuse the
same resolved width when KeyHog created the pool. A later request for a
different width fails before scanner construction because Rayon cannot resize
an initialized global pool. An externally initialized pool is rejected even at
the requested width because KeyHog cannot attest its stack size, thread names,
or ownership. The actual KeyHog-owned width is included in effective config and
autoroute identity.

Autoroute also distinguishes runtime lifetime. Each GPU calibration record
contains the first real dispatch and warm trials. A normal one-shot scan derives
a cold-aware winner; a ready daemon derives a persistent-runtime winner from
the warm GPU evidence in the same record. These routes may select different
backends without changing detector policy or canonical matches. Options that
the daemon protocol cannot represent (custom detector/config policy, explicit
backend/GPU controls, source modes, verification, and similar orchestration)
stay in process under `--daemon=auto` and fail explicitly under `--daemon=on`.

## Source limits

Source byte/count ceilings resolve through the same precedence chain:
compiled `SourceLimits::default()` → `.keyhog.toml` `[limits]` → CLI
`--limit-*` flags.

| Limit | Default | `.keyhog.toml` key | CLI flag |
|---|---:|---|---|
| Stdin bytes | 10 MiB | `[limits].stdin_bytes` | `--limit-stdin-bytes` |
| Web response bytes | 10 MiB | `[limits].web_response_bytes` | `--limit-web-response-bytes` |
| S3 object bytes | 10 MiB | `[limits].s3_object_bytes` | `--limit-s3-object-bytes` |
| GCS object bytes | 10 MiB | `[limits].gcs_object_bytes` | `--limit-gcs-object-bytes` |
| Azure blob bytes | 10 MiB | `[limits].azure_blob_bytes` | `--limit-azure-blob-bytes` |
| Cloud listed objects | 100000 | `[limits].cloud_max_objects` | `--limit-cloud-max-objects` |
| Docker tar entry bytes | 128 MiB | `[limits].docker_tar_entry_bytes` | `--limit-docker-tar-entry-bytes` |
| Docker config/manifest bytes | 16 MiB | `[limits].docker_image_config_bytes` | `--limit-docker-image-config-bytes` |
| Docker tar total bytes | 8 GiB | `[limits].docker_tar_total_bytes` | `--limit-docker-tar-total-bytes` |
| Git stdout line bytes | 10 MiB | `[limits].git_line_bytes` | `--limit-git-line-bytes` |
| Git aggregate or hosted-clone materialized bytes | 256 MiB | `[limits].git_total_bytes` | `--limit-git-total-bytes` |
| Git blob bytes | 10 MiB | `[limits].git_blob_bytes` | `--limit-git-blob-bytes` |
| Git emitted chunks or hosted-clone entries | 500000 | `[limits].git_chunks` | `--limit-git-chunks` |
| Hosted-git listing pages or GitHub collaboration API requests | 1000 | `[limits].hosted_git_pages` | `--limit-hosted-git-pages` |
| Binary strings bytes | 64 MiB | `[limits].binary_read_bytes` | `--limit-binary-read-bytes` |
| Ghidra output bytes | 50 MiB | `[limits].binary_decompiled_bytes` | `--limit-binary-decompiled-bytes` |

Every one of these caps is exact and inclusive. A cap of `N` bytes admits an
input of exactly `N` bytes and refuses `N + 1`. A cap of `N` items admits
exactly `N` items.

```console
$ printf 'x%.0s' $(seq 1024) | keyhog scan --stdin --limit-stdin-bytes 1024B
$ printf 'x%.0s' $(seq 1024) | keyhog scan --stdin --limit-stdin-bytes 1023B
error: stdin exceeds 1023 byte limit
```

### Which source honors which limit

A limit belongs to one source class. `--limit-git-blob-bytes` does not bound a
cloud object, and `--max-file-size` does not bound a git blob. Set the cap that
matches the input you are scanning.

| Limit | Applies to |
|---|---|
| `--max-file-size` | Filesystem files, and every member extracted from an archive, compressed stream, or document on the filesystem |
| `--limit-stdin-bytes` | `--stdin` only |
| `--limit-web-response-bytes` | `--url` responses, and every cloud and hosted-git API response body (listings included) |
| `--limit-s3-object-bytes` / `--limit-gcs-object-bytes` / `--limit-azure-blob-bytes` | One object body from that store |
| `--limit-cloud-max-objects` | Objects listed from one S3, GCS, or Azure container |
| `--limit-docker-tar-entry-bytes` | One entry in the image tar or in any layer tar |
| `--limit-docker-image-config-bytes` | Image config, manifest, and index JSON |
| `--limit-docker-tar-total-bytes` | Cumulative unpacked bytes for the WHOLE image, summed across the image tar and every layer tar. A budget that covers the largest layer is not enough if the layers together exceed it |
| `--limit-git-line-bytes` | One line of git plumbing output, counting the line and not its newline |
| `--limit-git-total-bytes` | Aggregate bytes a `--git-history`, `--git-diff`, or `--git-staged` scan emits. Checked between chunks, so the last chunk may carry the total past the budget |
| `--limit-git-blob-bytes` | One blob object under `--git-blobs` and `--git-staged`. Under `--git-history` and `--git-diff` the same value is the flush size for one diff hunk, so lowering it splits chunks instead of dropping content |
| `--limit-git-chunks` | Chunks a history, diff, or staged scan emits |
| `--limit-hosted-git-pages` | Listing pages per GitHub org, GitLab group, Bitbucket workspace, or Slack channel walk |
| `--limit-binary-read-bytes` | Bytes read from one binary for strings extraction under `--binary` |
| `--limit-binary-decompiled-bytes` | Ghidra decompiled output accepted for parsing |

Two derived caps have no flag and follow `--max-file-size`. Archive and
compressed-stream extraction stops at four times the per-file cap, so the
default 100 MiB file cap allows 400 MiB of expansion per container. A CRX
package additionally refuses any entry whose compression ratio exceeds 1000.

### What you see when a limit is exceeded

Exceeding a limit is never silent. Input a cap excluded is recorded as a
coverage gap, not dropped, because a scan that quietly read less than you asked
for reports a clean that was never measured.

You get, in every case: a `WARN` naming the input, its measured size, and the
cap; a source error row in the report; and a non-zero exit. When the cap
excluded every requested input, the run refuses to report a result at all.

```console
$ keyhog scan --git-blobs . --limit-git-blob-bytes 64B
WARN git blob exceeds the per-blob size cap; NOT scanned oid=037d4125 size=65 cap=64
WARN source: failed to access git source: git blob 037d4125 at c1.txt exceeds
     per-blob size cap (65 bytes > 64 bytes); blob was not scanned
FAIL 2 source error row(s) emitted: requested input was NOT fully scanned.
```

A count of zero is refused up front rather than accepted as a scan of nothing.
`--limit-cloud-max-objects 0`, `--limit-git-chunks 0`, and
`--limit-hosted-git-pages 0` all fail at argument parsing.

A hosted-git listing that does not fit its page budget is the one case that
refuses even a partial result. Repositories the listing never reached would
otherwise be reported clean, so the whole source fails instead.

### Availability in this build

Each limit needs its source backend compiled in. `keyhog config --effective`
lists every limit on every build, and marks the ones this binary cannot reach:

```console
$ keyhog config --effective | grep limit_binary
limit_binary_read_bytes = unavailable (requires the `binary` feature in this keyhog build)
limit_binary_decompiled_bytes = unavailable (requires the `binary` feature in this keyhog build)
```

An unavailable limit has no CLI flag, and its `.keyhog.toml` key is rejected
with the same feature name rather than accepted and ignored.

> Library note: `ScanConfig::max_file_size` and `ScanConfig::dedup` are scan
> pipeline settings, not regex-engine settings. The CLI applies them through
> the filesystem source and final deduplication stage; `FilesystemSource::new`
> uses the same `DEFAULT_MAX_FILE_SIZE_BYTES` as `ScanConfig::default()` so the
> shipped default cannot drift.

## Presets

| Preset | TOML | CLI | What it does |
|---|---|---|---|
| Fast | `fast = true` | `--fast` | Keeps named regex and multiline detection, but disables recursive decode, entropy discovery, and ML scoring. This is the widest recall tradeoff and is refused under `--lockdown`. |
| Deep | `deep = true` | `--deep` | Enables source-file entropy, keeps heuristic evidence instead of an ML-only entropy veto, removes comment confidence penalties, sets decode depth 10, raises prepared decode-chunk admission to 1 MiB, and keeps the 0.40 floor. |
| Precision | `precision = true` | `--precision` | Disables entropy discovery and the relaxed keyword-low-entropy bridge, keeps ML enabled, sets decode depth 1, and clamps global and detector confidence floors to at least **0.85**. |

`--fast`, `--deep`, and `--precision` are scan presets. They are mutually
exclusive and conflict with `--no-decode` and `--no-entropy`.

A preset seeds a base. Compatible explicit options then refine that base. For
example, `--deep --decode-depth 3` uses the deep preset with decode depth 3, and
`--deep --min-confidence 0.9` raises its confidence floor. Two refinements are
one-directional. Under `--precision`, `--min-confidence` may raise the 0.85
floor but cannot lower it. A preset that disables the relaxed keyword floor
cannot be used with a flag that assumes that path is active.

`--lockdown` is not a fourth preset. It is a Linux-only, fail-closed execution
security mode and may be required by `[lockdown] require = true`; that config
key does not enable it. Lockdown refuses fast and other
completeness-reducing switches, and the scan remains in process.

`--profile` is not a named configuration profile. It emits low-overhead fixed
scanner-stage timings and one causal operator-run record to standard error. The
record names the source, workload, backend, cache, thread configuration, input
totals, run states, CPU time, memory, observed process threads, exact binary
SHA-256, enabled-feature SHA-256, target triple, build profile, compiler,
allocator, linked-backend SHA-256, detector-corpus SHA-256,
enabled-detector BLAKE3, compiled-plan BLAKE3, hashed detector provenance,
complete resolved-configuration BLAKE3, performance-policy BLAKE3, preset,
applied protection state, source adapters, hashed source-target BLAKE3,
hashed source-partition BLAKE3, raw source bytes, source-unit fanout,
decode-derived bytes, completed backend-dispatch bytes, and stable size/fanout
buckets. Byte domains that their source adapter cannot yet distinguish remain
explicitly unavailable instead of becoming measured zeroes. It never includes
source content, credential values, raw paths, raw URLs, or raw configuration
values. Use `--perf-trace` when you need the higher-overhead per-pattern and
backend diagnostic counters. Neither flag selects the fast, deep, or precision
preset.

## Policy tables

Each setting has one TOML owner. The main reporting, entropy, routing-identity,
and worker settings live under `[scan]`; the core-settings table above names
the few canonical root keys (presets, verification, decode/ML switches, and
scan-wide keyword lists). Other tables own source, detector, system, and
security policy. Unknown keys and retired duplicate spellings fail closed.
When migrating an older file, move the retired flat scan keys named by the
parser under `[scan]` and rename `exclude_paths` to `[scan].exclude`.

### `detectors` and `detectors_mode`

The corpus path and composition mode are two independently resolved settings.
Each follows the ordinary default, file, then CLI precedence. Their composition
semantics are defined once in [Detectors](../detectors.md#custom-detector-corpora).

```toml
# /srv/acme/app/.keyhog.toml
detectors = "keyhog-detectors"
detectors_mode = "overlay"
```

The file above selects `/srv/acme/app/keyhog-detectors`, regardless of the
caller's working directory:

```sh
keyhog scan /srv/acme/app --config /srv/acme/app/.keyhog.toml
```

A CLI path overrides only the path. If the file still supplies `overlay`, that
mode applies to the CLI directory. Override both settings when you want a full
replacement:

```sh
keyhog scan /srv/acme/app \
  --config /srv/acme/app/.keyhog.toml \
  --detectors /opt/acme/keyhog-detectors \
  --detectors-mode replace
```

If neither the file nor CLI supplies a mode, a selected directory uses
`replace`. A mode without a detector path in either layer is an error. A
missing, non-directory, empty, or invalid explicit corpus is also an error.
Overlay ID collisions fail before scanning. None of these errors falls back to
the embedded corpus.

### `[scan]`

The canonical owner for scan execution and reporting policy. This includes
`severity`, `min_confidence`, `ml_threshold`, `decode_depth`, entropy policy,
`format`, `exclude`, worker and fused-pipeline sizing, chunk timeout, dedup,
incremental scanning, and the GPU batch-input limit.

```toml
[scan]
severity = "high"
min_confidence = 0.40       # raise toward 0.85 for fewer false positives
decode_depth = 10           # 1-10, same ceiling as --decode-depth
exclude = ["**/test/fixtures/**", "vendor/"]
threads = 8
reader_threads = 2
fused_batch = 1024
fused_depth = 0
per_chunk_timeout_ms = 30000
```

### `[detector.<id>]`: per-detector overrides

Apply an override to the exact ID shown by `keyhog detectors` or `keyhog explain
<id>`:

```toml
[detector.generic-api-key]
enabled = false

[detector.twilio-api-key]
min_confidence = 0.6
```

`enabled = false` removes the matching detector after replace or overlay
composition and before scanner compilation. Detectors that `require` it are
removed transitively. Surviving `conflicts` and `subsumes` relations to it are
pruned. The override cannot restore a detector absent from a replacement
corpus. An unknown ID produces a warning. Disabling every loaded detector,
including dependency removals, fails before scanning.

A detector confidence floor resolves in this order:

1. `[scan].min_confidence` supplies the global floor.
2. `[detector] min_confidence` in the active detector TOML replaces the global
   floor for that detector.
3. `.keyhog.toml` `[detector.<id>] min_confidence` replaces the detector's
   declared floor.
4. The precision preset clamps the resolved global and detector floors to at
   least 0.85.

There is no CLI per-detector override. A scan-wide `--min-confidence` changes
the global floor but does not replace a detector-specific floor. Shipped
availability and detector floors have no hidden Rust override list.

### `[lockdown]`

```toml
[lockdown]
require = true              # refuse to run unless --lockdown is passed
```

A repo that demands hardened scanning sets this so a plain `keyhog scan`
**fails closed** instead of silently running unhardened. See
the [`scan --help` output](./cli.md) for the current `--lockdown` checks.

### `[system]`

```toml
[system]
trusted_bin_dirs = ["/nix/store/example-system-bin/bin"]
cache_dir = "/home/alice/.cache/keyhog"
autoroute_cache = "/home/alice/.cache/keyhog/autoroute.json"
matcher_cache = "/home/alice/.cache/keyhog-matcher-artifacts"
calibration_cache = "/home/alice/.cache/keyhog/calibration.json"
gpu = "auto"
autoroute_gpu = false
batch_pipeline = false
```

`trusted_bin_dirs` extends the absolute directory allowlist used for external
binaries such as `git` and `docker`. This is for Nix/Guix or other
non-standard install roots. Relative paths are rejected because the trust
boundary must not depend on the process working directory.

`cache_dir` overrides the Hyperscan compiled-database cache directory. It uses
the same precedence as scan flags: compiled platform default, then TOML, then
`--cache-dir`. Relative paths, symlinks, paths outside the user's home or the
per-user keyhog temp cache root, and paths owned by another user fail closed.

`autoroute_cache` overrides the persisted autoroute calibration evidence file.
It uses the same precedence as scan flags: compiled platform default, then TOML,
then `--autoroute-cache`. The value must be an absolute file path or `off`.
The cache path is printed by `keyhog config --effective`; it is storage
configuration, not part of the scan identity digest.

`matcher_cache` overrides the MatcherArtifact cache directory used to reuse the eager compiled matcher graph across process invocations. This is not the Hyperscan `--cache-dir` database cache: a directory that only contains `hs-*.db` shards still pays the detector-spec compile floor. When unset, KeyHog defaults to `dirs::cache_dir()/keyhog-matcher-artifacts` (sibling of the Hyperscan `keyhog/` cache root so lockdown's past-findings audit of `<cache>/keyhog` is not tripped by matcher graphs). Pass an absolute directory or `off`. The trust model matches Hyperscan `.db` shards: the artifact is unsigned local state bound by binary/config/detector digests under a uid-owned allowlisted path; `--lockdown` disables MatcherArtifact entirely rather than reading unsigned detector graphs. The cache key binds binary identity, target/features, detector corpus digest, matcher-relevant config digest (scanner tuning / disabled detectors / confidence floors / regex DFA limit - not thread counts, exclude paths, or volatile cache locations), pack/generation identity when packs apply, and backend-relevant runtime identity. A mismatch misses and rebuilds; a foreign matcher is never served. LazyRegex programs remain compile-on-first-use, so peak RSS stays near the MemoryFootprint baseline rather than retaining every detector regex.

`calibration_cache` opts a scan into per-detector Bayesian confidence
calibration written by `keyhog calibrate`. The scanner never reads the default
calibration file implicitly. The value must be an absolute file path in TOML;
missing, unreadable, corrupt, or schema-incompatible explicit files fail closed
before scanning. The resolved path, entry count, and digest are printed by
`keyhog config --effective`.

`gpu` resolves GPU init policy. `auto` leaves GPU available to autoroute and
explicit GPU backends, `off` behaves like `--no-gpu`, and `required` behaves
like `--require-gpu`. The resolved value is printed by
`keyhog config --effective` and is part of the autoroute scan identity.

`autoroute_gpu` is a low-level control for direct
`scan --autoroute-calibrate` diagnostics. The supported maintenance command,
`keyhog calibrate-autoroute`, always supplies GPU candidate admission so every
eligible backend is a peer. Normal scans do not hash or benchmark from this
value; they consume persisted fastest-correct decisions. A direct calibration
that excludes an otherwise eligible GPU is stored under a diagnostic-only
config identity, so its incomplete candidate set cannot replace normal
all-candidate evidence. A calibration with GPU disabled by the resolved runtime
policy shares the matching CPU-only scan identity.

`batch_pipeline` forces the coalesced batch pipeline. Leave it `false` for the
default fused filesystem route; set it only for calibration, diagnostics, or
pipeline parity checks. The resolved value is printed by
`keyhog config --effective` and is part of the autoroute scan identity.

### `[http]`

```toml
[http]
proxy = "off"
insecure_tls = false
allow_private_endpoint = false
```

`proxy` is an explicit outbound proxy URL or `off`; ambient proxy environment
variables are ignored. `insecure_tls` disables certificate validation for
outbound HTTP and should be limited to controlled interception environments.
`allow_private_endpoint` permits cloud source endpoints that resolve to private,
loopback, link-local, or metadata addresses; it is off by default to preserve
the SSRF boundary. CLI flags override these values. All three settings are
operator-visible and never enabled by an ambient environment variable.

### `[aws]`

```toml
[aws]
canary_accounts = ["609629065308"]
knockoff_accounts = ["000000000001"]
```

`canary_accounts` and `knockoff_accounts` extend the embedded AWS canary-token
issuer baseline used by offline access-key metadata. Each entry must be a
12-digit AWS account ID. Invalid IDs fail closed as configuration errors.
Configured accounts are part of the resolved scan config, `keyhog config
--effective` prints their count, and daemon scans route in-process because a
running daemon cannot consume client-local `[aws]` config.

### `[tuning]`

```toml
[tuning]
fallback_hs = true
hs_prefilter_max_len = 4096
hs_shard_target = 320
fallback_anchor = true
homoglyph_gate = true
homoglyph_ascii_skip = true
fallback_reverse = false
prefilter_truncate = true
fallback_prefix_gate = false
decode_focus = true
confirmed_suffix_gate = true
confirmed_companion_gate = true
no_candidate_gate = true
fallback_localizer = true
gpu_recall_floor = false
chunk_lane_threshold = 65536
```

These keys tune scanner-internal detection and recall route gates. They are
operator-visible resolved config, included in the autoroute config digest, and
printed by `keyhog config --effective`. They do not have CLI flags because
per-run hidden recall changes would invalidate installer calibration.
`hs_shard_target` controls Hyperscan patterns-per-shard during compile; changing
it affects compile/cache shape and autoroute identity but not detector recall.
`confirmed_companion_gate` skips confirmed patterns whose required mid-literals
are all absent in the chunk (recall-identical to running those patterns cold).
`fallback_localizer` moves plain phase-two candidates to one ASCII anchor index.
It is enabled by default, which avoids compiling and scanning the full portable
phase-two marking set when the anchor index can localize candidates. Autoroute
still measures both settings because the faster route depends on the workload.
Each setting creates a distinct autoroute configuration that must be calibrated
before automatic use.
`gpu_recall_floor` forces the VYRE region-presence path to compute the full CPU
trigger net during parity/debug scans and report any GPU under-fire it recovers.
Authenticated GPU routes score eligible candidates through a separate bounded
quantized VYRE program. CPU and SIMD use the same fixed-point model, while
CPU-owned rows and the shared confidence-policy tail remain on the CPU.
`chunk_lane_threshold` sets the byte boundary between coalesced small-chunk
lanes and independently scheduled large chunks. It accepts values from
`ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MIN` through
`ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MAX`, currently 1 through one less
than the platform `usize` maximum. Zero and the platform maximum fail closed as
configuration errors. The default is 65536 bytes.

### `[allowlist]`

`file` selects the line-based allowlist file (default `.keyhogignore` at the
scan root). `require_reason`, `require_approved_by`, and `max_expires_days`
enforce governance before any suppression is active. Missing required metadata,
expired entries, malformed entries, or expiry windows beyond the configured
limit fail closed with an operator-visible config error. See
[Suppressions](../suppressions.md).

### `[guard]`

The guard section configures the perpetual repository and filesystem guard
runtime. See [Guard workflow](../workflows/guard.md) for operational details.

| Key | Type | Default | Description |
|---|---|---|---|
| `hot_index_memory` | string | unlimited | Hot clean attestation index memory budget (e.g. `64MiB`). |
| `max_pending_events_per_root` | integer | 8192 | Maximum queued filesystem events per root. |
| `coalesce_window` | string | 100ms | Event coalescing window before applying state transitions. |
| `scanner_idle_timeout` | string | 5m | Scanner idle-unload timeout. After this duration without guard activity, the residency label reports `idle-unload`. |
| `scrub_interval` | string | disabled | Periodic re-scan interval for `current` roots. Catches changes that filesystem events missed. |
| `state_path` | string | disabled | Durable guard state path (e.g. `~/.local/state/keyhog/guard.redb`). Persists root records and attestations across daemon restarts. Rejected in lockdown mode. |
| `subtree_max_files` | integer | 10000 | Maximum files for one subtree reconciliation. |
| `subtree_max_depth` | integer | 64 | Maximum depth for one subtree reconciliation. |

## Where the numbers live

- Canonical detection defaults: `crates/core/src/config.rs`
  (`ScanConfig::default`).
- Scanner route tuning defaults: `crates/scanner/src/scanner_config.rs`
  (`ScannerTuningConfig`).
- TOML schema + merge precedence: `crates/cli/src/config.rs`
  (`ConfigFile`, `apply_config_file`).
- The resolved struct the live scanner reads (defaults + file + flags folded
  into one): `crates/cli/src/orchestrator_config.rs`
  (`resolve_scan_config` → `ResolvedScanConfig`). The scanner, router,
  reporter, and verifier consume that resolved policy rather than independently
  re-reading raw arguments.
