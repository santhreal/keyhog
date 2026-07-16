# Configuration

A verified-installer KeyHog release runs with **zero hand-written
configuration**: the installer calibrates every eligible backend, after which
`keyhog scan .` uses the canonical tuned defaults. A freshly built
multi-backend binary must first run `keyhog calibrate-autoroute`; a portable
single-backend build has no routing choice. Everything on this page is an
optional policy override, not a substitute for required autoroute evidence.

## Precedence

Settings resolve in this order, rightmost winning:

```text
compiled defaults  →  .keyhog.toml  →  CLI flags
(ScanConfig::default)  (walked up from    (always win)
                        the scan path)
```

- **Compiled defaults** are typed at their owning boundary. Detection defaults
  live in `ScanConfig::default()`; source limits, verifier policy, runtime
  workers, and scanner tuning have their own typed defaults. The effective
  resolver folds those owners into one `ResolvedScanConfig`, and behavioral
  tests pin the operator-visible result.
- **`.keyhog.toml`** is discovered by walking up from the scan path to the
  filesystem root (first one found wins). Copy
  [`.keyhog.toml.example`](https://github.com/santhreal/keyhog/blob/main/.keyhog.toml.example)
  to your repo root and delete what you don't need. A malformed `.keyhog.toml`
  fails closed with the path and TOML error before any scan output is written.
  Unknown tables and keys are parse failures, not ignored compatibility shims.
  Use `--no-config` when you intentionally want compiled defaults.
  A multi-root scan may use automatic discovery only when every root resolves
  the same config identity (or every root resolves none). If roots belong to
  repositories with different policies, KeyHog fails before scanning; pass one
  explicit `--config PATH`, split the scan by repository, or use `--no-config`.
- **CLI flags** always override the file. A flag left unset falls through to
  the file, then to the compiled default.

There is no separate system/user config tier today: the walk-up `.keyhog.toml`
is the only file layer.

Detector policy has a separate, explicit provenance. `keyhog explain
<detector-id>` prints fields declared by the loaded detector TOML and labels
unset optional fields as unresolved there: detector-field defaults or scan
policy apply only at scan time. `keyhog config --effective` is the scan-level
view and reports whether the BPE ceiling came from an explicit `scan-override`
or the compiled `scan-fallback`. During scanning, an eligible detector's
declared BPE ceiling wins over that fallback, while an explicit scan override
wins over every eligible detector ceiling.

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
| Detector corpus | embedded | `detectors` | `--detectors` | Select the complete detector TOML directory. A config-relative path resolves from the config directory; a CLI path resolves from the caller's working directory. |
| Min confidence | **0.40** | `[scan].min_confidence` | `--min-confidence` | Drop findings scoring below this (0.0-1.0). Bench-tuned for max F1. |
| Decode depth | **10** | `[scan].decode_depth` | `--decode-depth` | Max recursive decode passes, e.g. `base64(hex(url(secret)))` (1-10). A zero value also disables bounded static JavaScript XOR/AES recovery. |
| Decode size limit | **512KB** | `decode_size_limit` | `--decode-size-limit` | Maximum prepared chunk admitted to decode-through. Large files are windowed, so this is not a whole-file limit. |
| Decoded payload validation | on | - | - | Validate decoded payloads (including UTF-8 validity) before recursive scanning. This engine safety policy is always included in `config --effective` and the autoroute identity; it has no public override. |
| Entropy enabled | on | `no_entropy = true` disables | `--no-entropy` | Shannon-entropy detection for novel high-entropy strings. |
| Entropy in source | off | `entropy_source_files` | `--entropy-source-files` | Run entropy inside `.py`/`.js`/`.go`/… (off by default to cut FPs). |
| Entropy threshold | **4.5** | `[scan].entropy_threshold` | `--entropy-threshold` | Scan-wide Shannon-entropy control in bits/byte. It is not a blanket replacement for detector `entropy_low`/`entropy_high`/`entropy_very_high`/length-bucket floors: each detection path composes it with the owning detector's evidence band. The byte-entropy domain is `[0.0, 8.0]`; non-finite and out-of-range requests fail closed. |
| BPE word-like bound | **2.2** | `[scan].entropy_bpe_max_bytes_per_token` | `--entropy-bpe-max-bytes-per-token` | With no explicit scan setting, detector TOML `bpe_max_bytes_per_token` wins over this compiled fallback. A `[scan]` value or the CLI flag becomes the visible Tier-A override for every BPE-enabled detector (CLI wins). Invalid, zero, negative, NaN, and infinite bounds fail closed. An eligible candidate above its resolved `cl100k_base` UTF-8 bytes-per-token ceiling is word-like and dropped; detector-owned canonical hex keys and encoded-text evidence bypass this language-likeness gate. Lower = higher precision/lower recall. Detectors for which token efficiency is inappropriate declare `bpe_enabled = false` and skip tokenization. `config --effective` reports `entropy_bpe_policy = scan-override` for explicit scan values and `scan-fallback` otherwise. |
| Entropy min length | **16** | `[scan].min_secret_len` | `--min-secret-len` | Minimum credential length for entropy-discovery candidates. Named detectors keep their own shape-specific length gates. |
| Keyword low-entropy | on | `generic_keyword_low_entropy` | `--no-keyword-low-entropy` | Admit credential-keyword-anchored values (`PASSWORD=`, `*_PASS=`, `secret:` …) on the `generic-keyword-secret` detector's lower floor. Shape/context policy and, when enabled, MoE scoring carry precision. Disabling restores the stricter `generic-secret` floor and can drop real low-randomness credentials. |
| Entropy ML enable | on | `no_entropy_ml_scoring = true` disables | `--no-entropy-ml-scoring` | Permit each entropy owner's compiled `ml.entropy_mode`. The scan switch can disable detector-owned ML but cannot choose authority. No effect when entropy or ML is disabled. |
| ML enabled | on | `no_ml = true` disables | `--no-ml` | Include the on-device MoE contribution in confidence policy. Disabling it changes which ambiguous candidates clear the resolved floor and makes entropy discovery use its non-ML scoring path. |
| ML weight override | detector policy | `ml_weight` | `--ml-weight` | Explicitly replace every detector TOML's ML scoring weight (`0.0..=1.0`) for diagnostics or controlled benchmarks. |
| Additional scan confidence floor | unset | `[scan].ml_threshold` | `--ml-threshold` | Despite its historical ML-oriented name, the live resolver composes this as `max(scan min_confidence, ml_threshold)`. It therefore tightens every finding that uses the global scan floor; a detector-specific floor still replaces that global floor. |
| Unicode norm | on | `no_unicode_norm = true` disables | `--no-unicode-norm` | Normalise homoglyphs before matching (anti-evasion). |
| Scan comments | off | - | `--scan-comments` | Treat secrets in code comments at full confidence (default downgrades them). |
| Threads | #cores | `[scan].threads` | `--threads` | Parallel scan workers. |
| Reader threads | scan-pool-derived | `[scan].reader_threads` | `--reader-threads` | Dedicated filesystem read workers. |
| Fused batch | `32` | `[scan].fused_batch` | `--fused-batch` | Chunk batch size for the fused filesystem pipeline. |
| Fused depth | worker-count-derived | `[scan].fused_depth` | `--fused-depth` | Bounded channel depth for fused filesystem batches. |
| Per-chunk timeout | off | `[scan].per_chunk_timeout_ms` | `--per-chunk-timeout-ms` | Optional hard deadline per chunk scan in milliseconds. |
| Dedup scope | `credential` | `[scan].dedup` | `--dedup` | `credential` / `file` / `none`. |
| HTTP verification timeout | `5` seconds | `timeout` | `--timeout` | Per-request verifier deadline; it does not bound scanning. Use `per_chunk_timeout_ms` for the optional scanner chunk deadline. |
| Verification concurrency | `5` per service | `verify_concurrency` | `--verify-concurrency` | Maximum in-flight verification requests per service; zero is rejected. Distinct from the requests/second limiter. |
| Verification request rate | `5.0` RPS per service | - | `--verify-rate` | Steady-state request-rate ceiling. `--verify-batch` additionally forces concurrency to one. |
| Max file size | 100 MiB | `max_file_size` | `--max-file-size` | Walker skips files larger than this. |
| GPU batch input limit | VRAM-adaptive (128 MiB to 1 GiB) | `[scan].gpu_batch_input_limit` | `--gpu-batch-input-limit` | Sets the CLI coalesced-batch and per-dispatch byte budget and is clamped to 128 MiB through 1 GiB. The pipeline can lower it further to keep its in-flight batches within host RAM headroom. A stricter backend ceiling still wins. Larger literal-presence requests shard between chunks and split an oversized chunk into overlap-preserving physical windows while retaining one logical result row. Retired MegaScan spellings are rejected. |
| Severity floor | (all) | `[scan].severity` | `--severity` | Minimum severity to report: info/client-safe/low/medium/high/critical. |
| Output format | `text` | `[scan].format` | `--format` | text/json/json-envelope/jsonl/jsonl-envelope/sarif/csv/github-annotations/gitlab-sast/html/junit. |
| Show secrets | off | `show_secrets` | `--show-secrets` | Print plaintext credentials. **Never enable in CI/logs.** |
| Incremental cache | off | `[scan].incremental` / `[scan].incremental_cache` | `--incremental` / `--incremental-cache` | BLAKE3 Merkle skip-cache; 10-100× on CI re-runs. |
| Hyperscan cache dir | platform cache dir | `[system].cache_dir` | `--cache-dir` | Compiled-database cache directory. Must be an absolute user-owned path under the home directory or per-user keyhog temp cache root. |
| Autoroute cache file | platform cache file | `[system].autoroute_cache` | `--autoroute-cache` | Persisted fastest-correct backend decisions. Use an absolute file path or `off` to disable persistence and force auto-route cache misses to fail loudly. |
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
| Backend | `auto` | - | `--backend <BACKEND>` | `auto`, `cpu` (`cpu-fallback`), `simd` (`simd-regex`), `gpu-cuda` (`gpu-cuda-region-presence`), or `gpu-wgpu` (`gpu-wgpu-region-presence`). Aliases are accepted spellings of the same backend, not extra routing candidates. CUDA and WGPU remain separate measured candidates with distinct route labels and timing evidence. Auto uses a persisted fastest-correct decision for the exact workload bucket; missing, stale, or incomplete calibration is an error. |

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

> Library note: `ScanConfig::max_file_size` and `ScanConfig::dedup` are scan
> pipeline settings, not regex-engine settings. The CLI applies them through
> the filesystem source and final deduplication stage; `FilesystemSource::new`
> uses the same `DEFAULT_MAX_FILE_SIZE_BYTES` as `ScanConfig::default()` so the
> shipped default cannot drift.

## Presets

| Preset | TOML | CLI | What it does |
|---|---|---|---|
| Fast | `fast = true` | `--fast` | Disables decode recursion (`max_decode_depth = 0`), entropy discovery, and ML scoring. Named regex and multiline detection remain active. Refused under `--lockdown`. |
| Deep | `deep = true` | `--deep` | Enables entropy and ML, keeps heuristic evidence instead of an ML-only entropy veto, scans source-file entropy, removes comment confidence penalties, sets depth 10, and raises decode-through to one 1 MiB chunk. It keeps the 0.40 floor. |
| Precision | `precision = true` | `--precision` | Disables entropy discovery and the relaxed keyword-low-entropy bridge, keeps ML enabled, sets decode depth 1, and clamps global and detector confidence floors to at least **0.85**. |

`--fast`, `--deep`, and `--precision` are mutually exclusive and conflict with
`--no-decode`/`--no-entropy`.

**A preset is a BASE, not a terminal state.** It seeds the decode/entropy/ML
defaults, then any explicit knob you pass on the same command line **overrides**
that base; `--deep --decode-depth 3` runs the deep base at decode-depth 3, and
`--deep --min-confidence 0.9` raises the floor on the deep base. Two overrides
are one-directional and cannot weaken a precision bar: under `--precision`,
`--min-confidence` may *raise* the 0.85 floor but never lower it, and
`--no-keyword-low-entropy` can only *disable* the relaxed keyword floor, never
re-enable it under a preset that turned it off. Everything else takes effect as
written.

## Policy tables

Each setting has one TOML owner. The main reporting, entropy, routing-identity,
and worker settings live under `[scan]`; the core-settings table above names
the few canonical root keys (presets, verification, decode/ML switches, and
scan-wide keyword lists). Other tables own source, detector, system, and
security policy. Unknown keys and retired duplicate spellings fail closed.
When migrating an older file, move the retired flat scan keys named by the
parser under `[scan]` and rename `exclude_paths` to `[scan].exclude`.

### `detectors`

The root `detectors = "path"` key selects the complete detector TOML corpus.
Relative paths resolve from the directory containing the loaded config file,
so the same repository policy is independent of the caller's working
directory. An explicit `--detectors PATH` takes precedence. This key selects a
corpus; it does not overlay files onto the embedded detector set.

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
fused_batch = 32
fused_depth = 4
per_chunk_timeout_ms = 30000
```

### `[detector.<id>]`: per-detector overrides

Keyed by detector id (`keyhog detectors` lists them; `keyhog explain <id>`
shows one):

```toml
[detector.generic-api-key]
enabled = false             # drop this detector from the corpus entirely

[detector.twilio-api-key]
min_confidence = 0.6        # per-detector floor, OVERRIDES the global one
```

There are **two** per-detector floor sources, in increasing precedence:

1. **Tier-B**: `min_confidence` inside the detector's own TOML under
   `detectors/<id>.toml` (`[detector] min_confidence`). The detector's
   shipped baseline.
2. **`.keyhog.toml` `[detector.<id>] min_confidence`**: validated operator
   intent; overrides the detector floor for that id and is compiled into the
   active scan policy before any candidate can be discarded.

`enabled = false` removes a detector from the active corpus. Shipped detector
availability and shipped confidence policy have no hidden Rust override lists;
the individual detector TOML is their single source.

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
no_candidate_gate = true
fallback_localizer = false
gpu_recall_floor = false
gpu_moe_timeout_ms = 30000
```

These keys tune scanner-internal detection and recall route gates. They are
operator-visible resolved config, included in the autoroute config digest, and
printed by `keyhog config --effective`. They do not have CLI flags because
per-run hidden recall changes would invalidate installer calibration.
`hs_shard_target` controls Hyperscan patterns-per-shard during compile; changing
it affects compile/cache shape and autoroute identity but not detector recall.
`gpu_recall_floor` forces the GPU region-presence path to compute the full CPU
trigger net during parity/debug scans and report any GPU under-fire it recovers.
`gpu_moe_timeout_ms` bounds one GPU MoE confidence readback; on timeout KeyHog
surfaces the GPU fault and scores the same candidates on CPU MoE.

### `[allowlist]`

`file` selects the line-based allowlist file (default `.keyhogignore` at the
scan root). `require_reason`, `require_approved_by`, and `max_expires_days`
enforce governance before any suppression is active. Missing required metadata,
expired entries, malformed entries, or expiry windows beyond the configured
limit fail closed with an operator-visible config error. See
[Suppressions](../suppressions.md).

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
