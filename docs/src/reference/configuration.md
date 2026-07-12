# Configuration

keyhog runs with **zero configuration**: `keyhog scan .` works out of the
box on the canonical tuned defaults. Everything on this page is optional
override.

## Precedence

Settings resolve in this order, rightmost winning:

```
compiled defaults  →  .keyhog.toml  →  CLI flags
(ScanConfig::default)  (walked up from    (always win)
                        the scan path)
```

- **Compiled defaults** live in one place: `ScanConfig::default()` in
  `crates/core/src/config.rs`. They are the *tuned == benched == shipped*
  values: the same numbers the SecretBench leaderboard is measured on. The
  unit test `crates/core/tests/unit/config.rs` pins them, so a change to a
  shipped default is a deliberate, test-gated decision.
- **`.keyhog.toml`** is discovered by walking up from the scan path to the
  filesystem root (first one found wins). Copy
  [`.keyhog.toml.example`](https://github.com/santhsecurity/keyhog/blob/main/.keyhog.toml.example)
  to your repo root and delete what you don't need. A malformed `.keyhog.toml`
  fails closed with the path and TOML error before any scan output is written.
  Unknown tables and keys are parse failures, not ignored compatibility shims.
  Use `--no-config` when you intentionally want compiled defaults.
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

## Core settings

Each row is the same knob across all three layers. Defaults are
`ScanConfig::default()`.

| Setting | Default | `.keyhog.toml` key | CLI flag | Effect |
|---|---|---|---|---|
| Min confidence | **0.40** | `min_confidence` | `--min-confidence` | Drop findings scoring below this (0.0-1.0). Bench-tuned for max F1. |
| Decode depth | **10** | `decode_depth` | `--decode-depth` | Max recursive decode passes, e.g. `base64(hex(url(secret)))` (1-10). |
| Decode size limit | **512KB** | `decode_size_limit` | `--decode-size-limit` | Per-file ceiling for decode-through; larger files skip encoding detection. |
| Entropy enabled | on | `no_entropy = true` disables | `--no-entropy` | Shannon-entropy detection for novel high-entropy strings. |
| Entropy in source | off | `entropy_source_files` | `--entropy-source-files` | Run entropy inside `.py`/`.js`/`.go`/… (off by default to cut FPs). |
| Entropy threshold | **4.5** | `[scan].entropy_threshold` (top-level alias accepted) | `--entropy-threshold` | Bits/byte cutoff (3.5 aggressive … 5.5 conservative). The byte-entropy domain is `[0.0, 8.0]`; non-finite and out-of-range requests fail closed instead of being silently clamped. |
| BPE word-like bound | **2.2** | `[scan].entropy_bpe_max_bytes_per_token` (top-level alias accepted) | `--entropy-bpe-max-bytes-per-token` | With no explicit scan setting, detector TOML `bpe_max_bytes_per_token` wins over this compiled fallback. Setting either scan TOML form or the CLI flag explicitly becomes the visible Tier-A override for every eligible detector (CLI wins). Defining both TOML aliases in one file fails closed as ambiguous; keep the canonical `[scan]` key. Invalid, zero, negative, NaN, and infinite bounds also fail closed. A surviving candidate above its resolved cl100k_base UTF-8 bytes-per-token ceiling is word-like and dropped. Lower = higher precision/lower recall. Detector families for which token efficiency is inappropriate declare `bpe_enabled = false` in their own TOML and skip tokenization. `config --effective` reports `entropy_bpe_policy = scan-override` for explicit scan values and `scan-fallback` otherwise. |
| Entropy min length | **16** | `min_secret_len` | `--min-secret-len` | Minimum credential length for entropy-fallback candidates. Named detectors keep their own shape-specific length gates. |
| Keyword low-entropy | on | `generic_keyword_low_entropy` | `--no-keyword-low-entropy` | Admit credential-keyword-anchored values (`PASSWORD=`, `*_PASS=`, `secret:` …) on a low entropy floor; precision is carried by the ML model. Surfaces real-world config passwords. Disabling raises precision but drops real recall. |
| ML enabled | on | `no_ml = true` disables | `--no-ml` | ML confidence gating. Disabling raises FPs and hurts recall. |
| ML weight | **0.5** | `ml_weight` | `--ml-weight` | Blend weight of the ML score vs heuristics (0.0-1.0). |
| Unicode norm | on | `no_unicode_norm = true` disables | `--no-unicode-norm` | Normalise homoglyphs before matching (anti-evasion). |
| Scan comments | off | - | `--scan-comments` | Treat secrets in code comments at full confidence (default downgrades them). |
| Threads | #cores | `threads` | `--threads` | Parallel scan workers. |
| Reader threads | scan-pool-derived | `reader_threads` | `--reader-threads` | Dedicated filesystem read workers. |
| Fused batch | `32` | `fused_batch` | `--fused-batch` | Chunk batch size for the fused filesystem pipeline. |
| Fused depth | worker-count-derived | `fused_depth` | `--fused-depth` | Bounded channel depth for fused filesystem batches. |
| Per-chunk timeout | off | `per_chunk_timeout_ms` | `--per-chunk-timeout-ms` | Optional hard deadline per chunk scan in milliseconds. |
| Dedup scope | `credential` | `dedup` | `--dedup` | `credential` / `file` / `none`. |
| Max file size | 100 MiB | `max_file_size` | `--max-file-size` | Walker skips files larger than this. |
| Severity floor | (all) | `severity` | `--severity` | Minimum severity to report: info/low/medium/high/critical. |
| Output format | `text` | `format` | `--format` | text/json/jsonl/sarif/csv/github-annotations/gitlab-sast/html/junit. |
| Show secrets | off | `show_secrets` | `--show-secrets` | Print plaintext credentials. **Never enable in CI/logs.** |
| Incremental cache | off | `incremental` / `incremental_cache` | `--incremental` / `--incremental-cache` | BLAKE3 Merkle skip-cache; 10-100× on CI re-runs. |
| Hyperscan cache dir | platform cache dir | `[system] cache_dir` | `--cache-dir` | Compiled-database cache directory. Must be an absolute user-owned path under the home directory or per-user keyhog temp cache root. |
| Autoroute cache file | platform cache file | `[system] autoroute_cache` | `--autoroute-cache` | Persisted fastest-correct backend decisions. Use an absolute file path or `off` to disable persistence and force auto-route cache misses to fail loudly. |
| Bayesian calibration cache | off | `[system] calibration_cache` | `--calibration-cache` | Explicit per-detector confidence calibration file written by `keyhog calibrate`. Missing or damaged explicit files fail closed before scanning. |
| GPU runtime policy | `auto` | `[system] gpu` | `--no-gpu` / `--require-gpu` | `auto` probes when routing can use GPU, `off` skips GPU init, and `required` fails closed when no usable GPU stack is available. Printed by `keyhog config --effective` and included in autoroute scan identity. |
| Autoroute GPU candidates | off | `[system] autoroute_gpu` | `--autoroute-gpu` / `--no-autoroute-gpu` | Allows calibration to include GPU candidates for eligible workload buckets. Normal scans still require persisted fastest-correct evidence; this never benchmarks during production scans. |
| Coalesced batch pipeline | off | `[system] batch_pipeline` | `--batch-pipeline` / `--no-batch-pipeline` | Diagnostic/calibration route that bypasses the fused filesystem pipeline. Printed by `keyhog config --effective` and included in autoroute scan identity. |
| AWS canary issuer extensions | embedded baseline | `[aws] canary_accounts` / `knockoff_accounts` | - | Extra 12-digit AWS account IDs treated as canary-token issuers during offline access-key metadata classification and verification suppression. |
| Scanner tuning | compiled scanner defaults | `[tuning]` | - | Detection/recall route gates that affect engine work selection. These are explicit config so autoroute calibration identity includes them; ambient `KEYHOG_*` tuning env vars are ignored. |
| Backend | `auto` | - | `--backend` | `auto`/`gpu`/`simd`/`cpu`. Profiles and persisted evidence use the descriptive engine labels `gpu-region-presence`/`simd-regex`/`cpu-fallback`; retired MegaScan and implementation-name aliases are rejected. Auto uses a persisted installer-calibrated fastest-correct decision for the exact workload bucket; missing/stale/incomplete calibration is an error, not permission to substitute another backend. |

## Source limits

Source byte/count ceilings resolve through the same precedence chain:
compiled `SourceLimits::default()` → `.keyhog.toml` `[limits]` → CLI
`--limit-*` flags.

| Limit | Default | `.keyhog.toml` key | CLI flag |
|---|---:|---|---|
| Stdin bytes | 10 MiB | `[limits] stdin_bytes` | `--limit-stdin-bytes` |
| Web response bytes | 10 MiB | `[limits] web_response_bytes` | `--limit-web-response-bytes` |
| S3 object bytes | 10 MiB | `[limits] s3_object_bytes` | `--limit-s3-object-bytes` |
| GCS object bytes | 10 MiB | `[limits] gcs_object_bytes` | `--limit-gcs-object-bytes` |
| Azure blob bytes | 10 MiB | `[limits] azure_blob_bytes` | `--limit-azure-blob-bytes` |
| Cloud listed objects | 100000 | `[limits] cloud_max_objects` | `--limit-cloud-max-objects` |
| Docker tar entry bytes | 128 MiB | `[limits] docker_tar_entry_bytes` | `--limit-docker-tar-entry-bytes` |
| Docker config/manifest bytes | 16 MiB | `[limits] docker_image_config_bytes` | `--limit-docker-image-config-bytes` |
| Docker tar total bytes | 8 GiB | `[limits] docker_tar_total_bytes` | `--limit-docker-tar-total-bytes` |
| Git stdout line bytes | 10 MiB | `[limits] git_line_bytes` | `--limit-git-line-bytes` |
| Git aggregate bytes | 256 MiB | `[limits] git_total_bytes` | `--limit-git-total-bytes` |
| Git blob bytes | 10 MiB | `[limits] git_blob_bytes` | `--limit-git-blob-bytes` |
| Git emitted chunks | 500000 | `[limits] git_chunks` | `--limit-git-chunks` |
| Hosted-git listing pages | 1000 | `[limits] hosted_git_pages` | `--limit-hosted-git-pages` |
| Binary strings bytes | 64 MiB | `[limits] binary_read_bytes` | `--limit-binary-read-bytes` |
| Ghidra output bytes | 50 MiB | `[limits] binary_decompiled_bytes` | `--limit-binary-decompiled-bytes` |

> Library note: `ScanConfig::max_file_size` and `ScanConfig::dedup` are scan
> pipeline settings, not regex-engine settings. The CLI applies them through
> the filesystem source and final deduplication stage; `FilesystemSource::new`
> uses the same `DEFAULT_MAX_FILE_SIZE_BYTES` as `ScanConfig::default()` so the
> shipped default cannot drift.

## Presets

| Preset | TOML | CLI | What it does |
|---|---|---|---|
| Fast | `fast = true` | `--fast` | Pattern-match only: **disables decode + entropy + ML**. Fastest; largest blind spot. Refused under `--lockdown`. |
| Deep | `deep = true` | `--deep` | Everything on, maximum recall. |
| Precision | - | `--precision` | High-precision mass scanning: drops entropy-only/ML-speculative findings, raises the confidence floor to **0.85**, shallow decode. Stays fully offline and fast. |

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

## Nested tables

`.keyhog.toml` also accepts nested tables. They must appear **after** all
flat top-level keys (a TOML rule). Define a scan knob through either its flat
compatibility alias or its canonical nested key, never both. Duplicate aliases
fail closed with an error naming the canonical `[scan]` key, rather than silently
discarding either value.

### `[scan]`

A readable grouping for the scan scalars (`severity`, `min_confidence`,
`decode_depth`, `format`, `exclude`, `threads`, `reader_threads`, `fused_batch`,
`fused_depth`, `per_chunk_timeout_ms`, `dedup`), exactly equivalent to setting
each one flat at the top level, and the form the rest of the docs show for
readability. Pick one form per key; duplicate flat and nested definitions fail
closed (per [Nested tables](#nested-tables) above).

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

`autoroute_gpu` controls whether calibration runs may include GPU candidates
for eligible workload buckets. It is off by default; installers pass
`--autoroute-gpu` during the visible calibration phase. Normal scans never
benchmark from this value; they consume persisted fastest-correct decisions.

`batch_pipeline` forces the coalesced batch pipeline. Leave it `false` for the
default fused filesystem route; set it only for calibration, diagnostics, or
pipeline parity checks. The resolved value is printed by
`keyhog config --effective` and is part of the autoroute scan identity.

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

- Canonical scan defaults + tuning rationale: `crates/core/src/config.rs`
  (`ScanConfig::default`).
- Scanner route tuning defaults: `crates/scanner/src/scanner_config.rs`
  (`ScannerTuningConfig`).
- TOML schema + merge precedence: `crates/cli/src/config.rs`
  (`ConfigFile`, `apply_config_file`).
- The resolved struct the live scanner reads (defaults + file + flags folded
  into one): `crates/cli/src/orchestrator_config.rs`
  (`resolve_scan_config` → `ResolvedScanConfig`). Reading this single struct
  (rather than re-deriving floors from raw args) is what keeps
  *tuned == benched == shipped* true on the live path.
