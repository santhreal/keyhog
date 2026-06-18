# Configuration

keyhog runs with **zero configuration** — `keyhog scan .` works out of the
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
  values — the same numbers the SecretBench leaderboard is measured on. The
  unit test `crates/core/tests/unit/config.rs` pins them, so a change to a
  shipped default is a deliberate, test-gated decision.
- **`.keyhog.toml`** is discovered by walking up from the scan path to the
  filesystem root (first one found wins). Copy
  [`.keyhog.toml.example`](https://github.com/santhsecurity/keyhog/blob/main/.keyhog.toml.example)
  to your repo root and delete what you don't need. A malformed file warns
  and is ignored (the scan still runs on defaults) — it never silently
  changes behaviour.
- **CLI flags** always override the file. A flag left unset falls through to
  the file, then to the compiled default.

There is no separate system/user config tier today: the walk-up `.keyhog.toml`
is the only file layer.

## Core settings

Each row is the same knob across all three layers. Defaults are
`ScanConfig::default()`.

| Setting | Default | `.keyhog.toml` key | CLI flag | Effect |
|---|---|---|---|---|
| Min confidence | **0.40** | `min_confidence` | `--min-confidence` | Drop findings scoring below this (0.0–1.0). Bench-tuned for max F1. |
| Decode depth | **10** | `decode_depth` | `--decode-depth` | Max recursive decode passes, e.g. `base64(hex(url(secret)))` (1–10). |
| Decode size limit | **512KB** | `decode_size_limit` | `--decode-size-limit` | Per-file ceiling for decode-through; larger files skip encoding detection. |
| Entropy enabled | on | `no_entropy = true` disables | `--no-entropy` | Shannon-entropy detection for novel high-entropy strings. |
| Entropy in source | off | `entropy_source_files` | `--entropy-source-files` | Run entropy inside `.py`/`.js`/`.go`/… (off by default to cut FPs). |
| Entropy threshold | **4.5** | `entropy_threshold` | `--entropy-threshold` | Bits/byte cutoff (3.5 aggressive … 5.5 conservative). |
| Entropy min length | **16** | `min_secret_len` | `--min-secret-len` | Minimum credential length for entropy-fallback candidates. Named detectors keep their own shape-specific length gates. |
| Keyword low-entropy | on | `generic_keyword_low_entropy` | `--no-keyword-low-entropy` | Admit credential-keyword-anchored values (`PASSWORD=`, `*_PASS=`, `secret:` …) on a low entropy floor; precision is carried by the ML model. Surfaces real-world config passwords. Disabling raises precision but drops real recall. |
| ML enabled | on | `no_ml = true` disables | `--no-ml` | ML confidence gating. Disabling raises FPs and hurts recall. |
| ML weight | **0.5** | `ml_weight` | `--ml-weight` | Blend weight of the ML score vs heuristics (0.0–1.0). |
| Unicode norm | on | `no_unicode_norm = true` disables | `--no-unicode-norm` | Normalise homoglyphs before matching (anti-evasion). |
| Scan comments | off | — | `--scan-comments` | Treat secrets in code comments at full confidence (default downgrades them). |
| Threads | #cores | `threads` | `--threads` | Parallel scan workers. |
| Dedup scope | `credential` | `dedup` | `--dedup` | `credential` / `file` / `none`. |
| Max file size | 10 MB | `max_file_size` | `--max-file-size` | Walker skips files larger than this. |
| Severity floor | (all) | `severity` | `--severity` | Minimum severity to report: info/low/medium/high/critical. |
| Output format | `text` | `format` | `--format` | text/json/jsonl/sarif/csv/github-annotations/gitlab-sast/html/junit. |
| Show secrets | off | `show_secrets` | `--show-secrets` | Print plaintext credentials. **Never enable in CI/logs.** |
| Incremental cache | off | `incremental` / `incremental_cache` | `--incremental` / `--incremental-cache` | BLAKE3 Merkle skip-cache; 10–100× on CI re-runs. |
| Hyperscan cache dir | platform cache dir | `[system] cache_dir` | `--cache-dir` | Compiled-database cache directory. Must be an absolute user-owned path under the home directory or per-user keyhog temp cache root. |
| Autoroute cache file | platform cache file | `[system] autoroute_cache` | `--autoroute-cache` | Persisted fastest-correct backend decisions. Use an absolute file path or `off` to disable persistence and force auto-route cache misses to fail loudly. |
| AWS canary issuer extensions | embedded baseline | `[aws] canary_accounts` / `knockoff_accounts` | — | Extra 12-digit AWS account IDs treated as canary-token issuers during offline access-key metadata classification and verification suppression. |
| Scanner tuning | compiled scanner defaults | `[tuning]` | — | Detection/recall route gates that affect engine work selection. These are explicit config so autoroute calibration identity includes them; ambient `KEYHOG_*` tuning env vars are ignored. |
| Backend | `auto` | — | `--backend` | `auto`/`simd`/`cpu`/`gpu`/`megascan`. Auto uses a persisted installer-calibrated fastest-correct decision for the exact workload bucket; missing/stale/incomplete calibration is an error, not permission to substitute another backend. |

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
| Docker tar entry bytes | 128 MiB | `[limits] docker_tar_entry_bytes` | `--limit-docker-tar-entry-bytes` |
| Docker config/manifest bytes | 16 MiB | `[limits] docker_image_config_bytes` | `--limit-docker-image-config-bytes` |
| Docker tar total bytes | 8 GiB | `[limits] docker_tar_total_bytes` | `--limit-docker-tar-total-bytes` |
| Git stdout line bytes | 10 MiB | `[limits] git_line_bytes` | `--limit-git-line-bytes` |
| Git aggregate bytes | 256 MiB | `[limits] git_total_bytes` | `--limit-git-total-bytes` |
| Git blob bytes | 10 MiB | `[limits] git_blob_bytes` | `--limit-git-blob-bytes` |
| Git emitted chunks | 500000 | `[limits] git_chunks` | `--limit-git-chunks` |
| Binary strings bytes | 64 MiB | `[limits] binary_read_bytes` | `--limit-binary-read-bytes` |
| Ghidra output bytes | 50 MiB | `[limits] binary_decompiled_bytes` | `--limit-binary-decompiled-bytes` |

> Honesty note — a few `ScanConfig` fields are parse-compatible no-ops on the
> live scan path: `max_file_size`/`dedup` on `ScanConfig` itself (the effective
> values come from the walker and the verifier via the CLI args, not from
> `ScanConfig`).
> They are documented here so the surface is complete. The table above lists
> the knobs that *do* reach behaviour through the CLI/TOML path.

## Presets

| Preset | TOML | CLI | What it does |
|---|---|---|---|
| Fast | `fast = true` | `--fast` | Pattern-match only — **disables decode + entropy + ML**. Fastest; largest blind spot. Refused under `--lockdown`. |
| Deep | `deep = true` | `--deep` | Everything on, maximum recall. |
| Precision | — | `--precision` | High-precision mass scanning: drops entropy-only/ML-speculative findings, raises the confidence floor to **0.85**, shallow decode. Stays fully offline and fast. |

`--fast`, `--deep`, and `--precision` are mutually exclusive and conflict with
`--no-decode`/`--no-entropy`.

**A preset is a BASE, not a terminal state.** It seeds the decode/entropy/ML
defaults, then any explicit knob you pass on the same command line **overrides**
that base — `--deep --decode-depth 3` runs the deep base at decode-depth 3, and
`--deep --min-confidence 0.9` raises the floor on the deep base. Two overrides
are one-directional and cannot weaken a precision bar: under `--precision`,
`--min-confidence` may *raise* the 0.85 floor but never lower it, and
`--no-keyword-low-entropy` can only *disable* the relaxed keyword floor, never
re-enable it under a preset that turned it off. Everything else takes effect as
written.

## Nested tables

`.keyhog.toml` also accepts nested tables. They must appear **after** all
flat top-level keys (a TOML rule). Where a nested key and its flat twin both
set a value, the flat form wins.

### `[scan]`

Mirrors the flat scalars (`severity`, `min_confidence`, `decode_depth`, `format`,
`exclude`, `threads`, `dedup`) — the shape the rest of the docs use as canonical.

```toml
[scan]
severity = "high"
min_confidence = 0.40       # raise toward 0.85 for fewer false positives
decode_depth = 10           # 1-10, same ceiling as --decode-depth
exclude = ["**/test/fixtures/**", "vendor/"]
```

### `[detector.<id>]` — per-detector overrides

Keyed by detector id (`keyhog detectors` lists them; `keyhog explain <id>`
shows one):

```toml
[detector.generic-api-key]
enabled = false             # drop this detector from the corpus entirely

[detector.twilio-api-key]
min_confidence = 0.6        # per-detector floor — OVERRIDES the global one
```

There are **three** per-detector floor sources, in increasing precedence:

1. **Tier-B** — `min_confidence` inside the detector's own TOML under
   `detectors/<id>.toml` (`[detector] min_confidence`). The detector's
   shipped baseline.
2. **Tier-A compiled** — `SHIPPED_DETECTOR_FLOORS` in
   `crates/cli/src/config.rs`. Ships in the binary and applies on **every**
   run, including the no-config bench/default path, so a noisy detector can
   be reined in without authoring a TOML.
3. **`.keyhog.toml` `[detector.<id>] min_confidence`** — operator intent;
   overrides the compiled floor for that id.

`enabled = false` removes a detector on any path; a file `enabled = true`
cannot currently re-enable a compiled disable (`SHIPPED_DISABLED_DETECTORS`)
— the merge is additive by design.

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
gpu_moe_timeout_ms = 30000
```

These keys tune scanner-internal detection and recall route gates. They are
operator-visible resolved config, included in the autoroute config digest, and
printed by `keyhog config --effective`. They do not have CLI flags because
per-run hidden recall changes would invalidate installer calibration.
`gpu_moe_timeout_ms` bounds one GPU MoE confidence readback; on timeout KeyHog
surfaces the GPU fault and scores the same candidates on CPU MoE.

### `[allowlist]` (parse-only)

`file` / `require_reason` / `require_approved_by` / `max_expires_days` parse
as compatibility fields, but the governance flags do not affect scan
behaviour. Suppression itself works via `.keyhogignore` — see
[Suppressions](../suppressions.md). This table is documented as parse-only so
nobody assumes governance enforcement from these fields.

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
  — rather than re-deriving floors from raw args — is what keeps
  *tuned == benched == shipped* true on the live path.
