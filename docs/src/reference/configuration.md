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
| Keyword low-entropy | on | `generic_keyword_low_entropy` | `--no-keyword-low-entropy` | Admit credential-keyword-anchored values (`PASSWORD=`, `*_PASS=`, `secret:` …) on a low entropy floor; precision is carried by the ML model. Surfaces real-world config passwords. Disabling raises precision but drops real recall. |
| ML enabled | on | `no_ml = true` disables | `--no-ml` | ML confidence gating. Disabling raises FPs and hurts recall. |
| ML weight | **0.5** | `ml_weight` | `--ml-weight` | Blend weight of the ML score vs heuristics (0.0–1.0). |
| Unicode norm | on | `no_unicode_norm = true` disables | `--no-unicode-norm` | Normalise homoglyphs before matching (anti-evasion). |
| Scan comments | off | — | `--scan-comments` | Treat secrets in code comments at full confidence (default downgrades them). |
| Threads | #cores | `threads` | `--threads` | Parallel scan workers. |
| Dedup scope | `credential` | `dedup` | `--dedup` | `credential` / `file` / `none`. |
| Max file size | 10 MB | `max_file_size` | `--max-file-size` | Walker skips files larger than this. |
| Severity floor | (all) | `severity` | `--severity` | Minimum severity to report: info/low/medium/high/critical. |
| Output format | `text` | `format` | `--format` | text/json/jsonl/sarif/csv/html/junit. |
| Show secrets | off | `show_secrets` | `--show-secrets` | Print plaintext credentials. **Never enable in CI/logs.** |
| Incremental cache | off | `incremental` / `incremental_cache` | `--incremental` / `--incremental-cache` | BLAKE3 Merkle skip-cache; 10–100× on CI re-runs. |
| Backend | `auto` | — | `--backend` | `auto`/`simd`/`cpu`/`gpu`/`megascan`. Auto picks the fastest present. |

> Honesty note — a few `ScanConfig` fields are parse-compatible no-ops on the
> live scan path: `min_secret_len` (engine uses its own length constants), and
> `max_file_size`/`dedup` on `ScanConfig` itself (the effective values come
> from the walker and the verifier via the CLI args, not from `ScanConfig`).
> They are documented here so the surface is complete. The table above lists
> the knobs that *do* reach behaviour through the CLI/TOML path.

## Presets

| Preset | TOML | CLI | What it does |
|---|---|---|---|
| Fast | `fast = true` | `--fast` | Pattern-match only — **disables decode + entropy + ML**. Fastest; largest blind spot. Refused under `--lockdown`. |
| Deep | `deep = true` | `--deep` | Everything on, maximum recall. |

`--fast` and `--deep` are mutually exclusive and conflict with
`--no-decode`/`--no-entropy`.

## Nested tables

`.keyhog.toml` also accepts nested tables. They must appear **after** all
flat top-level keys (a TOML rule). Where a nested key and its flat twin both
set a value, the flat form wins.

### `[scan]`

Mirrors the flat scalars (`severity`, `min_confidence`, `format`, `exclude`,
`threads`, `dedup`) — the shape the rest of the docs use as canonical.

```toml
[scan]
severity = "high"
min_confidence = 0.40       # raise toward 0.85 for fewer false positives
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

### `[allowlist]` (parse-only)

`file` / `require_reason` / `require_approved_by` / `max_expires_days` parse
as compatibility fields, but the governance flags do not affect scan
behaviour. Suppression itself works via `.keyhogignore` — see
[Suppressions](../suppressions.md). This table is documented as parse-only so
nobody assumes governance enforcement from these fields.

## Where the numbers live

- Canonical defaults + tuning rationale: `crates/core/src/config.rs`
  (`ScanConfig::default`).
- TOML schema + merge precedence: `crates/cli/src/config.rs`
  (`ConfigFile`, `apply_config_file`).
- The resolved struct the live scanner reads (defaults + file + flags folded
  into one): `crates/cli/src/orchestrator_config.rs`
  (`resolve_scan_config` → `ResolvedScanConfig`). Reading this single struct
  — rather than re-deriving floors from raw args — is what keeps
  *tuned == benched == shipped* true on the live path.
