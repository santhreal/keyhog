# Your first scan

Start with a synthetic token whose checksum is valid for the detector but which
is not a live credential. This confirms detection and redaction without putting
a real secret in your shell history.

On Linux or macOS:

```sh
demo_dir=$(mktemp -d)
token='ghp_'
token="${token}aBcD1234EFgh5678ijkl9012MNop343hK7n2"
printf 'GH_TOKEN="%s"\n' "$token" > "$demo_dir/demo.env"
if keyhog scan "$demo_dir/demo.env"; then status=0; else status=$?; fi
printf 'keyhog exit code: %s\n' "$status"
rm -rf "$demo_dir"
test "$status" -eq 1
```

On Windows PowerShell:

```powershell
$Demo = Join-Path ([IO.Path]::GetTempPath()) "keyhog-first-scan-$PID.env"
$Token = 'ghp_' + 'aBcD1234EFgh5678ijkl9012MNop343hK7n2' # keyhog:ignore detector=github-classic-pat
Set-Content -Path $Demo -Value "GH_TOKEN=`"$Token`""
keyhog scan $Demo
$Status = $LASTEXITCODE
Write-Output "keyhog exit code: $Status"
Remove-Item $Demo
if ($Status -ne 1) { throw "expected finding exit 1, got $Status" }
```

You should see a `GitHub Classic PAT` finding with the credential rendered as
`ghp_...K7n2`, followed by `keyhog exit code: 1`. <!-- keyhog:ignore detector=entropy-token --> File paths, timing, host
capabilities, and detector counts vary by installation.

KeyHog redacts credential values by default in every output format, including
the `--output` file, not only the terminal. `--show-secrets` deliberately
prints plaintext and can leak it into logs, artifacts, or scrollback. Do not
use that flag for routine scans, and never in CI.

Now scan your repository:

```sh
cd /path/to/your/repository
keyhog scan .
```

That walks the current directory and reports findings. A successful scan
returns exactly one process exit code:

| Exit code | Meaning |
|-----------|---------|
| `0` | No finding blocks the active evidence policy and no failing source-coverage condition occurred. Under the default policy, review-tier findings remain visible without blocking. |
| `1` | At least one finding blocks the active evidence policy, but none were confirmed live. The default blocks `likely` and `confirmed`; `--evidence-policy paranoid` also blocks `review`. |
| `2` | User error, such as a bad flag or config, a missing or unreadable path, a missing baseline, detector-load failure, or invalid autoroute calibration |
| `3` | Local system failure, such as low-level I/O, a fatal daemon failure, or an unavailable selected SIMD/Hyperscan backend |
| `10` | At least one credential was confirmed live under `--verify` |
| `11` | A scanner thread panicked; partial output is not a trustworthy clean verdict |
| `12` | A required or explicitly selected GPU was unavailable |
| `13` | A requested source failed or failing input coverage was incomplete, and no finding outcome took precedence. |
| `130` | You interrupted the scan with Ctrl-C/SIGINT |

`keyhog scan --help` prints the same canonical table. CI does not need `grep`,
`jq`, or exit-code arithmetic. When several conditions apply, a scanner panic
takes precedence over findings, a confirmed-live finding takes precedence over
other findings, and a blocking finding takes precedence over a later cache or
source-coverage failure. Read the coverage warning and structured `scan_status`
before treating partial output as complete.

## What you get out of it

Findings go to stdout as redacted boxes followed by a summary:

```text
┌    CRITICAL ─── GitHub Classic PAT
│ Secret:     ghp_...K7n2
│ Location:   /tmp/keyhog-first-scan/demo.env:1
│ Evidence:   likely/vendor-pattern  ■■■■■■ 100%
└─────────────────────────────────────────────

━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1 secret found · 1 unverified
```

Each finding gives you the detector, the redacted credential, the location,
the exact evidence tier and reason code, an optional evidence score, and
remediation guidance. Use `--output` to write the report to a file instead of
stdout.

Add `--progress` when you need to see which engine ran the scan. It writes a
banner to stderr before the findings:

```text
    K E Y H O G
    ───────────
    v0.5.78 · secret scanner · 926 detectors
    by santh

  ⚡ 16 cores | SIMD: AVX-512 | Hyperscan | 926 detectors (5803 patterns) io_uring | backend=simd-regex | gpu=none
```

The banner reports this host's CPU and GPU labels, the scanner engine, the
compiled pattern count, the selected backend, and the GPU engagement result.
KeyHog writes it only when stderr is a terminal, so a redirected log or a CI
capture never contains it.

## Default suppressions

KeyHog ships with a Tier-B suppression list of **publicly documented
test fixtures** - credentials that appear in vendor docs as examples.
Findings on these are suppressed by default. Examples:

- Stripe's `sk_live_4eC39HqLyjWDarjtT1zdp7dc` (docs sample)
- AWS's `AKIAIOSFODNN7EXAMPLE` (docs sample)
- The RFC 7519 specimen JWT
- GitHub's `ghp_aBcDeFgHiJ…` placeholder

To see what was suppressed, pass `--no-suppress-test-fixtures`. The
list lives at `crates/cli/data/suppressions/test-fixtures.toml`
inside the source tree and is baked into the binary at build time. It is one
visible suppression layer; detector-owned examples, structural/context gates,
default path policy, `.keyhogignore`, and `.keyhogignore.toml` have distinct
documented ownership. See [Suppressions](./suppressions.md) for the full order.

## JSON output

```sh
keyhog scan . --format json-envelope
```

The compatibility `--format json` form remains a top-level findings array;
choose `json-envelope` when a durable schema identity and scan metadata are
needed.

The output is a versioned envelope. `schema_version.major` selects the
incompatible schema generation; consumers must reject an unsupported major.
Minor revisions are additive, so a reader that understands major `2` may
accept a newer minor and ignore fields it does not know. The optional
`metadata` object identifies the scan; `coverage_gap_summary` preserves any
source or scanner coverage gaps; `findings` contains the redacted finding
objects. Every finding has a canonical `evidence` object with exact `tier` and
`reason_code`. `entropy` and `evidence_score` are included only when measured.
A present entropy value is Shannon bits-per-byte evidence, not an evidence
score and not a claim that entropy alone caused the finding. The optional
`correlations` array is emitted only when the scan ran with
[`--correlate`](./reference/cli.md); the key is absent, not empty, otherwise.
See [Output formats](./output-formats.md#cross-file-correlation).
The `source_bytes_scanned` and `source_chunks_scanned` counters are the exact
workload consumed by the scanner, so an importer can calculate throughput from
the artifact without scraping console progress.

```json
{
  "schema_version": {"major": 2, "minor": 0},
  "scan_status": "success",
  "metadata": {
    "scan_id": "0123456789abcdef0123456789abcdef",
    "scan_status": "success",
    "keyhog_version": "0.5.78",
    "git_hash": "<build-commit>",
    "detector_digest": "926-<digest>",
    "config_digest": "<effective-config-digest>",
    "resolved_scan": {
      "schema_version": 1,
      "preset": "default",
      "effective": {"max_decode_depth": "10", "entropy_enabled": "true"},
      "overrides": []
    },
    "generated_at": "2026-07-14T00:00:01",
    "scan_started_at": "2026-07-14T00:00:00",
    "scan_finished_at": "2026-07-14T00:00:01",
    "duration_ms": 1000,
    "targets": ["."],
    "source_chunks_scanned": 1,
    "source_bytes_scanned": 128,
    "detector_count": 926
  },
  "coverage_gap_summary": [],
  "findings": [
    {
      "detector_id":        "stripe-secret-key",
      "detector_name":      "Stripe Secret Key",
      "service":            "stripe",
      "severity":           "critical",
      "credential_redacted": "sk_l...p7dc",
      "credential_hash":     "sha256-hex",
      "companions_redacted": {},
      "location": {
        "source":    "filesystem",
        "file_path": "src/config/.env.staging",
        "line":      14,
        "offset":    12,
        "commit":    null,
        "author":    null,
        "date":      null
      },
      "verification": "skipped",
      "metadata": {},
      "additional_locations": [],
      "evidence": {
        "tier": "likely",
        "reason_code": "vendor-pattern",
        "provenance": {
          "schema_version": 1,
          "detector_digest": "0123456789abcdef",
          "pattern_index": 0,
          "candidate_channel": "pattern",
          "source_role": "environment-assignment-value",
          "context_class": "vendor-pattern"
        }
      },
      "entropy": 4.5,
      "evidence_score": 1.0,
      "remediation": {
        "action":     "Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.",
        "revoke_url":  "https://docs.stripe.com/keys#roll-api-key",
        "docs_url":    "https://docs.stripe.com/keys"
      }
    }
  ]
}
```

Pipe `.findings` into `jq`, into a SARIF converter for the GitHub Security
tab, or into your own dedup / triage tooling.

## Limiting scope

```sh
keyhog scan src/                        # one subdirectory
keyhog scan src/config/staging.env      # one file
keyhog scan --stdin < staging.env       # from stdin (CI: cat | keyhog)
keyhog scan . --exclude-paths 'docs/*'  # exclude a glob
```

The default walk skips a file when any segment of its path is one of these
directory names, at any depth:

```text
.git  node_modules  target  .cache  __pycache__  .venv  venv  .tox
dist  build  out  .next  .nuxt  vendor  swagger  swagger-ui
```

It also skips lock files, editor backups, and filenames containing `.min.` or
`.bundle.`. A skipped file produces a `WARN` line on stderr and no finding, and
the scan still exits `0`. Check that list against your repository before you
trust a clean result: `build/`, `dist/`, `out/`, and `vendor/` hold real source
in some projects. Scan them with `keyhog scan . --no-default-excludes`, which
also stops the scanner discarding findings inside minified and vendored
bundles, or name one tree directly with `keyhog scan vendor/`. See
[files the walker never reads](./suppressions.md#files-the-walker-never-reads).

## Going further

A first scan of a real repository usually reports credentials that were already
there. Decide what to do with them before you wire KeyHog into anything:

- Rotate what you can. A leaked credential in the working tree is also in Git
  history.
- Record the rest once with `--create-baseline`, then gate on new findings
  only. See
  [Fail only on new secrets](./workflows/ci.md#fail-only-on-new-secrets).

Then continue with:

- [Suppressions and baselines](./suppressions.md) - allowlists, inline
  directives, per-detector floors, and what a baseline does and does not match.
- [Output formats](./output-formats.md) - JSON, SARIF, plain text.
- [Verification](./verification.md) - `--verify` makes API calls to
  confirm credentials are live; a dead credential is downgraded one
  severity tier (`critical` → `high`, …), never collapsed to a fixed
  level.
- [Pre-commit hook](./workflows/precommit.md) - block leaked creds
  before they hit the repo.
- [CI integration](./workflows/ci.md) - GitHub Actions, GitLab CI,
  CircleCI patterns.
