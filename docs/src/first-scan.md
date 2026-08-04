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

KeyHog redacts credential values in terminal, JSON, JSONL, CSV, SARIF, and HTML
output by default. `--show-secrets` deliberately prints plaintext and can leak
it into logs, artifacts, or scrollback. Do not use that flag for routine scans.

Now scan your repository:

```sh
cd /path/to/your/repository
keyhog scan .
```

That walks the current directory and reports findings. A successful scan
returns exactly one process exit code:

| Exit code | Meaning |
|-----------|---------|
| `0` | Scan completed with no reportable findings |
| `1` | Findings are present, but none were confirmed live; skipped, unverified, dead, and revoked credentials use this verdict |
| `2` | User error, such as a bad flag or config, a missing or unreadable path, a missing baseline, detector-load failure, or invalid autoroute calibration |
| `3` | Local system failure, such as low-level I/O, a fatal daemon failure, or an unavailable selected SIMD/Hyperscan backend |
| `10` | At least one credential was confirmed live under `--verify` |
| `11` | A scanner thread panicked; partial output is not a trustworthy clean verdict |
| `12` | A required or explicitly selected GPU was unavailable |
| `13` | A requested source failed or input coverage was incomplete |
| `130` | You interrupted the scan with Ctrl-C/SIGINT |

`keyhog scan --help` prints the same canonical table. A scan with findings exits
nonzero by design, so CI does not need `grep`, `jq`, or exit-code arithmetic.
When several conditions apply, a scanner panic takes precedence over findings,
a confirmed-live finding takes precedence over other findings, and findings
take precedence over a later cache or source-coverage failure. Read the
coverage warning and structured `scan_status` before treating partial output as
complete.

## What you get out of it

Human-readable output includes a redacted finding and a summary:

With `--progress`, stderr starts with the live scanner and routing banner:

```text
    K E Y H O G
    ───────────
    v0.5.60 · secret scanner · 923 detectors
    by santh

  ⚡ 16 cores | SIMD: AVX-512 | Hyperscan | 923 detectors (5822 patterns) io_uring | backend=simd-regex | gpu=none
```

```text
┌    CRITICAL ─── GitHub Classic PAT
│ Secret:     ghp_...K7n2
│ Location:   /tmp/keyhog-first-scan/demo.env:1
│ Confidence: ■■■■■■ 100%
└─────────────────────────────────────────────

━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1 secret found · 1 unverified
```

The banner is written to stderr only when stderr is a terminal. Pass
`--progress` to include the current host's CPU/GPU labels, scanner engine,
compiled pattern count, selected backend, and GPU engagement result. Findings
go to stdout unless you use `--output`. Each finding gives you the detector,
redacted credential, location, confidence when measured, and remediation
guidance.

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
Minor revisions are additive, so a reader that understands major `1` may
accept a newer minor and ignore fields it does not know. The optional
`metadata` object identifies the scan; `coverage_gap_summary` preserves any
source or scanner coverage gaps; `findings` contains the redacted finding
objects. `entropy` and `confidence` are included when the detection
path measured them; otherwise they are omitted. A present entropy value is
Shannon bits-per-byte evidence, not a confidence score and not a claim that
entropy alone caused the finding.
The `source_bytes_scanned` and `source_chunks_scanned` counters are the exact
workload consumed by the scanner, so an importer can calculate throughput from
the artifact without scraping console progress.

```json
{
  "schema_version": {"major": 1, "minor": 8},
  "scan_status": "success",
  "metadata": {
    "scan_id": "0123456789abcdef0123456789abcdef",
    "scan_status": "success",
    "keyhog_version": "0.5.60",
    "git_hash": "<build-commit>",
    "detector_digest": "923-<digest>",
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
    "detector_count": 923
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
        "file_path": "src/config/staging.env",
        "line":      14,
        "offset":    12,
        "commit":    null,
        "author":    null,
        "date":      null
      },
      "verification": "skipped",
      "metadata": {},
      "additional_locations": [],
      "entropy": 4.5,
      "confidence": 1.0,
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

Common patterns the default walk **already** skips include `.git/`,
`node_modules/`, `__pycache__/`, vendored/build output, minified assets, and
editor backup files. The canonical behavior and opt-out are documented under
[path suppressions](./suppressions.md#path-based).

## Going further

Once the basic scan works:

- [Output formats](./output-formats.md) - JSON, SARIF, plain text.
- [Verification](./verification.md) - `--verify` makes API calls to
  confirm credentials are live; a dead credential is downgraded one
  severity tier (`critical` → `high`, …), never collapsed to a fixed
  level.
- [Pre-commit hook](./workflows/precommit.md) - block leaked creds
  before they hit the repo.
- [CI integration](./workflows/ci.md) - GitHub Actions, GitLab CI,
  CircleCI patterns.
