# Your first scan

You have the binary on your `PATH`. Now:

```sh
keyhog scan .
```

That walks the current directory, hands every file through the scanner,
and prints findings. The exit code carries the verdict:

| Exit code | Meaning                                    |
|-----------|--------------------------------------------|
| `0`       | Scan finished, no findings                 |
| `1`       | Findings present, none confirmed live      |
| `2`       | User error - bad config, bad path, unsupported flag |
| `3`       | System error - local I/O or detector-corpus audit failure |
| `10`      | Live credential confirmed under `--verify` |
| `11`      | Scanner thread panicked; re-run before trusting results |
| `12`      | Required GPU unavailable                   |
| `13`      | Requested source failed or coverage incomplete |

So a CI step that should fail the build when a credential leaks is just:

```sh
keyhog scan .
```

No grep, no jq, no exit-code arithmetic. Findings exit non-zero, so
the build goes red; with `--verify`, live credentials use exit `10`.

## What you get out of it

By default, output is human-readable:

```text
$ keyhog scan .
K E Y H O G
───────────
v0.5.40 · secret scanner · 922 detectors
by santh

⚡ 16 cores | GPU: NVIDIA GeForce RTX 5090 | SIMD: AVX-512 | Hyperscan | 922 detectors (6061 patterns) io_uring | backend=simd-regex | gpu=none

  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/staging.env:14
  │ Confidence: ■■■■■■ 100%
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified

  1. Revoke active secrets in the provider's dashboard.
```

The banner (on stderr, only when it is a terminal) tells you the binary
version and detector count. With `--progress`, the capability line also
shows the current host's CPU/GPU labels, scanner engine, compiled pattern
count, selected backend, and GPU engagement result. Each finding renders
as a severity-colored box: header severity + detector, then `Secret:`
(redacted to its first and last few characters), `Location:`, a
`Confidence:` bar, and an `Action:`/`Docs:` remediation hint. The
`Results` footer joins the counts with ` · ` and lists the numbered next
steps.

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
inside the source tree, baked into the binary at build time, and is
the ONLY built-in suppression list - there's no opaque allow-list.

## JSON output

```sh
keyhog scan . --format json
```

Each finding is a JSON object with these fields, every one always
present (consumers like SARIF converters and CI gates rely on the
schema being stable):

```json
{
  "detector_id":        "stripe-secret-key",
  "detector_name":      "Stripe Secret Key",
  "service":            "stripe",
  "severity":           "critical",
  "credential_redacted": "sk_l...p7dc",
  "credential_hash":     "sha256-hex",
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
  "confidence": 1.0,
  "remediation": {
    "action":     "Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.",
    "revoke_url":  "https://docs.stripe.com/keys#roll-api-key",
    "docs_url":    "https://docs.stripe.com/keys"
  }
}
```

Pipe it into `jq`, into a SARIF converter for the GitHub Security tab,
or into your own dedup / triage tooling.

## Limiting scope

```sh
keyhog scan src/                        # one subdirectory
keyhog scan src/config/staging.env      # one file
keyhog scan --stdin < staging.env       # from stdin (CI: cat | keyhog)
keyhog scan . --exclude-paths 'docs/*'  # exclude a glob
```

Common patterns the default walk **already** skips: `.git/`,
`node_modules/`, `__pycache__/`, `vendor/`, `dist/`, `build/`, `out/`,
`.min.js`, `.min.css`, `.bak`, `.swp`. To see the full list, look at
`is_default_excluded_path` in `crates/sources/src/filesystem.rs`.

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
