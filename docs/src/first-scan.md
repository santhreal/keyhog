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
| `2`       | Runtime error - bad config, bad path, I/O failure |
| `10`      | Live credential confirmed under `--verify` |
| `11`      | Scanner thread panicked; re-run before trusting results |

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
keyhog v0.5.37 │ 894 detectors │ 1658 patterns │ avx-512 + hyperscan

src/config/staging.env:14:12  HIGH  stripe-secret-key
                              sk_live_4eC39H…Tcd3Hc (redacted, last 6)
                              entropy 5.21 │ confidence 0.999 │ unverified

scanned 12,841 files in 1.4 s
1 finding · 0 verified live · 1041 example fixtures suppressed
```

The header tells you the binary version, the detector count, and which
hardware acceleration is active (AVX-512, Hyperscan/Vectorscan SIMD,
CUDA, etc.). The body lists each finding with its location, severity,
detector, redacted credential, and confidence. The footer summarizes
counts and runtime.

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
  "credential_redacted": "sk_live_4e…3Hc",
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
  "confidence": 0.999
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
`is_default_excluded` in `crates/sources/src/filesystem.rs`.

## Interactive TUI dashboard

For an interactive scan with a live finding feed, current-file
banner, and stats panel showing throughput and backend choice:

```sh
keyhog tui .                       # scan CWD with live dashboard
keyhog tui src/ --throttle-ms 200  # paced scan, good for demos/recordings
keyhog tui . --feed-depth 500      # keep last 500 findings in feed
```

The TUI builds on the same scanner core; `q` or `Esc` quits, and a
non-zero exit code is returned when any findings are surfaced. Useful
for sitting next to a developer demoing keyhog, or recording a vhs
GIF for a README or talk.

## Going further

Once the basic scan works:

- [Output formats](./output-formats.md) - JSON, SARIF, plain text.
- [Verification](./verification.md) - `--verify` makes API calls to
  confirm credentials are live, downgrades dead ones to severity LOW.
- [Pre-commit hook](./workflows/precommit.md) - block leaked creds
  before they hit the repo.
- [CI integration](./workflows/ci.md) - GitHub Actions, GitLab CI,
  CircleCI patterns.
