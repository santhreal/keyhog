# CVE / known-leak replay corpus

Each `*.toml` file pins ONE publicly disclosed credential leak and
asserts keyhog still surfaces it. The runner
(`tests/cve_replay_runner.rs`) walks this directory the same way the
per-detector contract runner walks `tests/contracts/`.

## Why this exists

A detector that fired on a vendored CVE fixture at commit N must
keep firing on that same fixture at commit N+M. Real public leaks
are the strongest possible recall test, they're the exact shapes
the engine will face in the wild.

## Schema

```toml
schema_version = 1

# Canonical CVE / advisory ID. Use the GitHub advisory ID when there
# is no CVE number (common for npm / PyPI supply-chain leaks).
cve_id          = "CVE-2024-XXXXX"

# Provenance: where the leaked secret came from. Required.
# Should be a permanent, citable source: a public CVE page, a
# vendor disclosure, a GHSA, a public commit on GitHub, etc.
source_url      = "https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"
source_commit   = "abc1234"     # optional, when source is a commit

# Detector(s) the leak is expected to fire. The runner asserts
# at least one of these labels appears on a finding for the fixture.
# (`OR` semantics, some shapes match multiple detectors via the
# cross-detector deduplication path.)
detectors       = ["aws-access-key"]

# Affected service. Used for human-readable scoreboard rollup.
service         = "aws"

# A one-line summary for the scoreboard. Keep it short.
description     = "AWS access key checked into committed config"

# The leaked text, verbatim from the public source.
#
# CRITICAL: this is the EXACT public-domain leaked bytes, not a
# fabrication, not a redaction. KeyHog must surface this credential
# under at least one detector listed above. If a credential is in
# this file and the source URL no longer publishes it (revoked,
# rotated), keep the entry, historic recall still matters and the
# regex shape was real.
leaked_text     = """
... raw leaked text including surrounding context (one line is
usually enough) ...
"""
```

## How the runner uses entries

For each TOML:

1. Build a `Chunk` whose `data` is `leaked_text`.
2. Call `scanner.scan(&chunk)` (default backend, default config).
3. Assert at least one finding's `detector_id` ∈ `detectors` OR the
   finding's `credential` string is contained verbatim in
   `leaked_text` (covers the cross-detector dedup relabel).
4. On failure, dump every finding the scanner produced so the diff
   is obvious.

## Adding entries, checklist

- [ ] Public, citable source URL (the keyhog repo cannot host
      live unrotated credentials without authorization).
- [ ] At least one detector listed.
- [ ] `leaked_text` literally contains the secret as it leaked.
- [ ] If revoking takes the secret out of circulation, keep the
      entry: the regex shape stays the gate.
- [ ] If the leak straddles multiple lines (PEM key, JSON config),
      include the full block; the contract is "find this exact
      bytes-on-disk shape," not "find a needle in a haystack."
