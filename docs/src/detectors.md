# Detectors

A **detector** is a single TOML file that teaches KeyHog one shape of
credential. There are 920 of them in the embedded corpus today,
spread across `detectors/*.toml`.

## Pattern counts

KeyHog counts **detectors** and **patterns** separately. A detector is one
TOML file; each file may define one or more `[[detector.patterns]]` rows.
The startup banner's parenthesized pattern total is the compiled scanner
count after the engine expands those rows (and related trigger keywords)
into the literal and regex slots it actually runs, so it is always larger
than the raw TOML row count. Use `keyhog detectors --json | jq length` for
the embedded detector count; the banner line shows the live compiled total
for your binary.

## Anatomy of a detector

```toml
# detectors/stripe-secret-key.toml

[detector]
id = "stripe-secret-key"
name = "Stripe Secret Key"
service = "stripe"
severity = "critical"
keywords = ["sk_live_", "sk_test_", "stripe"]

[[detector.patterns]]
regex = "sk_(?:live|test)_[a-zA-Z0-9]{24,}"
description = "Stripe secret key - live or test mode"
group = 0

[detector.verify]
method = "GET"
url = "https://api.stripe.com/v1/charges?limit=1"

[detector.verify.auth]
type = "bearer"
field = "match"

[detector.verify.success]
status = 200
```

That's the whole contract for one service. Every other detector
follows the same shape.

### Fields

`detector.id` - kebab-case, globally unique. Shows up in JSON output
as `detector_id` and in CLI output as the third column.

`detector.name` - human-readable name. Shows up in `keyhog detectors`
listing and IDE plugins.

`detector.service` - the upstream service slug. Used for grouping
findings (e.g. "you leaked 3 stripe credentials"); a single service
can have multiple detectors (`stripe-secret-key`,
`stripe-restricted-key`, `stripe-publishable-key`).

`detector.severity` - one of `critical | high | medium | low | client-safe | info`.
The CLI exits non-zero when any finding clears the active gate; under
`--verify`, confirmed live credentials escalate that outcome to exit `10`.
SARIF / GitHub Code Scanning surface severity prominently.

`client-safe` is the bug-bounty tier for keys public by design
(Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, Firebase
Web API key, Google Maps browser key, Mixpanel project token,
Algolia search-only, Datadog browser RUM, Bugsnag, Segment write
key). The detector still fires (a token grep is a token grep), but
the finding renders below `low` and `--hide-client-safe` filters it
out entirely. Set per-pattern via the `client_safe = true` field on
a `[[detector.patterns]]` block - detectors that fire on both the
public and the secret prefix (Stripe `pk_*` vs `sk_*`, Mapbox `pk.`
vs `sk.`) tag only the public pattern so a misused secret key still
surfaces at its nominal severity.

`detector.keywords` - strings the prefilter Aho-Corasick automaton matches on.
At least ONE keyword in the chunk is required before the regex even
runs. Pick keywords that are short, distinctive, and likely to appear
near a real credential (`stripe`, `sk_live_`, `STRIPE_SECRET_KEY`).

`detector.patterns[]` - one or more regexes. Each carries:

- `regex` - the pattern. Every regex is compiled `case_insensitive`, so
  it matches both cases without explicit alternation. To make a single
  pattern case-SENSITIVE (AWS `AKIA` is uppercase; some GCP/Snowflake ids
  are lowercase), prefix its regex with the inline flag `(?-i)` in the
  TOML - no schema field needed.
- `group` - which capture group is the credential. `0` = whole match,
  `1` = first captured group, etc.
- `description` - what shape this captures (env var, header, URL, …).
- `client_safe` - optional bool, default `false`. When `true`, any
  match against this pattern collapses to `Severity::ClientSafe`
  regardless of the detector's nominal severity. Use for patterns
  that capture keys the vendor expects to ship in client bundles
  (Sentry DSN, Stripe `pk_*`, etc.). Per-pattern (not per-detector)
  so a detector that covers both the public and the secret prefix
  can tag only the public one.

Multiple patterns means "any of these shapes". A typical detector has
1-3 patterns covering env-var, JSON, and inline forms.

`detector.companions[]` - optional. Some credentials are only useful
in pairs (AWS access key + secret key). A companion is a second regex
that must match within N lines of the primary; without it, the
primary's finding is dropped.

`detector.verify` - optional. If present, `keyhog scan --verify`
makes the documented API call with the captured credential and:
- live + valid -> keep severity, mark `verification: "live"`
- live + invalid -> downgrade severity one tier, mark `verification: "dead"`

## Per-detector recall/precision knobs

Under KeyHog's architecture, there is no global or overall entropy, length, or recall/precision gate applied uniformly to every candidate. Instead, every threshold, filter, allowlist, and tuning parameter that affects whether a candidate match is reported is a **per-detector field**, owned directly inside the detector's TOML file under the `[detector]` table.

This follows the design precedent established by `min_confidence` (the per-detector confidence floor) and `entropy_floor` (the low-entropy suppression floor).

If a detector leaves these fields unset, KeyHog falls back to single-owner global defaults (e.g. the default thresholds defined in the scanner's entropy module). However, if set, the detector's TOML configuration overrides the defaults.

The available per-detector tuning fields are:

### Entropy Thresholds
*   **`entropy_high`** (float, optional): Per-detector high-entropy threshold (bits/byte) for keyword-independent detection. Falls back to `HIGH_ENTROPY_THRESHOLD` (4.5) if unset.
*   **`entropy_low`** (float, optional): Per-detector keyword-context (low) entropy threshold. Falls back to `LOW_ENTROPY_THRESHOLD` (3.0) if unset.
*   **`entropy_very_high`** (float, optional): Per-detector very-high entropy threshold for keyword-free or isolated tokens. Falls back to `VERY_HIGH_ENTROPY_THRESHOLD` (5.8) if unset.
*   **`mixed_alnum_floor`** (float, optional): Per-detector mixed alpha-numeric token entropy floor. Falls back to `MIXED_ALNUM_TOKEN_THRESHOLD` (4.0) if unset.
*   **`entropy_floor`** (array of tables, optional): Length-bucketed low-entropy suppression floor mapping maximum lengths to minimum entropy scores. Falls back to `EntropyFloorTable::DEFAULT_FLOOR` if unset.

### BPE token efficiency
*   **`bpe_max_bytes_per_token`** (float, optional): Per-detector
    `cl100k_base` characters-per-token ceiling. Values above the ceiling are
    efficiently tokenized, word-like candidates and are suppressed after the
    cheaper shape and entropy gates. The detector field takes precedence over
    the compiled scan fallback. An explicitly configured
    `[scan].entropy_bpe_max_bytes_per_token` or CLI flag is the final Tier-A
    override for all eligible detectors. Lower ceilings favor precision and
    higher ceilings favor recall. This is the
    token-efficiency mechanism popularized by Betterleaks, not another Shannon
    entropy calculation: it measures language-model subword compressibility.
    A generic detector may use it as the main **precision discriminator** by
    choosing a permissive detector-local entropy floor and a measured BPE
    ceiling, or compose both gates when byte-distribution and language-likeness
    each reject different noise. It is not a candidate generator: the
    detector's regex or phase-2 assignment/entropy discovery path must first
    produce a candidate. Betterleaks' current source calls this Token Efficiency,
    not BPD; KeyHog uses `bpe_...` field names to keep that distinction explicit.

### Candidate Lengths
*   **`keyword_free_min_len`** (integer, optional): Per-detector minimum length for an anchor-free (keyword-free or isolated) candidate. Falls back to `KEYWORD_FREE_MIN_LEN` (20) if unset.
*   **`min_len`** (integer, optional): Per-detector minimum candidate length for any candidate this detector emits. Falls back to no detector-specific floor beyond the path-wide default if unset.

### Allowlists & Exclusions
*   **`allowlist_paths`** (array of strings, optional): Per-detector path-exclusion regexes (betterleaks-style allowlist). Any candidate match whose file path matches any of these regexes is suppressed.
*   **`allowlist_values`** (array of strings, optional): Per-detector value-exclusion regexes. Any candidate secret value matching any of these regexes is suppressed (useful for filtering out test, example, or placeholder values).
*   **`stopwords`** (array of strings, optional): Per-detector literal stopwords. A matched value equal to or containing any of these strings (case-insensitive) is suppressed.

### Confidence Floors
*   **`min_confidence`** (float, optional): Per-detector minimum confidence floor. Overrides the global scan confidence floor.

## Listing detectors

```sh
keyhog detectors                  # human-readable list, grouped by service
keyhog detectors --json           # one JSON object per detector
keyhog detectors --json | jq length
920
```

Filter by service:

```sh
keyhog detectors --json \
  | jq '.[] | select(.service == "stripe")'
```

## Explaining one detector

```sh
keyhog explain stripe-secret-key
```

Prints the full TOML contents, the keywords, the patterns with their
descriptions, the verification endpoint, and any companions. Useful
when debugging "why didn't this fire?" - usually the answer is in the
regex or keywords.

## Custom detectors

Drop a `.toml` next to the binary or in `~/.config/keyhog/detectors/`:

```toml
# ~/.config/keyhog/detectors/my-internal-token.toml

[detector]
id = "acme-internal-token"
name = "ACME internal API token"
service = "acme-internal"
severity = "high"
keywords = ["ACME_API_TOKEN", "acme_internal_"]

[[detector.patterns]]
regex = "acme_internal_[a-zA-Z0-9]{32}"
group = 0
```

Restart the scanner and the new detector is loaded alongside the
built-ins. There's no opt-in, no flag, no rebuild - TOML in, detector
out.

## Disabling specific detectors

Turn off a detector by id in `.keyhog.toml`:

```toml
[detector.aws-access-key]
enabled = false

[detector.generic-secret]
enabled = false
```

Detector ids are the `detector_id` field in `--format json`/`jsonl` output, or
the left column of `keyhog detectors`. The high-precision fast-path detectors
are prefixed `hot-` (e.g. `hot-aws_key`); a service like AWS can have both a
`hot-` detector and a TOML detector, so disable both to silence it entirely:

```toml
[detector.hot-aws_key]
enabled = false
[detector.aws-access-key]
enabled = false
```

Disabled TOML detectors are dropped before the corpus compiles (zero scan
cost); disabled hot-pattern findings are filtered from the report. If an id
matches nothing in the loaded corpus, keyhog warns rather than silently
ignoring it.

## Running only a chosen subset

To run a curated set instead of the full corpus, point `--detectors` at a
directory holding only the TOMLs you want:

```sh
mkdir my-detectors
cp detectors/stripe-secret-key.toml detectors/aws-*.toml my-detectors/
keyhog scan . --detectors my-detectors/
```

## Quieting a noisy detector

When a detector produces persistent false positives in your repo,
down-weight it instead of dropping it entirely so a real hit still
surfaces:

```sh
keyhog calibrate --fp generic-api-key       # record a false positive
keyhog scan . --min-confidence 0.7          # filter low-confidence hits
```

Each `--fp` lowers that detector's Bayesian confidence multiplier
(persisted under the platform cache directory, normally
`$XDG_CACHE_HOME/keyhog/calibration.json`). Scans use those counters only when
you pass `--calibration-cache <PATH>` or set `[system].calibration_cache`, so
repeated FPs steadily push that detector below your `--min-confidence` floor
without hidden host-state drift. To suppress *specific* findings rather than a
whole detector, use a
[`.keyhogignore`](./suppressions.md), the `[allowlist]` config, or a
`--baseline`.

## Severity bumps and downgrades

Severity is a property of the detector, but can shift per-finding:

- **Git history → severity one tier lower.** A credential present only
  in non-HEAD git history (the developer already removed it from
  `main`) is still a leak - anyone can fetch it - but strictly less
  urgent than one live in HEAD. Reported in the `chunk.metadata.commit`
  field of the finding.

- **Verification: dead → severity one tier lower.** The credential was
  format-valid but the API rejected it. Could be a rotated key, a fake
  in a test file, or a typo.

- **Verification: live → severity unchanged.** The credential authenticates
  successfully. As bad as it can get.

## Writing your own - the short version

1. Find a real example of the credential format (vendor docs, leaked
   public sample, source).
2. Write the regex. Test it against the example, against a similar
   non-credential ("looks like, isn't"), and against an attacker-rotated
   form.
3. Add to `detectors/<service>-<thing>.toml` - `id`, `keywords`,
   `patterns`, optionally `verify`.
4. Add a contract file at `crates/scanner/tests/contracts/<id>.toml`
   with at least:
   - 2 positives (env-var form, quoted form)
   - 2 negatives (placeholder, EXAMPLE marker)
   - 2 evasions (the actual deployed credential shape from production)
5. Run `cargo test -p keyhog-scanner --test contracts_runner` - must
   pass for your detector to ship.

That's it. The contracts gate enforces that every shipped detector
catches what it claims to catch.
