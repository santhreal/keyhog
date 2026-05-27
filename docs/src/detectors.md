# Detectors

A **detector** is a single TOML file that teaches KeyHog one shape of
credential. There are 891 of them in the embedded corpus today,
spread across `detectors/*.toml`.

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
The CLI's exit code only depends on whether ANY finding exists, but
SARIF / GitHub Code Scanning surface severity prominently.

`client-safe` is the bug-bounty tier for keys public by design
(Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, Firebase
Web API key, Google Maps browser key, Mixpanel project token,
Algolia search-only, Datadog browser RUM, Bugsnag, Segment write
key). The detector still fires (a token grep is a token grep), but
the finding renders below `low` and `--hide-client-safe` filters it
out entirely. Set per-pattern via the `client_safe = true` field on
a `[[detector.patterns]]` block — detectors that fire on both the
public and the secret prefix (Stripe `pk_*` vs `sk_*`, Mapbox `pk.`
vs `sk.`) tag only the public pattern so a misused secret key still
surfaces at its nominal severity.

`detector.keywords` - strings the prefilter ahokorasick matches on.
At least ONE keyword in the chunk is required before the regex even
runs. Pick keywords that are short, distinctive, and likely to appear
near a real credential (`stripe`, `sk_live_`, `STRIPE_SECRET_KEY`).

`detector.patterns[]` - one or more regexes. Each carries:

- `regex` - the pattern. Compiled with `CASELESS` (matches both cases
  without explicit alternation).
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
1–3 patterns covering env-var, JSON, and inline forms.

`detector.companions[]` - optional. Some credentials are only useful
in pairs (AWS access key + secret key). A companion is a second regex
that must match within N lines of the primary; without it, the
primary's finding is dropped.

`detector.verify` - optional. If present, `keyhog scan --verify`
makes the documented API call with the captured credential and:
- live + valid → keep severity, mark `verification: "verified-live"`
- live + invalid → downgrade severity one tier, mark `"verified-dead"`

## Listing detectors

```sh
keyhog detectors                  # human-readable list, grouped by service
keyhog detectors --json           # one JSON object per detector
keyhog detectors --json | jq length
891
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

## Disabling detectors

```sh
keyhog scan . --disable-detectors stripe-secret-key,aws-access-key
```

Or via config (`.keyhog.toml` in the repo root):

```toml
[scan]
disable_detectors = ["stripe-secret-key", "aws-access-key"]
```

The disabled set is checked AFTER detection, so the regex still runs;
the finding is just dropped at emit time. Use this when a detector
generates persistent FPs in your repo and you want to silence it
while keeping the rest of the scan.

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
