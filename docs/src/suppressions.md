# Suppressions

A suppression is a filter that drops a candidate match before it becomes a
reported finding. KeyHog has **two kinds**:

- **Operator surfaces**: things *you* configure to silence findings you have
  reviewed and accepted (allowlists, inline directives, per-detector floors,
  baselines). This page is the single map of all of them.
- **Always-on shape/path heuristics**: built-in precision filters that drop
  shapes that are universally not credentials. You cannot turn these off; they
  are summarised at the bottom and detailed in
  [How detection works](./detection.md#stage-4---post-process).

> **There is no `.keyhog.toml [suppress]` table.** Older docs showed a
> `[suppress] hashes = […] / paths = […] / detectors = […]` block. It never
> existed. Current `.keyhog.toml` parsing rejects unknown tables and keys
> before scanning, so `[suppress]` fails loudly instead of creating a silent
> no-op. Use the surfaces below instead. Per-detector control lives under
> `[detector.<id>]`; hash/path/detector allowlisting lives in `.keyhogignore`.

## Where each surface fires

Suppression runs at one chokepoint, in this order. Earlier surfaces act on raw
matches (before dedup/verify); later ones act on resolved findings.

| # | Surface | Keyed on | Stage | Opt-out / scope |
|---|---------|----------|-------|-----------------|
| 1 | `[detector.<id>] enabled = false` (Tier-A compiled + Tier-B `.keyhog.toml`) | detector id | raw match | per-detector |
| 2 | Bundled `test-fixtures.toml` | exact / substring of the credential value | raw match | `--no-suppress-test-fixtures` |
| 3 | Self-scan test-data paths (keyhog repo only) | `detectors/` `tests/` `fixtures/` `benches/` segment | raw match | `--no-suppress-test-fixtures`; only inside keyhog's own tree |
| 4 | `.keyhogignore`: `path:` | path glob | raw match | file |
| 5 | `.keyhogignore`: `hash:` / bare hash | SHA-256 of value | raw match | file |
| 6 | `.keyhogignore`: `detector:` | detector id | raw match | file |
| 7 | `[detector.<id>] min_confidence` / `--min-confidence` | confidence score | raw match | floor |
| 8 | `--severity` | severity rank | raw match | floor |
| 9 | Inline `keyhog:ignore` (and aliases) | the line itself | raw match | in-source |
| 10 | `.keyhogignore.toml` `[[suppress]]` rules | composable predicate | resolved finding | file |
| 11 | `--hide-client-safe` | client-safe tier | resolved finding | flag |
| 12 | Baseline (`--baseline` / `--update-baseline`) | finding identity | resolved finding | flag |

Everything is wired through `filter_and_resolve` (raw stage) and the run loop
(resolved stage), so the `--daemon` route and every output format apply the
exact same set; there is no path that scans under a weaker suppression policy.

---

## Operator surfaces

### `.keyhogignore`: line-based allowlist (opt-in, project-scoped)

A `.keyhogignore` at your scan root, one rule per line. It accepts explicit
`hash:`, `detector:`, and `path:` rules. A bare 64-hex line is a credential hash;
other bare entries are path globs, so ordinary `.gitignore` entries work.

```text
# Ignore a specific credential by SHA-256 of the captured value (64 hex chars).
hash:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# A bare 64-hex line is also read as a hash (the jq-append workflow below).
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# Ignore every finding from one detector.
detector:generic-password

# Ignore files by glob.
path:fixtures/**
path:docs/example_*.env

# A bare glob with no prefix is a path rule (gitignore-style).
node_modules/
*.min.js
```

Hashes are bare 64-character hex (no `sha256:` prefix). Generate the exact line
to append from an existing run:

```sh
keyhog scan . --format jsonl | jq -r '"hash:" + .credential_hash' >> .keyhogignore
```

The `hash:` prefix is recommended for readability but optional for an exact
64-hex digest. `.credential_hash` is already the SHA-256 hex the rule expects.

**Governance metadata** (optional) trails an entry after `;`:

```text
hash:5e88…42d8 ; reason="published OAuth client_id" ; expires=2026-12-31 ; approved_by="secops"
```

An entry whose `expires` date is in the past is dropped at load time with a
fail-closed operator error, so short-lived approvals force a deliberate renewal.
The `require_reason` / `require_approved_by` / `max_expires_days` governance
flags under `[allowlist]` in `.keyhog.toml` are enforced before any suppression
is active; missing required metadata or an overlong expiry stops the scan.

### `.keyhogignore.toml`: declarative rule allowlist (opt-in, composable)

When a single glob/hash/detector line is too blunt, a `.keyhogignore.toml`
alongside it gives composable `[[suppress]]` rules. Fields within one table AND
together; separate tables OR together. Full schema and field list:
[`.keyhogignore.toml` reference](./reference/keyhogignore-toml.md).

```toml
# Drop aws-access-key findings under any tests directory.
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"

# Drop low-or-lower stripe findings on one fixture file.
[[suppress]]
service = "stripe"
severity_lte = "low"
path_eq = "fixtures/stripe.yml"

# Drop one credential everywhere (mirrors a .keyhogignore hash: line).
[[suppress]]
credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

A `[[suppress]]` table with no conditions is rejected (it would silently drop
every finding); write `literal_true = true` if you truly mean "drop all". A
malformed present `.keyhogignore.toml` is a policy failure and stops the scan
instead of being treated as an empty suppressor.

### Inline directives: suppress at the source line

Put a directive in a comment on the finding's line, or the line directly above
it. Recognised forms: `keyhog:ignore`, `keyhog:allow`, `gitleaks:allow`,
`betterleaks:allow` (the last two ease migration). Comment markers understood:
`//`, `#`, `--`, `/*`, `<!--`.

```python
API_KEY = "AKIA…EXAMPLE"  # keyhog:ignore
```

Scope it to one detector so an unrelated finding on the same line still fires:

```js
const token = "…";  // keyhog:ignore detector=stripe-secret-key
```

With no `detector=` token the directive suppresses every finding on that line.

### Per-detector control: `.keyhog.toml [detector.<id>]`

```toml
# Turn a noisy detector off entirely.
[detector.generic-password]
enabled = false

# Or keep it but raise its confidence floor (precedence over --min-confidence).
[detector.slack-webhook-url]
min_confidence = 0.85
```

Shipped floors and availability live in each detector's own TOML, which is
embedded into the binary and used by benches and default scans. Repository
`.keyhog.toml` entries are validated operator overrides composed into that
active corpus before scanning; there is no hidden Rust floor or disable list.

### Bundled test fixtures (always on, opt-out)

`crates/cli/data/suppressions/test-fixtures.toml`, baked into the binary, lists
publicly documented credentials that vendor docs ship as examples. It is matched
on the **exact captured value** (plus a tiny `substring` list for tokens like
`EXAMPLE` / `PLACEHOLDER`). Schema:

```toml
schema_version = 1

[[exact]]
credential = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
service = "stripe"
source = "https://docs.stripe.com/api/authentication"

[[substring]]
needle = "EXAMPLE"
```

Pass `--no-suppress-test-fixtures` to see them fire (useful when validating that
a detector still matches the canonical shape). The same flag also disables the
self-scan test-data path filter (#3), which only ever applies inside keyhog's
own source tree.

### Confidence and severity floors

- `--min-confidence <f>` (or `[scan].min_confidence`) drops findings below a
  score. A per-detector `[detector.<id>].min_confidence` takes precedence for
  that detector.
- `--severity <level>` drops findings below a severity rank.
- `--hide-client-safe` drops the client-safe tier (public-by-design keys).

### Baselines: suppress what already existed

Record the current findings, then on later runs report only *new* ones:

```sh
keyhog scan . --create-baseline .keyhog-baseline.json   # snapshot, report nothing
keyhog scan . --baseline .keyhog-baseline.json          # report only new findings
keyhog scan . --update-baseline .keyhog-baseline.json   # report new AND fold them in
```

---

## Always-on heuristics (cannot opt out)

### Shape-based

List-independent heuristics about credential shape that are universally true.

| Filter                             | Drops shapes like                                |
|------------------------------------|--------------------------------------------------|
| `punctuation_decorated_identifier` | `--api-secret`, `&password`, `$API_KEY`, `Password:`, `apiKey!` |

For generic-only / entropy-only / weakly-anchored detectors, additional shape
gates apply (pure-identifier, scheme-URI, UUID, base64-blob, …). See
[How detection works](./detection.md#stage-4---post-process) for the full list and
rationale.

Printable base64 is decoded once for the same structural checks. Encoded UUIDs,
IAM ARNs, labelled and canonical digests, license serials, prose, and placeholder
text remain non-secrets after transport encoding. The generic API-key detector's
`decoded_hex_key_material_lengths = [32, 48]` policy keeps those two encoded key
widths; 40-character SHA-1 and 64-character SHA-256 shapes remain
digest-suppressed. Structured decoding preserves transport provenance, so a
direct-assignment allowance cannot leak into a decoded value. Service-specific
detector TOMLs can supply stronger syntax and bypass only the shape gates their
anchor proves safe.

For direct pure-hex assignments, a phase-2 detector can declare exact
`canonical_hex_key_material` keyword/length pairs. The shipped generic API-key
detector admits 32/48-hex for strong key roles and 64-hex only for its explicit
cryptographic roles such as `encryption_key`, `signing_key`, and `hmac_secret`;
the generic-secret detector separately owns `private_key` and `signing_secret`.
Generic UUID assignments, public salts, and nonces stay suppressed; a named
detector or structural authorization envelope must provide stronger evidence.
Canonical policy does not bypass placeholder or degenerate-value checks. Short
repeated runs remain valid because they occur naturally in random material over
the 16-symbol hex alphabet; a run of ten identical bytes is treated as filler.

### Path-based

Specific directories produce findings that are almost always not credentials.
KeyHog ships a small, high-precision path policy:

| Path pattern | Why |
|--------------|-----|
| `node_modules/`, `vendor/`, `bower_components/`, `jspm_packages/`, `site-packages/` | Vendored third-party code; minified bytes coincide with secret prefixes |
| `wp-content/plugins/`, `wp-content/themes/`, `wp-includes/` | WordPress vendored trees |
| `app/assets/javascripts/bootstrap*.js`, `…/jquery*.js`, etc. | Rails legacy asset path, vendored JS |
| `*.min.js`, `*.bundle.js`, `*.min.css` | Minified bundles |
| `.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `Jenkinsfile`, `.travis.yml`, `azure-pipelines*`, `bitbucket-pipelines*` | CI config; `${{ secrets.X }}` is syntactic |
| `locale/`, `locales/`, `i18n/`, `l10n/`, `translations/`, `lang/`, `langs/`, `*.po`, `*.pot` | i18n files; translated `password`/`token` words are not credentials |
| Paths containing `secretscanner`, `secret-scanner`, `trufflehog`, `gitleaks`, `detect-secrets` | The file IS a secret scanner; its regex literals shouldn't fire on itself |

These are not configurable: their precision is high enough that making them
opt-in would only make the scanner louder. If one suppresses a path you care
about, that is a bug worth reporting.

> Not a suppression surface: `[lockdown] require = true` in `.keyhog.toml` (and
> `--lockdown`) is a fail-*closed* hardening control: it refuses to run, mlocks
> memory, and forbids disk cache / `--verify` / `--show-secrets`. It never hides
> a finding. Likewise `audit.toml` is cargo-audit's RustSec advisory ignore-list
> for keyhog's *own* dependencies (a supply-chain CI gate), unrelated to scan
> findings.

## Telemetry: what got suppressed

`--dogfood` prints one JSON object to **stderr**, separate from the findings
report on stdout. It includes exact example and static-recovery aggregates, a
bounded detail list, and `detail_events_dropped` when that list fills:

```json
{"dogfood":{"example_suppressions_total":0,"static_recovery_rejections":{},"detail_events_dropped":0,"events":[]}}
```

Capture stderr to inspect it:

```sh
keyhog scan . --dogfood 2>&1 >/dev/null | jq '.dogfood.events[]'
```

`2>&1 >/dev/null` sends the dogfood object (stderr) to `jq` while discarding
the normal report (stdout). `--dogfood` is independent of `--format`, so the
report format does not matter here.

Suppression events carry the path, redacted credential, and rule that fired.
`static_recovery_rejected` events carry the decoder, reason, source type, path,
optional commit, and absolute expression byte offset. Source type plus commit
keeps equal paths from separate history revisions distinct. The events never
contain source or recovered bytes. Detail retention is capped at 1,024 events
per scan. Aggregate rejection counts remain exact after the cap, and
`detail_events_dropped` reports every omitted detail, including an unavailable
detail buffer.

## Adding a suppression for an FP cluster

If you find a cluster of 5+ FPs that share a shape, file an issue with:

1. The detector that fired.
2. A sanitized example (replace the captured value with `[REDACTED]`).
3. Why it is not a credential (regex shouldn't have matched, or a shape gate
   should have caught it).

The right fix is a tightened regex, a new shape filter, or a path exclusion.
Adding the literal credential to the test-fixtures list is the LAST resort: it
hides one specific value, not the underlying shape.
