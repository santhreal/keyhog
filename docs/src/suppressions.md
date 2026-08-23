# Suppressions

A suppression removes a match that you have reviewed and accepted. Use the
narrowest rule that describes the exception. A path-wide or detector-wide rule
can hide a different credential later.

KeyHog has three layers, and only the last two are suppression:

- The directory walker, which decides whether a file is read at all. See
  [Files the walker never reads](#files-the-walker-never-reads) below. This
  layer is the one that surprises people, because a file it drops produces no
  finding and no detector ever sees it.
- Operator surfaces that you configure, such as allowlists, inline directives,
  per-detector floors, and baselines.
- Always-on shape and path heuristics. These remove shapes that are not
  credentials. You cannot disable them. See
  [How detection works](./detection.md#stage-4---post-process).

> **There is no `.keyhog.toml [suppress]` table.** Older docs showed a
> `[suppress] hashes = […] / paths = […] / detectors = […]` block. It never
> existed. Current `.keyhog.toml` parsing rejects unknown tables and keys
> before scanning, so `[suppress]` fails loudly instead of creating a silent
> no-op. Use the surfaces below instead. Per-detector control lives under
> `[detector.<id>]`; hash/path/detector allowlisting lives in `.keyhogignore`.

## Files the walker never reads

A directory scan skips some files before detection starts. Put a credential in
`vendor/lib/conf.env` and `keyhog scan .` exits `0`:

```text
  No secrets detected in the scanned files.
```

```text
WARN 1 path(s) skipped by the DEFAULT exclusion policy (lock files, minified/bundled assets, vendored and build-output trees). Default-excluded directories are pruned during discovery and counted once each; nested files under them are not enumerated. Pass `--no-default-excludes` to scan them.
```

The warning goes to stderr and the exit code stays `0`, so a CI job that reads
only stdout and the exit status sees a clean scan.

Discovery prunes a default-excluded directory as soon as its name matches, so
an 80,000-file `node_modules` tree contributes one Excluded path rather than
eighty thousand. File-level default excludes (lock files, `.min.` / `.bundle.`
names) are still counted one per file. A path is skipped when any segment of
it, at any depth, is one of these names:

```text
.git  node_modules  target  .cache  __pycache__  .venv  venv  .tox
dist  build  out  .next  .nuxt  vendor  swagger  swagger-ui
```

`services/out/conf.env` and `app/dist/conf.env` are both skipped. The list also
covers lock files, editor backups, and filenames containing `.min.` or
`.bundle.`. The shipped list is `crates/sources/rules/default_excludes.toml`.

Decide whether that list matches your repository. Go and PHP projects keep
dependencies in `vendor/`. Java and many JavaScript projects build into
`build/`, `dist/`, or `out/`, and some teams keep hand-written code in a
directory that happens to carry one of those names. Scan everything with:

```sh
keyhog scan . --no-default-excludes
```

To scan one excluded tree without disabling the list, name it directly:

```sh
keyhog scan vendor/
```

Minified and vendored paths get a second rule that runs after matching, not
just at the walker. A finding in `.min.js`, `.bundle.js`, `.min.css`, or under
a vendored tree is dropped by default, because random bytes in a third-party
bundle collide with credential shapes often. The drop is counted and reported
as its own coverage-gap row naming how many matches were dropped, and
`--no-default-excludes` turns off this rule as well as the walker skip:

```sh
keyhog scan dist/ --no-default-excludes
```

Build tooling inlines API keys into frontend bundles, so treat a nonzero count
on that row as worth one rerun rather than as noise.

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
| 12 | Baseline (`--baseline` / `--update-baseline`) | detector id + credential hash, never the path | resolved finding | flag |

Everything is wired through `filter_and_resolve` (raw stage) and the run loop
(resolved stage), so the `--daemon` route and every output format apply the
exact same set; there is no path that scans under a weaker suppression policy.

### Precedence and discovery

Suppression is additive. A match removed by any surface stays removed. There is
no negation rule that restores a match removed by an earlier surface.

For a directory scan, KeyHog loads `.keyhogignore` and
`.keyhogignore.toml` from the scan root. For a single-file scan, it uses the
file's parent directory. Source modes without a filesystem scan path use the
current directory. `[allowlist].file` in `.keyhog.toml` replaces the discovered
line-based `.keyhogignore`; it does not replace `.keyhogignore.toml`.

That last rule has a sharp edge. `keyhog scan --stdin` has no scan path, so it
picks up whatever `.keyhogignore` sits in the directory you happen to be
standing in, and applies it to input that has nothing to do with that
repository:

```sh
cd ~/work/some-repo
kubectl get secret app -o yaml | keyhog scan --stdin
```

A credential whose hash that repository has allowlisted is reported when you
run the same pipe from `/tmp`, and silently dropped when you run it from the
checkout. Exit `0`, empty report, and nothing saying an allowlist was
consulted.

Only `hash:` entries can do this. A `path:` rule needs a path to match, and a
pipe has none. So the size of the risk is the number of live hash entries in
that file, not its total length, and the values most likely to be listed are
vendor-docs examples, fixture shapes, and documentation credentials, which is
exactly the class that also turns up in somebody else's real configuration.

Run piped scans from a directory with no `.keyhogignore`, or pass `--config`
with a `.keyhog.toml` whose `[allowlist].file` names the policy you intend.

Within `.keyhogignore`, every active line is an alternative. Within one
`.keyhogignore.toml` table, predicates use AND. Separate tables use OR. The two
files also use OR, so a broad line-based rule cannot be narrowed by adding a
declarative rule.

---

## Operator surfaces

Choose a surface by scope:

| Exception | Prefer | Avoid |
|---|---|---|
| One value in one fixture | `.keyhogignore.toml` with detector, path, and hash | Disabling the detector |
| One value wherever it appears | `hash:` in `.keyhogignore` | Storing the plaintext credential |
| One finding in a local source file | Detector-scoped inline directive | Unscoped directive on a line with several values |
| Findings that predate adoption | Baseline | Path rules for the whole legacy tree |
| A detector that is not applicable to the repository | `[detector.<id>] enabled = false` | A large list of per-file rules |

### Triage artifacts

`keyhog triage` imports a redacted finding envelope and creates two different
artifacts. `--suppressions` contains dismissed decisions for the `exact`,
`path`, and `repository` scopes. `--pattern-feedback` contains validated
training observations. A `pattern-feedback-only` decision appears only in
training feedback and can never become runtime suppression.

The envelope and both outputs have independent version fields. Each record
carries a finding hash, a stable detector ID, the exact public
`evidence.provenance` object from the scanner, a bounded context digest, a typed
reason, and one scope. Provenance binds the 16-hex active detector digest,
nullable pattern index, candidate channel, source role, context class, and the
channel-specific detector owner. A reported `:reassembled` suffix resolves to
the same embedded detector; every other synthetic suffix fails closed.
Path and repository scopes carry BLAKE3 identities. None of these files accepts
a credential value, context text, filesystem path, repository URL, or free-form
reason.

```json
{
  "version": 1,
  "detector_digest": "0123456789abcdef",
  "records": [{
    "finding_hash": "blake3:<64-lowercase-hex>",
    "detector_id": "<stable-detector-id>",
    "provenance": {
      "schema_version": 1,
      "detector_digest": "0123456789abcdef",
      "pattern_index": 0,
      "candidate_channel": "pattern",
      "source_role": "standalone-token",
      "context_class": "unsupported-context"
    },
    "context_digest": "blake3:<64-lowercase-hex>",
    "disposition": "dismissed",
    "reason": "false-positive",
    "scope": {
      "path": {
        "path_hash": "blake3:<64-lowercase-hex>"
      }
    }
  }]
}
```

The command accepts only the detector corpus built into the running binary. On
Unix, every input read, output create, and failed-output cleanup resolves
relative to held no-follow directory descriptors. Windows builds fail before
reading the envelope because equivalent reparse-point-safe held-handle I/O is
not available. Stale detector or pattern identities, unknown fields, malformed
digests, version mismatches, excessive input, symbolic links, special input
files, and existing output files fail without publishing either output. See
[Triage and feedback interchange](./guides/triage-feedback.md) and
[`keyhog triage`](./reference/cli.md#keyhog-triage).

### `.keyhogignore`: one condition per line

Create `.keyhogignore` at the scan root. Each non-comment line suppresses by
credential hash, detector ID, or path glob:

```text
# One reviewed credential value, stored only as its SHA-256 digest.
hash:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

# Every finding from one detector.
detector:generic-password

# Files below fixtures/ at the scan root.
path:fixtures/**

# A bare non-hash entry is also a path glob.
**/*.min.js
```

A bare 64-character hexadecimal line is a credential hash. Prefer the `hash:`
prefix because a 64-character path would otherwise be ambiguous. `*` matches
one path segment. `**` matches zero or more segments. A trailing slash matches
the directory and its descendants. Patterns without a leading `**` are rooted,
so `fixtures/**` does not match `packages/app/fixtures/demo.env`.

Generate a candidate hash rule from the exact finding you reviewed:

```sh
keyhog scan fixtures/oauth.env --format json \
  | jq -r '.[] | select(.detector_id == "generic-api-key" and .location.line == 3) |
      "hash:" + .credential_hash'
```

Review the printed line before you add it. This command prints nothing if the
detector ID or line does not match. Do not substitute the redacted display value
or add a `sha256:` prefix.

Optional governance metadata follows an entry after `;`:

```text
hash:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 ; reason="published OAuth client_id" ; expires=2026-12-31 ; approved_by="secops"
```

`require_reason`, `require_approved_by`, and `max_expires_days` under
`[allowlist]` in `.keyhog.toml` can require this metadata. These governance
rules are enforced before any suppression is active. An expired entry,
invalid hash, unknown metadata key, missing required field, or overlong expiry
stops the scan with exit `2`. No line from that file becomes active.

### `.keyhogignore.toml`: combine conditions

Use `.keyhogignore.toml` when one condition is too broad. The following rule
suppresses only one reviewed AWS fixture value:

```toml
[[suppress]]
detector = "aws-access-key"
path_eq = "fixtures/aws.env"
credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
```

All three predicates must match. A finding with the same hash in another file,
or a different credential in this file, still reports. See the
[`.keyhogignore.toml` reference](./reference/keyhogignore-toml.md) for every
predicate and more examples.

An empty `[[suppress]]` table and `literal_true = false` by itself are rejected.
Write `literal_true = true` only for an intentional match-everything policy.
Unreadable TOML, invalid TOML, an unknown predicate, or an invalid severity
stops the scan with exit `2`. KeyHog does not continue with an empty
declarative policy.

### Inline directives: suppress one local source line

Put a directive in a comment on the finding's line or the line immediately
above it. Scope the directive to a detector whenever the line can contain more
than one value:

```js
const token = process.env.STRIPE_TEST_TOKEN; // keyhog:ignore detector=stripe-secret-key
```

Recognized directives are `keyhog:ignore`, `keyhog:allow`, `gitleaks:allow`,
and `betterleaks:allow`. Recognized comment markers are `//`, `#`, `--`, `/*`,
and `<!--`.

Without `detector=`, the directive suppresses every finding on that line. A
different detector ID does not suppress the finding. Inline directives are read
from local filesystem source text. They do not act as an allowlist for archive
members, Git history, or remote sources. Use an allowlist file for those modes.

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

Surface #3 leaves no coverage-gap row. Its drops are recorded only as dogfood
telemetry, so a credential planted under `detectors/`, `tests/`, `fixtures/`,
or `benches/` inside a keyhog checkout comes back clean with no gap and no
warning. Pass `--no-suppress-test-fixtures` for any scan of keyhog's own tree
that has to be trustworthy.

### Confidence and severity floors

- `--min-confidence <f>` (or `[scan].min_confidence`) drops findings below a
  score. A per-detector `[detector.<id>].min_confidence` takes precedence for
  that detector.
- `--severity <level>` drops findings below a severity rank.
- `--hide-client-safe` drops the client-safe tier (public-by-design keys).

### Baselines: suppress what already existed

A baseline is a JSON file listing findings you have already reviewed. Later
scans report only the findings that are not in it. Adopt one in two commands:

```sh
keyhog scan . --create-baseline .keyhog-baseline.json
keyhog scan . --baseline .keyhog-baseline.json
```

`--create-baseline` writes the file, prints no findings, and exits `0`. The
second command reports only new findings, so an unchanged repository exits `0`
and a newly committed credential exits `1`. Commit the file and review changes
to it like code.

#### What counts as a new finding

A baseline entry is keyed on one pair: the detector ID and the SHA-256 of the
credential value. `file_path` and `line` are written for human review. Neither
one takes part in matching.

```json
{
  "version": 2,
  "created": "2026-08-04T09:12:33.104882731+00:00",
  "entries": [
    {
      "detector_id": "github-classic-pat",
      "credential_hash": "sha256:94b9b7f8b35f61bbec1125726f7a794010497975d7f69ce6d0dcb43b7a5913db",
      "file_path": "/home/dev/service/app.env",
      "line": 1,
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
      }
    }
  ]
}
```

Baseline schema 2 records the finding's required evidence verdict and
schema-1 candidate provenance. Schema 1 baselines and entries without exact
evidence provenance are rejected; regenerate them before scanning.

That key decides every outcome:

| Change in the repository | Result |
|---|---|
| The credential moves to another line or another file | Still suppressed |
| The tree is checked out at a different path, or the file is renamed | Still suppressed |
| The same credential is copied into a second file | Still suppressed, in both places |
| The credential is rotated to a new value | Reported as new |
| A different credential appears in a baselined file | Reported as new |
| A second detector matches the same value | Reported as new, under that detector ID |

Plan for the third row. A baseline accepts a credential value, not a location.
If someone copies a baselined key into a new service, the gate stays silent.
Rotate anything you are not willing to accept everywhere, and keep the baseline
small enough that a reviewer can read it.

`file_path` is an absolute path from the machine that wrote the file. Generate
the baseline from one place so a committed baseline does not churn with each
developer's checkout directory.

#### Accept new findings after review

`--update-baseline` folds new findings into the file and still reports them:

```sh
keyhog scan . --update-baseline .keyhog-baseline.json
```

The scan prints each new finding and applies the active evidence policy, exactly
as `--baseline` does. Updating the file does not change the exit code. Run this
locally once you have reviewed the findings and decided to accept them, then
commit the result. Never run it in CI: a job that rewrites its own baseline
accepts every secret it finds.

KeyHog never removes an entry. After you rotate a credential, delete its entry
by hand or regenerate the file with `--create-baseline`. A stale entry keeps
suppressing the old value indefinitely.

#### Compare two baselines

`keyhog diff` reports what changed between two baseline files, which is how you
review a proposed baseline update:

```sh
keyhog scan . --create-baseline proposed.json
keyhog diff .keyhog-baseline.json proposed.json
```

```text
keyhog diff

  PASS 0 new   PASS 0 removed   = 2 unchanged

UNCHANGED entropy-api-key @ /home/dev/service/sub/other.env:2
UNCHANGED github-classic-pat @ /home/dev/service/app.env:1
PASS no new or unverified live-risk findings
```

Add `--json` to gate on the result in CI, or `--hide-unchanged` when only the
changes matter. Run `keyhog diff --help` for every option.

#### What a baseline does not do

- It does not exclude bytes from scanning. Use a `path:` rule in
  `.keyhogignore` when a tree should not be read at all.
- It does not suppress a coverage gap. A scan with unreadable or truncated
  input still reports the gap, and a gap with no blocking finding still exits
  `13`.
- It is not a shared allowlist. Matching ignores the path, so one file would
  work across several repositories, and that is exactly the problem: one team's
  accepted credential would silently pass another team's gate. Keep one
  reviewed set per repository.

For a complete CI gate built on a baseline, see
[Fail only on new secrets](./workflows/ci.md#fail-only-on-new-secrets).

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
`canonical_hex_key_material` keyword/length pairs plus detector-owned suffixes
for vendor-prefixed names. A named regex detector declares a length-only rule;
the matched pattern is its scope. The shipped generic API-key detector admits
32/48-hex for strong key roles and vendor-prefixed `*_key`/`*_secret` names, and 64-hex
only for its explicit cryptographic roles such as `encryption_key`,
`signing_key`, and `hmac_secret`; the generic-secret detector separately owns
`private_key`, `signing_secret`, `secret`, and its vendor-prefixed forms. Bare
`key` and `license_key` remain suppressed. There is no scanner-global service-key
width fallback: omitting the detector policy leaves the value digest-suppressed.
Generic UUID assignments, public salts, and nonces stay suppressed; a named
detector or structural authorization envelope must provide stronger evidence.
Canonical policy does not bypass placeholder or degenerate-value checks. Short
repeated runs remain valid because they occur naturally in random material over
the 16-symbol hex alphabet; a run of ten identical bytes is treated as filler.

### Path-based

Path policy is mechanism-specific. CI and localization paths do not disable
named detectors. A valid GitHub, AWS, or other service credential still reports
there. Those paths suppress only broad entropy candidates whose positive
evidence is the file's prose or syntax.

| Path class | Named detector | Generic assignment | Entropy fallback |
|---|---|---|---|
| Recognized vendored or minified trees and bundles | Suppressed after matching | Suppressed | Suppressed |
| CI workflows and pipeline files | Scanned | Scanned | Suppressed |
| Localization and translation files | Scanned | Scanned | Suppressed |
| Secret-scanner implementation paths | Suppressed after matching | Normal generic policy | Normal entropy policy |

Decoded and recovered candidates keep their source path and return through the
ordinary detector and suppression pipeline. A transform does not erase path
policy or turn a CI or localization path into a blanket exclusion.

Vendored and minified classes include `node_modules/`, specific static or
vendored asset pairs, WordPress trees, recognized Rails legacy vendored assets,
`*.min.js`, `*.bundle.js`, and `*.min.css`. A bare `vendor/` directory is not a
blanket exclusion at this layer, but the directory walker drops it earlier, so
a `vendor/` credential is still absent from a plain `keyhog scan .`. See
[Files the walker never reads](#files-the-walker-never-reads).
CI classes include GitHub Actions, GitLab CI, CircleCI,
`Jenkinsfile`, Travis, Azure Pipelines, and Bitbucket Pipelines. Localization
classes include locale, i18n, l10n, translation, and language directories plus
gettext files. Secret-scanner paths match shipped scanner-name markers.

These built-in predicates are not configurable. "Normal policy" means the
mechanism evaluates its ordinary value, context, and path gates. It is not a
blanket suppression for secret-scanner paths. If a predicate suppresses a real
credential under a mechanism shown as scanned, report it as a recall bug.

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
keyhog scan . --dogfood --quiet 2>&1 >/dev/null | jq '.dogfood.events[]'
```

`2>&1 >/dev/null` sends the dogfood object (stderr) to `jq` while discarding
the normal report (stdout). `--quiet` is required for a parseable stream:
without it, materialization, cache, and autoroute status lines share stderr and
precede the object. `--dogfood` is independent of `--format`, so the report
format does not matter here.

Suppression events carry the path, redacted credential, and rule that fired.
`static_recovery_rejected` events carry the decoder, reason, path, and absolute
expression byte offset. Internal detail deduplication also uses source type and
optional commit, so equal paths from separate history revisions remain separate
events. Aggregate counts measure every rejected evaluation attempt. Repeated
evaluation of one expression can therefore increment an aggregate without
duplicating its retained detail.
The events never contain source or recovered bytes. Detail retention is capped
at 1,024 events per scan. Aggregate rejection counts remain exact after the cap.
`detail_events_dropped` reports retention-bound drops and recording attempts
rejected because the detail buffer was unavailable.

## Adding a suppression for an FP cluster

If you find a cluster of 5+ FPs that share a shape, file an issue with:

1. The detector that fired.
2. A sanitized example (replace the captured value with `[REDACTED]`).
3. Why it is not a credential (regex shouldn't have matched, or a shape gate
   should have caught it).

The right fix is a tightened regex, a new shape filter, or a path exclusion.
Adding the literal credential to the test-fixtures list is the LAST resort: it
hides one specific value, not the underlying shape.
