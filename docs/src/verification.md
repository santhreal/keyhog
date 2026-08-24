# Verification

`keyhog scan --verify` makes HTTP requests for eligible findings whose detector
declares a verification endpoint. The provider response becomes a structured
verification outcome. Detectors without a verifier are `unverifiable`, and
low-confidence findings that do not meet the verifier floor are `skipped`.

> **Data-egress boundary:** verification sends credential material outside the
> scanner process. Depending on the detector declaration, the captured
> credential or a companion value is placed in an HTTPS request URL, query,
> authorization/header field, or body and sent to the detector-declared
> provider. Only eligible findings with a verifier are sent; this is not every
> finding. Review custom detector TOML and the outbound network boundary before
> enabling verification. `--verify` is refused under lockdown.

`--no-verify` explicitly disables credential verification and overrides
`verify = true` discovered in `.keyhog.toml`. The Action's default
`verify: 'false'` maps to this flag, so committed configuration cannot silently
enable network egress in an Action run.

`--timeout <SECONDS>` (or `.keyhog.toml` `timeout`) sets the HTTP timeout for
each verification request; the default is five seconds. It is not a whole-scan
deadline. `--per-chunk-timeout-ms` is the separate optional scanner deadline,
and `--oob-timeout` controls callback observation waits. On the command line,
timeout, concurrency, and request-rate controls require `--verify`; TOML may
store their defaults for runs that explicitly enable verification.

The text reporter renders each finding as a bordered box. With `--verify`, the
verification verdict is appended to the `Evidence:` line in parentheses:
`(LIVE)` for an active credential, `(dead)` for one the provider rejected,
`(revoked)`, `(limited)` (rate-limited), or `(error)`. Live verification also
upgrades the evidence verdict to `confirmed/live-verification`. Dead, revoked,
and other non-live outcomes retain the scanner's evidence verdict. A `dead` or
`revoked` credential is downgraded one severity tier (see the table below), so
its box header drops accordingly (`CRITICAL` → `HIGH`).

```text
  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/staging.env:14
  │ Evidence:   confirmed/live-verification  ■■■■■■ 100%  (LIVE)
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ┌        HIGH ─── Stripe Secret Key
  │ Secret:     sk_l...ab12
  │ Location:   src/old/legacy.env:8
  │ Evidence:   likely/vendor-pattern  ■■■■■■ 100%  (dead)
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────
```

The second finding's header reads `HIGH`, not its declared
`CRITICAL`: a `dead` credential is downgraded one tier (see "Severity
shift on verification" below). The verdict words shown here (`LIVE`,
`dead`, `revoked`, `limited`, `error`) are the *text-reporter*
labels. The machine-readable `--format json` value is the lowercase
`VerificationResult` variant instead: `"live"`, `"dead"`,
`"revoked"`, `"rate_limited"`, `"unverifiable"`, `"skipped"`, or an
`{"error": "..."}` object; never the `verified-live`/`verified-dead`
strings. See [Output formats](./output-formats.md#combining-with---verify).

The JSON form is exact and preserves errors as data:

```json
{"verification":"live"}
{"verification":"rate_limited"}
{"verification":{"error":"connection failed: could not open a connection to the endpoint. Fix: check DNS resolution, firewall/egress rules, and proxy settings for the credential's host"}}
```

These are fragments from finding objects, not three complete findings. Error
text never contains the credential. The default reporters emit only
`credential_redacted`. Do not use `--show-secrets` in CI, retained logs, or
machine-readable artifacts.

## What "live" means

Each detector's `verify` block in its TOML defines:

- `method` (`GET` / `POST`)
- `url` (with `{{match}}` placeholder for the captured credential)
- `auth.type` (`bearer`, `basic`, `header`, `query`, `none`)
- `auth.field` (`match`, `companion-name`, ...)
- `success.status` (HTTP status code, default `200`)
- `success.policy`, an explicit evidence classification in the current corpus
  schema:
  - `body_positive` requires stable positive body evidence from
    `body_contains` or `json_path`
  - `status_with_error_backstop` accepts the declared status only when the
    response is not a recognized error shape
  - `status_authoritative` treats the declared status as sufficient even when
    the provider's body resembles an error
- optional `success.body_contains` (substring the response body must
  contain)
- optional `success.json_path` and `success.equals` for structured JSON
  responses
- optional `metadata` selectors for reviewed response evidence attached to live findings

Schema-2 and schema-3 corpora must write this policy; omission fails validation. A
manifest-free or explicitly schema-1 custom corpus retains its historical
status behavior by normalizing an omitted policy to
`status_with_error_backstop`, never `status_authoritative`. See
[Custom detector corpora](./detectors.md#custom-detector-corpora) for the
version boundary and corpus identity rules.

Response selectors use one `$`-rooted grammar:

- `$` selects the full response value.
- `$.account.email` selects exact, case-sensitive object keys.
- `$.orgs[0].name` selects a zero-based array item.
- `$["account.name"]` selects a key that contains a dot.

Wildcards, filters, recursive descent, RFC 6901 `/path` forms, whitespace
outside quoted keys, and implicit roots are rejected when the detector loads.
Selectors are limited to 1,024 bytes, 64 segments, and array indexes up to
1,000,000. A success selector
that is absent or resolves to `null` does not satisfy the success contract.
`equals` compares strings, numbers, and booleans exactly and requires a
`json_path`. Metadata fields are optional enrichment, so a valid selector miss
omits that field. Every direct metadata entry declares `sensitivity = "public"
| "hashed" | "secret"` in its detector TOML. Public evidence must be one
string, number, or boolean no larger than 256 bytes. Hashed evidence emits only
a `sha256:` digest and may summarize a structured value. Secret evidence never
enters finding metadata. Omission retains the fail-closed `hashed` behavior for
older custom detectors.

Metadata names resolve to a reviewed provider-neutral role such as
`account_id`, `email`, `scope`, `status`, `team_id`, or `user_id`. Unknown names
and duplicate canonical roles reject the detector instead of creating
provider-controlled report keys. Invalid selector syntax is also a detector
configuration error. A malformed successful JSON response is a verification
error rather than a dead credential. Direct verification metadata and
multi-step `extract` fields use the same selector grammar. Multi-step extracts
are request transport state for later templates and never enter reports.

The verifier:
1. Renders the URL with the credential substituted in
2. Builds the auth header / query param as specified
3. Sends the request
4. Compares the response status (and optionally body) to the success
   criteria

If the success contract matches, the result is `live`. A normal rejection is
`dead`. A provider-specific disabled state can be `revoked`. HTTP 429 and
retryable 5xx responses are `rate_limited`. KeyHog tries transient outcomes at
most three times. A timeout, DNS failure, blocked destination, redirect, TLS
failure, or other transport failure is an `{"error":"..."}` machine value.
Errors and rate limits are inconclusive. They leave severity unchanged.

### Verification outcome and process exit

Verification failures do not turn the scan into a system error. They remain
finding outcomes:

| Reported findings | Exit |
| --- | --- |
| No findings | `0` |
| At least one finding, none `live` | `1` |
| At least one `live` finding | `10` |

One live finding makes the exit `10` even when other findings are dead,
rate-limited, or errors. A source-coverage failure can still make the artifact
`partial`; findings take precedence in process-exit selection. Read
`scan_status` from `json-envelope` or SARIF rather than treating exit `1` or
`10` as proof that all requested input was scanned.

## Permissions and blast radius

`live` proves only that the detector's declared request was accepted. It does
not mean KeyHog enumerated everything the credential can read, write, delete,
administer, or bill. Provider evidence is included only when the detector TOML
declares a reviewed role and sensitivity for a response selector and the
endpoint returns it. The JSON `metadata` object contains only an allowed public
value or hashed digest. An absent field is unknown, not empty or denied.

KeyHog does not currently compute effective IAM policy, inherited group roles,
resource-level grants, organization policy, network restrictions, or reachable
resource inventories. It also cannot infer whether a successful low-impact
request represents the credential's maximum privilege. Treat every live result
as exposed authority whose full blast radius must be reviewed in the provider's
own audit and access-control tools.

## Severity shift on verification

The verification result is the lowercase `VerificationResult` variant in JSON;
the text reporter prints the corresponding label in the `Evidence:` line's
`(...)` suffix.

| Verification result | Severity action                                  |
|---------------------|--------------------------------------------------|
| `live`              | Unchanged (it really is what it claims to be)    |
| `dead`              | Downgrade one tier (`critical` -> `high`, `high` -> `medium`, ...) |
| `revoked`           | Downgrade one tier (same as `dead`)              |
| `rate_limited`      | Unchanged, treated as unverified                 |
| `error`             | Unchanged, treated as unverified                 |
| `unverifiable` (detector has no `verify` block) | Unchanged            |
| `skipped` (no `--verify` flag) | Unchanged                              |

The one-tier downgrade is the canonical `Severity::downgrade_one`
step (`critical` -> `high` -> `medium` -> `low` -> `client-safe` ->
`info`); it never collapses to a fixed level. A dead or revoked
credential is still a leak (developer typed it into a file once), so
KeyHog doesn't drop it entirely. The downgrade just means "this is
less urgent than a credential someone could authenticate with right
now." A credential found only in non-HEAD git history is downgraded
once on that axis too, so a `dead` credential in git history drops two
tiers.

## Network behavior

`--verify` makes network calls. Two flags shape what the verifier
talks to:

- `--proxy <url>` routes verification through an explicit HTTP, HTTPS, or
  SOCKS5 proxy. The same scan-wide flag also routes remote-source HTTP
  clients. When unset, no proxy is used. Ambient `HTTPS_PROXY`, `HTTP_PROXY`,
  `ALL_PROXY`, and `NO_PROXY` variables are ignored. Use `--proxy off` to
  force a direct connection when TOML configured a proxy.
- `--insecure` accepts invalid or self-signed certificates in verification and
  remote-source HTTP clients. Use it only for endpoints you control. Strict TLS
  is the default, and no environment variable can disable certificate verification.

An invalid proxy URL prevents the verification engine from starting. A proxy
that cannot connect produces an `error` result for the affected finding after
the bounded retries. It does not silently retry direct. `--proxy off` also
prevents ambient proxy discovery.

The verifier never follows redirects. A redirect produces an error beginning
`too many redirects: the endpoint issued a redirect, but redirects are disabled
for SSRF safety`. This prevents a provider endpoint from redirecting a
secret-bearing request to a private address. If a legitimate endpoint
redirects, update the detector to use its canonical API URL.

Outbound destinations are filtered at the client level:

- Shipped HTTP verifier blocks declare `allowed_domains` in their owning
  detector TOML. Literal endpoint hosts are checked when the detector loads.
  Interpolated hosts are checked again before every request with the same
  exact-or-subdomain matcher.
- Public multi-tenant suffixes are exact-only. An allowlist entry for a shared
  suffix never licenses arbitrary tenant subdomains.
- No `localhost`, `127.0.0.0/8`, `169.254.0.0/16`, or other RFC 1918
  private ranges.
- No IPv4-mapped IPv6 of the above.
- No cloud-metadata IPs (`169.254.169.254` AWS/Azure/GCP).

These rules are enforced for every detector even if its TOML
specifies a localhost URL by mistake. If a project configures a proxy
but a particular run must be direct, pass `--proxy off`; shell proxy
variables are ignored by design.

`verify.service` inherits the detector's service when omitted. It owns rate
limiting and remains a compatibility source for custom detectors that use the
built-in provider map. The shipped corpus uses detector-local
`allowed_domains`, so the endpoint and its network authority are reviewed in
one file.

## Out-of-band callbacks

`--verify-oob` requires `--verify` and starts one interactsh collector session.
Only detectors with a validated `[detector.verify.oob]` block use that session.
The v0.5.85 shipped detector corpus contains no OOB-enabled detector, so the
flag has no effect on shipped findings. It is for reviewed custom corpora.

If the collector handshake fails, KeyHog prints a stderr warning naming the
configured server and a redacted handshake error. Ordinary HTTP verifiers keep
running. OOB-required findings fail closed as verification errors with an
`error` result before their HTTP probe is sent. See the
[OOB verification reference](./reference/oob-verification.md) for detector,
collector, DNS, egress, and output prerequisites.

## Rate limits

Verification is rate-limited per-service within a single `keyhog scan`
invocation. The default is 5 requests/second per service (a 200 ms gap
between calls to the same service), tunable with `--verify-rate <RPS>`.
That's slow enough to avoid tripping vendor rate limits for typical
scans (dozens of findings) and fast enough to feel interactive. Pass
`--verify-batch` to additionally serialise calls per service (one
in-flight at a time) on top of the rate cap.

Concurrency is a separate bound: `--verify-concurrency <N>` (or
`.keyhog.toml` `verify_concurrency`) sets the maximum in-flight verification
requests per service, default `5`. `--verify-rate` owns the requests/second
dimension. Zero is invalid rather than silently becoming one.

If you have hundreds of candidates and want parallelism, the right
approach is to scan first WITHOUT `--verify` to get the candidate
list, then verify in batches with a script that respects each
service's documented rate limit.

## Low-confidence candidates

`--verify` sends only findings that meet the verifier confidence floor.
Findings below that floor still appear in every output format with
`"verification":"skipped"`. The `verification` field stays `skipped`, and
KeyHog prints a stderr warning with the count and floor. `skipped` is not
evidence that the credential is dead. A machine consumer that requires complete
verification must reject both `skipped` and `unverifiable`, as well as
`rate_limited` and `error`.

## Detectors without verification

Not every detector has a `verify` block. Query the installed corpus instead of
relying on a copied count:

```sh
keyhog detectors --format json | jq '[.[] | select(.verify)] | length'
```

Detectors counted there ship a live verification endpoint. The rest include:

- Format-only detectors, such as private keys and certificates, for which
  there is no service endpoint to call.
- Services without a known low-impact verification endpoint.

With `--verify`, these findings are reported as
`"verification":"unverifiable"`. Without `--verify`, every finding is
`"verification":"skipped"`.

## What you can't do

- `--verify` is not guaranteed to use GET. The owning detector TOML declares
  the method, URL, headers, query, and optional body, and some shipped providers
  require POST to perform an authentication or low-impact probe. Verification
  can create provider audit events, consume rate limits, or incur provider-side
  effects. Inspect `keyhog explain <detector-id>` before enabling it in a
  sensitive account.
- The verifier does NOT cache results across runs. Each `keyhog scan
  --verify` makes fresh calls. Caching would risk reporting a
  rotated credential as "live" hours after it was revoked.
- You can't call verification on a credential that wasn't captured
  by a scan. There's no `keyhog verify <credential>` subcommand,
  because verification depends on knowing which detector it came from.
