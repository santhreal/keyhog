# Verification

`keyhog scan --verify` makes an HTTP call to each detector's
documented verification endpoint with the captured credential.
The response tells you if the credential is live.

The text reporter renders each finding as a bordered box. With
`--verify`, the verification verdict is appended to the `Confidence:`
line in parentheses: `(LIVE)` for an active credential, `(dead)` for
one the provider rejected, `(revoked)`, `(limited)` (rate-limited), or
`(error)`. A `dead` or `revoked` credential is downgraded one severity
tier (see the table below), so its box header drops accordingly
(`CRITICAL` → `HIGH`).

```text
  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/staging.env:14
  │ Confidence: ■■■■■■ 100%  (LIVE)
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ┌        HIGH ─── Stripe Secret Key
  │ Secret:     sk_l...ab12
  │ Location:   src/old/legacy.env:8
  │ Confidence: ■■■■■■ 100%  (dead)
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
strings. See [Output formats](./output-formats.md#combining-with-verify).

## What "live" means

Each detector's `verify` block in its TOML defines:

- `method` (`GET` / `POST`)
- `url` (with `{{match}}` placeholder for the captured credential)
- `auth.type` (`bearer`, `basic`, `header`, `query`, `none`)
- `auth.field` (`match`, `companion-name`, ...)
- `success.status` (HTTP status code, default `200`)
- optional `success.body_contains` (substring the response body must
  contain)

The verifier:
1. Renders the URL with the credential substituted in
2. Builds the auth header / query param as specified
3. Sends the request
4. Compares the response status (and optionally body) to the success
   criteria

If the criteria match: `live`. If not: `dead`. If the provider says
the credential was explicitly disabled: `revoked`. If it returns a
rate-limit error (e.g. HTTP 429): `rate_limited`. If the request times
out or DNS fails: an `error` (treated as unverified, severity
unchanged).

## Severity shift on verification

The verdict is the lowercase `VerificationResult` variant (the JSON
value; the text reporter prints the same word upper/lower-cased in the
`Confidence:` line's `(...)` suffix).

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

- `--proxy <url>` -- route all verification through an HTTPS proxy.
  Useful in corp networks and interception labs. When unset, no proxy
  is used; ambient `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` /
  `NO_PROXY` variables are ignored so shell or CI state cannot silently
  reroute secret-bearing verifier traffic. Use `--proxy off` to force a
  direct connection when TOML configured a proxy.
- `--insecure` -- accept self-signed certs. ONLY use against
  internal endpoints you control. The default is strict TLS verify, and
  no environment variable can disable certificate verification.

The verifier never follows redirects (SSRF defense -- a 302 to a
private IP could otherwise leak the credential to an internal
service). If a vendor's auth endpoint returns 302 to follow into the
API, that endpoint's verify block in the detector TOML is wrong;
report a bug.

Outbound destinations are filtered at the client level:

- No `localhost`, `127.0.0.0/8`, `169.254.0.0/16`, or other RFC 1918
  private ranges.
- No IPv4-mapped IPv6 of the above.
- No cloud-metadata IPs (`169.254.169.254` AWS/Azure/GCP).

These rules are enforced for every detector even if its TOML
specifies a localhost URL by mistake. If a project configures a proxy
but a particular run must be direct, pass `--proxy off`; shell proxy
variables are ignored by design.

## Out-of-band callbacks

`--verify-oob` enables callback-style verification for detectors that
need an external collector. If the collector handshake fails, keyhog
prints a stderr warning naming the `--verify-oob` server and the
handshake error. Detectors that require OOB verification then report
verification errors, while detectors with normal HTTP verification
continue through their usual path.

## Rate limits

Verification is rate-limited per-service within a single `keyhog scan`
invocation. The default is 5 requests/second per service (a 200 ms gap
between calls to the same service), tunable with `--verify-rate <RPS>`.
That's slow enough to avoid tripping vendor rate limits for typical
scans (dozens of findings) and fast enough to feel interactive. Pass
`--verify-batch` to additionally serialise calls per service (one
in-flight at a time) on top of the rate cap.

If you have hundreds of candidates and want parallelism, the right
approach is to scan first WITHOUT `--verify` to get the candidate
list, then verify in batches with a script that respects each
service's documented rate limit.

## Low-confidence candidates

`--verify` only sends findings that meet the verifier confidence floor
to external services. Findings below that floor still appear in every
output format, but their `verification` field stays `skipped`. When
that happens, keyhog prints a stderr warning naming how many findings
were skipped and the verifier confidence floor that caused it, so a
partial verification pass cannot look complete.

## Detectors without verification

Not every detector has a `verify` block. Query the installed corpus instead of
relying on a copied count:

```sh
keyhog detectors --format json | jq '[.[] | select(.verify)] | length'
```

Detectors counted there ship a live verification endpoint. The rest are:

- Format-only detectors (private keys, certificates, JWTs) where the
  credential itself has provable structure but no service to call.
- Services without a known low-impact verification endpoint (some
  internal APIs, deprecated services).

For these, `--verify` is a no-op. The `verification` field of the
finding stays `skipped`.

## What you can't do

- `--verify` does NOT POST data. Every verification call is either a
  GET or a benign read-only endpoint (e.g. `GET /me`, `GET /charges?limit=1`).
- The verifier does NOT cache results across runs. Each `keyhog scan
  --verify` makes fresh calls. Caching would risk reporting a
  rotated credential as "live" hours after it was revoked.
- You can't call verification on a credential that wasn't captured
  by a scan. There's no `keyhog verify <credential>` subcommand,
  because verification depends on knowing which detector it came from.
