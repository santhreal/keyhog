# Verification

`keyhog scan --verify` makes an HTTP call to each detector's
documented verification endpoint with the captured credential.
The response tells you if the credential is live.

```sh
$ keyhog scan . --verify
src/config/staging.env:14:12  CRITICAL  stripe-secret-key
                              sk_live_4eC39H...Tcd3Hc
                              entropy 5.21 | confidence 0.999 | verified-live
src/old/legacy.env:8:5        LOW       stripe-secret-key   (downgraded)
                              sk_live_oldKEy...xyz12
                              verified-dead | originally CRITICAL
```

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

If the criteria match: `verified-live`. If not: `verified-dead`. If
the request times out or DNS fails: `verification-error` (treated as
unverified, severity unchanged).

## Severity shift on verification

| Verification result | Severity action                                  |
|---------------------|--------------------------------------------------|
| `verified-live`     | Unchanged (it really is what it claims to be)    |
| `verified-dead`     | Downgrade one tier (`critical` -> `high`, `high` -> `medium`, ...) |
| `verification-error` | Unchanged, treated as unverified                |
| `skipped` (no `--verify` flag) | Unchanged                              |

A dead credential is still a leak (developer typed it into a file
once), so KeyHog doesn't drop it entirely. The downgrade just means
"this is less urgent than a credential someone could authenticate
with right now."

## Network behavior

`--verify` makes network calls. Two flags shape what the verifier
talks to:

- `--proxy <url>` -- route all verification through an HTTPS proxy.
  Useful in corp networks. Same as `HTTPS_PROXY` env var.
- `--insecure-tls` -- accept self-signed certs. ONLY use against
  internal endpoints you control. The default is strict TLS verify.

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
specifies a localhost URL by mistake. Set `KEYHOG_PROXY=off` to
disable proxy resolution (useful for air-gapped builds where the
proxy env vars are set but no proxy is actually reachable).

## Rate limits

Verification is sequential per-finding within a single `keyhog scan`
invocation, with a 100 ms gap between calls to the same hostname.
That's slow enough to avoid tripping vendor rate limits for typical
scans (dozens of findings) and fast enough to feel interactive.

If you have hundreds of candidates and want parallelism, the right
approach is to scan first WITHOUT `--verify` to get the candidate
list, then verify in batches with a script that respects each
service's documented rate limit.

## Detectors without verification

Not every detector has a `verify` block. About 60% do. The rest are:

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
