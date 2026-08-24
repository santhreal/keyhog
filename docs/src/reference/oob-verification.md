# Out-of-band verification

Out-of-band (OOB) verification checks whether a service calls an interactsh
collector after KeyHog sends a detector-defined probe. It is useful for
webhook, mail, and callback credentials. A callback proves the behavior named
by the detector. It does not prove the credential's full permissions.

OOB is off by default. In v0.5.83, the shipped detector corpus contains no
`[detector.verify.oob]` block. `--verify-oob` therefore changes no shipped
finding. Use it only with a reviewed custom detector corpus that declares an
OOB probe.

## Prerequisites

You need all of the following:

1. A custom detector with a valid `[detector.verify]` request, explicit
   `allowed_domains`, and a `[detector.verify.oob]` block.
2. An `{{interactsh}}`, `{{interactsh.host}}`, `{{interactsh.url}}`, or
   `{{interactsh.id}}` token in that verifier's URL, header, or body.
3. A reachable interactsh collector. The default is the public `oast.fun`
   collector.
4. DNS and HTTPS egress from the KeyHog host to the collector.
5. Network egress from the verified service to the collector protocol selected
   by the detector.
6. `--verify --verify-oob` on the scan command.

The collector host must pass KeyHog's SSRF checks. A self-hosted collector must
resolve to a public address. A loopback, link-local, RFC 1918, or cloud-metadata
address is rejected even when you configured an explicit proxy.

Audit the custom corpus before scanning:

```sh
keyhog detectors --detectors ./company-detectors --audit

keyhog scan ./repo \
  --detectors ./company-detectors \
  --detectors-mode overlay \
  --verify \
  --verify-oob \
  --oob-server oast.fun \
  --oob-timeout 30 \
  --format json-envelope \
  --output keyhog-results.json
```

`--oob-server` and `--oob-timeout` require `--verify-oob`.
`--verify-oob` requires `--verify`. Clap rejects invalid combinations before a
scan begins.

## Detector configuration

Add OOB configuration to an otherwise complete detector. This excerpt shows
the verification portion:

```toml
[detector.verify]
method = "POST"
url = "https://api.example.test/probe"
allowed_domains = ["api.example.test"]
body = '{"callback":"{{interactsh.url}}/keyhog-probe"}'

[detector.verify.success]
status = 200
policy = "status_with_error_backstop"

[detector.verify.oob]
protocol = "http"
timeout_secs = 30
policy = "oob_and_http"
```

The detector validator rejects these unsafe or ineffective shapes:

- An OOB block without an interactsh token.
- An interactsh token without an OOB block.
- OOB on a multi-step verifier.
- An unapproved verification destination.

Never put `{{match}}` or a secret companion into a collector URL, collector
header, or callback payload. The credential belongs only in the request to the
legitimate provider endpoint.

### Tokens

| Token | Expanded value |
| --- | --- |
| `{{interactsh}}` | Bare per-finding collector host |
| `{{interactsh.host}}` | Bare per-finding collector host |
| `{{interactsh.url}}` | Full `https://` collector URL |
| `{{interactsh.id}}` | Per-finding ID without the collector suffix |

KeyHog creates a 24-character per-session correlation ID and appends a
24-character random suffix for each finding. The resulting per-finding ID is
48 lowercase alphanumeric characters. Token values are sanitized to the DNS
hostname character set before interpolation. They are not URL-encoded.

## Policies and outcomes

| Policy | HTTP result | Matching callback | Finding result |
| --- | --- | --- | --- |
| `oob_and_http` | Live | Observed | `live` |
| `oob_and_http` | Live | Not observed | `dead` |
| `oob_and_http` | Not live | Not consulted | Original HTTP result |
| `oob_only` | Live or dead | Observed | `live` |
| `oob_only` | Live or dead | Not observed | `dead` |
| `oob_only` | Rate-limited or error | Not observed | Original HTTP result |
| `oob_optional` | Any | Either | Original HTTP result |

`protocol = "dns"`, `"http"`, `"smtp"`, or `"any"` selects which collector
interaction counts. Use `"any"` only when any of those callbacks proves the
detector's intended behavior.

`--oob-timeout` is the default wait for a detector that omits `timeout_secs`.
A detector-specific timeout replaces that default. In v0.5.83, the CLI value is
not a strict upper bound on detector-specific timeouts. The runtime cap is
120 seconds or the CLI value, whichever is larger.

## Machine-readable result

The default output remains redacted. A successful OOB finding can contain this
metadata. All values below are synthetic:

```json
{
  "verification": "live",
  "metadata": {
    "oob_observed": "true",
    "oob_protocol": "Http",
    "oob_remote_address": "203.0.113.42",
    "oob_timestamp": "2026-07-25T12:00:00Z",
    "oob_unique_id": "aaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbb"
  }
}
```

When no callback arrives, `oob_observed` is `"false"`. When strict
`oob_and_http` skips the wait because HTTP already failed, metadata also
contains `"oob_skipped":"http-failed-under-oob-and-http"`. If the session is
disabled, metadata contains `oob_disabled` and verification is an
`{"error":"..."}` object.

JSON and JSONL place these values in the finding's `metadata` object. SARIF
prefixes each property with `metadata.`, for example
`properties["metadata.oob_observed"]`. Text and the remaining projections use
their normal finding-metadata representation.

OOB metadata is not a credential, but it identifies a scan session and callback
source. Store it with the same access controls as the rest of the report. Never
use `--show-secrets` for a retained OOB report.

The process exit follows the normal verification contract. A `live` OOB
finding makes the scan exit `10`. A dead, rate-limited, or error finding exits
`1` when findings are present and none is live. OOB infrastructure failure does
not by itself produce a special process exit.

## Failure behavior

- **No `--verify-oob`:** OOB-required detectors fail closed before sending any
  HTTP probe. The metadata contract is
  `oob_disabled = "no active OOB session"`.
- **Collector handshake failure:** KeyHog prints one stderr warning with the
  server and a redacted error. Ordinary HTTP verifiers continue. OOB-required
  findings fail closed before their provider probe.
- **Collector disabled during a wait:** the finding becomes `error`, and
  `oob_disabled` records the reason.
- **No matching callback before the timeout:** the observation is not an
  infrastructure error. The selected OOB policy determines `dead` or preserves
  the HTTP result.
- **Poll errors:** the poller backs off from one second to at most 32 seconds.
  Once it is degraded, pending waits fail closed instead of treating missing
  callbacks as dead credentials.

Transport errors redact collector URLs before they reach warnings or finding
errors.

## Collector privacy

The collector sees the session and per-finding correlation IDs. It also sees
the callback source IP, timestamp, protocol, and raw callback payload. That
payload can contain provider-selected headers or body data. Review the detector
probe and the provider's callback behavior before using a public collector.

The collector does not receive the scanned repository path, commit, or finding
metadata from KeyHog. KeyHog sends the credential to the legitimate provider
verification endpoint, not to the collector. A badly designed custom detector
or a provider that reflects credential material in its callback can violate
that separation. This is why OOB detector review is a prerequisite.

Use a self-hosted collector for regulated code, customer repositories, or any
provider whose callback payload is not known to be non-sensitive.

## Self-hosting interactsh

Your domain needs public DNS delegation to a publicly reachable host. Install
and run the upstream server:

```sh
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

interactsh-server \
  -domain "$YOUR_DOMAIN" \
  -ip "$YOUR_PUBLIC_IP" \
  -listen-ip 0.0.0.0 \
  -tls-cert "/etc/letsencrypt/live/$YOUR_DOMAIN/fullchain.pem" \
  -tls-key "/etc/letsencrypt/live/$YOUR_DOMAIN/privkey.pem"
```

Then pass the public domain:

```sh
keyhog scan ./repo \
  --detectors ./company-detectors \
  --detectors-mode overlay \
  --verify \
  --verify-oob \
  --oob-server "$YOUR_DOMAIN" \
  --format json-envelope \
  --output keyhog-results.json
```
