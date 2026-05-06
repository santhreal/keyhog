# Out-of-Band (OOB) Verification

> Live key ≠ exploitable key.

Standard verification asks "does the API return 200?" — a per-service heuristic
that confirms a credential parses. For webhook-, mailer-, and callback-shaped
credentials that's necessary but not sufficient: a 200 OK can mean "your key
parses but has no useful scope," "the webhook URL is dead but silent," or
"your credential reached our staging system and got swallowed." OOB
verification proves the credential is **exfil-capable**: we mint a unique
per-finding subdomain on an interactsh collector, embed it in the verification
probe, and confirm the service actually called back. A callback means the
credential really moved attacker-controlled traffic.

## Quick start

```bash
# Default: HTTP-only verification (what you've always had)
keyhog scan ./repo --verify

# Opt in to OOB verification using the public oast.fun collector
keyhog scan ./repo --verify --verify-oob

# Self-host an interactsh-server and point keyhog at it
keyhog scan ./repo --verify --verify-oob --oob-server interactsh.mycorp.internal

# Tune how long we wait for callbacks per finding (default 30s, max 120s)
keyhog scan ./repo --verify --verify-oob --oob-timeout 60
```

OOB is **off by default**. A normal `--verify` run never speaks to a
collector. This is intentional: OOB ships traffic to a third-party server
(or a self-hosted one) and you should opt in deliberately.

## Threat model

What the collector sees:

- 20-character correlation IDs — random, per-scan.
- 33-character per-finding subdomains.
- Source IP, timestamp, and protocol (DNS / HTTP / SMTP) of services
  calling back.
- Whatever the calling service includes in its outbound request — typically
  a User-Agent, no body, no credentials.

What the collector **never** sees:

- The leaked credential. The credential is sent to the legitimate service
  (Slack, Mailgun, etc.), not to the collector.
- The repository, file path, or commit being scanned.
- Any other finding metadata.

For high-sensitivity scans (regulated environments, customer code, audits),
self-host `projectdiscovery/interactsh-server` and pass
`--oob-server <your-host>`. The protocol is wire-compatible.

## Detector schema

Detectors opt into OOB verification by adding `[detector.verify.oob]` to
their TOML. The verifier substitutes a per-finding callback URL into any
`{{interactsh}}` / `{{interactsh.host}}` / `{{interactsh.url}}` /
`{{interactsh.id}}` token inside the verify spec.

```toml
[detector]
id = "example-webhook"
service = "example"
# ... patterns, keywords ...

[detector.verify]
method = "POST"
url = "{{match}}"
# Embed the OOB host in the request body. The service will (we expect)
# fetch the URL we control, and the callback proves exfil-capability.
body = '{"text":"https://{{interactsh}}/probe"}'

[detector.verify.success]
# Probe-level HTTP success — the webhook has to accept the payload.
status = 200

[detector.verify.oob]
# Wait for an outbound HTTP request. `dns` / `smtp` / `any` also valid.
protocol = "http"
# Per-finding wait timeout in seconds. Optional; defaults to --oob-timeout.
timeout_secs = 30
# Verification policy:
#   "oob_and_http"  — both must hold (default; strict)
#   "oob_only"      — ignore HTTP, trust the callback
#   "oob_optional"  — HTTP success suffices; OOB enriches metadata only
policy = "oob_and_http"
```

### Token expansion

| Token                 | Value                                     | Example                                                           |
|-----------------------|-------------------------------------------|-------------------------------------------------------------------|
| `{{interactsh}}`      | bare host                                 | `abc...xyz.oast.fun`                                              |
| `{{interactsh.host}}` | bare host (alias)                         | `abc...xyz.oast.fun`                                              |
| `{{interactsh.url}}`  | full HTTPS URL                            | `https://abc...xyz.oast.fun`                                      |
| `{{interactsh.id}}`   | 33-char unique ID without server suffix  | `abc...xyz`                                                       |

These tokens are NOT URL-encoded — the host is already URL-safe and we
expect templates to embed it verbatim into JSON bodies, headers, and URL
paths.

### Verification policy

`policy = "oob_and_http"` (default) is the strict mode for webhook-style
detectors. A finding is `Live` only when both the HTTP probe succeeds AND
the OOB callback arrives within `timeout_secs`. If HTTP says alive but no
callback comes, the verdict is `Dead` — the credential parses but isn't
exfil-capable, which for a webhook is the security-relevant question.

`policy = "oob_only"` skips HTTP success entirely. Use for credentials
where the API has no useful HTTP response shape (one-way push tokens, fire-
and-forget event triggers) but provably triggers an outbound request.

`policy = "oob_optional"` is HTTP-only verification with OOB observation
enriching the metadata. Use to roll out OOB to a detector for visibility
before flipping to strict mode.

## Metadata

Verified findings produced under OOB verification carry:

- `oob_unique_id` — the 33-char correlation ID minted for this finding.
- `oob_observed` — `"true"` or `"false"`.
- `oob_protocol` — `"Dns"`, `"Http"`, `"Smtp"`, `"Other"` (when observed).
- `oob_remote_address` — IP that called back (when observed).
- `oob_timestamp` — collector timestamp (when observed).
- `oob_disabled` — reason string (only when the session degraded mid-scan).

These propagate to every output format (JSON, JSONL, SARIF, plain-text).

## Failure modes

OOB infrastructure failures are non-fatal. Specifically:

- **Collector unreachable at startup**: the engine logs a warning and
  continues with HTTP-only verification. The scan completes normally.
- **Collector goes silent mid-scan**: the poller backs off (1s → 32s),
  in-flight waits time out as `NotObserved`, downstream verdicts fall back
  to HTTP-only. The next successful poll resumes normal operation.
- **OOB session not enabled but detector requests it**: tokens resolve to
  empty strings; HTTP-only verification proceeds. The finding metadata
  carries no `oob_*` keys, signaling the dimension wasn't measured.

## Performance

The interactsh handshake costs ~150ms at engine boot (RSA-2048 keygen +
register POST). That cost is paid once per scan, not per finding.

The polling loop adds one HTTPS request every `poll_interval` (default 2s)
and decrypts batched interactions in-process. AES-256-CFB decryption is a
few hundred bytes per callback — negligible relative to scan cost.

The dominant added latency is the per-finding wait. For a webhook-shaped
detector you're paying `oob_timeout` worst-case per finding that doesn't
call back. Tune `--oob-timeout` to your service profile: aggressive
real-time webhooks can use `--oob-timeout 5`; queued mail systems need
30+.

## Self-hosting interactsh

```bash
# On a server with public DNS pointed at it (NS records for $YOUR_DOMAIN
# delegated to this host):
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest

interactsh-server \
  -domain $YOUR_DOMAIN \
  -ip $YOUR_PUBLIC_IP \
  -listen-ip 0.0.0.0 \
  -tls-cert /etc/letsencrypt/live/$YOUR_DOMAIN/fullchain.pem \
  -tls-key  /etc/letsencrypt/live/$YOUR_DOMAIN/privkey.pem
```

Then run keyhog with `--oob-server $YOUR_DOMAIN`. The wire protocol is
identical to the public oast.fun deployment — keyhog's client does not
care which it talks to.
