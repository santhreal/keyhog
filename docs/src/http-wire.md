# HTTP and wire scanning

Real credentials don't always sit on disk. They flow through:

- **Live web bundles** that ship from production at a public URL.
- **HAR files** that browsers (Chrome / Firefox / Safari DevTools)
  produce when you click "Save all as HAR with content."
- **mitmproxy / Burp captures** of an authenticated session.
- **curl / httpie / Postman exports** of one specific request you
  want to verify.

KeyHog scans every one of these, but the surface is split across a
few flags and sources. This page is the map.

## TL;DR

| Workflow                                  | Command                                                      |
|-------------------------------------------|--------------------------------------------------------------|
| Scan a public JS bundle                   | `keyhog scan --url https://app.example.com/static/main.js`   |
| Scan every URL in a list                  | `keyhog scan --url $(cat urls.txt)`                          |
| Scan a source-map exposed by Webpack      | `keyhog scan --url https://app.example.com/static/main.js.map` |
| Scan a HAR export from DevTools           | `keyhog scan capture.har` *(planned, see [Roadmap](#roadmap))* |
| Scan a single curl response               | `curl -s https://api/... \| keyhog scan --stdin`             |
| Scan a saved Burp / mitmproxy capture     | `keyhog scan dump.txt`  *(treats as text — no protocol parsing)* |
| Route every fetch through Burp            | `keyhog scan --url https://... --proxy http://burp:8080 --insecure` |
| Scan in an air-gapped network             | `keyhog scan --url https://... --proxy off`                  |

## The `--url` flag (Web Source)

```sh
keyhog scan --url https://app.example.com/static/main.js
keyhog scan --url https://app.example.com/static/main.js \
            https://app.example.com/static/runtime.js \
            https://app.example.com/static/vendor.js
```

Each URL is fetched with the shared HTTP client policy (see
[Proxy and TLS](#proxy-and-tls) below). The response is routed by
extension:

- `.js`  → one chunk per file, scanned as plain text.
- `.map` → JSON parsed, each `sourcesContent[i]` becomes its own
  chunk tagged with the original filename. This is how a Webpack
  build with `devtool: 'source-map'` accidentally exposes server-
  side env vars baked into the bundle at build time.
- `.wasm` → linear-memory + import section dumped as strings (best-
  effort; native WASM symbol extraction lives behind the `binary`
  feature).
- Everything else → one chunk of text.

Findings are tagged `source: "web:js"`, `web:sourcemap`,
`web:sourcemap:raw`, `web:wasm`, or `web:other`. The original URL
is the `file_path`.

### SSRF defense

`--url` refuses to fetch:

- Private RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`).
- Loopback (`127.0.0.0/8`, `::1`).
- Link-local (`169.254.0.0/16`, `fe80::/10`).
- Cloud metadata endpoints (`169.254.169.254`, the GCP / Azure /
  AWS / DigitalOcean / Hetzner variants).

This isn't a CLI flag — it's hardcoded so a user can't accidentally
turn an `--url` invocation into a metadata-service IAM exfil.

## Proxy and TLS

Everything outbound — `--url`, `--github-org`, `--s3-bucket`,
`--verify`'s API calls — runs through one HTTP client builder.
Policy:

| Source                       | Effect                                            |
|------------------------------|---------------------------------------------------|
| `--proxy http://burp:8080`   | Explicit. Wins over everything.                   |
| `--proxy off`                | Disable proxying entirely, ignore env vars.       |
| `KEYHOG_PROXY` env var       | Same as `--proxy`. Useful inside CI containers.   |
| `HTTPS_PROXY` / `HTTP_PROXY` | reqwest's default. Last resort.                   |
| `--insecure`                 | Accept any TLS cert (self-signed Burp CA, etc.).  |
| `KEYHOG_INSECURE_TLS=1`      | Same as `--insecure`.                             |

Order: explicit flag → KEYHOG_PROXY → standard env vars.

`User-Agent: keyhog/<version>` is always set so you can grep your
proxy logs for keyhog traffic without guessing.

## Scanning a single HTTP exchange (stdin)

The most common ad-hoc workflow:

```sh
curl -s https://api.example.com/v1/me \
     -H "Authorization: Bearer $TOKEN" \
| keyhog scan --stdin
```

Or just pipe a saved response:

```sh
keyhog scan --stdin < response.txt
```

`keyhog scan -` (bare dash) is the same as `--stdin` (grep / wc
convention; added in v0.5.28).

`--stdin` reads up to ~1 GiB; beyond that, write to a temp file and
scan the path. Use `--source-type wire` when you want findings
tagged with a meaningful source instead of the default `stdin`.

## Headers, bodies, URL params — where the secret sits

KeyHog is content-blind: it greps the raw bytes. That means a
`Bearer ghp_…` in an HTTP header gets the same finding as a
`"token": "ghp_…"` in a JSON body or a `?token=ghp_…` in the URL.

For an HTTP capture this is usually what you want — the location
column in the finding gives the byte offset within the capture, and
the surrounding context (line ±2) is enough to tell whether it was
a header or a body.

What KeyHog does **not** do today:

- Parse the HTTP wire format and emit `header:Authorization`
  vs `body:json:$.token` provenance fields.
- Distinguish a secret in a request from a secret in the response
  (one is being sent OUT, one is being sent IN — different threat
  model).

Those land in the roadmap below.

## Roadmap

The wire-scanning surface is intentionally narrow today. Items
queued for a later release, with their issue links:

1. **`.har` file auto-detection.** Browser DevTools "Save all as
   HAR with content" produces a single JSON file with every
   request + response. Today you can `keyhog scan capture.har` and
   it scans the JSON as text (works, but no provenance). The
   roadmap is to detect the `.har` extension, parse the JSON, and
   emit one chunk per `entries[i].request` (tagged
   `wire:har:request`) and `entries[i].response` (tagged
   `wire:har:response`). Findings would then carry the URL,
   method, and which side of the exchange they came from.

2. **mitmproxy `.mitm` flow-dump support.** Same shape as HAR but
   binary-framed. Use the `mitmproxy-rs` crate to decode.

3. **Header / body / URL-param provenance.** Once HAR/mitm parsing
   lands, attach `wire_location: header:<name> | body | query`
   to each finding so the JSON consumer can filter
   `wire_location == "header:Authorization"` for the highest-
   signal subset (intentional auth tokens vs accidental body
   leaks vs URL-logged secrets).

4. **Live proxy mode.** Run `keyhog proxy --listen :8080` and have
   it act as an HTTP proxy that scans every flow inline, writing
   findings to stdout. The use case is recording a browsing
   session against a target and getting a single report of every
   credential the site shipped to the client.

5. **WebSocket frame scanning.** HAR files don't include WebSocket
   payloads. mitmproxy dumps do. Frame-level scanning would catch
   tokens passed over upgraded connections (Slack, Discord,
   collaborative editors).

No promises on timeline — track via
[github.com/santhsecurity/keyhog/issues](https://github.com/santhsecurity/keyhog/issues).

## Why this matters for bug bounties

A modern SPA bundle on a typical SaaS app can ship 200+ npm
dependencies and a sourcemap that exposes every server-side env
var the build process touched. Manual code review of one
`main.js.map` against the 891-detector corpus is hours; running
`keyhog scan --url https://app.target.com/static/main.js.map`
takes seconds.

Pair it with `--hide-client-safe` (see
[CLI reference](./reference/cli.md)) to filter out keys that the
vendor designed to ship in client bundles (Sentry DSN, Stripe
`pk_*`, Mapbox `pk.`, PostHog `phc_`, etc.) and you're left with
the keys that actually represent an exfiltration boundary.
