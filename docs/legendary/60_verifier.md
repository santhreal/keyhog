# 60 — Verifier: live verification breadth + SSRF safety

Live credential verification turns a "shape match" into a proven-live finding —
the highest-signal output. The bar: broad provider coverage, never a false "live"
claim (Screwdriver: report what happened, don't overclaim), and bulletproof SSRF
safety (verification fetches attacker-influenced endpoints). Hardest-first: the
provider matrix breadth + the SSRF/OOB safety proofs lead.

Numbers: KH-L-0620 … KH-L-0709.

## SSRF / network safety (verification fetches are the attack surface)

- KH-L-0620 [VR1,AV15,ENG][VERIFIER][L] Every verifier request routes through the SSRF guard (`ssrf.rs` + `bogon.rs` + `domain_allowlist.rs`); no provider verifier issues a raw request. Proof: a `no_raw_request_in_verifier` gate + an SSRF-bypass corpus all blocked.
- KH-L-0621 [AV15][VERIFIER][M] Bogon/private-range blocking is complete (IPv4 + IPv6 + mapped + decimal/octal encodings). Proof: a bogon-encoding corpus, all blocked.
- KH-L-0622 [AV15][VERIFIER][M] Redirect-pinning: a provider redirect to an internal address is blocked; the resolved IP is pinned across the request. Proof: a redirect-to-internal test.
- KH-L-0623 [AV15][VERIFIER][M] Domain-allowlist is per-provider (verification only hits the provider's real API domains), not a blanket allow. Proof: a per-provider allowlist test.
- KH-L-0624 [AV15][VERIFIER][M] OOB (`oob/`) verification (out-of-band callbacks) can't be turned into an SSRF/exfil primitive; the OOB endpoint is operator-controlled + authenticated. Proof: an OOB-abuse test.

## Provider coverage + truth

- KH-L-0625 [SCR,AV3][VERIFIER][RESEARCH] Provider verification matrix: every high-value detector (aws/gcp/github/gitlab/stripe/slack/twilio/sendgrid/...) has a live verifier OR a documented "no safe verifier" reason. Proof: a provider→verifier coverage map.
- KH-L-0626 [VR8,SCR][VERIFIER][M] Never a false "live": a revoked/invalid key verifies as invalid; a network error verifies as Unknown, never Live (the `VerificationResult` contract). Proof: revoked-key + network-error fixtures per provider.
- KH-L-0627 [SCR,L6][VERIFIER][M] Verification is non-destructive: it never mutates provider state (read-only probes only). Proof: a per-verifier read-only assertion (request method/endpoint audit).
- KH-L-0628 [ENG,L10][VERIFIER][M] Verifier requests are constant-time-safe where they compare secrets; no timing oracle. Proof: a constant-time audit of any secret compare.
- KH-L-0629 [AV3][VERIFIER][M] Multi-step verification (token→whoami→scopes) reports the credential's actual privilege/scope. Proof: a scope-reporting test (mock).

## Rate-limit / cache / robustness

- KH-L-0630 [L7,AV15][VERIFIER][M] Rate-limit (`rate_limit.rs`) prevents hammering a provider; verification of N findings respects per-provider limits. Proof: a rate-limit-respecting bench.
- KH-L-0631 [L7][VERIFIER][M] Response cache (`cache.rs`) dedups identical-credential verifications without leaking plaintext to disk. Proof: a cache-hit + no-plaintext-on-disk test.
- KH-L-0632 [VR1,AV15][VERIFIER][M] Malicious provider response (huge body, slow-loris, malformed JSON) is bounded + safe. Proof: an adversarial-response corpus.
- KH-L-0633 [ENG][VERIFIER][M] Verifier errors carry context + the operator fix (expired/forbidden/network). Proof: error-message contract per failure mode.

## Wiring + interpolation

- KH-L-0634 [AV9][VERIFIER][M] `interpolate.rs` builds requests from detector templates correctly; no injection via the credential value into the request (CRLF/header injection). Proof: a request-injection corpus, all neutralized.
- KH-L-0635 [AV9][CLI][M] `--verify` flag + verification results reach the report (JSON/SARIF `verification` field) + exit codes. Proof: a verify e2e per output format.
- KH-L-0636 [TC,AV12][VERIFIER][L] Each verifier: valid/invalid/revoked/network-error/rate-limited + SSRF-blocked coverage. Proof: a per-verifier 6-case matrix.
- KH-L-0637 [CFG][VERIFIER][M] Provider endpoints + allowlists are Tier-B data (drop-in to add a provider), not hardcoded. Proof: a provider-data file + loader.

(Breadth: provider verifiers × {valid, invalid, revoked, net-error, rate-limit,
ssrf-blocked} enumerated per provider as the matrix fills. ~90 items.)
