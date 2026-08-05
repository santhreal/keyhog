# keyhog-verifier

Live credential verification for the KeyHog secret scanner. Takes deduplicated
matches, asks the owning service whether each credential is still active, and
returns a typed verdict per finding. Also owns the shared SSRF classifier, the
per-service rate limiter, and AWS SigV4 request signing that the source crates
delegate to rather than forking.

Part of the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

```rust
use keyhog_verifier::ssrf::is_private_url;
use keyhog_verifier::VerifyConfig;

// One SSRF classifier for the whole fleet. Sources call this instead of
// carrying a local copy, so a loopback or link-local target is refused in
// exactly one place.
assert!(is_private_url("http://169.254.169.254/latest/meta-data/"));
assert!(is_private_url("http://127.0.0.1:8080/"));
assert!(!is_private_url("https://api.github.com/user"));

// Verification is opt in and configured, never ambient.
let config = VerifyConfig::default();
let _ = config;
```

## Public entry points

- `VerificationEngine` holds the shared HTTP client, the response cache, and the
  global and per-service concurrency limits. Build one and reuse it;
  constructing several defeats the cache and the rate limits.
- `VerificationEngine::verify_all` takes `Vec<DedupedMatch>` and returns one
  `VerifiedFinding` per input group.
- `VerifyConfig` carries every knob that changes network behavior, including
  TLS posture and proxy handling. `proxy_is_active` reports the resolved state.
- `ssrf::is_private_url` and `is_private_ip_addr` are the canonical private and
  link-local classifiers.
- `rate_limit::get_rate_limiter` is the shared limiter. `sigv4` signs AWS
  requests.

## Failure behavior

A credential that cannot be checked is never reported as inactive. Network
failure, rate limiting, and an unreachable service each produce their own
verdict, distinct from a service answering that the credential is dead. That
distinction is the whole point of the crate: treating an unreachable service as
a revoked credential would hide a live secret.

## Features

`default = ["live"]`. Building without `live` removes the network verification
path; the SSRF, rate limiting, and signing helpers stay available. Verification
never runs unless the caller asks for it.

## Documentation

- [Verification](https://santhreal.github.io/keyhog/verification.html) describes
  the verdicts and what each one means.
- [Hardening and data handling](https://santhreal.github.io/keyhog/hardening.html)
  describes what leaves the process during verification.
- API documentation is on [docs.rs](https://docs.rs/keyhog-verifier).
