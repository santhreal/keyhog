# keyhog-verifier

[![santh](https://img.shields.io/badge/santh-alpha-ffd60a?style=flat-square&labelColor=0a0a0a)](https://santh.dev/keyhog/)

Live credential verification for the KeyHog secret scanner. Takes deduplicated
matches, queries the target service to check whether each credential is active,
and returns a typed verdict per finding. Defines the shared SSRF classifier,
the per-service rate limiter, and AWS SigV4 request signing used by source
crates.

Part of the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

```rust
use keyhog_verifier::ssrf::is_private_url;
use keyhog_verifier::VerifyConfig;

// Shared SSRF classifier for the workspace. Sources call this function so
// loopback and link-local targets are rejected in one place.
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
- `VerifyConfig` holds network verification settings, including TLS posture and
  proxy handling. `proxy_is_active` reports the resolved state.
- `ssrf::is_private_url` and `is_private_ip_addr` are the canonical private and
  link-local classifiers.
- `rate_limit::get_rate_limiter` is the shared limiter. `sigv4` signs AWS
  requests.

## Failure behavior

A credential that cannot be checked is never reported as inactive. Network
failure, rate limiting, and an unreachable service each produce a distinct
verdict separate from a revoked credential response.

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
