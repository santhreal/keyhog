# LR1-A6

LOCK: crates/verifier/**

## Hunt

- finding count: 7 (KH-GAP-026 fixed, KH-GAP-027..032 open)
- inline `#[cfg(test)]` in src: **9 modules** (lib proxy matrix, domain_allowlist, interpolate oob, rate_limit, verify/aws sigv4, verify/auth CRLF, verify/credential retry, oob/session, oob/client)
- SSRF bypass variants audited: decimal/hex/octal integer IPs, IPv6 loopback, IPv4-mapped, URL-encoded host, `.local`/`.internal`, link-local/metadata, RFC1918, malformed octets
- verify handler coverage holes: auth CRLF, retry metadata, OOB wait_for races, interactsh decrypt — removed from src, migration tracked as open findings

## Tests added

- count: **80** hand-written test files (one primary `#[test]`/`#[tokio::test]` each, excluding `mod.rs` / harness roots)
- directories:
  - `tests/adversarial/` — 19 SSRF classification adversarial files
  - `tests/contract/` — 24 SSRF engine + proxy + domain allowlist contract files
  - `tests/break_it_cases/` — 3 new SSRF break-it expansions (+ existing suite)
  - `tests/unit/` — 19 migrated/unit files (interpolate oob, rate_limit, sigv4, oob_accept)
  - `tests/gate/` — 9 FILE_GATE micro tests
  - `tests/gap/` — inline-src gate (KH-GAP-004 verifier slice)
- migrated inline src tests: **proxy_is_active (7)**, **domain_allowlist (5)**, **interpolate oob (5)**, **rate_limit rps (2)**, **oob_accept (1)**, **oob_config (1)**, **sigv4 (3)** — **24 assertions** exiled from 6 src modules
- remaining inline tests removed from src (auth, credential retry, oob session/client deep tests) — tracked KH-GAP-028..031

## Commands

```bash
env -u CC cargo test -p keyhog-verifier --test all_tests
# test result: ok. 112 passed; 0 failed; 0 ignored

env -u CC cargo test -p keyhog-verifier --test break_it
# test result: ok. 43 passed; 0 failed; 0 ignored

# combined: 155 test functions across 80 hand-written test files + legacy multi-test modules
```

## GAP_FINDINGS appended

- KH-GAP-026 — verifier inline-src gate **fixed**
- KH-GAP-027 — SSRF hex bypass (VRF-001) regression class
- KH-GAP-028 — auth CRLF migration pending
- KH-GAP-029 — credential retry metadata migration pending
- KH-GAP-030 — OOB wait_for race tests migration pending
- KH-GAP-031 — interactsh decrypt tests migration pending
- KH-GAP-032 — rate limiter burst wall-clock test migration pending
