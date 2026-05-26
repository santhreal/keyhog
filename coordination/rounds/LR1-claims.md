# LR1 claims ledger — detectors + README (Agent A9)

**Repo:** `/mnt/santh-desktop/software/keyhog`  
**Slice:** `detectors/**`, `README.md`, `crates/*/README.md`, `crates/*/SPEC.md`, claim scripts  
**Updated:** 2026-05-26

---

## Numeric claims (root README.md)

| Claim | Location | Verified | Evidence |
|-------|----------|----------|----------|
| **891 service-specific detectors** | README L16, L31, L91, L121, L211, L280, L349 | **TRUE** | `load_detectors` → 891; `detectors/*.toml` count = 891 |
| **891 filterable in site catalog** | README L35, L121 | **TRUE** (count) | Same loader path |
| **1675 patterns** (startup banner) | README (banner example) | **UNVERIFIED in A9** | `readme_claims.rs` band test exists; not re-run (Hyperscan host) |
| **~500 MB/s** SIMD throughput | README L25 | **UNVERIFIED** | Marketing table; no per-build repro in CI |
| **96% / 69% recall** | README L152–153 | **UNVERIFIED in CI** | Repro cites `cargo bench --bench scan_throughput` + secretbench — manual only |
| **0.5 s / 1.1 s / 2.5 s** speed rows | README L156–158 | **UNVERIFIED in CI** | Same |
| **33% more real secrets** | README L160 | **UNVERIFIED** | Derived from recall table |
| **~3 s cold start** compile | README L211 | **UNVERIFIED** | Daemon docs; no A9 contract gate |
| **105× faster re-scan / ~7 ms** | README L209–213 | **UNVERIFIED** | Daemon marketing |

---

## Stale / conflicting claims

| Claim | Where | Actual | Status |
|-------|-------|--------|--------|
| **889 service-specific detectors** | `scripts/generate_contracts.py` `README_CLAIM` | README + loader = **891** | **FIXED** (A9 → 891) |
| **889 service-specific detectors** | 484× `tests/contracts/*.toml` `readme_claim` | README = **891** | **OPEN** (KH-GAP-011) |
| **889 first-class detectors** | `tools/secretbench/access/REQUEST_TEMPLATE.md` | **891** loaded | **OPEN** (doc drift) |
| **889-detector corpus** | `docs/vyre-usage.md` L577 | **891** | **OPEN** (KH-GAP-015) |

---

## Detector catalog integrity

| Check | Result |
|-------|--------|
| `detectors/*.toml` on disk | 891 |
| `load_detectors()` count | 891 |
| Top-level `tests/contracts/<id>.toml` | 893 files (891 ids + 2 orphans/extra) |
| Missing contracts | `data-gov-api-key`, `npm-access-token` |
| Orphan contract (no detector) | `nih-pubmed-api` |
| Filename ≠ id (loader still OK) | `usda-api.toml` → id `usda-api-key`; `data-gov-api.toml` → `data-gov-api-key`; `npm-token.toml` → `npm-access-token`; `twitch-client-credentials.toml` → `twitch-client-id` |
| Contracts with `[[evasion]]` | 764 / 893 (after A9 +5) |
| Contracts without `[[evasion]]` | 129 |

---

## Crate README / SPEC (slice audit)

| Path | Claims | Notes |
|------|--------|-------|
| `crates/core/README.md` | Pointer to main README | No independent numeric claims |
| `crates/scanner/README.md` | Pointer to main README | No independent numeric claims |
| `crates/cli/README.md` | Pointer to main README | No independent numeric claims |
| `crates/sources/README.md` | Pointer to main README | No independent numeric claims |
| `crates/verifier/README.md` | Pointer to main README | No independent numeric claims |
| `crates/*/SPEC.md` | Behavioral guarantees only | No detector-count claims |

---

## Claim scripts

| Script | Role | A9 action |
|--------|------|-----------|
| `scripts/generate_contracts.py` | Batch contract TOML generator; embeds `readme_claim` | Fixed `README_CLAIM` 889→891 |

---

## Contract tests wired (A9)

**Directory:** `crates/scanner/tests/contract/`  
**Count:** 23 hand-written files (20 new in LR1-A9 + 3 pre-existing)  
**mod.rs + `all_tests.rs`:** wired

---

## Evasion TOMLs added (A9)

| Contract | Evasion shape |
|----------|---------------|
| `weatherapi-api-key.toml` | URL query `?key=` on weatherapi.com |
| `twitch-client-id.toml` | `TWITCH_CLIENT_ID` + companion secret env pair |
| `webex-access-token.toml` | JSON `webex_access_token` key |
| `transifex-api-token.toml` | Bearer + transifex.com URL comment |
| `uk-gov-notify-api-key.toml` | `NOTIFY_API_KEY=live-…` env assignment |

**New evasion sections:** 5
