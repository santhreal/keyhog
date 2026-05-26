# LR1 CI runner matrix — 14 contract multipliers

**Owner:** A10 (CI + infra)  
**Repo:** `/mnt/santh-desktop/software/keyhog`  
**Sources:** `TESTING_PROGRAM.md` §3.1, `.github/workflows/ci.yml`, `.github/workflows/runners-nightly.yml`

---

## Summary

| Gate | Runners | Strict env | Hyperscan install | `env -u CC` |
|------|---------|------------|-------------------|-------------|
| PR (`ci.yml` → `strict-runners`) | **4 / 14** | 3 env vars | `libhyperscan-dev` | **no** |
| Nightly (`runners-nightly.yml`) | **14 / 14** | 11 env vars | `libhyperscan-dev` | **no** |
| Unit test job (`ci.yml` → `test`) | 0 runners | — | yes | **no** |
| macOS build (`ci.yml` → `macos-build`) | 0 runners | — | **skipped** (`--no-default-features`) | **no** |

**Gap tests:** `coordination/ci-operability/tests/gap/` (7 files)

---

## Full matrix (14 runners)

| # | Test binary | ~scale | Strict mode | Strict env var | PR CI | Nightly CI | Notes |
|---|-------------|--------|-------------|----------------|-------|------------|-------|
| 1 | `contracts_runner` | ~3k | always | *(none — always strict)* | ✅ | ✅ | Per-detector contract gate |
| 2 | `adversarial_explosion_runner` | ~14k | env-gated | `KEYHOG_ADVERSARIAL_STRICT=1` | ✅ | ✅ | Format-wrapper evasion |
| 3 | `encoding_explosion_runner` | ~12k | env-gated | `KEYHOG_ENCODING_STRICT=1` | ✅ | ✅ | Decode-through recall |
| 4 | `path_shape_runner` | ~10k | env-gated | `KEYHOG_PATH_SHAPE_STRICT=1` | ✅ | ✅ | Production path shapes |
| 5 | `noise_injection_runner` | ~8k | env-gated | `KEYHOG_NOISE_STRICT=1` | ❌ | ✅ | PR deferred — nightly only |
| 6 | `unicode_confusable_runner` | ~8k | env-gated | `KEYHOG_UNICODE_STRICT=1` | ❌ | ✅ | Homoglyph / confusable |
| 7 | `whitespace_normalization_runner` | ~8k | env-gated | `KEYHOG_WHITESPACE_STRICT=1` | ❌ | ✅ | Whitespace variants |
| 8 | `line_length_runner` | ~8k | env-gated | `KEYHOG_LINE_LEN_STRICT=1` | ❌ | ✅ | Long-line wrapping |
| 9 | `entropy_edge_runner` | ~8k | env-gated | `KEYHOG_ENTROPY_STRICT=1` | ❌ | ✅ | Entropy boundary |
| 10 | `compound_encoding_runner` | multi-layer | env-gated | `KEYHOG_COMPOUND_STRICT=1` | ❌ | ✅ | Nested encode stacks |
| 11 | `multi_secret_runner` | colliding | env-gated | `KEYHOG_MULTI_STRICT=1` | ❌ | ✅ | Multi-secret collisions |
| 12 | `comment_embed_runner` | comments | env-gated | `KEYHOG_COMMENT_STRICT=1` | ❌ | ✅ | Secrets in comments |
| 13 | `companion_contracts_runner` | companion | always | *(none — hard fail on miss)* | ❌ | ✅ | Parity issues warn-only |
| 14 | `cve_replay_runner` | CVE corpus | always | *(none — hard fail per entry)* | ❌ | ✅ | Vacuous pass if corpus empty |

**Not in the 14:** `chunk_ad_runner.rs` (AC prefilter ad-hoc suite, not a contract multiplier).

---

## Workflow cross-reference

### `ci.yml` jobs vs Hyperscan / strict

| Job | Ubuntu | Hyperscan | Strict runners | LFS checkout |
|-----|--------|-----------|----------------|--------------|
| `strict-runners` | yes | `libhyperscan-dev` | 4 binaries | yes |
| `test` | yes | `libhyperscan-dev` | lib + e2e + proptest | yes |
| `macos-build` | no (macOS) | **none** | none (`--no-default-features`) | no |
| `feature-matrix` | yes | `libhyperscan-dev` | none (`cargo check`) | no |
| `clippy` | yes | `libhyperscan-dev` | none | no |
| `fmt` | yes | n/a | none | yes |
| `deny` | yes | **none** | none | no |
| `audit` | yes | **none** | none | no |
| `build` | yes | `libhyperscan-dev` | smoke binary | no |
| `publish` | yes | `libhyperscan-dev` | none | no |

### Other workflows

| Workflow | Hyperscan | Runners | Gap |
|----------|-----------|---------|-----|
| `runners-nightly.yml` | dev libs | 14/14 strict | no `env -u CC` |
| `secretbench-nightly.yml` | **missing** | 0 | default-feature build without libhs |
| `differential-bench.yml` | runtime `libhyperscan5` | 0 | prebuilt release binary |
| `keyhog.yml` | runtime `libhyperscan5` | 0 | dogfood scan, not test matrix |
| `release.yml` | Linux dev; mac/win portable | 0 | macOS ships no-Hyperscan binary |
| `health-check.yml` | n/a | 0 | dispatch smoke only |
| `vendor-vyre.yml` | n/a | 0 | vendor refresh |

---

## Operability gaps (registered)

| ID | Severity | Title |
|----|----------|-------|
| KH-GAP-011 | bar-miss | PR CI gates only 4/14 strict runners |
| KH-GAP-012 | micro-flaw | No `env -u CC` distcc guard in workflows |
| KH-GAP-013 | bar-miss | secretbench-nightly builds without Hyperscan |
| KH-GAP-014 | micro-flaw | macOS CI skips default-features Hyperscan path |
| KH-GAP-015 | bar-miss | fuzz/ targets not wired into CI |
| KH-GAP-016 | micro-flaw | companion parity issues warn-only |
| KH-GAP-017 | bar-miss | cve_replay vacuous pass on empty corpus |

---

## Local red-wall command (full 14)

```bash
cd /mnt/santh-desktop/software/keyhog
export KEYHOG_ADVERSARIAL_STRICT=1 KEYHOG_ENCODING_STRICT=1 KEYHOG_PATH_SHAPE_STRICT=1
export KEYHOG_NOISE_STRICT=1 KEYHOG_UNICODE_STRICT=1 KEYHOG_WHITESPACE_STRICT=1
export KEYHOG_LINE_LEN_STRICT=1 KEYHOG_ENTROPY_STRICT=1 KEYHOG_MULTI_STRICT=1
export KEYHOG_COMPOUND_STRICT=1 KEYHOG_COMMENT_STRICT=1
env -u CC cargo test -p keyhog-scanner --profile release-fast \
  --test contracts_runner --test adversarial_explosion_runner \
  --test encoding_explosion_runner --test path_shape_runner \
  --test noise_injection_runner --test unicode_confusable_runner \
  --test whitespace_normalization_runner --test line_length_runner \
  --test entropy_edge_runner --test compound_encoding_runner \
  --test multi_secret_runner --test comment_embed_runner \
  --test companion_contracts_runner --test cve_replay_runner
```

## CI operability tests

```bash
env -u CC cargo test --manifest-path coordination/ci-operability/Cargo.toml
```

Expected LR1: **2 pass**, **5 fail** (intentional RED gap tests).
