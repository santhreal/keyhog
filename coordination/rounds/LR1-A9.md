# LR1-A9

LOCK: detectors/**, README.md, crates/*/README.md, crates/*/SPEC.md, scripts/generate_contracts.py, crates/scanner/tests/contract/**, crates/scanner/tests/contracts/{weatherapi-api-key,twitch-client-id,webex-access-token,transifex-api-token,uk-gov-notify-api-key}.toml, coordination/rounds/LR1-claims.md, GAP_FINDINGS.toml

## Hunt

- finding count: **6** (KH-GAP-011 … KH-GAP-016)
- detectors on disk: **891** TOMLs; loader: **891**
- contracts (top-level): **893**; missing for **2** ids (`data-gov-api-key`, `npm-access-token`)
- orphan contract: **nih-pubmed-api** (no detector)
- stale `readme_claim = "889 …"`: **484** contracts (pre-fix script)
- contracts without `[[evasion]]`: **129** (was 134; A9 added 5)
- README perf table: cites repro command but **not CI-gated**
- crate READMEs: no stray numeric claims (all defer to root README)
- `generate_contracts.py`: `README_CLAIM` was **889** (doc lie vs README **891**)

## Tests added

- count: **20** new hand-written contract test files (+3 pre-existing → **23** total)
- directories: `crates/scanner/tests/contract/`
- wired: `crates/scanner/tests/contract/mod.rs` (already exported from `all_tests.rs`)

### New contract tests (20)

1. `detector_toml_files_on_disk_equal_891.rs`
2. `every_detector_has_non_empty_service.rs`
3. `every_detector_has_at_least_one_pattern.rs`
4. `every_detector_id_is_unique.rs`
5. `every_detector_has_non_empty_name.rs`
6. `generate_contracts_script_readme_claim_is_891.rs`
7. `no_contract_readme_claim_stale_889.rs` (RED — 484 stale)
8. `orphan_nih_pubmed_contract_has_no_matching_detector.rs` (RED)
9. `data_gov_api_key_contract_file_exists.rs` (RED)
10. `npm_access_token_contract_file_exists.rs` (RED)
11. `every_contract_schema_version_one.rs`
12. `github_pat_fine_grained_first_positive_fires.rs`
13. `stripe_secret_key_first_positive_fires.rs`
14. `openai_api_key_legacy_sk_positive_fires.rs`
15. `readme_performance_section_lists_reproduce_command.rs`
16. `root_readme_claims_891_service_specific_detectors.rs`
17. `detector_filename_maps_to_unique_id.rs`
18. `twitch_client_id_first_positive_fires.rs`
19. `twilio_auth_token_dot_property_evasion_fires.rs`
20. `contracts_evasion_coverage_meets_minimum_floor.rs`

## Evasion TOMLs added

- count: **5**
- files:
  - `crates/scanner/tests/contracts/weatherapi-api-key.toml`
  - `crates/scanner/tests/contracts/twitch-client-id.toml`
  - `crates/scanner/tests/contracts/webex-access-token.toml`
  - `crates/scanner/tests/contracts/transifex-api-token.toml`
  - `crates/scanner/tests/contracts/uk-gov-notify-api-key.toml`

## Commands

```bash
# Host lacks libhs — build blocked on this runner
env -u CC cargo test -p keyhog-scanner --test all_tests contract:: -- --list 2>&1
# → build FAIL (hyperscan-sys / libhs not found)

# Metadata-only spot checks (no compile):
python3 -c "from pathlib import Path; import re
con=Path('crates/scanner/tests/contracts')
ev=sum(1 for p in con.glob('*.toml') if '[[evasion]]' in p.read_text())
print('evasion contracts', ev, 'contract tests', len(list(Path('crates/scanner/tests/contract').glob('*.rs')))-1)"
```

## GAP_FINDINGS appended

- KH-GAP-011 — stale readme_claim 889 in 484 contracts
- KH-GAP-012 — missing contracts data-gov-api-key, npm-access-token
- KH-GAP-013 — orphan nih-pubmed-api contract
- KH-GAP-014 — 129 contracts still lack [[evasion]]
- KH-GAP-015 — docs/vyre-usage.md 889 vs README 891
- KH-GAP-016 — README perf recall table not CI-gated

## Script fix

- `scripts/generate_contracts.py`: `README_CLAIM` **889 → 891**

## Claims ledger

- `coordination/rounds/LR1-claims.md` (created)

## Return counts

| Metric | Count |
|--------|------:|
| Hand-written contract test files (A9 new) | **20** |
| Hand-written contract test files (total in `contract/`) | **23** |
| New `[[evasion]]` contract TOMLs (A9) | **5** |
| Contracts with evasion (post-A9) | **764** |
