pub mod adversarial;
pub mod concurrent;
pub mod contract;
pub mod gap;
pub mod integration;
pub mod property;
pub mod regression;
// Top-level standalone `tests/*.rs` files aggregated as sibling modules. CI runs
// keyhog-core tests only via `--test all_tests` (+ `--lib`, `--test
// new_core_finding_dedup`), so a top-level file not aggregated here (or named by
// a `--test` step) is a CI-orphan whose `#[test]`s never run — including the
// HTML-report XSS / CSV-formula-injection / SARIF security locks and the
// detector-corpus integrity guard. `scripts/gates/tests_wired.py` enforces this
// (verifier + core); keep every top-level `tests/*.rs` reachable from here.
pub mod dedup_decoder_alias;
pub mod detector_corpus_integrity;
pub mod encoding_decode_boundary_truth_matrix;
pub mod new_core_allowlist_spec;
pub mod new_core_types;
pub mod perf_algo_complexity;
pub mod perf_suppression;
pub mod regression_allowlist_governance;
pub mod regression_allowlist_typoed_entries_fail_closed;
pub mod regression_auto_fix_runtime_extension_hook;
pub mod regression_auto_fix_tier_b_service_env_map;
pub mod regression_csv_formula_injection;
pub mod regression_encoding_base64_padding_edge_cases;
pub mod regression_html_report_coverage_panel;
pub mod regression_html_report_scan_metadata_wired;
pub mod regression_html_report_script_breakout_xss;
pub mod regression_lane7_law10_recall_guards;
pub mod regression_lockdown_cache_fail_closed_on_unreadable_dir;
pub mod regression_oob_multistep_fail_closed;
pub mod regression_org_split_merkle_and_allowlist_api;
pub mod regression_sarif_information_uri;
pub mod regression_text_summary_revoked_is_inactive;
pub mod test_toml_compat;
pub mod wave9_edge;
pub mod wave9_proptest;
pub mod support {
    pub mod reporters;
}
pub mod unit;
