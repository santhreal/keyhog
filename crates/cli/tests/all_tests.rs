// `adversarial` and `property` are NOT here: each is its own bounded test
// binary (`tests/adversarial.rs`, `tests/property.rs`). They were silently
// orphaned (empty mod.rs) and, for adversarial, each test spawns the keyhog
// binary, folding 75 of those into this already-large binary is the
// OOM-SIGKILL driver. Standalone binaries bound peak memory and link size.
//
// Heavy binary-spawning suites (`e2e`, `reliability`, `stress`, `dogfood`, and
// `gap`) are split into standalone `tests/*_all.rs` integration-test binaries.
// This keeps `all_tests` a fast contract/unit/gate aggregator that finishes in
// CI time; the process-spawning suites still run via explicit `--test` steps.
pub mod concurrent;
pub mod contract;
// `gap` is intentionally absent here; see `tests/gap_all.rs`.
pub mod gate;
pub mod integration;
pub mod regression;
pub mod unit;
pub mod unit_daemon_stdin_replay;

// Shared e2e support helpers used by contract/gap/concurrent tests.
#[path = "e2e/support.rs"]
pub mod support;

// Top-level standalone `tests/*.rs` that are PURE (in-process; they do NOT spawn
// the keyhog binary), so folding them into this aggregator does not grow the
// OOM/link footprint the way the process-spawning `e2e_*`/`audit_*`/`lane5_*`
// files would (those stay standalone and run via explicit `--test` CI steps).
// CI ran keyhog's tests only via specific `--test` targets, so these were
// CI-orphans whose fail-closed / wiring / coherence assertions never ran.
// `scripts/gates/tests_wired.py` keeps every top-level `tests/*.rs` reachable.
pub mod action_root_mirror_parity;
pub mod advisory_ignores_are_justified;
pub mod cross_os_target_spec;
pub mod docs_claim_matches_router;
pub mod feature_matrix_combination_parity;
pub mod github_collaboration_selection;
pub mod install_script_parity;
pub mod lane10_daemon_accept_resilience;
pub mod lane10_daemon_terminal_failure;
pub mod lane10_silent_fallback_surfacing;
pub mod platform_compat;
pub mod profiling_reporting;
pub mod profiling_startup;
pub mod regression_ambient_source_env_ignored;
pub mod regression_cli_daemon_hook_lifecycle_e2e;
pub mod regression_incremental_cache_config_wiring;
pub mod regression_install_static_analysis_gate;
pub mod regression_install_windows_unblock;
pub mod regression_ml_threshold_wired_to_confidence_floor;
pub mod regression_row_155_install_bench_config_parity;
pub mod regression_scan_system_mount_filters_tier_b;
pub mod regression_scanargs_field_contract;
pub mod regression_stable_hash_field_identity;
pub mod regression_value_parser_fix_guidance;
pub mod release_attestation_contract;
pub mod release_floating_tag_predicate_single_owner;
pub mod target_spec_org_contracts;
