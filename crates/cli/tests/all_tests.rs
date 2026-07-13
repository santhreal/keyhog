// `adversarial` and `property` are NOT here: each is its own bounded test
// binary (`tests/adversarial.rs`, `tests/property.rs`). They were silently
// orphaned (empty mod.rs) and, for adversarial, each test spawns the keyhog
// binary, folding 75 of those into this already-large binary is the
// OOM-SIGKILL driver. Standalone binaries bound peak memory and link size.
pub mod concurrent;
pub mod contract;
pub mod dogfood;
pub mod e2e;
pub mod gap;
pub mod gate;
pub mod integration;
pub mod regression;
pub mod reliability;
pub mod stress;
pub mod unit;

// Top-level standalone `tests/*.rs` that are PURE (in-process; they do NOT spawn
// the keyhog binary), so folding them into this aggregator does not grow the
// OOM/link footprint the way the process-spawning `e2e_*`/`audit_*`/`lane5_*`
// files would (those stay standalone and run via explicit `--test` CI steps).
// CI ran keyhog's tests only via specific `--test` targets, so these were
// CI-orphans whose fail-closed / wiring / coherence assertions never ran.
// `scripts/gates/tests_wired.py` keeps every top-level `tests/*.rs` reachable.
pub mod cross_os_target_spec;
pub mod fused_dispatch_panic_contract;
pub mod lane10_installer_orphan_reap;
pub mod lane10_silent_fallback_surfacing;
pub mod platform_compat;
pub mod regression_ambient_source_env_ignored;
pub mod regression_daemon_frame_incremental_read;
pub mod regression_incremental_cache_config_wiring;
pub mod regression_ml_threshold_wired_to_confidence_floor;
pub mod regression_scan_system_mount_filters_tier_b;
pub mod regression_value_parser_fix_guidance;
// NOTE: `target_spec_org_contracts` is deliberately NOT aggregated yet. Running
// it (it was a CI-orphan) surfaces 9 REAL organizational-contract violations 
// `keyhog-core` exposes 120 reachable `pub` items (budget 90), `keyhog-verifier`
// is over its `pub` budget, and `keyhog-sources` has 5 top-level `pub use` lines
// (target <= 3). Wiring the guard before pruning that surface would turn CI red,
// so the fix is sequenced: prune the public surface (make dead/over-broad `pub`
// items `pub(crate)`, collapse the re-export ladders) FIRST, then aggregate this
// guard. Tracked as its own task; the file stays a standalone target until then.
