#![allow(clippy::needless_borrow, clippy::needless_update, clippy::useless_vec)]

#[path = "gap/analyze_keyword_only_must_assert.rs"]
mod analyze_keyword_only_must_assert;
#[path = "gap/checksum_github.rs"]
mod checksum_github;
#[path = "gap/checksum_gitlab_npm_slack_stripe.rs"]
mod checksum_gitlab_npm_slack_stripe;
#[path = "gap/confidence_floor_policy.rs"]
mod confidence_floor_policy;
#[path = "gap/context_tokio_async_fn_test_body_is_test_code.rs"]
mod context_tokio_async_fn_test_body_is_test_code;
#[path = "gap/cross_platform_cfg_gates_absent.rs"]
mod cross_platform_cfg_gates_absent;
#[path = "gap/csr_hot_maps_adopted.rs"]
mod csr_hot_maps_adopted;
#[path = "gap/decode_pipeline_exceeds_modularity_cap.rs"]
mod decode_pipeline_exceeds_modularity_cap;
#[path = "gap/detector_contract_coverage_100pct.rs"]
mod detector_contract_coverage_100pct;
#[path = "gap/docs_megakernel_env_claim_matches_engine.rs"]
mod docs_megakernel_env_claim_matches_engine;
#[path = "gap/engine_backend_parity.rs"]
mod engine_backend_parity;
#[path = "gap/entropy_keyword_only_requires_keyword_line.rs"]
mod entropy_keyword_only_requires_keyword_line;
#[path = "gap/file_gate_matrix_scanner_adversarial_unmarked.rs"]
mod file_gate_matrix_scanner_adversarial_unmarked;
#[path = "gap/file_gate_matrix_scanner_missing_submodule_rows.rs"]
mod file_gate_matrix_scanner_missing_submodule_rows;
#[path = "gap/findings_registry_integrity.rs"]
mod findings_registry_integrity;
#[allow(dead_code)]
#[path = "gap/inline_gate.rs"]
mod inline_gate;
#[path = "gap/inline_migrated_tests_not_wired.rs"]
mod inline_migrated_tests_not_wired;
#[path = "gap/multiline_reassembly.rs"]
mod multiline_reassembly;
#[path = "gap/nightly_exports_all_strict_env_vars.rs"]
mod nightly_exports_all_strict_env_vars;
#[path = "gap/nightly_matrix_has_fourteen_runner_binaries.rs"]
mod nightly_matrix_has_fourteen_runner_binaries;
#[path = "gap/no_suppress_test_fixtures_clears_generic_fallback_haircut.rs"]
mod no_suppress_test_fixtures_clears_generic_fallback_haircut;
#[path = "gap/orphan_github_pat_contract.rs"]
mod orphan_github_pat_contract;
#[path = "gap/phase2_always_active_sparse.rs"]
mod phase2_always_active_sparse;
#[path = "gap/pipeline_exceeds_modularity_cap.rs"]
mod pipeline_exceeds_modularity_cap;
#[path = "gap/pipeline_hot_path_allocs.rs"]
mod pipeline_hot_path_allocs;
#[path = "gap/r5_chunk_boundary_adversarial_floor_12.rs"]
mod r5_chunk_boundary_adversarial_floor_12;
#[path = "gap/r5_chunk_boundary_not_only_aws.rs"]
mod r5_chunk_boundary_not_only_aws;
#[path = "gap/r5_chunk_boundary_subdir_wired.rs"]
mod r5_chunk_boundary_subdir_wired;
#[path = "gap/r5_concat_adversarial_floor_7.rs"]
mod r5_concat_adversarial_floor_7;
#[path = "gap/r5_concat_beyond_engine_cases.rs"]
mod r5_concat_beyond_engine_cases;
#[path = "gap/r5_concat_subdir_wired.rs"]
mod r5_concat_subdir_wired;
#[path = "gap/r5_decode_hostile_adversarial_floor_15.rs"]
mod r5_decode_hostile_adversarial_floor_15;
#[path = "gap/r5_decode_hostile_not_only_engine_cases.rs"]
mod r5_decode_hostile_not_only_engine_cases;
#[path = "gap/r5_gap_expansion_total_floor_55.rs"]
mod r5_gap_expansion_total_floor_55;
#[path = "gap/r5_handwritten_twin_gap_vs_detector_load.rs"]
mod r5_handwritten_twin_gap_vs_detector_load;
#[path = "gap/r5_homoglyph_adversarial_floor_7.rs"]
mod r5_homoglyph_adversarial_floor_7;
#[path = "gap/r5_homoglyph_beyond_single_aws.rs"]
mod r5_homoglyph_beyond_single_aws;
#[path = "gap/r5_homoglyph_subdir_wired.rs"]
mod r5_homoglyph_subdir_wired;
#[path = "gap/r5_near_miss_handwritten_twin_floor_50.rs"]
mod r5_near_miss_handwritten_twin_floor_50;
#[path = "gap/r5_per_detector_near_miss_runner_present.rs"]
mod r5_per_detector_near_miss_runner_present;
#[path = "gap/r5_reverse_adversarial_floor_7.rs"]
mod r5_reverse_adversarial_floor_7;
#[path = "gap/r5_reverse_beyond_unit_misc.rs"]
mod r5_reverse_beyond_unit_misc;
#[path = "gap/r5_reverse_subdir_wired.rs"]
mod r5_reverse_subdir_wired;
#[path = "gap/r5_top50_near_miss_wired_in_adversarial_mod.rs"]
mod r5_top50_near_miss_wired_in_adversarial_mod;
#[path = "gap/santh_contract_dir_exists.rs"]
mod santh_contract_dir_exists;
#[path = "gap/scanner_src_files_exceed_standard_500_loc.rs"]
mod scanner_src_files_exceed_standard_500_loc;
#[path = "gap/simd_no_hit_multiline_fast_path.rs"]
mod simd_no_hit_multiline_fast_path;
#[path = "gap/single_line_implicit_concat_not_appended.rs"]
mod single_line_implicit_concat_not_appended;
#[path = "gap/suppression_postprocess_exceeds_modularity_cap.rs"]
mod suppression_postprocess_exceeds_modularity_cap;
#[path = "gap/suppression_shape_gate_pipeline_twins_incomplete.rs"]
mod suppression_shape_gate_pipeline_twins_incomplete;
#[path = "gap/vyre_usage_matches_workspace_pin.rs"]
mod vyre_usage_matches_workspace_pin;
