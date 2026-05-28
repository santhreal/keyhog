//! R5-D1/R5-D2 dogfood stress regressions — CLI surface / worst-case contracts.

pub mod concurrent_scans_no_corrupt_json;
pub mod detectors_help_detector_count_drift;
pub mod empty_corpus_json_array_exit_zero;
pub mod git_diff_head_worktree_stress;
pub mod git_history_committed_secret;
pub mod git_staged_secret_in_index;
pub mod hook_install_no_daemon_readme_lie;
pub mod lockdown_verify_refused_before_preflight;
pub mod piped_stderr_scan_json_stdout_valid;
pub mod remote_source_failure_nonzero_exit;
pub mod require_gpu_scan_when_self_test_passes;
pub mod scan_dogfood_one_event_per_example;
pub mod sigint_mid_scan_exits_130;
pub mod stream_progress_line_matches_file;
pub mod symlink_follows_secret_target;
pub mod unreadable_dir_warns_scan_continues;
