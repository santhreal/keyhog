//! Adversarial / evasion suite for the keyhog CLI, as its OWN bounded test
//! binary. Each test spawns the keyhog binary; folding all 75 into all_tests
//! was the OOM-SIGKILL driver (LG2). They were ALSO silently orphaned (empty
//! adversarial/mod.rs). The all-wired guard enforces completeness.

#[path = "adversarial/adversarial_missing_path_no_stdout_json.rs"]
mod adversarial_missing_path_no_stdout_json;
#[path = "adversarial/backend_patterns_non_numeric_rejected.rs"]
mod backend_patterns_non_numeric_rejected;
#[path = "adversarial/backend_probe_bytes_overflow_string_rejected.rs"]
mod backend_probe_bytes_overflow_string_rejected;
#[path = "adversarial/calibrate_cache_parent_is_file_fails.rs"]
mod calibrate_cache_parent_is_file_fails;
#[path = "adversarial/calibrate_show_missing_cache_file_exits_zero.rs"]
mod calibrate_show_missing_cache_file_exits_zero;
#[path = "adversarial/completion_extra_trailing_arg_exits_two.rs"]
mod completion_extra_trailing_arg_exits_two;
#[path = "adversarial/concurrent_four_scans_json_unix.rs"]
mod concurrent_four_scans_json_unix;
#[path = "adversarial/concurrent_four_scans_json_windows_stub.rs"]
mod concurrent_four_scans_json_windows_stub;
#[path = "adversarial/concurrent_json_output_integrity.rs"]
mod concurrent_json_output_integrity;
#[path = "adversarial/config_parse_warns_once.rs"]
mod config_parse_warns_once;
#[path = "adversarial/daemon_start_help_documents_socket_flag.rs"]
mod daemon_start_help_documents_socket_flag;
#[path = "adversarial/daemon_status_without_running_daemon_fails.rs"]
mod daemon_status_without_running_daemon_fails;
#[path = "adversarial/daemon_stop_nonexistent_socket_path.rs"]
mod daemon_stop_nonexistent_socket_path;
#[path = "adversarial/daemon_stop_without_running_daemon_emits_actionable_stderr.rs"]
mod daemon_stop_without_running_daemon_emits_actionable_stderr;
#[path = "adversarial/detectors_missing_detectors_dir_hostile.rs"]
mod detectors_missing_detectors_dir_hostile;
#[path = "adversarial/detectors_search_no_match_empty_stdout.rs"]
mod detectors_search_no_match_empty_stdout;
#[path = "adversarial/diff_after_file_missing_exits_two.rs"]
mod diff_after_file_missing_exits_two;
#[path = "adversarial/diff_before_after_same_invalid_json.rs"]
mod diff_before_after_same_invalid_json;
#[path = "adversarial/diff_before_file_missing_exits_two.rs"]
mod diff_before_file_missing_exits_two;
#[path = "adversarial/diff_invalid_json_baseline_exits_two.rs"]
mod diff_invalid_json_baseline_exits_two;
#[path = "adversarial/diff_json_flag_invalid_baseline_exits_two.rs"]
mod diff_json_flag_invalid_baseline_exits_two;
#[path = "adversarial/exclude_paths_massive_glob_list.rs"]
mod exclude_paths_massive_glob_list;
#[path = "adversarial/explain_detectors_path_is_file_fails.rs"]
mod explain_detectors_path_is_file_fails;
#[path = "adversarial/explain_unknown_detector_hostile_argv.rs"]
mod explain_unknown_detector_hostile_argv;
#[path = "adversarial/hook_install_foreign_hook_rejects_hostile.rs"]
mod hook_install_foreign_hook_rejects_hostile;
#[path = "adversarial/hook_install_outside_git_repo_fails_hostile.rs"]
mod hook_install_outside_git_repo_fails_hostile;
#[path = "adversarial/hook_uninstall_foreign_hook_refuses.rs"]
mod hook_uninstall_foreign_hook_refuses;
#[path = "adversarial/hook_uninstall_outside_git_repo_fails_hostile.rs"]
mod hook_uninstall_outside_git_repo_fails_hostile;
#[path = "adversarial/huge_exclude_paths_glob_completes.rs"]
mod huge_exclude_paths_glob_completes;
#[path = "adversarial/invalid_utf8_filename_rejected_unix.rs"]
mod invalid_utf8_filename_rejected_unix;
#[path = "adversarial/invalid_utf8_filename_windows_stub.rs"]
mod invalid_utf8_filename_windows_stub;
#[path = "adversarial/keyhog_backend_env_with_scan.rs"]
mod keyhog_backend_env_with_scan;
#[path = "adversarial/keyhog_detectors_missing_path_ignored.rs"]
mod keyhog_detectors_missing_path_ignored;
#[path = "adversarial/keyhog_detectors_valid_path_unix.rs"]
mod keyhog_detectors_valid_path_unix;
#[path = "adversarial/keyhog_threads_empty_string_ignored.rs"]
mod keyhog_threads_empty_string_ignored;
#[path = "adversarial/keyhog_threads_invalid_value_ignored.rs"]
mod keyhog_threads_invalid_value_ignored;
#[path = "adversarial/keyhog_threads_overflow_clamped.rs"]
mod keyhog_threads_overflow_clamped;
#[path = "adversarial/keyhog_threads_zero_uses_defaults.rs"]
mod keyhog_threads_zero_uses_defaults;
#[path = "adversarial/pipe_stdout_json_valid_unix.rs"]
mod pipe_stdout_json_valid_unix;
#[path = "adversarial/pipe_stdout_json_windows_stub.rs"]
mod pipe_stdout_json_windows_stub;
#[path = "adversarial/r5t_backend_prints_backend_line.rs"]
mod r5t_backend_prints_backend_line;
#[path = "adversarial/r5t_backend_unknown_subcommand_exits_two.rs"]
mod r5t_backend_unknown_subcommand_exits_two;
#[path = "adversarial/r5t_calibrate_help_documents_show_subcommand.rs"]
mod r5t_calibrate_help_documents_show_subcommand;
#[path = "adversarial/r5t_calibrate_show_unknown_detector_exits_two.rs"]
mod r5t_calibrate_show_unknown_detector_exits_two;
#[path = "adversarial/r5t_completion_elvish_exits_zero.rs"]
mod r5t_completion_elvish_exits_zero;
#[path = "adversarial/r5t_completion_invalid_shell_exits_two.rs"]
mod r5t_completion_invalid_shell_exits_two;
#[path = "adversarial/r5t_daemon_start_help_documents_socket_flag.rs"]
mod r5t_daemon_start_help_documents_socket_flag;
#[path = "adversarial/r5t_daemon_status_missing_socket_exits_two.rs"]
mod r5t_daemon_status_missing_socket_exits_two;
#[path = "adversarial/r5t_daemon_stop_missing_socket_exits_two.rs"]
mod r5t_daemon_stop_missing_socket_exits_two;
#[path = "adversarial/r5t_detectors_json_flag_emits_array.rs"]
mod r5t_detectors_json_flag_emits_array;
#[path = "adversarial/r5t_detectors_search_no_match_empty_stdout.rs"]
mod r5t_detectors_search_no_match_empty_stdout;
#[path = "adversarial/r5t_diff_before_not_json_exits_two.rs"]
mod r5t_diff_before_not_json_exits_two;
#[path = "adversarial/r5t_diff_hide_unchanged_omits_section.rs"]
mod r5t_diff_hide_unchanged_omits_section;
#[path = "adversarial/r5t_diff_identical_baselines_json_stdout_valid.rs"]
mod r5t_diff_identical_baselines_json_stdout_valid;
#[path = "adversarial/r5t_diff_new_entry_exits_one.rs"]
mod r5t_diff_new_entry_exits_one;
#[path = "adversarial/r5t_explain_missing_detector_arg_exits_two.rs"]
mod r5t_explain_missing_detector_arg_exits_two;
#[path = "adversarial/r5t_explain_unknown_detector_stderr_names_id.rs"]
mod r5t_explain_unknown_detector_stderr_names_id;
#[path = "adversarial/r5t_hook_install_help_documents_force_flag.rs"]
mod r5t_hook_install_help_documents_force_flag;
#[path = "adversarial/r5t_hook_install_outside_repo_stderr_actionable.rs"]
mod r5t_hook_install_outside_repo_stderr_actionable;
#[path = "adversarial/r5t_hook_uninstall_clean_repo_exits_zero.rs"]
mod r5t_hook_uninstall_clean_repo_exits_zero;
#[path = "adversarial/r5t_scan_system_help_documents_threads_flag.rs"]
mod r5t_scan_system_help_documents_threads_flag;
#[path = "adversarial/r5t_scan_system_zero_threads_rejected.rs"]
mod r5t_scan_system_zero_threads_rejected;
#[path = "adversarial/r5t_watch_file_instead_of_directory_exits_two.rs"]
mod r5t_watch_file_instead_of_directory_exits_two;
#[path = "adversarial/r5t_watch_help_documents_quiet_flag.rs"]
mod r5t_watch_help_documents_quiet_flag;
#[path = "adversarial/r5t_watch_missing_directory_exits_two.rs"]
mod r5t_watch_missing_directory_exits_two;
#[path = "adversarial/scan_baseline_missing_file_rejects_hostile_path.rs"]
mod scan_baseline_missing_file_rejects_hostile_path;
#[path = "adversarial/scan_system_invalid_space_unit_exits_two.rs"]
mod scan_system_invalid_space_unit_exits_two;
#[path = "adversarial/scan_system_lockdown_forbids_include_network_hostile.rs"]
mod scan_system_lockdown_forbids_include_network_hostile;
#[path = "adversarial/scan_system_missing_detectors_dir_hostile.rs"]
mod scan_system_missing_detectors_dir_hostile;
#[path = "adversarial/scan_system_zero_space_rejected.rs"]
mod scan_system_zero_space_rejected;
#[path = "adversarial/support.rs"]
mod support;
#[path = "adversarial/unicode_path_scan_parent_unix.rs"]
mod unicode_path_scan_parent_unix;
#[path = "adversarial/unicode_path_scan_windows_stub.rs"]
mod unicode_path_scan_windows_stub;
#[path = "adversarial/watch_detectors_path_is_file_fails.rs"]
mod watch_detectors_path_is_file_fails;
#[path = "adversarial/watch_nonexistent_path_exits_before_blocking.rs"]
mod watch_nonexistent_path_exits_before_blocking;
#[path = "adversarial/watch_quiet_flag_on_missing_path_fails.rs"]
mod watch_quiet_flag_on_missing_path_fails;
