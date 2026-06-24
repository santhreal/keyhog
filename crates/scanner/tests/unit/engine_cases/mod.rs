//! LR1-A2 hand-written unit tests (one `#[test]` per file).

mod clear_fragment_cache_idempotent;
mod compile_rejects_invalid_regex;
mod compiled_scanner_detector_count;
mod compiled_scanner_pattern_count;
mod floor_char_boundary_at_zero;
mod floor_char_boundary_mid_multibyte;
mod floor_char_boundary_past_end;
mod line_number_at_eof;
mod line_number_first_line;
mod line_number_second_line;
mod next_window_offset_applies_overlap;
mod next_window_offset_at_text_end;
mod next_window_offset_zero_overlap;
mod pattern_regex_strs_includes_ac_and_phase2;
mod preferred_backend_label_nonempty;
mod record_window_match_adjusts_offset;
mod record_window_match_dedups;
mod scan_chunks_preserves_chunk_count;
#[cfg(feature = "simd")]
mod scan_coalesced_phase2_trigger_rows;
mod scan_cpu_fallback_finds_match;
mod scan_does_not_cross_chunk_boundary;
mod scan_git_history_source_type_downgrades_severity;
mod scan_simd_cpu_empty_chunk;
mod scan_skips_detectors_directory_path;
mod scan_skips_keyhogignore_path;
mod scan_windowed_overlap_dedups_end_to_end;
mod scan_windowed_with_triggered_parallel_parity;
mod warm_backend_cpu_always_true;
mod window_chunk_preserves_path;
mod window_chunk_zero_width_range;
mod window_end_offset_ascii_stays_in_bounds;
mod window_end_offset_at_eof;
mod window_end_offset_invalid_start;
mod window_end_offset_multibyte_never_splits;
