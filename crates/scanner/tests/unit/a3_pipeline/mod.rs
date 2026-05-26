// LR1-A3: one #[test] per file
mod compute_line_offsets_empty;
mod compute_line_offsets_single_line;
mod compute_line_offsets_trailing_newline;
mod find_companion_respects_within_lines;
mod floor_char_boundary_utf8;
mod is_within_hex_context_neighbor;
mod is_within_hex_context_rejects_prose;
mod line_window_offsets_bounded;
mod local_context_window_clamps_end;
mod local_context_window_clamps_start;
mod match_entropy_positive_mixed;
mod match_entropy_zero_uniform;
mod match_line_number_first_line;
mod match_line_number_last_line;
mod normalize_chunk_data_idempotent;
mod should_suppress_example_akia;
