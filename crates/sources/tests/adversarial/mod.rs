//! Adversarial coverage for source backends - bomb-prevention,
//! malformed inputs, evasions.
//!
//! Mirrors the audit release-2026-04-26 hardening: gzip/zstd 4× budget,
//! per-archive-entry size cap, dropped io_uring single-op path, etc.

mod binary_oversized_file_survives;
mod binary_strings_only_min_len_eight;
mod empty_jar_does_not_panic;
mod filesystem_minified_js_skipped;
mod git_non_repo_path_rejected;
mod git_ref_double_dot_rejected;
mod git_ref_glob_star_rejected;
mod git_ref_leading_dash_rejected;
mod git_repo_path_leading_dash_rejected;
mod gzip_bomb_caps;
mod gzip_single_member_secret_survives;
mod jar_oversized_entry_metadata_skipped;
mod lz4_random_bytes_no_panic;
mod max_file_size_skips_oversize_plain_file;
mod nested_archive;
mod oversize_compressed_input_refused;
mod pdf_magic_file_not_scanned_as_text;
mod png_magic_file_not_scanned_as_text;
mod snappy_random_bytes_no_panic;
mod unicode_filename_in_jar_scanned;
mod zst_oversize_window_refused;
mod zst_truncated_header_no_panic;
