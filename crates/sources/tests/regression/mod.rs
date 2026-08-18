//! Regression tests pinning specific bugs that shipped fixes.
//! Each test must reference the audit / commit that drove its addition.

mod binary_literal_decode;
mod binary_literal_decode_escape_contract;
mod compressed_open_errors_visible;
mod git_blob_batch_streaming;
mod git_blob_parent_diff_recall;
mod max_file_size_cap;
#[path = "../regression_oom_unbounded_read_caps.rs"]
mod oom_unbounded_read_caps;
mod raw_container_read_errors_visible;
mod tar_entry_errors_visible;
#[path = "../regression_row_100_derived_counter_reset.rs"]
mod regression_row_100_derived_counter_reset;
