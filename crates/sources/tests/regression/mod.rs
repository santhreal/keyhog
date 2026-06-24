//! Regression tests pinning specific bugs that shipped fixes.
//! Each test must reference the audit / commit that drove its addition.

mod compressed_open_errors_visible;
mod max_file_size_cap;
mod tar_entry_errors_visible;
