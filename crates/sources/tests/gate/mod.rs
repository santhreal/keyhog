mod filesystem_read_missing_path_err;
mod git_diff_invalid_ref_errors;
mod git_history_non_repo_yields_no_chunks;
mod git_source_non_repo_name_only;
#[cfg(any(
    feature = "azure",
    feature = "web",
    feature = "slack",
    feature = "s3",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "gcs"
))]
mod http_default_no_explicit_proxy;
mod read_file_safe_bytes_size_cap;
mod s3_empty_bucket_name;
mod stdin_name_is_stdin;
mod strings_binary_extracts_ascii;
