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
#[path = "a5_lr2/http_proxy_flag_overrides_env.rs"]
mod a5_lr2_http_proxy_flag_overrides_env;
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
#[path = "a5_lr2/http_proxy_off_preserved.rs"]
mod a5_lr2_http_proxy_off_preserved;
#[path = "a5_lr2/read_safe_cap_refuses_huge.rs"]
mod a5_lr2_read_safe_cap_refuses_huge;
pub mod archive_entry_name_traversal_contract;
pub mod basic_sources;
pub mod binary;
pub mod binary_sections_fat_macho;
#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
pub mod cloud;
pub mod file_gate;
pub mod filesystem;
pub mod filesystem_filter;
pub mod filesystem_filter_generated;
pub mod gates;
pub mod git_diff;
pub mod git_diff_head_worktree;
pub mod git_history;
#[cfg(feature = "git")]
pub mod git_max_commits_shared_owner;
#[cfg(feature = "github")]
pub mod github_org_pagination;
pub mod har;
pub mod http;
pub mod internal_contracts;
pub mod lib;
pub mod magic;
pub mod magic_generated;
#[cfg(any(
    feature = "git",
    feature = "docker",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
pub mod process_excerpt;
pub mod src_inline_skip_counter_isolation;
#[cfg(feature = "web")]
pub mod ssrf_generated;
pub mod strings_extract;
pub mod timeouts;
#[cfg(feature = "web")]
pub mod url_redaction_generated;
#[cfg(feature = "web")]
pub mod web_redact_url_userinfo_boundary;
#[cfg(feature = "web")]
pub mod web_redirect_pin_key;
