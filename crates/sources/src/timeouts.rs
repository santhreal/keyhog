//! Shared timeouts for remote / subprocess sources (avoid magic-number drift).

/// Typical HTTP(S) request timeout (web fetch, Slack API, S3/GCS REST).
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
pub(crate) const HTTP_REQUEST: std::time::Duration = std::time::Duration::from_secs(30);

/// Shallow `git clone` for org scans (and other long-running subprocess work).
#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
pub(crate) const GIT_CLONE: std::time::Duration = std::time::Duration::from_secs(300);

/// Ghidra `analyzeHeadless` wall-clock budget.
#[cfg(feature = "binary")]
pub(crate) const GHIDRA_ANALYSIS: std::time::Duration = std::time::Duration::from_secs(300);
