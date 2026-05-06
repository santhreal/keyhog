//! Shared timeouts for remote / subprocess sources (avoid magic-number drift).

use std::time::Duration;

/// Typical HTTP(S) request timeout (web fetch, Slack API, S3 REST).
#[cfg(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))]
pub const HTTP_REQUEST: Duration = Duration::from_secs(30);

/// Shallow `git clone` for org scans (and other long-running subprocess work).
#[cfg(feature = "github")]
pub const GIT_CLONE: Duration = Duration::from_secs(300);

/// Ghidra `analyzeHeadless` wall-clock budget.
#[cfg(feature = "binary")]
pub const GHIDRA_ANALYSIS: Duration = Duration::from_secs(300);
