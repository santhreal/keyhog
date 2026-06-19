//! Micro gate for `sources/timeouts.rs` - shared HTTP/subprocess budgets.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))]
#[test]
fn http_request_timeout_is_thirty_seconds() {
    assert_eq!(
        TestApi.http_request_timeout(),
        std::time::Duration::from_secs(30),
        "HTTP_REQUEST must stay aligned with http.rs DEFAULT_TIMEOUT"
    );
}

#[cfg(feature = "github")]
#[test]
fn git_clone_timeout_is_five_minutes() {
    assert_eq!(
        TestApi.git_clone_timeout(),
        std::time::Duration::from_secs(300)
    );
}

#[cfg(feature = "binary")]
#[test]
fn ghidra_analysis_timeout_is_five_minutes() {
    assert_eq!(
        TestApi.ghidra_analysis_timeout(),
        std::time::Duration::from_secs(300)
    );
}
