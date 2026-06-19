//! R5-T http adversarial: public https example.com allowed.

use keyhog_sources::testing::{SourceTestApi, TestApi};
#[cfg(feature = "web")]
#[test]
fn r5t_web_accepts_public_https_example() {
    assert!(!TestApi.is_disallowed_web_host("https://example.com/app.js"));
}

#[cfg(not(feature = "web"))]
#[test]
fn r5t_web_accepts_public_https_example() {}
