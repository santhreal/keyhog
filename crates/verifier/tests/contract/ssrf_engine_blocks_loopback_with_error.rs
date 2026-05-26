use crate::common::ssrf_engine::{verify_url_blocked_as_private, PRIVATE_URL_ERROR};

#[tokio::test]
async fn ssrf_engine_blocks_loopback_with_specific_error() {
    let message = verify_url_blocked_as_private("http://127.0.0.1/").await;
    assert_eq!(message, PRIVATE_URL_ERROR);
}
