//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_malformed_too_many_octets() {
    verify_url_blocked_before_https_check("http://0.0.0.0.0/").await;
}
