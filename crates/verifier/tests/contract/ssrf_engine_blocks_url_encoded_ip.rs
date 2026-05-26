//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_url_encoded_ip() {
    verify_url_blocked_before_https_check("http://%31%32%37%2e%30%2e%30%2e%31/").await;
}
