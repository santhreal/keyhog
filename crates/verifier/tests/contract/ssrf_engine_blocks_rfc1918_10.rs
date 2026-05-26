//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_rfc1918_10() {
    verify_url_blocked_before_https_check("http://10.255.255.255/").await;
}
