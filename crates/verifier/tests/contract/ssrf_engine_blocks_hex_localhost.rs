//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_hex_localhost() {
    verify_url_blocked_before_https_check("http://0x7F000001/").await;
}
