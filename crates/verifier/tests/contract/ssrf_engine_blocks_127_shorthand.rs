//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_127_shorthand() {
    verify_url_blocked_before_https_check("http://127.1/").await;
}
