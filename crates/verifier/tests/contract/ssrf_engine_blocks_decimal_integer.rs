//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_decimal_integer() {
    verify_url_blocked_before_https_check("http://2130706433/").await;
}
