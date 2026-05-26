//! Contract: verification engine rejects private URL before fetch.

use crate::common::ssrf_engine::verify_url_blocked_before_https_check;

#[tokio::test]
async fn ssrf_engine_blocks_link_local_metadata() {
    verify_url_blocked_before_https_check("http://169.254.169.254/latest/meta-data/").await;
}
