//! SSRF adversarial: .internal suffix

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_internal_domain_suffix() {
    assert!(is_private_url("http://api.corp.internal/v1"), "SSRF guard must block http://api.corp.internal/v1");
}
