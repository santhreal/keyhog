//! SSRF adversarial: CGNAT 100.64.0.0/10

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_cgnat_carrier_grade_nat() {
    assert!(is_private_url("http://100.64.0.1/"), "SSRF guard must block http://100.64.0.1/");
}
