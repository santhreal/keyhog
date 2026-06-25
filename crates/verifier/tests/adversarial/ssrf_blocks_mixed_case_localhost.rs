//! SSRF adversarial: mixed-case localhost

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_mixed_case_localhost() {
    assert!(
        is_private_url("http://LoCaLhOsT/"),
        "SSRF guard must block http://LoCaLhOsT/"
    );
}
