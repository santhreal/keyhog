//! SSRF must classify cloud metadata IP as private before fetch.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn metadata_ip_is_private_url() {
    assert!(
        is_private_url("http://169.254.169.254/latest/meta-data/"),
        "169.254.169.254 must be classified private (SSRF metadata guard)"
    );
}
