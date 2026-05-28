//! SSRF adversarial: credential loopback

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_credential_userinfo_loopback() {
    assert!(is_private_url("http://user:secret@127.0.0.1/"), "SSRF guard must block http://user:secret@127.0.0.1/");
}
