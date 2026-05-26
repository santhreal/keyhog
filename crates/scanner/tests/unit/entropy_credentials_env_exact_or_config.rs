//! credentials.env exact filename is entropy-appropriate.

use keyhog_scanner::entropy::is_entropy_appropriate;

#[test]
fn entropy_credentials_env_exact_or_config() {
    assert!(
        is_entropy_appropriate(Some("deploy/credentials.env"), false),
        "credentials.env must be entropy-appropriate"
    );
}
