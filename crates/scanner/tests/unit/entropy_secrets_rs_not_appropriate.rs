//! secrets.rs source file must not run entropy by default.

use keyhog_scanner::entropy::is_entropy_appropriate;

#[test]
fn entropy_secrets_rs_not_appropriate() {
    assert!(
        !is_entropy_appropriate(Some("src/tui/secrets.rs"), false),
        "secrets.rs is source code about secrets, not a secret file"
    );
}
