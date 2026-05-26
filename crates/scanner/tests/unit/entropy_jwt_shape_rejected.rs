//! Three-part JWT-looking strings are rejected as secrets.

use keyhog_scanner::entropy::keywords::is_secret_plausible;

#[test]
fn entropy_jwt_shape_rejected() {
    assert!(
        !is_secret_plausible("eyJhbG.aWQiOi.abc123signature", &[]),
        "JWT-shaped token must be rejected by universal rejection list"
    );
}
