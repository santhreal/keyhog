//! data: URIs must not pass secret plausibility.

use keyhog_scanner::entropy::keywords::is_secret_plausible;

#[test]
fn entropy_data_uri_rejected() {
    assert!(
        !is_secret_plausible("data:image/png;base64,iVBORw0KGgo=", &[]),
        "data URI must be rejected"
    );
}
