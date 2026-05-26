//! secrets.yaml config file must allow entropy scanning.

use keyhog_scanner::entropy::is_entropy_appropriate;

#[test]
fn entropy_secrets_yaml_is_appropriate() {
    assert!(
        is_entropy_appropriate(Some("config/secrets.yaml"), false),
        "secrets.yaml is a config secret file"
    );
}
