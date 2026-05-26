//! Cargo.toml manifest must skip entropy scanning by default.

use keyhog_scanner::entropy::is_entropy_appropriate;

#[test]
fn entropy_cargo_toml_not_appropriate() {
    assert!(
        !is_entropy_appropriate(Some("crates/scanner/Cargo.toml"), false),
        "package manifest must not run entropy fallback without --entropy-source-files"
    );
}
