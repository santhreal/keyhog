//! Lockfiles must skip entropy scanning.

use keyhog_scanner::entropy::is_entropy_appropriate;

#[test]
fn entropy_package_lock_not_appropriate() {
    assert!(
        !is_entropy_appropriate(Some("frontend/package-lock.json"), false),
        "package-lock.json must be excluded from entropy fallback"
    );
}
