//! Adversarial (Unix): scanning parent of a unicode filename succeeds.

#[test]
fn unicode_path_scan_parent_unix() {
    crate::support::oracle_unicode_path_scan();
}
