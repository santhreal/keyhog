//! Adversarial (Unix): concurrent scans from temp dirs yield valid JSON.

#[test]
fn concurrent_four_scans_json_unix() {
    crate::adversarial::support::oracle_concurrent_four_scans_json();
}
