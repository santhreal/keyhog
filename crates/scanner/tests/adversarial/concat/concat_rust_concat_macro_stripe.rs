//! R5-T-SCAN concat reassembly: rust concat macro stripe.

#[path = "../oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn concat_rust_concat_macro_stripe() {
    let body = r#"#[allow(dead_code)]
const SK: &str = concat!("sk_", "live_", "abcdefghijklmnopqrstuvwxyz");
"#;
    let matches = scan_text(body, "concat.txt");

    assert!(
        matches
            .iter()
            .any(|m| m.detector_id.as_ref() == "stripe-secret-key"
                && m.credential.as_ref() == "sk_live_abcdefghijklmnopqrstuvwxyz"),
        "stripe-secret-key concat must surface sk_live_abcdefghijklmnopqrstuvwxyz; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
