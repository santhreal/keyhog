//! KH-GAP-126 FN twin: near shape-gate boundary realistic password must fire.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn generic_password_near_shape_gate_boundary_still_fires() {
    let credential = "S4oxj2N-bVEi6ivQsrW3";
    let text = format!("database_password=\"{credential}\"");
    let matches = scan_text(&text, "suppression-shape-gate-fn.txt");
    assert!(
        matches.iter().any(|m| {
            m.detector_id.as_ref() == "generic-password"
                && m.credential.as_ref().contains(credential)
        }),
        "realistic generic-password must not be wrongly suppressed; got {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
