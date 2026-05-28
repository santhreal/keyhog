//! KH-GAP-126 FP twin: shape-gated export DB_PASSWORD must not surface.

#[path = "oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn no_generic_password_finding_on_shape_gated_near_miss() {
    let matches = scan_text(
        "export DB_PASSWORD=\"0000000000000000000000000000\"\n",
        "suppression-shape-gate-fp.txt",
    );
    let hits: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "generic-password")
        .collect();
    assert!(
        hits.is_empty(),
        "shape-gated near-miss must not surface as generic-password finding; got {:?}",
        hits.iter().map(|m| m.credential.as_ref()).collect::<Vec<_>>()
    );
}
