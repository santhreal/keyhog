//! R5-T-SCAN homoglyph must not evade `aws-access-key` when body is real.

#[path = "../oracle_support.rs"]
mod oracle_support;
use oracle_support::scan_text;

#[test]
fn homoglyph_fullwidth_latin_akia() {
    let prefix: String = ['\u{FF21}', '\u{FF4B}', '\u{FF49}', '\u{FF41}']
        .iter()
        .collect();
    let text = format!("export TOKEN=\"{prefix}QYLPMN5HFIQR7XYA\"");
    let tail = "QYLPMN5HFIQR7XYA";
    let matches = scan_text(&text, "homoglyph.env");
    assert!(
        matches.iter().any(|m| m.credential.as_ref().contains(tail)),
        "Fullwidth AKIA prefix must not fully evade — tail {tail:?}; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
