//! Cyrillic homoglyphs in AKIA prefix must not evade detection when body is real.

use super::oracle_support::scan_text;

#[test]
fn unicode_cyrillic_akia_homoglyph_no_evade() {
    // Latin A replaced with Cyrillic А (U+0410) in prefix only — body stays canonical.
    let homoglyph_prefix = "\u{0410}KIA"; // АKIA visually similar
    let body = format!("{homoglyph_prefix}QYLPMN5HFIQR7XYA");
    let matches = scan_text(&format!("export AWS_KEY=\"{body}\""), "homoglyph.env");
    let aws_hits: Vec<_> = matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .collect();
    assert!(
        !aws_hits.is_empty(),
        "homoglyph-prefixed AKIA body must not evade aws-access-key; matches={:?}",
        matches
            .iter()
            .map(|m| m.credential.as_ref())
            .collect::<Vec<_>>()
    );
}
