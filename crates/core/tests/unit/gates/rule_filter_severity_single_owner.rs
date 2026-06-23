#[test]
fn rule_filter_uses_severity_enum_for_filter_labels_and_rank() {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/spec.rs"))
        .expect("spec source readable");
    let rule_filter =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/rule_filter.rs"))
            .expect("rule_filter source readable");

    for required in [
        "pub(crate) const ORDERED: [Severity; 6]",
        "pub(crate) fn from_filter_label(label: &str) -> Option<Self>",
        "pub(crate) fn rank(self) -> usize",
        "pub(crate) fn label_for_rank(rank: usize) -> &'static str",
    ] {
        assert!(
            spec.contains(required),
            "Severity must own filter label/rank contract `{required}`"
        );
    }
    for required in [
        "Severity::from_filter_label(s)",
        ".map(Severity::rank)",
        "Severity::label_for_rank(rank)",
        "Severity::FILTER_EXPECTED_LABELS",
    ] {
        assert!(
            rule_filter.contains(required),
            "rule_filter must consume Severity-owned filter contract `{required}`"
        );
    }
    for forbidden in [
        "\"info\" => Ok(0)",
        "\"client-safe\" => Ok(1)",
        "0 => \"info\"",
        "1 => \"client-safe\"",
        "\"info\" | \"low\" | \"medium\" | \"high\" | \"critical\"",
    ] {
        assert!(
            !rule_filter.contains(forbidden),
            "rule_filter must not restore hardcoded severity table `{forbidden}`"
        );
    }
}
