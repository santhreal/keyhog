use super::*;

#[test]
fn live_classification_rules_parse() {
    let rules = parse_classification_rules(DETECTOR_CLASSIFICATION_TOML).unwrap();
    assert!(rules
        .stripe_hot_confirmed_prefix
        .iter()
        .any(|prefix| prefix == "sk_live_"));
}

#[test]
fn parse_rejects_duplicate_prefixes() {
    let err = parse_classification_rules(
        r#"
stripe_hot_confirmed_prefix = ["sk_live_", "sk_live_"]
"#,
    )
    .unwrap_err();

    assert!(err.contains("stripe_hot_confirmed_prefix"));
    assert!(err.contains("more than once"));
}

/// The `weak_anchor` / `private_key_block` id lists were MIGRATED OUT to
/// per-detector `DetectorSpec` fields. `deny_unknown_fields` must now REJECT
/// them if they reappear here, so the migration cannot silently regress into
/// a second home for the same data (ONE PLACE law).
#[test]
fn parse_rejects_migrated_out_id_lists() {
    let weak_err = parse_classification_rules(r#"weak_anchor = ["flickr-api-key"]"#)
        .expect_err("weak_anchor must no longer be a valid classification field");
    assert!(
        weak_err.contains("weak_anchor") || weak_err.contains("unknown field"),
        "expected an unknown-field rejection for weak_anchor, got: {weak_err}"
    );

    let pkb_err = parse_classification_rules(r#"private_key_block = ["private-key"]"#)
        .expect_err("private_key_block must no longer be a valid classification field");
    assert!(
        pkb_err.contains("private_key_block") || pkb_err.contains("unknown field"),
        "expected an unknown-field rejection for private_key_block, got: {pkb_err}"
    );
}
