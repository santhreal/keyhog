use keyhog_scanner::confidence::known_prefix_confidence_floor;
#[test]
fn known_prefix_floor_matches_expected_prefixes() {
    assert_eq!(
        known_prefix_confidence_floor("sk_live_51H7xKjGf0a1b2c3"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("ghp_xxxxxxxxxxxxxxxxxxxx"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("github_pat_xxxxxxxxxxxxxx"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("AKIAIOSFODNN7EXAMPLE"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("sk-proj-xxxxxxxxxxxxxxxx"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("dop_v1_xxxxxxxxxxxxxxxxx"),
        Some(0.8)
    );
}

#[test]
fn known_prefix_floor_returns_none_for_unknown_prefixes() {
    assert_eq!(known_prefix_confidence_floor("random_string"), None);
    assert_eq!(known_prefix_confidence_floor(""), None);
    assert_eq!(known_prefix_confidence_floor("sk_live"), None);
    assert_eq!(known_prefix_confidence_floor("ghp"), None);
}
