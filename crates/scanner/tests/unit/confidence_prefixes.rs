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
        // A realistic AKIA id, not the AWS docs `...EXAMPLE` key: the floor is
        // deliberately withheld from placeholder/example credentials, so the
        // canonical EXAMPLE key correctly returns None and cannot be used here.
        known_prefix_confidence_floor(concat!("AK", "IAJ4F7K9P2QWX5R8NZ")),
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
