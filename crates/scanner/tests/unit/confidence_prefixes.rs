use keyhog_scanner::confidence::known_prefix_confidence_floor;
#[test]
fn known_prefix_floor_matches_expected_prefixes() {
    // Bodies must be NON-degenerate. The floor is deliberately withheld from
    // degenerate runs (>=10 identical chars, e.g. an all-`x` placeholder body)
    // exactly as it is from `...EXAMPLE` keys, so realistic random-looking bodies
    // are required to exercise the known-prefix path. See the AKIA case below.
    assert_eq!(
        known_prefix_confidence_floor("sk_live_51H7xKjGf0a1b2c3"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("ghp_aK7xP9mQ2wE5rT8yU1iO3pL6"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("github_pat_aK7xP9mQ2wE5rT8yU1iO"),
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
        known_prefix_confidence_floor("sk-proj-aK7xP9mQ2wE5rT8yU1iO"),
        Some(0.8)
    );
    assert_eq!(
        known_prefix_confidence_floor("dop_v1_aK7xP9mQ2wE5rT8yU1iO"),
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
