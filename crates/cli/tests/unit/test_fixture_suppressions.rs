use keyhog::test_fixture_suppressions::TestFixtureSuppressions;

#[test]
fn bundled_loads_and_parses() {
    let s = TestFixtureSuppressions::bundled();
    assert!(
        s.exact_count() >= 5,
        "expected at least 5 exact entries; got {}",
        s.exact_count(),
    );
}

#[test]
fn bundled_suppresses_known_demo_keys() {
    let s = TestFixtureSuppressions::bundled();
    assert!(s.suppresses(concat!("sk_li", "ve_4eC39HqLyjWDarjtT1zdp7dc")));
    assert!(s.suppresses(concat!("gh", "p_aBcD1234EFgh5678ijklMNop9012qrSTuvWX")));
    assert!(s.suppresses(concat!("xox", "b-123456789012-1234567890123")));
    assert!(s.suppresses("API_KEY_EXAMPLE"));
    assert!(s.suppresses("PLACEHOLDER_token"));
}

#[test]
fn bundled_does_not_suppress_real_aws_key() {
    let s = TestFixtureSuppressions::bundled();
    assert!(!s.suppresses(concat!("AK", "IAQYLPMN5HFIQR7XYA")));
    assert!(!s.suppresses("just some text"));
    assert!(!s.suppresses(""));
}

#[test]
fn empty_never_suppresses() {
    let s = TestFixtureSuppressions::empty();
    assert!(!s.suppresses(concat!("sk_li", "ve_4eC39HqLyjWDarjtT1zdp7dc")));
    assert!(!s.suppresses("API_KEY_EXAMPLE"));
    assert_eq!(s.exact_count(), 0);
}
