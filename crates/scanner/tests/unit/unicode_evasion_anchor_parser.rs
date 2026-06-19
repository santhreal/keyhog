use keyhog_scanner::testing::unicode_hardening::parse_evasion_anchors_for_test;

#[test]
fn evasion_anchor_tier_b_parser_rejects_invalid_vocabularies() {
    let empty = parse_evasion_anchors_for_test("anchors = []\n")
        .expect_err("empty evasion anchor list must fail closed");
    assert!(
        empty.contains("at least one entry"),
        "unexpected empty-list error: {empty}"
    );

    let blank = parse_evasion_anchors_for_test("anchors = [\"ghp_\", \"  \"]\n")
        .expect_err("blank evasion anchor must fail closed");
    assert!(
        blank.contains("must not be empty"),
        "unexpected blank-anchor error: {blank}"
    );

    let duplicate = parse_evasion_anchors_for_test("anchors = [\"AKIA\", \"AKIA\"]\n")
        .expect_err("duplicate evasion anchor must fail closed");
    assert!(
        duplicate.contains("duplicate evasion anchor"),
        "unexpected duplicate-anchor error: {duplicate}"
    );
}
