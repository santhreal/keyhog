#[test]
fn checksum_gap_tests_use_shared_fixture_builders_not_crc_copies() {
    for (name, src) in [
        (
            "checksum_gitlab_npm_slack_stripe.rs",
            include_str!("../../gap/checksum_gitlab_npm_slack_stripe.rs"),
        ),
        (
            "confidence_floor_policy.rs",
            include_str!("../../gap/confidence_floor_policy.rs"),
        ),
        (
            "detector_recall_prefixes.rs",
            include_str!("../../gap/detector_recall_prefixes.rs"),
        ),
    ] {
        assert!(
            !src.contains("fn crc32("),
            "{name} must mint checksum fixtures through keyhog_scanner::testing::checksum"
        );
        assert!(
            !src.contains("fn base62_encode_u32("),
            "{name} must not carry a private base62 encoder"
        );
        assert!(
            !src.contains("const BASE62_DIGITS"),
            "{name} must not carry a production-checksum alphabet owner"
        );
    }

    let github = include_str!("../../gap/checksum_github.rs");
    assert!(
        github.contains("github_classic_pat_with_checksum(entropy)"),
        "checksum_github.rs may keep an independent golden-vector oracle, but valid fixture minting must use the shared builder"
    );
}
