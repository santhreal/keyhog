//! Behavioral coverage for the shared CRC32 and base62 checksum owner.
//!
//! Production primitives stay crate-private. These tests exercise them through
//! exact token bytes and both validators that consume the shared owner.

use keyhog_scanner::testing::checksum::{
    github_classic_pat_with_checksum, github_fine_grained_pat_with_checksum,
    npm_token_with_checksum, ChecksumResult, GithubClassicPatValidator,
    GithubFineGrainedPatValidator, NpmTokenValidator,
};
use proptest::prelude::*;

#[test]
fn shared_owner_matches_known_github_and_npm_bytes() {
    let body = "A".repeat(30);
    assert_eq!(
        github_classic_pat_with_checksum(&body),
        "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"
    );
    assert_eq!(
        npm_token_with_checksum(&body),
        "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"
    );

    let left = "A".repeat(22);
    let right = "B".repeat(53);
    assert_eq!(
        github_fine_grained_pat_with_checksum(&left, &right),
        "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0fqbVo"
    );
}

fn corrupt_checksum(token: &str) -> String {
    let mut bytes = token.as_bytes().to_vec();
    let last = bytes
        .last_mut()
        .expect("checksum-bearing fixture cannot be empty");
    *last = if *last == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).expect("fixture remains ASCII")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn classic_and_npm_share_byte_identical_suffixes(body in "[A-Za-z0-9]{30}") {
        let github = github_classic_pat_with_checksum(&body);
        let npm = npm_token_with_checksum(&body);

        prop_assert_eq!(&github["ghp_".len()..], &npm["npm_".len()..]);
        prop_assert_eq!(GithubClassicPatValidator.validate(&github), ChecksumResult::Valid);
        prop_assert_eq!(NpmTokenValidator.validate(&npm), ChecksumResult::Valid);
        prop_assert_eq!(
            GithubClassicPatValidator.validate(&corrupt_checksum(&github)),
            ChecksumResult::Invalid
        );
        prop_assert_eq!(
            NpmTokenValidator.validate(&corrupt_checksum(&npm)),
            ChecksumResult::Invalid
        );
    }

    #[test]
    fn fine_grained_builder_is_accepted(
        left in "[A-Za-z0-9]{22}",
        right in "[A-Za-z0-9]{53}",
    ) {
        let token = github_fine_grained_pat_with_checksum(&left, &right);
        prop_assert_eq!(
            GithubFineGrainedPatValidator.validate(&token),
            ChecksumResult::Valid
        );
    }
}
