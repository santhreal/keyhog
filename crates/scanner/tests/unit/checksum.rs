use base64::Engine;
use keyhog_scanner::checksum::*;

#[test]
fn github_classic_valid() {
    let token = "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";
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_classic_all_as_valid() {
    let token = "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";
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_classic_invalid_checksum() {
    let token = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1rpRcx";
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_classic_not_applicable_variants() {
    assert_eq!(
        GithubClassicPatValidator.validate("gho_something"),
        ChecksumResult::NotApplicable
    );
    assert_eq!(
        GithubClassicPatValidator.validate("ghp_tooshort"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_fine_grained_valid() {
    let token = "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB0ImpdU";
    assert_eq!(
        GithubFineGrainedPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_fine_grained_invalid_checksum() {
    let token = "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB000000";
    assert_eq!(
        GithubFineGrainedPatValidator.validate(token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_not_applicable() {
    assert_eq!(
        GithubFineGrainedPatValidator.validate("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_valid_and_invalid() {
    let token = "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";
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Valid);

    let invalid = "npm_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC48bxyX";
    assert_eq!(
        NpmTokenValidator.validate(&invalid),
        ChecksumResult::Invalid
    );
    assert_eq!(
        NpmTokenValidator.validate("npm_tooshort"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn slack_valid_and_invalid_variants() {
    assert_eq!(
        SlackTokenValidator.validate("xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate("xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx"),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator
            .validate("xoxp-1234567890-1234567890-1234567890-abcdef1234567890abcdef1234567890"),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate("xoxb-nodashes"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        SlackTokenValidator.validate("not-a-slack-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn pypi_valid_and_invalid_variants() {
    let blob = base64::engine::general_purpose::URL_SAFE.encode(vec![0u8; 120]);
    let token = format!("pypi-{blob}");
    assert_eq!(PypiTokenValidator.validate(&token), ChecksumResult::Valid);
    assert_eq!(
        PypiTokenValidator.validate("pypi-!!!not-valid-base64!!!"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        PypiTokenValidator.validate("pypi-short"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        PypiTokenValidator.validate("not-pypi-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn registry_routes_and_rejects() {
    let github = "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";
    assert_eq!(validate_checksum(&github), ChecksumResult::Valid);

    let npm = "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";
    assert_eq!(validate_checksum(&npm), ChecksumResult::Valid);

    let slack = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
    assert_eq!(validate_checksum(slack), ChecksumResult::Valid);

    let blob = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 120]);
    let pypi = format!("pypi-{blob}");
    assert_eq!(validate_checksum(&pypi), ChecksumResult::Valid);

    assert_eq!(
        validate_checksum("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        validate_checksum("npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000"),
        ChecksumResult::Invalid
    );
    assert_eq!(validate_checksum("xoxb-bad"), ChecksumResult::Invalid);
    assert_eq!(validate_checksum("pypi-!!!bad!!!"), ChecksumResult::Invalid);
    assert_eq!(
        validate_checksum("AKIAIOSFODNN7EXAMPLE"),
        ChecksumResult::NotApplicable
    );
}
