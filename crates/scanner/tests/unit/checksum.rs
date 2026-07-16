use base64::Engine;
use keyhog_scanner::testing::checksum::*;

#[test]
fn github_classic_valid() {
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_classic_all_as_valid() {
    let token = concat!("gh", "p_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPlr");
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_classic_invalid_checksum() {
    let token = concat!("gh", "p_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1rpRcx");
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_classic_not_applicable_variants() {
    // Wrong-length payloads are NotApplicable regardless of which recognised
    // prefix they carry (gho_ is now a recognised sibling prefix, so this
    // exercises the length gate, not prefix rejection).
    assert_eq!(
        GithubClassicPatValidator.validate("gho_something"),
        ChecksumResult::NotApplicable
    );
    assert_eq!(
        GithubClassicPatValidator.validate("ghp_tooshort"),
        ChecksumResult::NotApplicable
    );
    // A genuinely unrecognised prefix (ghz_) is NotApplicable even at the right
    // length (the validator only claims the five real github families).
    assert_eq!(
        GithubClassicPatValidator.validate("ghz_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPlr"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_oauth_family_shares_classic_checksum() {
    // gho_/ghu_/ghs_/ghr_ share the classic body: 30-char entropy + 6-char
    // CRC32-base62 checksum, CRC over the entropy ONLY (prefix-independent). A
    // correct classic checksum stays valid under every sibling prefix; a
    // mismatch is rejected. Before this fix only ghp_ was validated, so
    // fabricated gho_/ghu_/ghs_/ghr_ tokens slipped through as false positives.
    // `0uCPlr` == base62(crc32("A" * 30)); see `github_classic_all_as_valid`.
    const ENTROPY_AND_CK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0uCPlr";
    for prefix in ["gho_", "ghu_", "ghs_", "ghr_"] {
        let valid = format!("{prefix}{ENTROPY_AND_CK}");
        assert_eq!(
            GithubClassicPatValidator.validate(&valid),
            ChecksumResult::Valid,
            "{prefix} token with a correct classic checksum must validate"
        );
        let fabricated = format!("{prefix}AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000");
        assert_eq!(
            GithubClassicPatValidator.validate(&fabricated),
            ChecksumResult::Invalid,
            "{prefix} token with a wrong checksum must be rejected"
        );
    }
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
        GithubFineGrainedPatValidator
            .validate(concat!("gh", "p_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
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
        SlackTokenValidator.validate(concat!(
            "xox",
            "b-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
        )),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate(concat!(
            "xox",
            "p-1234567890-1234567890-abcdefghijklmnopqrstuvwx"
        )),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate(concat!(
            "xox",
            "p-1234567890-1234567890-1234567890-abcdef1234567890abcdef1234567890"
        )),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate(concat!("xox", "b-nodashes")),
        ChecksumResult::Invalid
    );
    assert_eq!(
        SlackTokenValidator.validate("not-a-slack-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn pypi_valid_and_invalid_variants() {
    let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 75]);
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
    let github = concat!("gh", "p_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDD3g9sWQ");
    assert_eq!(validate_checksum(&github), ChecksumResult::Valid);

    let npm = "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";
    assert_eq!(validate_checksum(&npm), ChecksumResult::Valid);

    let slack = concat!("xox", "b-1234567890-1234567890-abcdefghijklmnopqrstuvwx");
    assert_eq!(validate_checksum(slack), ChecksumResult::StructurallyValid);

    let blob = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec![0u8; 75]);
    let pypi = format!("pypi-{blob}");
    assert_eq!(validate_checksum(&pypi), ChecksumResult::Valid);

    assert_eq!(
        validate_checksum(concat!("gh", "p_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000")),
        ChecksumResult::Invalid
    );
    assert_eq!(
        validate_checksum("npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        validate_checksum(concat!("xox", "b-bad")),
        ChecksumResult::Invalid
    );
    assert_eq!(validate_checksum("pypi-!!!bad!!!"), ChecksumResult::Invalid);
    assert_eq!(
        validate_checksum(concat!("AK", "IAIOSFODNN7EXAMPLE")),
        ChecksumResult::NotApplicable
    );
}

/// CONSOLIDATION GUARD (DR-321): every checksum-family prefix is single-owned in
/// `crate::checksum::prefixes` and the validators strip it from there, but the
/// SAME prefix is also the detection signal in the family's detector TOML. This
/// binds the two so the detector is the source of truth: each bound prefix MUST
/// appear verbatim in its detector's TOML, so a pattern edit can never silently
/// diverge from the validator that gates the finding (nor the reverse). The
/// `checksum_prefixes()` accessor cross-checks the binding against the real
/// single-owner set so no newly-added checksum family can slip past unbound.
#[test]
fn checksum_prefixes_are_backed_by_their_detector() {
    // `(checksum prefix, authoritative detector)`: the detector is the source of
    // truth for the prefix; the validator const is a mirror this test keeps
    // honest. This binding lives in the TEST (detector-id strings belong only to
    // `detector_ids.rs` in src, per the `detector_id_owner` gate).
    // DELIBERATE OMISSION: Stripe `pk_live_`/`pk_test_`: the validator
    // structurally recognises publishable keys, but NO detector surfaces them
    // (a publishable key is PUBLIC, not a secret), so they are validator-only.
    let bindings: &[(&str, &str)] = &[
        ("ghp_", "github-classic-pat"),
        ("gho_", "github-oauth-access-token"),
        ("ghu_", "github-user-to-server-token"),
        ("ghs_", "github-app-installation-token"),
        ("ghr_", "github-refresh-token"),
        ("github_pat_", "github-pat-fine-grained"),
        ("glpat-", "gitlab-personal-access-token"),
        ("glcbt-", "gitlab-package-registry-token"),
        ("glrt-", "gitlab-runner-authentication-token"),
        ("npm_", "npm-access-token"),
        ("pypi-", "pypi-api-token"),
        ("xoxb-", "slack-bot-token"),
        ("xoxp-", "slack-user-token"),
        ("sk_live_", "stripe-secret-key"),
        ("sk_test_", "stripe-secret-key"),
        ("rk_live_", "stripe-secret-key"),
        ("rk_test_", "stripe-secret-key"),
    ];

    // Consistency: every single-owner prefix the validators actually strip is
    // bound above (except the publishable-key pk_ prefixes, validator-only), so
    // this test can never silently miss a newly-added checksum family.
    for prefix in keyhog_scanner::testing::checksum_prefixes() {
        if prefix.starts_with("pk_") {
            continue;
        }
        assert!(
            bindings.iter().any(|(bound, _)| *bound == prefix),
            "checksum prefix {prefix:?} (crate::checksum::prefixes) is not bound to a \
             detector in this guard, add its (prefix, detector) row"
        );
    }

    // Authority: every bound prefix MUST appear verbatim in its detector TOML.
    let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../core/detectors"));
    let mut drifted: Vec<String> = Vec::new();
    for (prefix, detector_id) in bindings {
        let path = dir.join(format!("{detector_id}.toml"));
        let toml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read authoritative detector {}: {e}", path.display()));
        if !toml.contains(prefix) {
            drifted.push(format!(
                "checksum prefix {prefix:?} is absent from its detector {detector_id}.toml \
The validator literal drifted from the detection pattern"
            ));
        }
    }
    assert!(
        drifted.is_empty(),
        "checksum prefix(es) drifted from their authoritative detector \
         (detector is the source of truth):\n  - {}",
        drifted.join("\n  - ")
    );
}
