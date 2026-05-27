use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

#[test]
fn real_credential_with_underscores_not_suppressed() {
    // Adversarial twin: a Stripe-shaped fake test key with the
    // `sk_test_` prefix + 24 chars of base58-shaped randomness.
    // It has 2 underscores AND digits, so it superficially looks
    // like the `word_separated_identifier` family — but its third
    // word is 24 chars > the max-word-length-≤-10 threshold. Must
    // NOT suppress.
    //
    // Literal defanged via concat!() so GitHub push-protection
    // doesn't flag this fixture as a leaked Stripe key.
    let stripe_shape = concat!("sk", "_test_", "4eC39HqLyjWDarjtT1zdp7dc");
    assert!(!should_suppress_named_detector_finding(
        stripe_shape,
        Some("app/config/billing.rs"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // MailChimp API key shape: `<32-hex>-<region>` — last segment
    // short, first segment long random hex. Must NOT suppress.
    let mailchimp_shape = concat!("a1b2c3d4e5f6789012345678901234ab", "-", "us12");
    assert!(!should_suppress_named_detector_finding(
        mailchimp_shape,
        Some("app/config/mail.env"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // Slack bot token shape: `xoxb-<workspace-id>-<channel-id>-<secret>`.
    // Last segment is long random. Must NOT suppress.
    let slack_shape = concat!(
        "xoxb-",
        "12345678-",
        "abcdef123456-",
        "AbCdEfGhIjKlMnOpQrStUvWx"
    );
    assert!(!should_suppress_named_detector_finding(
        slack_shape,
        Some("config/slack.toml"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
}
