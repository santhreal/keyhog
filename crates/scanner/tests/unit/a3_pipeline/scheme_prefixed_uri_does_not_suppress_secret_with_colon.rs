use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

#[test]
fn long_random_secret_with_one_colon_not_suppressed() {
    // Adversarial twin: a connection-string-style value with one
    // internal colon (e.g., `host:5432/...`) and a long random
    // password segment MUST still fire.
    // Scheme reject requires: scheme is 3-15 alpha chars + ≥2 more `:`
    // OR `://`. A single mid-value colon flanked by random alphanumerics
    // does not match either.
    assert!(!should_suppress_named_detector_finding(
        "RandomP4ssw0rdAbXyZ1234567890",
        Some("config/database.yml"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // GitHub PAT with `_` separators but long random suffix — must fire.
    // `ghp_<36 chars>` form: `ghp` is a 3-char scheme-like prefix but has
    // NO `:`, so the URI gate doesn't trip.
    //
    // Literal defanged via concat!() so GitHub push-protection doesn't
    // flag this fixture as a leaked PAT.
    let ghp_shape = concat!("ghp", "_", "abcdef0123456789ABCDEFghijKLMNopqrst");
    assert!(!should_suppress_named_detector_finding(
        ghp_shape,
        Some("app/scripts/release.sh"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
}
