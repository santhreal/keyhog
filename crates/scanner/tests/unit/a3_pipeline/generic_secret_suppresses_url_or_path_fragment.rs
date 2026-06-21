use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn template_path_and_url_fragment_suppressed() {
    // Dogfood: gogs internal/route/user/setting.go:45 declares Go template
    // path constants like
    //   `tmplUserSettingsPassword = "user/settings/password"`
    // and auth.go has `user/auth/forgot_passwd`. These are TEMPLATE paths,
    // not credentials. v0.5.22 wires `looks_like_url_or_path_segment`.
    assert!(named_detector_suppressed(
        "user/settings/password",
        Some("gogs/internal/route/user/setting.go"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
    assert!(named_detector_suppressed(
        "user/auth/forgot_passwd",
        Some("gogs/internal/route/user/auth.go"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
    // alist drivers/123_open/api.go:14 has `ApiToken = "/api/v1/access_token"`
    // - that's a URL path string, not a token value.
    assert!(named_detector_suppressed(
        "/api/v1/access_token",
        Some("alist/drivers/123_open/api.go"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
}
