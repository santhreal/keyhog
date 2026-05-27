use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

#[test]
fn scheme_prefixed_uri_and_urn_suppressed() {
    // Dogfood: shopify-api-js token-exchange.ts:13-14 has
    //   `OnlineAccessToken = 'urn:shopify:params:oauth:token-type:online-access-token'`
    // The trailing `token-type:online-access-token` triggers the
    // generic-secret keyword anchor; the captured value is the full URN.
    // v0.5.22 wires `looks_like_scheme_prefixed_uri` which catches the
    // `<3-15-char-alpha-scheme>:<at-least-one-more-colon>` shape.
    assert!(should_suppress_named_detector_finding(
        "urn:shopify:params:oauth:token-type:online-access-token",
        Some("shopify-api-js/packages/shopify-api/lib/auth/oauth/token-exchange.ts"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // bat-go merchant README log-line example: `secret-token:<base64>`
    // is a scheme-prefixed identifier for Brave SKU macaroons documented
    // inline. The README shows the format, not a deployable secret.
    assert!(should_suppress_named_detector_finding(
        "secret-token:wjOtYCQypY5ky1AM_co1lTXNJdOe3Q_waNnnfdyl5u3eOKHCKL-galY9Wklf",
        Some("bat-go/tools/merchant/cmd/README.md"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // Generic URL form
    assert!(should_suppress_named_detector_finding(
        "https://api.example.com/v1/token",
        Some("docs/api.md"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
}
