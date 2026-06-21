use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn multi_hyphen_train_case_header_name_suppressed() {
    // Dogfood: shopify-api-js packages/shopify-api/lib/types.ts:24 has
    //   `AccessToken = 'X-Shopify-Access-Token',`
    // and storefront.rb:32 has the literal `"Shopify-Storefront-Private-Token"`.
    // These are HTTP header NAMES (string literals naming a header),
    // not header VALUES - never credentials.
    // v0.5.22 wires `looks_like_word_separated_identifier` which catches
    // multi-hyphen alpha-only train-case via max-word-length ≤ 10.
    assert!(named_detector_suppressed(
        "X-Shopify-Access-Token",
        Some("shopify-api-js/packages/shopify-api/lib/types.ts"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    assert!(named_detector_suppressed(
        "Shopify-Storefront-Private-Token",
        Some("shopify-api-ruby/lib/shopify_api/clients/graphql/storefront.rb"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // Generic train-case header
    assert!(named_detector_suppressed(
        "X-Auth-Token",
        Some("server/middleware.go"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
}
