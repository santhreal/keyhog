use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::named_detector_suppressed;

#[test]
fn cli_flag_pointer_ref_sql_bind_label_suppressed() {
    // Dogfood: shopify-cli lib/project_types/extension/loaders/project.rb:36
    //   `{ api_key: "--api-key", secret: "--api-secret" }`
    // CLI flag names captured as values.
    assert!(named_detector_suppressed(
        "--api-secret",
        Some("shopify-cli/lib/project_types/extension/loaders/project.rb"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // curl lib/socks_gssapi.c:299 - `gss_token = &gss_recv_token;`
    assert!(named_detector_suppressed(
        "&gss_recv_token",
        Some("curl/lib/socks_gssapi.c"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // webgoat Login_i.java:41 - `PASSWORD = @v_password`
    // (T-SQL stored procedure parameter binding).
    assert!(named_detector_suppressed(
        "@v_password",
        Some("webgoat/lessons/instructor/DBSQLInjection/Login_i.java"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // claude-code setupGitHubActions.ts:129 -
    //   `has_api_key: !!apiKeyOrOAuthToken,`
    // JS truthy coercion captured with leading `!!`.
    assert!(named_detector_suppressed(
        "!!apiKeyOrOAuthToken",
        Some("claude-code/src/commands/install-github-app/setupGitHubActions.ts"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // shopify-cli lib/project_types/theme/messages/messages.rb:58 -
    //   `ask_password: "Password:",`
    // UI prompt label captured with trailing colon.
    assert!(named_detector_suppressed(
        "Password:",
        Some("shopify-cli/lib/project_types/theme/messages/messages.rb"),
        CodeContext::Unknown,
        None,
        "generic-password",
    ));
    // shopify-api-js storefront-api-client.ts:71 -
    //   `privateAccessToken: privateAccessToken!,`
    // TS non-null assertion captured with trailing `!`.
    assert!(named_detector_suppressed(
        "privateAccessToken!",
        Some("shopify-api-js/packages/storefront-api-client/src/storefront-api-client.ts"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
}
