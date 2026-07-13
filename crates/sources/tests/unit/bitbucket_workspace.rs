    use super::list_repositories;

    fn api_root(server: &httpmock::MockServer) -> reqwest::Url {
        reqwest::Url::parse(&server.url("/2.0")).expect("valid mock API root")
    }

    #[test]
    fn missing_https_clone_link_is_row_error_not_listing_abort() {
        let server = httpmock::MockServer::start();
        let _list = server.mock(|when, then| {
            when.method(httpmock::Method::GET)
                .path("/2.0/repositories/acme")
                .query_param("pagelen", "100");
            then.status(200).header("content-type", "application/json")
                .body(r#"{"values":[{"slug":"good","links":{"clone":[{"name":"https","href":"https://bitbucket.org/acme/good.git"}]}},{"slug":"bad","links":{"clone":[{"name":"ssh","href":"ssh://git@bitbucket.org/acme/bad.git"}]}}],"next":null}"#);
        });

        let (repos, errors) = list_repositories(
            &http_client(),
            &api_root(&server),
            "acme",
            1,
            crate::SourceLimits::default().web_response_bytes,
        )
        .expect("listing");
        assert_eq!(repos.len(), 1, "valid sibling repo must be preserved");
        assert_eq!(repos[0].display_path, "good");
        assert_eq!(errors.len(), 1, "bad sibling must become one row error");
        let error = errors[0].to_string();
        assert!(
            error.contains("bad")
                && error.contains("did not include an HTTPS clone link")
                && error.contains("repository was not scanned"),
            "bad repo error must explain the unscanned malformed record, got {error}"
        );
        // The single error ROW above is the deterministic proof the malformed
        // record was accounted unreadable: `list_repositories` bumps the global
        // unreadable counter in the same path that emits this row. Reading that
        // process-global counter here would race the other backends' `--lib`
        // tests, so this stays a behavioral assertion.
    }

    fn http_client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .build()
            .expect("mock client")
    }

    #[test]
    fn validate_basic_auth_rejects_header_injection_vectors() {
        use super::validate_basic_auth;

        // A clean credential pair passes.
        assert!(validate_basic_auth("alice", "app-password-value").is_ok());

        // `:` in the USERNAME is banned: the Basic-auth pre-image is `user:pass`,
        // so a colon in the username forges an extra field / ambiguous split. (A
        // colon in the TOKEN is legal, everything after the first `:` is the
        // password, so it must NOT be rejected.)
        let colon = validate_basic_auth("al:ice", "tok").expect_err("colon username rejected");
        assert!(
            colon.to_string().contains("unsafe characters"),
            "colon-username error must carry the shared 'unsafe characters' contract, got {colon}"
        );
        assert!(
            validate_basic_auth("alice", "tok:with:colons").is_ok(),
            "a colon inside the token is a legal password byte, not an injection"
        );

        // Control characters (CR/LF/NUL/TAB/DEL) in EITHER field are banned: raw
        // bytes in the `Authorization: Basic …` header enable CRLF header/request
        // splitting.
        for bad in ["a\rb", "a\nb", "a\0b", "a\tb", "a\u{7f}b"] {
            assert!(
                validate_basic_auth(bad, "tok").is_err(),
                "control char in username must be rejected: {bad:?}"
            );
            assert!(
                validate_basic_auth("user", bad).is_err(),
                "control char in token must be rejected: {bad:?}"
            );
        }

        // Empty username or token is rejected (an unauthenticated pre-image).
        assert!(
            validate_basic_auth("", "tok").is_err(),
            "empty username rejected"
        );
        assert!(
            validate_basic_auth("user", "").is_err(),
            "empty token rejected"
        );
    }

    #[test]
    fn source_from_params_requires_three_nonempty_fields() {
        use super::source_from_params;
        // `HttpClientConfig` moves into each call; build a fresh default per call
        // rather than assume it is `Clone`. `SourceLimits` is `Copy`.
        let cfg = || crate::http::HttpClientConfig::default();
        let limits = crate::SourceLimits::default();

        // Fewer than three newline-separated fields → error (missing app password).
        assert!(
            source_from_params("ws\nuser", cfg(), limits, true).is_err(),
            "missing app-password line must be an error"
        );
        // Present-but-EMPTY fields hit the explicit empty-field guard → error.
        assert!(
            source_from_params("ws\n\ntoken", cfg(), limits, true).is_err(),
            "empty username must be an error"
        );
        assert!(
            source_from_params("\nuser\ntoken", cfg(), limits, true).is_err(),
            "empty workspace must be an error"
        );
        // Three non-empty fields parse; endpoint defaults when absent, and a
        // trailing empty 4th field falls back to the default endpoint (the
        // `Some(_) if !empty` else-arm), not an error.
        assert!(
            source_from_params("ws\nuser\ntoken", cfg(), limits, true).is_ok(),
            "three non-empty fields parse successfully"
        );
        assert!(
            source_from_params("ws\nuser\ntoken\n", cfg(), limits, true).is_ok(),
            "trailing empty endpoint line falls back to the default endpoint"
        );
        assert!(
            source_from_params(
                "ws\nuser\ntoken\nhttps://api.example.test/2.0",
                cfg(),
                limits,
                true
            )
            .is_ok(),
            "an explicit 4th endpoint field parses"
        );
    }
