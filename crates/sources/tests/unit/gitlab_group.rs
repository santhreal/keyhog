    use super::{source_from_params, validate_token};

    #[test]
    fn validate_token_rejects_control_chars_and_empty() {
        // A clean PAT passes (a benign non-credential-shaped value, never a
        // `glpat-`-prefixed literal, which self-scan would flag).
        assert!(validate_token("clean-token-value").is_ok());

        // Control characters (CR/LF/NUL/TAB/DEL) are banned: raw bytes injected
        // into the `PRIVATE-TOKEN: …` request header enable CRLF header/request
        // splitting. Every reject carries the shared 'unsafe characters' contract.
        for bad in ["a\rb", "a\nb", "a\0b", "a\tb", "a\u{7f}b"] {
            let err = validate_token(bad).expect_err("control char rejected");
            assert!(
                err.to_string().contains("unsafe characters"),
                "gitlab token control-char error must carry the shared contract, got {err}"
            );
        }

        // Empty token is rejected (an unauthenticated request pre-image).
        assert!(validate_token("").is_err(), "empty token rejected");
    }

    #[test]
    fn source_from_params_requires_group_and_token() {
        // `HttpClientConfig` moves into each call; build a fresh default per call.
        // `SourceLimits` is `Copy`.
        let cfg = || crate::http::HttpClientConfig::default();
        let limits = crate::SourceLimits::default();

        // Fewer than two newline-separated fields → error (missing token).
        assert!(
            source_from_params("acme", cfg(), limits, true).is_err(),
            "missing token line must be an error"
        );
        // Present-but-EMPTY fields hit the explicit empty-field guard → error.
        assert!(
            source_from_params("acme\n", cfg(), limits, true).is_err(),
            "empty token must be an error"
        );
        assert!(
            source_from_params("\ntok", cfg(), limits, true).is_err(),
            "empty group must be an error"
        );
        // Two non-empty fields parse; endpoint defaults when the 3rd field is
        // absent OR present-but-empty (the `Some(_) if !empty` else-arm), not error.
        assert!(
            source_from_params("acme\ntok", cfg(), limits, true).is_ok(),
            "group + token parse successfully"
        );
        assert!(
            source_from_params("acme\ntok\n", cfg(), limits, true).is_ok(),
            "trailing empty endpoint line falls back to the default endpoint"
        );
        assert!(
            source_from_params(
                "acme\ntok\nhttps://gitlab.example.test",
                cfg(),
                limits,
                true
            )
            .is_ok(),
            "an explicit 3rd endpoint field parses"
        );
    }
