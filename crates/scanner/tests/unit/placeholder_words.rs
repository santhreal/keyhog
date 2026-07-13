    use super::*;

    // The exact UPPERCASE forms the scanner matched BEFORE the Tier-B move (the old
    // `INSTRUCTIONAL_FRAGMENTS` / `DOC_MARKER_SUBSTRINGS` consts in
    // `suppression/doc_markers.rs`). The loaded vocab must reproduce them
    // byte-for-byte (this is the zero-behavior-change parity proof).
    const LEGACY_INSTRUCTIONAL: &[&str] = &["YOUR_", "YOUR-", "INSERT", "CHANGE", "REPLACE"];
    const LEGACY_SUBSTRINGS: &[&str] = &[
        "EXAMPLE",
        "PLACEHOLDER",
        "NOT_A_REAL",
        "NOTAREAL",
        "INSERT_TOKEN_HERE",
        "INSERT-TOKEN-HERE",
        "CHANGE-ME",
        "CHANGEME",
        "REPLACE_ME",
        "REPLACEME",
        "REDACTED",
        "FAKE_KEY",
        "FAKEKEY",
        "TEST_KEY",
        "TESTKEY",
        "SAMPLE_KEY",
        "SAMPLEKEY",
    ];

    /// A valid TOML with the given `[doc_markers]` body appended to a minimal
    /// `[placeholder_words]` section.
    fn toml_with_markers(body: &str) -> String {
        format!("[placeholder_words]\nwords = [\"example\"]\n[doc_markers]\n{body}")
    }

    #[test]
    fn instructional_fragments_reproduce_the_legacy_const_exactly() {
        let loaded: Vec<&str> = instructional_fragments()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY_INSTRUCTIONAL);
    }

    #[test]
    fn marker_substrings_reproduce_the_legacy_const_exactly() {
        let loaded: Vec<&str> = doc_marker_substrings().iter().map(String::as_str).collect();
        assert_eq!(loaded.as_slice(), LEGACY_SUBSTRINGS);
    }

    #[test]
    fn instructional_fragments_are_nonempty() {
        assert!(!instructional_fragments().is_empty());
    }

    #[test]
    fn marker_substrings_are_nonempty() {
        assert!(!doc_marker_substrings().is_empty());
    }

    #[test]
    fn loaded_instructional_fragments_are_all_uppercase() {
        for frag in instructional_fragments() {
            assert_eq!(
                frag,
                &frag.to_ascii_uppercase(),
                "stored non-uppercase: {frag}"
            );
        }
    }

    #[test]
    fn loaded_marker_substrings_are_all_uppercase() {
        for marker in doc_marker_substrings() {
            assert_eq!(
                marker,
                &marker.to_ascii_uppercase(),
                "stored non-uppercase: {marker}"
            );
        }
    }

    #[test]
    fn no_duplicate_instructional_fragments() {
        let mut seen = BTreeSet::new();
        for frag in instructional_fragments() {
            assert!(seen.insert(frag), "duplicate fragment {frag}");
        }
    }

    #[test]
    fn no_duplicate_marker_substrings() {
        let mut seen = BTreeSet::new();
        for marker in doc_marker_substrings() {
            assert!(seen.insert(marker), "duplicate marker {marker}");
        }
    }

    #[test]
    fn bundled_markers_include_known_specimens() {
        let subs = doc_marker_substrings();
        for expected in [
            "EXAMPLE",
            "PLACEHOLDER",
            "TESTKEY",
            "NOT_A_REAL",
            "REDACTED",
        ] {
            assert!(subs.iter().any(|m| m == expected), "missing {expected}");
        }
        assert!(instructional_fragments().iter().any(|f| f == "YOUR_"));
    }

    #[test]
    fn parse_vocab_uppercases_lowercase_markers() {
        let vocab = parse_vocab(&toml_with_markers(
            "instructional_fragments = [\"your_\"]\nmarker_substrings = [\"not_a_real\"]\n",
        ))
        .expect("valid");
        assert_eq!(vocab.instructional_fragments, vec!["YOUR_".to_string()]);
        assert_eq!(vocab.marker_substrings, vec!["NOT_A_REAL".to_string()]);
    }

    #[test]
    fn parse_vocab_allows_underscore_and_hyphen_markers() {
        let vocab = parse_vocab(&toml_with_markers(
            "marker_substrings = [\"change-me\", \"test_key\"]\n",
        ))
        .expect("valid");
        assert_eq!(
            vocab.marker_substrings,
            vec!["CHANGE-ME".to_string(), "TEST_KEY".to_string()]
        );
    }

    #[test]
    fn parse_vocab_rejects_uppercase_marker_in_file() {
        let err =
            parse_vocab(&toml_with_markers("marker_substrings = [\"EXAMPLE\"]\n")).unwrap_err();
        assert!(err.contains("must be lowercase"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_empty_marker() {
        let err = parse_vocab(&toml_with_markers("marker_substrings = [\"\"]\n")).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_duplicate_marker() {
        let err = parse_vocab(&toml_with_markers(
            "marker_substrings = [\"example\", \"example\"]\n",
        ))
        .unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_marker_with_space() {
        let err =
            parse_vocab(&toml_with_markers("marker_substrings = [\"bad marker\"]\n")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_non_ascii_marker() {
        let err =
            parse_vocab(&toml_with_markers("marker_substrings = [\"caf\u{e9}\"]\n")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_vocab_without_doc_markers_section_parses_with_empty_markers() {
        // Back-compat: a `[placeholder_words]`-only TOML (what confidence_penalties
        // passes) still parses; markers default empty (permissive parse, the
        // fail-closed non-empty check lives on the bundled-file VOCAB loader).
        let vocab = parse_vocab("[placeholder_words]\nwords = [\"example\"]\n").expect("valid");
        assert!(vocab.instructional_fragments.is_empty());
        assert!(vocab.marker_substrings.is_empty());
        assert_eq!(vocab.words.len(), 1);
    }

    #[test]
    fn parse_vocab_with_explicit_empty_marker_lists_parses() {
        let vocab = parse_vocab(&toml_with_markers(
            "instructional_fragments = []\nmarker_substrings = []\n",
        ))
        .expect("valid");
        assert!(vocab.instructional_fragments.is_empty());
        assert!(vocab.marker_substrings.is_empty());
    }

    #[test]
    fn parse_placeholder_words_wrapper_returns_only_words() {
        let words =
            parse_placeholder_words(&toml_with_markers("marker_substrings = [\"example\"]\n"))
                .expect("valid");
        assert!(words.iter().any(|w| w.lower() == "example"));
    }

    #[test]
    fn parse_vocab_preserves_word_validation_uppercase_rejected() {
        let err = parse_vocab("[placeholder_words]\nwords = [\"Example\"]\n").unwrap_err();
        assert!(err.contains("lowercase"), "got: {err}");
    }

    #[test]
    fn parse_vocab_preserves_word_validation_empty_list_rejected() {
        let err = parse_vocab("[placeholder_words]\nwords = []\n").unwrap_err();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn bundled_file_parses_and_matches_accessors() {
        // The real bundled file parses cleanly and a fresh parse equals the VOCAB
        // accessors (no drift between the cached static and the parser).
        let vocab = parse_vocab(include_str!("../../../../rules/placeholder_words.toml"))
            .expect("bundled file valid");
        assert_eq!(
            vocab.instructional_fragments.as_slice(),
            instructional_fragments()
        );
        assert_eq!(vocab.marker_substrings.as_slice(), doc_marker_substrings());
    }

    #[test]
    fn validate_markers_is_order_preserving() {
        let vocab = parse_vocab(&toml_with_markers(
            "marker_substrings = [\"zebra\", \"alpha\", \"mid\"]\n",
        ))
        .expect("valid");
        assert_eq!(
            vocab.marker_substrings,
            vec!["ZEBRA".to_string(), "ALPHA".to_string(), "MID".to_string()]
        );
    }

    // ── entropy_markers (bytes_contain_entropy_placeholder_marker) ──

    // The exact lowercase forms the old hardcoded `||` chain matched (categories 1
    // and 5 of `bytes_contain_entropy_placeholder_marker`). Categories 2/3/4
    // (secret_key length-gate, AKIA compound, angle brackets) are bespoke rules that
    // stay in code, not lists.
    const LEGACY_ENTROPY_CI: &[&str] = &[
        "your_",
        "replace_me",
        "change_me",
        "insert_here",
        "fake_",
        "dummy_",
        "mock_",
    ];
    const LEGACY_ENTROPY_EXACT: &[&str] = &[
        "null",
        "none",
        "undefined",
        "empty",
        "default",
        "secret",
        "password",
    ];

    fn toml_with_entropy(body: &str) -> String {
        format!("[placeholder_words]\nwords = [\"example\"]\n[entropy_markers]\n{body}")
    }

    #[test]
    fn entropy_ci_substrings_reproduce_legacy_exactly() {
        let loaded: Vec<&str> = entropy_marker_ci_substrings()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY_ENTROPY_CI);
    }

    #[test]
    fn entropy_exact_values_reproduce_legacy_exactly() {
        let loaded: Vec<&str> = entropy_marker_exact_values()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY_ENTROPY_EXACT);
    }

    #[test]
    fn is_exact_entropy_placeholder_matches_whole_value_only() {
        // The ONE owner shared by the entropy-marker check and the named-detector
        // Tier-A gate: whole-value EXACT (case-sensitive) against the loaded list.
        for exact in LEGACY_ENTROPY_EXACT {
            assert!(
                is_exact_entropy_placeholder(exact.as_bytes()),
                "{exact:?} is an exact placeholder and must match",
            );
        }
        // A value that merely CONTAINS a placeholder word is NOT an exact match
        // this is what keeps a real credential like `mysecretkey123` alive.
        assert!(!is_exact_entropy_placeholder(b"password123"));
        assert!(!is_exact_entropy_placeholder(b"mysecretkey123"));
        assert!(!is_exact_entropy_placeholder(b"defaultKeyX7"));
        // Case-sensitive, matching Category 5 of the entropy-marker check.
        assert!(!is_exact_entropy_placeholder(b"PASSWORD"));
        assert!(!is_exact_entropy_placeholder(b""));
    }

    #[test]
    fn entropy_ci_substrings_are_stored_lowercase() {
        // Unlike doc-markers (uppercased at load), entropy markers stay lowercase.
        for marker in entropy_marker_ci_substrings() {
            assert_eq!(
                marker,
                &marker.to_ascii_lowercase(),
                "not lowercase: {marker}"
            );
        }
    }

    #[test]
    fn entropy_exact_values_are_stored_lowercase() {
        for marker in entropy_marker_exact_values() {
            assert_eq!(
                marker,
                &marker.to_ascii_lowercase(),
                "not lowercase: {marker}"
            );
        }
    }

    #[test]
    fn entropy_marker_lists_are_nonempty() {
        assert!(!entropy_marker_ci_substrings().is_empty());
        assert!(!entropy_marker_exact_values().is_empty());
    }

    #[test]
    fn no_duplicate_entropy_markers() {
        let mut seen = BTreeSet::new();
        for marker in entropy_marker_ci_substrings() {
            assert!(seen.insert(marker), "dup ci marker {marker}");
        }
        let mut seen = BTreeSet::new();
        for marker in entropy_marker_exact_values() {
            assert!(seen.insert(marker), "dup exact marker {marker}");
        }
    }

    #[test]
    fn parse_vocab_keeps_entropy_markers_lowercase_not_uppercased() {
        let vocab = parse_vocab(&toml_with_entropy(
            "ci_substrings = [\"your_\"]\nexact_values = [\"null\"]\n",
        ))
        .expect("valid");
        assert_eq!(vocab.entropy_ci_substrings, vec!["your_".to_string()]);
        assert_eq!(vocab.entropy_exact_values, vec!["null".to_string()]);
    }

    #[test]
    fn parse_vocab_rejects_uppercase_entropy_marker() {
        let err = parse_vocab(&toml_with_entropy("ci_substrings = [\"YOUR_\"]\n")).unwrap_err();
        assert!(err.contains("must be lowercase"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_duplicate_entropy_marker() {
        let err =
            parse_vocab(&toml_with_entropy("exact_values = [\"null\", \"null\"]\n")).unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_vocab_without_entropy_section_parses_empty() {
        let vocab = parse_vocab("[placeholder_words]\nwords = [\"example\"]\n").expect("valid");
        assert!(vocab.entropy_ci_substrings.is_empty());
        assert!(vocab.entropy_exact_values.is_empty());
    }

    #[test]
    fn bundled_entropy_markers_match_accessors() {
        let vocab = parse_vocab(include_str!("../../../../rules/placeholder_words.toml"))
            .expect("bundled file valid");
        assert_eq!(
            vocab.entropy_ci_substrings.as_slice(),
            entropy_marker_ci_substrings()
        );
        assert_eq!(
            vocab.entropy_exact_values.as_slice(),
            entropy_marker_exact_values()
        );
    }

    // Behavioral parity spot-checks (the full truth-table lives in
    // tests/unit/root_facade/entropy_placeholder_marker_truth_table.rs); these
    // confirm the Tier-B-backed fn preserves each category through this module.

    #[test]
    fn entropy_ci_substring_still_suppresses() {
        assert!(bytes_contain_entropy_placeholder_marker(b"YOUR_API_TOKEN"));
        assert!(bytes_contain_entropy_placeholder_marker(
            b"please_replace_me_now"
        ));
    }

    #[test]
    fn entropy_exact_value_suppresses_case_sensitively() {
        assert!(bytes_contain_entropy_placeholder_marker(b"null"));
        assert!(
            !bytes_contain_entropy_placeholder_marker(b"NULL"),
            "uppercase NULL is not the case-sensitive exact marker (pinned behavior)"
        );
        assert!(
            !bytes_contain_entropy_placeholder_marker(b"null_value"),
            "`null` as a substring is not the whole-value exact marker"
        );
    }

    #[test]
    fn entropy_secret_key_length_gate_preserved() {
        assert!(
            bytes_contain_entropy_placeholder_marker(b"secret_key"),
            "short secret_key is a decoy"
        );
        assert!(
            !bytes_contain_entropy_placeholder_marker(b"my_secret_key_padding_xx"),
            "secret_key at >= 20 bytes is past the length gate (recall boundary)"
        );
    }

    #[test]
    fn entropy_real_secret_not_suppressed() {
        assert!(!bytes_contain_entropy_placeholder_marker(
            b"aB3xK9mQ2pL7vR4nT8wZ"
        ));
        assert!(!bytes_contain_entropy_placeholder_marker(b""));
    }
