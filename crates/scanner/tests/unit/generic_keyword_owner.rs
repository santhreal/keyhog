    use super::*;

    /// Callers pass SORTED keys, the real builder emits a `BTreeSet` and every
    /// ownership lookup `binary_search`es the slice.
    fn owned(keys: &[&str]) -> Vec<Arc<str>> {
        keys.iter().map(|k| Arc::from(*k)).collect()
    }

    #[test]
    fn leading_assignment_key_extracts_key_before_delimiter() {
        assert_eq!(leading_assignment_key("stripe_key=abc"), Some("stripe_key"));
        assert_eq!(leading_assignment_key("api-key:tok"), Some("api-key"));
        assert_eq!(leading_assignment_key("a.b~c"), Some("a.b"));
    }

    #[test]
    fn leading_assignment_key_rejects_non_assignments() {
        assert_eq!(leading_assignment_key("nodelimiter"), None); // no delimiter, run == whole string
        assert_eq!(leading_assignment_key("=leading"), None); // empty key before delimiter
        assert_eq!(leading_assignment_key("key = spaced"), None); // space breaks the key run before '='
        assert_eq!(leading_assignment_key(""), None);
    }

    #[test]
    fn is_assignment_key_byte_admits_identifier_bytes_only() {
        for b in [b'a', b'Z', b'5', b'_', b'-', b'.'] {
            assert!(
                is_assignment_key_byte(b),
                "{} should be a key byte",
                b as char
            );
        }
        for b in [b' ', b'=', b':', b'"', b'/'] {
            assert!(
                !is_assignment_key_byte(b),
                "{} must not be a key byte",
                b as char
            );
        }
    }

    #[test]
    fn normalized_lookup_is_exact_binary_search() {
        let set = owned(&["aws_secret_key", "stripe_secret_key"]); // sorted
        assert!(normalized_assignment_keyword_owned_by_named_detector(
            &set,
            "stripe_secret_key"
        ));
        assert!(normalized_assignment_keyword_owned_by_named_detector(
            &set,
            "aws_secret_key"
        ));
        assert!(!normalized_assignment_keyword_owned_by_named_detector(
            &set,
            "gcp_secret_key"
        ));
        assert!(!normalized_assignment_keyword_owned_by_named_detector(
            &set, "stripe"
        )); // prefix, not exact
    }

    #[test]
    fn owned_keyword_normalizes_and_requires_secret_suffix() {
        let set = owned(&["stripe_secret_key"]);
        // Case/separator variants normalize onto the owned key.
        assert!(assignment_keyword_owned_by_named_detector(
            &set,
            "Stripe-Secret-Key"
        ));
        assert!(assignment_keyword_owned_by_named_detector(
            &set,
            "STRIPE.SECRET.KEY"
        ));
        // No secret suffix -> rejected before the lookup even runs.
        assert!(!assignment_keyword_owned_by_named_detector(
            &set,
            "stripe_id"
        ));
        // Secret-suffixed but not an owned key.
        assert!(!assignment_keyword_owned_by_named_detector(
            &set,
            "unknown_key"
        ));
        // Empty owned set is never ownership.
        assert!(!assignment_keyword_owned_by_named_detector(
            &owned(&[]),
            "stripe_secret_key"
        ));
    }

    #[test]
    fn candidate_prefix_ownership_requires_longer_secret_suffixed_prefix() {
        let set = owned(&["stripe_secret_key"]);
        assert!(candidate_starts_with_owned_assignment_key(
            &set,
            "stripe_secret_key_prod"
        ));
        // Exact length is not a strict prefix, so it is not claimed by this predicate.
        assert!(!candidate_starts_with_owned_assignment_key(
            &set,
            "stripe_secret_key"
        ));
        assert!(!candidate_starts_with_owned_assignment_key(
            &set,
            "other_secret_key"
        ));
    }

    #[test]
    fn candidate_embeds_owned_key_via_delimiter_or_prefix() {
        let set = owned(&["stripe_secret_key"]);
        // Delimited assignment: the leading key matches an owned key.
        assert!(candidate_embeds_owned_assignment_key(
            &set,
            "stripe_secret_key=abc123"
        ));
        // No delimiter, but the candidate starts with the owned key.
        assert!(candidate_embeds_owned_assignment_key(
            &set,
            "stripe_secret_key_prod_xyz"
        ));
        assert!(!candidate_embeds_owned_assignment_key(
            &set,
            "random_token=v"
        ));
    }

    #[test]
    fn keyword_span_expands_to_the_full_owned_key() {
        let set = owned(&["stripe_secret_key"]);
        let line = "stripe_secret_key=v";
        assert!(keyword_span_owned_by_named_detector(&set, line, 0, 17)); // exact span
        assert!(keyword_span_owned_by_named_detector(&set, line, 7, 17)); // sub-span expands left to full key
        assert!(!keyword_span_owned_by_named_detector(
            &set,
            "user_id=5",
            0,
            7
        )); // unowned
        assert!(!keyword_span_owned_by_named_detector(&set, line, 5, 3)); // start > end fails closed
        assert!(!keyword_span_owned_by_named_detector(&set, line, 0, 999)); // end past line fails closed
    }

    #[test]
    fn entropy_candidate_ownership_uses_embedded_key_without_a_line() {
        let set = owned(&["stripe_secret_key"]);
        assert!(entropy_candidate_owned_by_named_assignment(
            &set,
            "stripe_secret_key=abc123",
            None
        ));
        assert!(!entropy_candidate_owned_by_named_assignment(
            &set,
            "plain_value",
            None
        ));
    }

    fn generic_detector(id: &str, keywords: &[&str]) -> DetectorSpec {
        DetectorSpec {
            id: id.to_string(),
            name: id.to_string(),
            service: "generic".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: keywords.iter().map(|k| k.to_string()).collect(),
            ..Default::default()
        }
    }

    fn generic_secret_detector() -> DetectorSpec {
        DetectorSpec {
            id: crate::detector_ids::GENERIC_SECRET.to_string(),
            name: "Generic Secret".to_string(),
            service: "generic".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: vec!["secret".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn owning_index_earliest_detector_wins_across_exact_and_normalized() {
        // Detector 0 owns "api_token"; detector 1 owns the literal "api-token".
        // Both normalize to "api_token". A query that hits detector 1 EXACTLY and
        // detector 0 via NORMALIZATION must resolve to the EARLIER detector (0),
        // exactly like the old linear `find` returning the first match by either
        // condition.
        let detectors = vec![
            generic_detector("api-a", &["api_token"]),
            generic_detector("api-b", &["api-token"]),
            generic_secret_detector(),
        ];
        let index = GenericOwningDetectorIndex::build(&detectors);

        assert_eq!(
            index.owning_index("API-TOKEN"),
            Some(0),
            "exact hit on detector 1 + normalized hit on detector 0 -> earliest (0) wins"
        );
        assert_eq!(
            index.owning_index("api_token"),
            Some(0),
            "exact match on detector 0's literal keyword"
        );
        assert_eq!(
            index.owning_index("totally_unknown_lhs"),
            Some(2),
            "unmatched keyword falls back to the GENERIC_SECRET detector index"
        );
        assert_eq!(index.index_for_id("api-a"), Some(0));
        assert_eq!(index.index_for_id("api-b"), Some(1));
        assert_eq!(
            index.index_for_id(crate::detector_ids::GENERIC_SECRET),
            Some(2),
            "synthetic entropy policy must resolve the active generic-secret spec"
        );
        assert_eq!(index.index_for_id("not-loaded"), None);
    }

    #[test]
    fn policy_index_includes_regex_backed_generic_password() {
        let mut password = generic_detector(crate::detector_ids::GENERIC_PASSWORD, &["password"]);
        password.kind = DetectorKind::Regex;
        let detectors = vec![generic_secret_detector(), password];
        let index = GenericOwningDetectorIndex::build(&detectors);

        assert_eq!(
            index.index_for_id(crate::detector_ids::GENERIC_PASSWORD),
            Some(1),
            "entropy-password policy must resolve the active regex-backed detector"
        );
        assert_eq!(
            index.owning_index("password"),
            Some(0),
            "regex-backed generic detectors must not claim Phase2 assignment ownership"
        );
    }

    #[test]
    fn owning_index_is_none_without_a_match_or_generic_secret() {
        let detectors = vec![generic_detector("api-a", &["api_token"])];
        let index = GenericOwningDetectorIndex::build(&detectors);
        assert_eq!(index.owning_index("api_token"), Some(0));
        assert_eq!(
            index.owning_index("unowned"),
            None,
            "no keyword owner AND no GENERIC_SECRET detector -> None (caller uses defaults)"
        );
    }

    #[test]
    fn owning_index_ignores_non_generic_service_detectors() {
        // A named (service != "generic") detector must not claim its assignment
        // keyword through the generic owner index, even if its kind is
        // Phase2Generic; the keyword falls through to GENERIC_SECRET.
        let named = DetectorSpec {
            id: "stripe".to_string(),
            name: "Stripe".to_string(),
            service: "stripe".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: vec!["stripe_key".to_string()],
            ..Default::default()
        };
        let detectors = vec![named, generic_secret_detector()];
        let index = GenericOwningDetectorIndex::build(&detectors);
        assert_eq!(index.owning_index("stripe_key"), Some(1));
    }
