    use super::*;

    fn aws_access_key_id() -> String {
        ["aws", "access", "key"].join("-")
    }

    fn anthropic_api_key_id() -> String {
        ["anthropic", "api", "key"].join("-")
    }

    #[test]
    fn exact_length_rule_rejects_wrong_length() {
        let rule = CredentialShapeRule::exact_length_for_test(20);

        assert!(rule.allows("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rule.allows("AKIAIOSFODNN7EXAMPL"));
    }

    #[test]
    fn prefix_body_range_only_applies_to_matching_prefix() {
        let rule = CredentialShapeRule::prefix_body_range_for_test("sk-ant-api03-", 80, 120);
        let valid_legacy = format!("sk-ant-api03-{}", "a".repeat(80));

        assert!(rule.allows(&valid_legacy));
        assert!(!rule.allows("sk-ant-api03-short"));
        assert!(rule.allows("sk-ant-modern-key-shape-not-owned-by-this-rule"));
    }

    /// Build a `keyhog_core::CredentialShape` for the validation tests below.
    fn shape(
        exact_length: Option<usize>,
        prefix: Option<&str>,
        body_min_length: Option<usize>,
        body_max_length: Option<usize>,
    ) -> CredentialShape {
        CredentialShape {
            exact_length,
            prefix: prefix.map(str::to_string),
            body_min_length,
            body_max_length,
        }
    }

    #[test]
    fn validate_rejects_no_constraints() {
        let err = shape(None, None, None, None).validate("bad").unwrap_err();
        assert!(err.contains("no shape constraints"));
    }

    #[test]
    fn validate_rejects_exact_length_zero() {
        let err = shape(Some(0), None, None, None)
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("exact_length=0"));
    }

    #[test]
    fn validate_rejects_body_range_without_prefix() {
        let err = shape(None, None, Some(80), None)
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("body length without a prefix"));
    }

    #[test]
    fn validate_rejects_inverted_body_range() {
        let err = shape(None, Some("sk-"), Some(120), Some(80))
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("body_min_length greater than body_max_length"));
    }

    /// The two live detector specs declare their shape in their OWN TOML
    /// (`[detector.credential_shape]`, DET-0), read it back from the embedded
    /// corpus and pin the exact values. This drift-guard replaces the old
    /// `rules/detector-credential-shapes.toml` parse test.
    #[test]
    fn live_credential_shapes_are_declared_per_detector() {
        let specs = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus loads");
        let by_id = |id: &str| {
            let spec = match specs.iter().find(|s| s.id == id) {
                Some(spec) => spec,
                None => panic!("{id} must be embedded"),
            };
            match spec.credential_shape.clone() {
                Some(shape) => shape,
                None => panic!("{id} must declare [detector.credential_shape]"),
            }
        };

        let aws = by_id(&aws_access_key_id());
        assert_eq!(aws.exact_length, Some(20));
        assert_eq!(aws.prefix, None);
        aws.validate(&aws_access_key_id()).expect("aws shape valid");

        let anthropic = by_id(&anthropic_api_key_id());
        assert_eq!(anthropic.prefix.as_deref(), Some("sk-ant-api03-"));
        assert_eq!(anthropic.body_min_length, Some(80));
        assert_eq!(anthropic.body_max_length, Some(120));
        anthropic
            .validate(&anthropic_api_key_id())
            .expect("anthropic shape valid");
    }

    #[test]
    fn build_maps_per_detector_shapes_to_compiled_rules() {
        // Each detector's shape rides on its OWN spec (DET-0); build reads it and
        // compiles the gate. A detector with no `credential_shape` maps to `None`.
        let aws = DetectorSpec {
            id: aws_access_key_id(),
            credential_shape: Some(shape(Some(20), None, None, None)),
            ..DetectorSpec::default()
        };
        let anthropic = DetectorSpec {
            id: anthropic_api_key_id(),
            credential_shape: Some(shape(None, Some("sk-ant-api03-"), Some(80), Some(120))),
            ..DetectorSpec::default()
        };
        let no_shape = DetectorSpec {
            id: "no-shape-detector".to_string(),
            ..DetectorSpec::default()
        };

        let rules = build_detector_shape_rules(&[aws, anthropic, no_shape]).unwrap();

        assert_eq!(rules.len(), 3);
        assert!(rules[0].as_ref().is_some_and(|rule| {
            rule.allows("AKIAIOSFODNN7EXAMPLE") && !rule.allows("AKIAIOSFODNN7EXAMPL")
        }));
        assert!(rules[1]
            .as_ref()
            .is_some_and(|rule| !rule.allows("sk-ant-api03-short")));
        assert!(rules[2].is_none(), "a detector with no shape maps to None");
    }

    #[test]
    fn build_fails_closed_on_a_malformed_shape() {
        // A per-detector shape that fails `CredentialShape::validate` is a build
        // error (fail-closed), never a silent skip.
        let bad = DetectorSpec {
            id: "bad-shape".to_string(),
            credential_shape: Some(shape(None, Some("sk-"), None, None)), // prefix, no length
            ..DetectorSpec::default()
        };
        let err = build_detector_shape_rules(&[bad]).unwrap_err();
        assert!(err.contains("prefix but no length constraint"));
    }

    #[test]
    fn validate_rejects_prefix_without_length_constraint() {
        let err = shape(None, Some("sk-"), None, None)
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("prefix but no length constraint"));
    }

    #[test]
    fn validate_rejects_exact_length_below_prefix_minimum() {
        let err = shape(Some(20), Some("sk-ant-api03-"), Some(80), None)
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("exact_length below prefix plus body_min_length"));
    }

    #[test]
    fn validate_rejects_exact_length_above_prefix_maximum() {
        let err = shape(Some(200), Some("sk-ant-api03-"), None, Some(80))
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("exact_length above prefix plus body_max_length"));
    }

    #[test]
    fn validate_rejects_empty_prefix() {
        let err = shape(Some(10), Some(""), None, None)
            .validate("bad")
            .unwrap_err();
        assert!(err.contains("empty prefix"));
    }

    // ── Boundary lock for `CredentialShapeRule::allows` ──────────────────────
    // `allows` is the per-credential shape gate: a candidate that does not fit a
    // detector's declared length/prefix shape is suppressed. These pin every branch
    // and boundary so a refactor cannot silently loosen (recall-costly false accepts
    // downstream) or tighten (dropping real secrets) the gate. The test module is a
    // child of the defining module, so it constructs the private struct directly.

    fn make_rule(
        exact_length: Option<usize>,
        prefix: Option<&str>,
        body_min_length: Option<usize>,
        body_max_length: Option<usize>,
    ) -> CredentialShapeRule {
        CredentialShapeRule {
            exact_length,
            prefix: prefix.map(str::to_string),
            body_min_length,
            body_max_length,
        }
    }

    #[test]
    fn exact_length_allows_the_exact_length() {
        assert!(make_rule(Some(20), None, None, None).allows("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn exact_length_rejects_one_too_long() {
        // The existing suite covers one-too-short; pin the upper side too.
        assert!(!make_rule(Some(20), None, None, None).allows("AKIAIOSFODNN7EXAMPLEX"));
    }

    #[test]
    fn exact_length_rejects_empty_credential() {
        assert!(!make_rule(Some(20), None, None, None).allows(""));
    }

    #[test]
    fn unconstrained_rule_allows_everything() {
        // An all-None rule is validation-rejected precisely because `allows` treats
        // it as permissive (pin that so the validation rule stays load-bearing).
        let rule = make_rule(None, None, None, None);
        assert!(rule.allows(""));
        assert!(rule.allows("anything at all"));
    }

    #[test]
    fn prefix_rule_allows_credentials_without_the_prefix() {
        // A rule only constrains the BODY of credentials that carry its prefix; an
        // unrelated shape is not owned by this rule and passes.
        let rule = make_rule(None, Some("sk-ant-api03-"), Some(80), Some(120));
        assert!(rule.allows("ghp_0123456789abcdef"));
        assert!(rule.allows("sk-different-family-token"));
    }

    #[test]
    fn body_at_min_length_is_allowed() {
        let rule = make_rule(None, Some("p-"), Some(5), Some(10));
        assert!(rule.allows("p-abcde")); // body len 5 == min
    }

    #[test]
    fn body_one_below_min_is_rejected() {
        let rule = make_rule(None, Some("p-"), Some(5), Some(10));
        assert!(!rule.allows("p-abcd")); // body len 4 < min
    }

    #[test]
    fn body_at_max_length_is_allowed() {
        let rule = make_rule(None, Some("p-"), Some(5), Some(10));
        assert!(rule.allows("p-abcdefghij")); // body len 10 == max
    }

    #[test]
    fn body_one_above_max_is_rejected() {
        let rule = make_rule(None, Some("p-"), Some(5), Some(10));
        assert!(!rule.allows("p-abcdefghijk")); // body len 11 > max
    }

    #[test]
    fn empty_body_below_min_is_rejected() {
        let rule = make_rule(None, Some("p-"), Some(1), None);
        assert!(!rule.allows("p-")); // body len 0 < min 1
    }

    #[test]
    fn prefix_without_body_bounds_allows_any_body() {
        // Degenerate (validation-rejected) shape: prefix present, no min/max. The
        // method allows every body (the reason validation forbids it).
        let rule = make_rule(None, Some("sk-"), None, None);
        assert!(rule.allows("sk-"));
        assert!(rule.allows("sk-anything-goes-here"));
        assert!(rule.allows("no-prefix-at-all"));
    }

    #[test]
    fn body_min_only_ignores_upper_bound() {
        let rule = make_rule(None, Some("p-"), Some(5), None);
        assert!(rule.allows("p-abcdefghijklmnop")); // long body, min met, no max
        assert!(!rule.allows("p-abc")); // below min
    }

    #[test]
    fn body_max_only_ignores_lower_bound() {
        let rule = make_rule(None, Some("p-"), None, Some(5));
        assert!(rule.allows("p-a")); // short body, no min, under max
        assert!(!rule.allows("p-abcdef")); // body len 6 > max
    }

    #[test]
    fn exact_length_and_prefix_both_satisfied_is_allowed() {
        let rule = make_rule(Some(10), Some("sk-"), Some(5), Some(7));
        assert!(rule.allows("sk-abcdefg")); // len 10, body "abcdefg" (7) in [5,7]
    }

    #[test]
    fn exact_length_checked_before_prefix() {
        // Wrong total length is rejected even if the prefix/body would fit.
        let rule = make_rule(Some(10), Some("sk-"), Some(3), Some(3));
        assert!(!rule.allows("sk-abc")); // len 6 != 10
    }

    #[test]
    fn matching_length_but_absent_prefix_is_allowed() {
        // Right total length, missing prefix: the body constraints do not apply, so
        // the rule does not own this shape and passes it through.
        let rule = make_rule(Some(10), Some("sk-"), Some(5), Some(7));
        assert!(rule.allows("0123456789")); // len 10, no "sk-" prefix
    }

    #[test]
    fn prefix_match_is_byte_and_case_sensitive() {
        // `strip_prefix` is exact bytes: an uppercased prefix does not match, so the
        // body bounds are not applied (the rule does not own the differently-cased
        // shape).
        let rule = make_rule(None, Some("sk-"), Some(5), Some(7));
        assert!(rule.allows("SK-abcdefghijklmnop")); // prefix cased differently
        assert!(!rule.allows("sk-abc")); // real prefix, body too short
    }

    #[test]
    fn exact_length_is_byte_length_not_char_count() {
        // Vendor tokens are ASCII, so byte-length == char-count for real inputs; pin
        // the byte-length contract explicitly (a multibyte string of the same char
        // count has more bytes and is rejected).
        let rule = make_rule(Some(4), None, None, None);
        assert!(rule.allows("abcd")); // 4 ascii bytes
        assert!(!rule.allows("caf\u{e9}")); // "café": 4 chars, 5 bytes
    }

    #[test]
    fn body_length_is_byte_length_not_char_count() {
        // Same byte-vs-char contract on the body side of the prefix.
        let rule = make_rule(None, Some("p-"), Some(3), Some(5));
        assert!(rule.allows("p-abcde")); // body "abcde": 5 ascii bytes == max
                                         // body "aaéé": 4 chars but 6 bytes (é is 2 bytes each), so it exceeds the
                                         // max of 5 by BYTES even though its char count (4) would fit.
        assert!(!rule.allows("p-aa\u{e9}\u{e9}"));
    }

    #[test]
    fn credential_shorter_than_the_prefix_is_allowed() {
        // `strip_prefix` returns None when the credential is shorter than the prefix,
        // so the body bounds never apply and the too-short candidate passes (the rule
        // does not own it) rather than being spuriously rejected.
        let rule = make_rule(None, Some("sk-ant-api03-"), Some(5), Some(10));
        assert!(rule.allows("sk-"));
        assert!(rule.allows(""));
    }
