//! Regression: the k8s `stringData:` block and the docker-compose
//! `environment:` mapping form extract scalar `<key>: <value>` pairs through a
//! single owner (`push_scalar_mapping_pairs`) instead of two byte-identical
//! inline loops, and that dedup changes no output (Law 6 + DEDUP).
//!
//! Both surfaces previously ran the same loop verbatim: read each scalar value,
//! skip empty keys, build the `<key>: <value>` line anchor + `<key>:` fallback,
//! push an owned-anchor-with-fallback pending pair. Two copies can drift; they
//! are now one helper. This pins the real extracted tuples (context, value,
//! 1-based line) for each surface so any divergence in the shared path is caught.

#[test]
fn docker_compose_environment_mapping_extracts_exact_pairs() {
    // Line 1: services:
    // Line 2:   web:
    // Line 3:     environment:
    // Line 4:       API_KEY: sk_live_abcdef0123456789
    // Line 5:       REGION: us-east-1
    let compose = "services:\n  web:\n    environment:\n      API_KEY: sk_live_abcdef0123456789\n      REGION: us-east-1\n";
    let pairs = keyhog_scanner::testing::parse_docker_compose_tuples(compose);

    assert_eq!(
        pairs,
        vec![
            (
                "API_KEY".to_string(),
                "sk_live_abcdef0123456789".to_string(),
                4
            ),
            ("REGION".to_string(), "us-east-1".to_string(), 5),
        ],
        "environment mapping must surface each scalar key/value at its anchored line"
    );
}

#[test]
fn k8s_string_data_extracts_exact_pairs() {
    // Line 1: apiVersion: v1
    // Line 2: kind: Secret
    // Line 3: metadata:
    // Line 4:   name: test
    // Line 5: stringData:
    // Line 6:   password: hunter2-plaintext
    // Line 7:   token: tok_abcdef0123456789
    let secret = "apiVersion: v1\nkind: Secret\nmetadata:\n  name: test\nstringData:\n  password: hunter2-plaintext\n  token: tok_abcdef0123456789\n";
    let pairs = keyhog_scanner::testing::parse_k8s_secret_tuples(secret);

    assert_eq!(
        pairs,
        vec![
            ("password".to_string(), "hunter2-plaintext".to_string(), 6),
            ("token".to_string(), "tok_abcdef0123456789".to_string(), 7),
        ],
        "stringData must surface each raw scalar key/value at its anchored line"
    );
}

#[test]
fn both_surfaces_route_through_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/structured/parsers/yaml.rs"))
        .expect("yaml parser source readable");

    // The shared owner exists and both surfaces delegate to it.
    assert!(
        src.contains("fn push_scalar_mapping_pairs("),
        "the single-owner scalar-mapping extractor must exist"
    );
    let delegations = src
        .matches("push_scalar_mapping_pairs(map, pending)")
        .count();
    assert_eq!(
        delegations, 2,
        "stringData and environment-mapping must both delegate to the one owner"
    );
    // Empty-key skip lives in exactly one place now (the owner), not duplicated
    // per surface. The owner body still guards it.
    assert!(
        src.contains("if key.is_empty() {"),
        "the empty-key guard must survive inside the shared owner"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one compose + one k8s document; these SWEEP the shared
// `push_scalar_mapping_pairs` owner over N distinct scalar entries per surface.
// Contract traced to parsers/yaml.rs: a mapping entry `key: value` under
// `environment:` (compose) / `stringData:` (k8s) surfaces as
// (key, scalar_value, 1-based line of the `key: value` anchor), in document
// order. Distinct `K{i}` keys keep every line-anchor unambiguous; `v_<rand>`
// values are always plain YAML scalars (no number/bool/null coercion). The line
// math matches the fixed tests exactly (compose header = 3 lines → entries from
// line 4; k8s Secret header = 5 lines → entries from line 6). NB the parser
// SOURCE is mid phase-2 refactor (dirty), so this round-trip asserts the CURRENT
// observable contract — a behavior change surfaces here as a regression signal.
// No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_000))]

    /// A docker-compose `environment:` mapping of N distinct scalar entries parses
    /// to EXACTLY those (key, value, line) tuples in document order; header
    /// occupies lines 1..=3, so entry i lands on line 4+i.
    #[test]
    fn compose_environment_mapping_round_trips(
        vals in prop::collection::vec("[a-z0-9]{4,12}", 2..=8),
    ) {
        let mut doc = String::from("services:\n  web:\n    environment:\n");
        let mut expected: Vec<(String, String, usize)> = Vec::new();
        for (i, r) in vals.iter().enumerate() {
            let key = format!("K{i}");
            let value = format!("v_{r}");
            doc.push_str(&format!("      {key}: {value}\n"));
            expected.push((key, value, 4 + i));
        }
        let got = keyhog_scanner::testing::parse_docker_compose_tuples(&doc);
        prop_assert_eq!(got, expected);
    }

    /// A k8s `stringData:` mapping of N distinct scalar entries parses to EXACTLY
    /// those (key, value, line) tuples in document order; the canonical Secret
    /// header occupies lines 1..=5, so entry i lands on line 6+i.
    #[test]
    fn k8s_string_data_mapping_round_trips(
        vals in prop::collection::vec("[a-z0-9]{4,12}", 2..=8),
    ) {
        let mut doc =
            String::from("apiVersion: v1\nkind: Secret\nmetadata:\n  name: test\nstringData:\n");
        let mut expected: Vec<(String, String, usize)> = Vec::new();
        for (i, r) in vals.iter().enumerate() {
            let key = format!("K{i}");
            let value = format!("v_{r}");
            doc.push_str(&format!("  {key}: {value}\n"));
            expected.push((key, value, 6 + i));
        }
        let got = keyhog_scanner::testing::parse_k8s_secret_tuples(&doc);
        prop_assert_eq!(got, expected);
    }
}
