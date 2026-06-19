//! Law 10 regression: a file that MATCHES a structured format but fails to parse
//! must be COUNTED (not just `tracing::debug!`-logged, which is filtered out at
//! default verbosity) so the scan can surface the lost decode-through at
//! completion. Before this, a malformed k8s Secret / tfstate / notebook /
//! docker-compose silently dropped the secrets encoded inside it with no
//! operator-visible trace.
//!
//! Own test binary so the process-global telemetry counter is isolated from the
//! parallel `all_tests` pool — the assertions are exact counts, not deltas.

use keyhog_scanner::telemetry::{structured_parse_failure_count, testing::reset};
use keyhog_scanner::testing::{parse_docker_compose, parse_k8s_secret, parse_tfstate};

#[test]
fn malformed_structured_files_are_counted_valid_ones_are_not() {
    reset();
    assert_eq!(
        structured_parse_failure_count(),
        0,
        "a fresh telemetry state has counted no parse failures"
    );

    // Malformed YAML (unclosed flow sequence) routed through the k8s Secret
    // parser: must fail, return no pairs, AND bump the failure counter.
    let bad_k8s = "apiVersion: v1\nkind: Secret\ndata:\n  api-key: [unclosed\n";
    let pairs = parse_k8s_secret(bad_k8s);
    assert!(
        pairs.is_empty(),
        "a YAML that does not parse yields no extracted pairs"
    );
    assert_eq!(
        structured_parse_failure_count(),
        1,
        "the malformed k8s Secret must be counted as a parse failure (Law 10 \
         decode-through coverage gap)"
    );

    // Malformed tfstate JSON and docker-compose YAML each add one more.
    let _ = parse_tfstate("{ not valid json ,, }");
    assert_eq!(
        structured_parse_failure_count(),
        2,
        "a malformed tfstate JSON must also be counted"
    );
    let _ = parse_docker_compose("services:\n  web:\n    environment: [oops\n");
    assert_eq!(
        structured_parse_failure_count(),
        3,
        "a malformed docker-compose YAML must also be counted"
    );

    // A VALID k8s Secret parses cleanly: the counter must NOT move, so the
    // warning only fires on genuine coverage gaps, never on healthy files.
    let good_k8s =
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  api-key: YWJjMTIz\n";
    let good_pairs = parse_k8s_secret(good_k8s);
    assert!(
        !good_pairs.is_empty(),
        "a valid k8s Secret must yield its decoded data pairs"
    );
    assert_eq!(
        structured_parse_failure_count(),
        3,
        "a successfully-parsed structured file must NOT increment the failure \
         counter (no false coverage-gap warning)"
    );
}
