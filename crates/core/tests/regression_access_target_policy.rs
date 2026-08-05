//! Contract coverage for the Tier-B access-target policy.
//!
//! The shipped `data/access-targets.toml` is the only place that knows what a
//! door looks like. The contracts worth defending are the ones a reader would
//! otherwise have to trust:
//!
//! * the shipped document compiles through exactly the code path the binary
//!   uses, so a bad regex is a test failure and not a first-scan panic;
//! * the policy fails closed on shapes that would leak an authenticator or make
//!   the pass claim coverage it never had;
//! * no rule captures group 0, which would emit surrounding document text;
//! * every connection-string rule keeps userinfo out of its captures.

use keyhog_core::{access_target_rule_ids, validate_access_target_policy};

const SHIPPED: &str = include_str!("../data/access-targets.toml");

#[test]
fn shipped_policy_compiles_through_the_binary_path() {
    validate_access_target_policy(SHIPPED, "shipped").expect("shipped policy must compile");
}

#[test]
fn shipped_policy_defines_the_documented_rule_set() {
    let ids = access_target_rule_ids();
    // A rule silently disappearing from the data file removes a whole provider
    // from every report without any other signal, so pin the ones the docs and
    // the mirror-corpus evidence depend on.
    for expected in [
        "database-uri-endpoint",
        "database-uri-name",
        "aws-s3-uri-bucket",
        "aws-arn",
        "azure-storage-account",
        "gcp-project-id",
        "slack-workspace",
        "declared-api-endpoint",
    ] {
        assert!(ids.contains(&expected), "rule {expected} disappeared: {ids:?}");
    }
    // The generic rule must stay last: rules run in file order and the named
    // providers must get first claim on a match.
    assert_eq!(ids.last().copied(), Some("declared-api-endpoint"));
}

#[test]
fn rule_ids_are_unique() {
    let mut ids = access_target_rule_ids();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "duplicate rule id in shipped policy");
}

fn reject(document: &str) -> String {
    validate_access_target_policy(document, "candidate")
        .expect_err("policy should have been rejected")
}

const HEADER: &str = "\
[settings]
max_file_bytes = 1024
max_total_bytes = 4096
max_targets_per_finding = 4
max_matches_per_rule = 8
min_confidence = 0.3
same_file_decay = 0.85
decay_line_step = 25
decay_max_steps = 4
decoded_confidence = 0.99
";

#[test]
fn group_zero_is_rejected_because_it_would_emit_document_text() {
    let error = reject(&format!(
        "{HEADER}
[[rule]]
id = \"whole-match\"
kind = \"endpoint\"
label = \"host\"
pattern = 'host=([a-z]+)'
group = 0
confidence = 0.9
redact = \"none\"
"
    ));
    assert!(error.contains("group must be at least 1"), "{error}");
}

#[test]
fn a_capture_group_the_pattern_does_not_have_is_rejected() {
    let error = reject(&format!(
        "{HEADER}
[[rule]]
id = \"missing-group\"
kind = \"endpoint\"
label = \"host\"
pattern = 'host=([a-z]+)'
group = 3
confidence = 0.9
redact = \"none\"
"
    ));
    assert!(error.contains("wants capture group 3"), "{error}");
}

#[test]
fn an_uncompilable_pattern_is_rejected() {
    let error = reject(&format!(
        "{HEADER}
[[rule]]
id = \"bad-regex\"
kind = \"endpoint\"
label = \"host\"
pattern = 'host=([a-z]+'
group = 1
confidence = 0.9
redact = \"none\"
"
    ));
    assert!(error.contains("pattern is invalid"), "{error}");
}

#[test]
fn tail_redaction_without_a_keep_length_is_rejected() {
    let error = reject(&format!(
        "{HEADER}
[[rule]]
id = \"tail-no-keep\"
kind = \"endpoint\"
label = \"host\"
pattern = 'host=([a-z]+)'
group = 1
confidence = 0.9
redact = \"tail\"
"
    ));
    assert!(error.contains("positive redact_keep"), "{error}");
}

#[test]
fn duplicate_rule_ids_are_rejected() {
    let error = reject(&format!(
        "{HEADER}
[[rule]]
id = \"dup\"
kind = \"endpoint\"
label = \"host\"
pattern = 'a=([a-z]+)'
group = 1
confidence = 0.9
redact = \"none\"

[[rule]]
id = \"dup\"
kind = \"endpoint\"
label = \"host\"
pattern = 'b=([a-z]+)'
group = 1
confidence = 0.9
redact = \"none\"
"
    ));
    assert!(error.contains("duplicate id"), "{error}");
}

#[test]
fn a_zero_byte_budget_is_rejected_because_it_would_index_nothing_and_claim_success() {
    let error = reject(
        "[settings]
max_file_bytes = 0
max_total_bytes = 4096
max_targets_per_finding = 4
max_matches_per_rule = 8
min_confidence = 0.3
same_file_decay = 0.85
decay_line_step = 25
decay_max_steps = 4
decoded_confidence = 0.99
",
    );
    assert!(error.contains("max_file_bytes must be positive"), "{error}");
}

#[test]
fn a_total_budget_below_the_per_file_cap_is_rejected() {
    let error = reject(
        "[settings]
max_file_bytes = 4096
max_total_bytes = 1024
max_targets_per_finding = 4
max_matches_per_rule = 8
min_confidence = 0.3
same_file_decay = 0.85
decay_line_step = 25
decay_max_steps = 4
decoded_confidence = 0.99
",
    );
    assert!(error.contains("must be at least max_file_bytes"), "{error}");
}

#[test]
fn zero_decay_steps_is_rejected() {
    let error = reject(
        "[settings]
max_file_bytes = 1024
max_total_bytes = 4096
max_targets_per_finding = 4
max_matches_per_rule = 8
min_confidence = 0.3
same_file_decay = 0.85
decay_line_step = 25
decay_max_steps = 0
decoded_confidence = 0.99
",
    );
    assert!(error.contains("decay_max_steps must be at least 1"), "{error}");
}

#[test]
fn an_unknown_field_is_rejected_rather_than_ignored() {
    let error = reject(&format!("{HEADER}bogus_setting = 3\n"));
    assert!(error.contains("failed to parse"), "{error}");
}

#[test]
fn connection_string_rules_never_capture_userinfo() {
    // Every scheme://user:pass@host rule in the shipped policy must skip the
    // userinfo with a NON-capturing group. A capturing `([^@]*@)?` there would
    // put a password into a report.
    for line in SHIPPED.lines() {
        let line = line.trim();
        if !line.starts_with("pattern =") || !line.contains("://") {
            continue;
        }
        assert!(
            !line.contains("([^\\s@"),
            "a connection-string rule captures userinfo: {line}"
        );
        if line.contains("@") {
            assert!(
                line.contains("(?:[^\\s@/\"'<>]*@)?"),
                "userinfo must be skipped by a non-capturing group: {line}"
            );
        }
    }
}
