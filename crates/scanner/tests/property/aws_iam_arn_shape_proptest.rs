//! AWS IAM ARN shape suppression contract
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! An IAM ARN (`arn:aws:iam::123456789012:role/Name`) is an identifier, not a
//! secret, and its long random-looking tail otherwise trips generic gates. Two
//! predicates recognise it, split by a deliberate, and easily-missed 
//! distinction this suite pins:
//!   • `looks_like_aws_iam_arn` requires the literal `arn:` lead (the full ARN).
//!   • `looks_like_trimmed_aws_iam_arn` requires the `arn:` lead to be ABSENT (a
//!     value the extractor already trimmed to `<partition>:iam::…`).
//! They are mutually exclusive on the `arn:` prefix, and BOTH additionally require
//! a real resource target (`:role/`, `:user/`, `:group/`, `:policy/`,
//! `:instance-profile/`) (a partition prefix alone is not enough).

use keyhog_scanner::testing::{
    looks_like_aws_iam_arn_for_test, looks_like_trimmed_aws_iam_arn_for_test,
};
use proptest::prelude::*;

const RESOURCE_TARGETS: &[&str] = &["role", "user", "group", "policy", "instance-profile"];
const PARTITIONS: &[&str] = &["aws", "aws-cn", "aws-us-gov"];

// ── the arn:-prefix split (the reason both functions exist) ───────────────────

#[test]
fn full_arn_matches_only_the_full_gate() {
    let arn = "arn:aws:iam::123456789012:role/MyRole";
    assert!(looks_like_aws_iam_arn_for_test(arn));
    assert!(!looks_like_trimmed_aws_iam_arn_for_test(arn)); // has arn: → trimmed rejects
}

#[test]
fn trimmed_body_matches_only_the_trimmed_gate() {
    let trimmed = "aws:iam::123456789012:role/MyRole";
    assert!(looks_like_trimmed_aws_iam_arn_for_test(trimmed));
    assert!(!looks_like_aws_iam_arn_for_test(trimmed)); // no arn: → full rejects
}

#[test]
fn all_partitions_are_recognized() {
    for p in PARTITIONS {
        let arn = format!("arn:{p}:iam::123456789012:user/Alice");
        assert!(looks_like_aws_iam_arn_for_test(&arn), "partition {p}");
        let trimmed = format!("{p}:iam::123456789012:user/Alice");
        assert!(
            looks_like_trimmed_aws_iam_arn_for_test(&trimmed),
            "partition {p}"
        );
    }
}

// ── rejections ───────────────────────────────────────────────────────────────

#[test]
fn arn_without_a_resource_target_is_not_matched() {
    // Correct prefix + partition + :iam:: but no role/user/group/policy/profile.
    assert!(!looks_like_aws_iam_arn_for_test(
        "arn:aws:iam::123456789012:something-else"
    ));
}

#[test]
fn wrong_service_or_partition_is_not_matched() {
    assert!(!looks_like_aws_iam_arn_for_test(
        "arn:aws:s3:::my-bucket/role/x"
    )); // s3, not iam
    assert!(!looks_like_aws_iam_arn_for_test(
        "arn:aws-gov:iam::1:role/x"
    )); // unknown partition
    assert!(!looks_like_aws_iam_arn_for_test("not-an-arn-at-all"));
    assert!(!looks_like_aws_iam_arn_for_test(""));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A well-formed full ARN (valid partition + a real resource target) is ALWAYS
    /// matched by the full gate and NEVER by the trimmed gate.
    #[test]
    fn well_formed_full_arn_hits_full_gate_only(
        p in 0usize..3,
        t in 0usize..5,
        acct in "[0-9]{12}",
        name in "[A-Za-z0-9_-]{1,20}",
    ) {
        let arn = format!("arn:{}:iam::{}:{}/{}", PARTITIONS[p], acct, RESOURCE_TARGETS[t], name);
        prop_assert!(looks_like_aws_iam_arn_for_test(&arn));
        prop_assert!(!looks_like_trimmed_aws_iam_arn_for_test(&arn));
    }

    /// Symmetric: the same body minus `arn:` hits ONLY the trimmed gate.
    #[test]
    fn well_formed_trimmed_body_hits_trimmed_gate_only(
        p in 0usize..3,
        t in 0usize..5,
        acct in "[0-9]{12}",
        name in "[A-Za-z0-9_-]{1,20}",
    ) {
        let body = format!("{}:iam::{}:{}/{}", PARTITIONS[p], acct, RESOURCE_TARGETS[t], name);
        prop_assert!(looks_like_trimmed_aws_iam_arn_for_test(&body));
        prop_assert!(!looks_like_aws_iam_arn_for_test(&body));
    }

    /// No value that lacks a `:iam::` segment is ever matched by either gate, no
    /// matter how ARN-like it otherwise looks.
    #[test]
    fn no_iam_segment_never_matches(value in "arn:aws:[a-z0-9:/_-]{0,40}") {
        if !value.contains(":iam::") {
            prop_assert!(!looks_like_aws_iam_arn_for_test(&value));
            prop_assert!(!looks_like_trimmed_aws_iam_arn_for_test(&value));
        }
    }
}
