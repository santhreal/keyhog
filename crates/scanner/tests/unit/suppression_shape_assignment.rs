use super::{
    looks_like_entropy_canonical_hex_digest, looks_like_entropy_canonical_non_secret_shape,
    looks_like_entropy_uuid_shape,
};
use crate::adjudicate::StageId;
use crate::context::CodeContext;

fn suppression_stage(value: &str) -> Option<StageId> {
    crate::suppression::decision::suppression_stage_inner(
        value,
        None,
        CodeContext::Assignment,
        None,
        false,
        false,
        true,
        None,
        false,
        false,
        false,
    )
}

/// The entropy assignment role stays uppercase-only for product serials while
/// report-time suppression preserves the exact dashed-serial reason for either case.
#[test]
fn assignment_serial_role_preserves_report_time_decisions() {
    let uppercase = "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY";
    let lowercase = "abcde-fghij-klmno-pqrst-uvwxy";

    assert!(looks_like_entropy_canonical_non_secret_shape(uppercase));
    assert!(!looks_like_entropy_canonical_non_secret_shape(lowercase));
    assert_eq!(
        suppression_stage(uppercase),
        Some(StageId::ShapeGate("dashed_serial_key"))
    );
    assert_eq!(
        suppression_stage(lowercase),
        Some(StageId::ShapeGate("dashed_serial_key"))
    );
}

/// Mixed-case hex remains an entropy canonical digest, but not the uniform-case
/// report-time digest shape; the role split must not invent a suppression trace.
#[test]
fn assignment_hex_role_preserves_mixed_case_differential() {
    let mixed = "164F08C3273fBb9913229Ab3027A987a";

    assert_eq!(mixed.len(), 32);
    assert!(looks_like_entropy_canonical_hex_digest(mixed));
    assert_eq!(suppression_stage(mixed), None);
}

/// Entropy digest widths remain exact at 32/40/64/128 bytes, and a Unicode
/// lookalike is rejected without producing a report-time suppression reason.
#[test]
fn assignment_hex_boundaries_and_unicode_remain_exact() {
    let below = "164f08c3273fbb9913229ab3027a98b";
    let unicode = "164f08c3273fbb9913229ab3027a98é";

    assert_eq!(below.len(), 31);
    assert_eq!(unicode.len(), 32);
    assert!(!looks_like_entropy_canonical_hex_digest(below));
    assert!(!looks_like_entropy_canonical_hex_digest(unicode));
    assert_eq!(suppression_stage(below), None);
    assert_eq!(suppression_stage(unicode), None);
}

/// A short algorithm-labelled base64 value is canonical only in entropy's
/// assignment role; report-time suppression retains its forty-byte integrity
/// floor and therefore emits no labelled-hash reason.
#[test]
fn assignment_integrity_role_preserves_report_time_floor() {
    let short_integrity = "sha256-YWJjZA==";

    assert!(looks_like_entropy_canonical_non_secret_shape(
        short_integrity
    ));
    assert_eq!(suppression_stage(short_integrity), None);
}

/// UUID assignment classification delegates to the one canonical owner, so
/// positive, mixed-case, boundary, and Unicode-dash decisions cannot diverge.
#[test]
fn assignment_uuid_role_matches_canonical_shape_exactly() {
    let canonical = "550e8400-e29b-41d4-a716-446655440000";
    let mixed_case = "550e8400-e29b-41D4-a716-446655440000";
    let short = "550e8400-e29b-41d4-a716-44665544000";
    let unicode_dash = "550e8400–e29b-41d4-a716-446655440000";

    assert!(looks_like_entropy_uuid_shape(canonical));
    assert!(!looks_like_entropy_uuid_shape(mixed_case));
    assert!(!looks_like_entropy_uuid_shape(short));
    assert!(!looks_like_entropy_uuid_shape(unicode_dash));
    assert_eq!(
        suppression_stage(canonical),
        Some(StageId::ShapeGate("uuid_v4_shape"))
    );
    assert_eq!(suppression_stage(mixed_case), None);
    assert_eq!(suppression_stage(short), None);
    assert_eq!(suppression_stage(unicode_dash), None);
}

#[test]
fn high_entropy_base64_secret_recall_and_negative_suppression_boundaries() {
    use super::{
        generic_base64_candidate_is_ambiguous, looks_like_generic_random_base64_blob_decoy,
    };

    let base64_secret = "qA9zM4nB7vC2xL8pR5tY1uI6oP3sD0fG9hJ2kL7mN4bV8cX1zQ6wE5rT0yU3iO";
    let entropy_secret = 5.2;

    assert!(!looks_like_generic_random_base64_blob_decoy(
        base64_secret,
        entropy_secret
    ));
    assert!(generic_base64_candidate_is_ambiguous(
        base64_secret,
        entropy_secret
    ));

    let doc_negative = "YOUR_API_KEY_HERE_PLACEHOLDER_VALUE_123456";
    let hex_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let low_entropy_b64 = "Y2FsaWNvK29uL2t1YmVz/2FtcGxlc3RyaW5nK2FkZA==";

    assert_eq!(
        suppression_stage(doc_negative),
        Some(StageId::ShapeGate("placeholder_word"))
    );
    assert!(looks_like_entropy_canonical_hex_digest(hex_digest));
    assert!(looks_like_generic_random_base64_blob_decoy(
        low_entropy_b64,
        1.0
    ));
}
