use super::is_canonical_service_hex_key;
use crate::adjudicate::StageId;
use crate::context::CodeContext;

fn suppression_stage(value: &str, allow_canonical_hex_key: bool) -> Option<StageId> {
    crate::suppression::decision::suppression_stage_inner(
        value,
        None,
        CodeContext::Assignment,
        None,
        false,
        false,
        true,
        None,
        allow_canonical_hex_key,
        false,
        false,
    )
}

fn detector_owned_stage(value: &str) -> Option<StageId> {
    suppression_stage(value, is_canonical_service_hex_key(value))
}

/// Detector-owned canonical hex suppresses as a bare digest without the
/// exception and produces no suppression trace when the exact exception applies.
#[test]
fn canonical_service_hex_exception_preserves_exact_trace() {
    let value = "c7a9e2d4f6b8c1a3e5d7f9b2c4a6e8f0";

    assert_eq!(value.len(), 32);
    assert!(is_canonical_service_hex_key(value));
    assert_eq!(
        suppression_stage(value, false),
        Some(StageId::ShapeGate("bare_hex_digest"))
    );
    assert_eq!(detector_owned_stage(value), None);
}

/// Every declared service-key width is admitted, while adjacent and digest-only
/// widths retain the exact bare-hex suppression reason rather than inheriting the exception.
#[test]
fn canonical_service_hex_exception_boundaries_are_closed() {
    for width in [32, 40, 48, 64] {
        let value = "c".repeat(width);
        assert!(is_canonical_service_hex_key(&value), "width {width}");
    }

    for width in [31, 33, 39, 41, 47, 49, 56, 63, 65, 72, 128] {
        let value = "c".repeat(width);
        assert!(!is_canonical_service_hex_key(&value), "width {width}");
    }

    let digest = "164f08c3273fbb9913229ab3027a987ad6415b0cfd6df3839a9ed8a0b0c583a82806c55062eb3ae2e2a4df08cd8b6c5661482747e6e0ce756683bfa9a182e71b";
    for width in [56, 72, 128] {
        assert_eq!(
            detector_owned_stage(&digest[..width]),
            Some(StageId::ShapeGate("bare_hex_digest")),
            "width {width}"
        );
    }
}

/// Mixed-case and Unicode-contaminated bodies are not detector-owned canonical
/// hex, and neither may acquire a suppression trace from the moved exception.
#[test]
fn canonical_service_hex_exception_rejects_case_and_unicode_ambiguity() {
    let mixed = "164F08C3273fBb9913229Ab3027A987a";
    let unicode = "164f08c3273fbb9913229ab3027a98é";

    assert_eq!(mixed.len(), 32);
    assert!(!is_canonical_service_hex_key(mixed));
    assert!(!is_canonical_service_hex_key(unicode));
    assert_eq!(detector_owned_stage(mixed), None);
    assert_eq!(detector_owned_stage(unicode), None);
}

/// The exception never overrides earlier explicit-decoy reasons: a repetitive
/// canonical-width body still reports the same repetitive-run gauntlet stage.
#[test]
fn canonical_service_hex_exception_does_not_bypass_decoy_gauntlet() {
    let repetitive = "c".repeat(32);

    assert!(is_canonical_service_hex_key(&repetitive));
    assert_eq!(
        detector_owned_stage(&repetitive),
        Some(StageId::ShapeGate("repetitive_run"))
    );
}
