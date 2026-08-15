use super::*;

fn diagnostic_match() -> CanonicalMatch<'static> {
    CanonicalMatch {
        chunk_idx: 0,
        detector_id: "detector",
        detector_name: "Detector",
        service: "service",
        severity: Severity::High,
        credential_value_hash: [0x11; 32].into(),
        credential_hash: [0x99; 32].into(),
        companions: vec![([0x22; 32].into(), [0x33; 32].into())],
        source: "git",
        file_path: Some("src/file.rs"),
        line: Some(7),
        offset: 13,
        commit: Some("commit-a"),
        author: Some("author-a@example.test"),
        date: Some("2026-07-14T00:00:00Z"),
        entropy_bits: Some(4.2_f64.to_bits()),
        confidence_bits: Some(0.9_f64.to_bits()),
        evidence_tier: EvidenceTier::Review,
        evidence_reason_code: EvidenceReasonCode::Unattributed,
    }
}

/// Regression: backend parity diagnostics must identify only the canonical match field that changed so operators can trust mismatch evidence.
#[test]
fn diagnostic_reports_only_differing_field_names() {
    let base = diagnostic_match();
    let mut variants = Vec::new();

    let mut changed = base.clone();
    changed.chunk_idx = 1;
    variants.push(("chunk_idx", changed));

    let mut changed = base.clone();
    changed.detector_id = "detector-b";
    variants.push(("detector_id", changed));

    let mut changed = base.clone();
    changed.detector_name = "Detector B";
    variants.push(("detector_name", changed));

    let mut changed = base.clone();
    changed.service = "service-b";
    variants.push(("service", changed));

    let mut changed = base.clone();
    changed.severity = Severity::Critical;
    variants.push(("severity", changed));

    let mut changed = base.clone();
    changed.credential_value_hash = [0x12; 32].into();
    variants.push(("credential_value", changed));

    let mut changed = base.clone();
    changed.credential_hash = [0x98; 32].into();
    variants.push(("credential_hash", changed));

    let mut changed = base.clone();
    changed.companions = vec![([0x22; 32].into(), [0x34; 32].into())];
    variants.push(("companions", changed));

    let mut changed = base.clone();
    changed.companions = vec![([0x23; 32].into(), [0x33; 32].into())];
    variants.push(("companions", changed));

    let mut changed = base.clone();
    changed.source = "filesystem";
    variants.push(("source", changed));

    let mut changed = base.clone();
    changed.file_path = Some("src/other.rs");
    variants.push(("file_path", changed));

    let mut changed = base.clone();
    changed.line = Some(8);
    variants.push(("line", changed));

    let mut changed = base.clone();
    changed.offset = 14;
    variants.push(("offset", changed));

    let mut changed = base.clone();
    changed.commit = Some("commit-b");
    variants.push(("commit", changed));

    let mut changed = base.clone();
    changed.author = Some("author-b@example.test");
    variants.push(("author", changed));

    let mut changed = base.clone();
    changed.date = Some("2026-07-15T00:00:00Z");
    variants.push(("date", changed));

    let mut changed = base.clone();
    changed.entropy_bits = Some(4.3_f64.to_bits());
    variants.push(("entropy", changed));

    let mut changed = base.clone();
    changed.confidence_bits = Some(0.8_f64.to_bits());
    variants.push(("confidence", changed));

    let mut changed = base.clone();
    changed.evidence_tier = EvidenceTier::Likely;
    variants.push(("evidence_tier", changed));

    let mut changed = base.clone();
    changed.evidence_reason_code = EvidenceReasonCode::UnsupportedContext;
    variants.push(("evidence_reason_code", changed));

    for (field, changed) in variants {
        assert_eq!(
            differing_canonical_match_fields(
                std::slice::from_ref(&base),
                std::slice::from_ref(&changed),
            ),
            vec![field],
            "the parity diagnostic must name only the changed field"
        );
    }

    assert_eq!(
        differing_canonical_match_fields(std::slice::from_ref(&base), &[]),
        vec!["match_count"]
    );
}
