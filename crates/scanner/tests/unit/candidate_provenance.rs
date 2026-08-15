use crate::candidate_provenance::{CandidateChannel, CandidateProvenance};
use crate::compiler::compiler_build::build_compile_state;
use crate::scan_state::ScanState;
use keyhog_core::{
    AnchorSemanticRole, Chunk, ChunkMetadata, CompanionMap, DetectorSemanticPolicySpec,
    DetectorSpec, EvidenceReasonCode, EvidenceTier, MatchLocation, PatternSpec, RawMatch,
    RequiredSemanticEvidence, SemanticSourceRole, Severity,
};
use std::sync::Arc;

fn raw_match(confidence: f64, credential: &'static str, offset: usize) -> RawMatch {
    RawMatch {
        detector_id: Arc::from("provenance-fixture"),
        detector_name: Arc::from("Provenance fixture"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: credential.into(),
        credential_hash: [0u8; 32].into(),
        companions: CompanionMap::new(),
        location: MatchLocation {
            source: Arc::from("unit"),
            file_path: Some(Arc::from("fixture.env")),
            line: Some(1),
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.5),
        confidence: Some(confidence),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

fn detector(patterns: Vec<PatternSpec>) -> DetectorSpec {
    DetectorSpec {
        id: "provenance-fixture".to_owned(),
        name: "Provenance fixture".to_owned(),
        service: "test".to_owned(),
        severity: Severity::High,
        patterns,
        keywords: vec!["PROV".to_owned()],
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|spec| spec.match_confidence),
        ..crate::testing::named_detector_fixture_defaults()
    }
}

/// WHY: the evidence model exposes the sidecar verdict while retaining every
/// pre-existing heap, identity, capacity, and non-evidence `RawMatch` field.
/// Attributed and compatibility insertion must differ only in exact evidence.
#[test]
fn provenance_sidecar_sets_only_the_public_evidence_verdict() {
    let low = raw_match(0.1, "low", 1);
    let high = raw_match(0.9, "high", 2);

    let mut attributed = ScanState::default();
    attributed.push_match_with_provenance(low.clone(), CandidateProvenance::named(0, 0), 1);
    attributed.push_match_with_provenance(high.clone(), CandidateProvenance::named(0, 1), 1);
    let retained = attributed.into_attributed_matches();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].credential.as_ref(), "high");
    assert_eq!(retained[0].provenance, CandidateProvenance::named(0, 1));

    let mut public = ScanState::default();
    public.push_unattributed_match(low, 1);
    public.push_unattributed_match(high, 1);
    let public = public.into_matches(0);
    assert_eq!(
        public[0].evidence.reason_code(),
        EvidenceReasonCode::Unattributed
    );

    let mut expected = public;
    expected[0].evidence = CandidateProvenance::named(0, 1).evidence(0);
    assert_eq!(
        retained
            .into_iter()
            .map(|matched| matched.into_raw(0))
            .collect::<Vec<_>>(),
        expected
    );
}

/// WHY: multiple patterns may produce the same raw identity in different backend
/// orders. The retained public provenance must always belong to the strongest
/// evidence, with a stable pattern ordinal tiebreak.
#[test]
fn duplicate_pattern_routes_choose_strongest_exact_provenance_deterministically() {
    for reverse in [false, true] {
        let weak = CandidateProvenance::named(0, 9);
        let strong = CandidateProvenance::named(0, 3).with_checksum_proof(true);
        let routes = if reverse {
            [strong, weak]
        } else {
            [weak, strong]
        };
        let mut state = ScanState::default();
        for provenance in routes {
            state.push_match_with_provenance(raw_match(0.8, "same", 1), provenance, 8);
        }
        let findings = state.into_matches(0x0123_4567_89ab_cdef);
        assert_eq!(findings.len(), 1);
        let evidence = findings[0].evidence;
        assert_eq!(evidence.reason_code(), EvidenceReasonCode::ChecksumValid);
        let provenance = evidence.provenance();
        assert_eq!(provenance.detector_digest(), Some(0x0123_4567_89ab_cdef));
        assert_eq!(provenance.pattern_index(), Some(3));
        assert_eq!(
            provenance.candidate_channel(),
            keyhog_core::FindingCandidateChannel::Pattern
        );
    }
}

/// WHY: the same candidate can be proven by multiple routes. When the existing
/// identity-upgrade rule selects a better finding, its provenance must move with
/// that finding rather than remaining attached to the displaced producer.
#[test]
fn identity_upgrade_keeps_the_winning_provenance() {
    let mut state = ScanState::default();
    state.push_match_with_provenance(
        raw_match(0.1, "same", 7),
        CandidateProvenance::named(3, 4),
        2,
    );
    state.push_match_with_provenance(
        raw_match(0.9, "same", 7),
        CandidateProvenance::named(3, 5),
        2,
    );

    let retained = state.into_attributed_matches();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].confidence, Some(0.9));
    assert_eq!(retained[0].provenance, CandidateProvenance::named(3, 5));
}

/// WHY: ML scoring delays `RawMatch` materialization. The producer sidecar must
/// survive that queue unchanged so model adjudication cannot erase attribution.
#[cfg(feature = "ml")]
#[test]
fn ml_materialization_preserves_provenance() {
    let raw = raw_match(0.4, "pending", 9);
    let provenance = CandidateProvenance::named(2, 6);
    let pending = crate::scan_state::PendingRawMatch {
        detector_id: raw.detector_id,
        detector_name: raw.detector_name,
        service: raw.service,
        severity: raw.severity,
        credential: raw.credential,
        companions: raw.companions,
        location: raw.location,
        entropy: raw.entropy,
        provenance,
    };

    let materialized = pending.materialize(0.8);
    assert_eq!(materialized.confidence, Some(0.8));
    assert_eq!(materialized.provenance, provenance);
}

/// WHY: synthetic channels carry no invented pattern identity. Invalid
/// channel/pattern combinations must fail the sidecar invariant.
#[test]
fn channel_identity_contract_is_total() {
    for provenance in [
        CandidateProvenance::named(0, 0),
        CandidateProvenance::generic_assignment(),
        CandidateProvenance::unattributed(),
    ] {
        assert!(provenance.is_well_formed());
    }
    assert!(CandidateProvenance::generic_assignment()
        .pattern()
        .is_none());
    #[cfg(feature = "entropy")]
    assert!(CandidateProvenance::entropy().pattern().is_none());
    assert!(CandidateProvenance::unattributed().pattern().is_none());
}

/// WHY: generated regexes are routing variants, not new detector patterns.
/// Every generated variant must retain the canonical source-pattern ordinal.
#[test]
fn generated_homoglyph_variants_retain_source_pattern_identity() {
    let detector = detector(vec![
        PatternSpec {
            regex: r"FIRST_[A-Za-z0-9]{20}".to_owned(),
            ..Default::default()
        },
        PatternSpec {
            regex: r"SECOND_[A-Za-z0-9]{20}".to_owned(),
            ..Default::default()
        },
    ]);
    let state = build_compile_state(&[detector]).expect("compile provenance fixture");
    let compiled = state
        .ac_map
        .iter()
        .chain(state.phase2_patterns.iter().map(|(pattern, _)| pattern));
    let variants = compiled
        .filter(|pattern| pattern.homoglyph_variant)
        .map(|pattern| (pattern.detector_index, pattern.pattern_index))
        .collect::<Vec<_>>();

    assert!(
        variants.contains(&(0, 0)),
        "first source pattern lost its variant"
    );
    assert!(
        variants.contains(&(0, 1)),
        "second source pattern lost its variant"
    );
    assert!(variants.iter().all(|(detector_index, pattern_index)| {
        *detector_index == 0 && (*pattern_index == 0 || *pattern_index == 1)
    }));
}

/// WHY: persisted matcher hydration must reproduce the exact source pattern
/// identity. A route can change backend representation, but not provenance.
#[test]
fn packed_matcher_hydration_preserves_pattern_identity() {
    fn identities(
        state: &crate::compiler::compiler_build::CompileState,
    ) -> Vec<(usize, u32, bool)> {
        state
            .ac_map
            .iter()
            .chain(state.phase2_patterns.iter().map(|(pattern, _)| pattern))
            .map(|pattern| {
                (
                    pattern.detector_index,
                    pattern.pattern_index,
                    pattern.homoglyph_variant,
                )
            })
            .collect()
    }

    let detectors = vec![detector(vec![
        PatternSpec {
            regex: r"FIRST_[A-Za-z0-9]{20}".to_owned(),
            ..Default::default()
        },
        PatternSpec {
            regex: r"[A-Za-z0-9]{4}PROV[A-Za-z0-9]{20}".to_owned(),
            ..Default::default()
        },
    ])];
    let ir = crate::execution_pack::CanonicalDetectorExecutionIr::compile(&detectors)
        .expect("compile provenance IR");
    let (sections, source) =
        crate::execution_pack::CompiledRouteMatcherSections::compile_with_state(
            &ir,
            crate::execution_pack::ExecutionPackBackend::Cpu,
        )
        .expect("compile provenance matcher sections");
    let hydrated = crate::execution_pack::matcher_sections::decode_compile_state_sections(
        crate::execution_pack::ExecutionPackBackend::Cpu,
        &sections.literal_index,
        &sections.regex_programs,
        &sections.suppression_policy,
        ir.digest(),
        &detectors,
    )
    .expect("hydrate provenance matcher sections");

    assert_eq!(identities(&hydrated), identities(&source));
}

/// WHY: every named finding reaches the common adjudication choke point. The
/// emitted sidecar must identify the exact canonical pattern rather than merely
/// the detector that happened to own the route.
#[test]
fn phase2_named_match_retains_exact_pattern_identity() {
    let scanner = crate::CompiledScanner::compile(vec![detector(vec![
        PatternSpec {
            regex: r"[A-Za-z0-9]{4}MISS[A-Za-z0-9]{20}".to_owned(),
            ..Default::default()
        },
        PatternSpec {
            regex: r"[A-Za-z0-9]{4}PROV[A-Za-z0-9]{20}".to_owned(),
            ..Default::default()
        },
    ])])
    .expect("compile provenance scanner");
    let chunk = Chunk {
        data: "token = aK7xPROVmQ2wE5rT8yU1iO9pL3sZ".to_owned().into(),
        metadata: ChunkMetadata {
            path: Some("src/config.rs".into()),
            ..Default::default()
        },
    };

    let matches = scanner
        .debug_scan_phase2_with_provenance(&chunk)
        .expect("phase-2 provenance scan");
    let finding = matches
        .iter()
        .find(|finding| finding.detector_id.as_ref() == "provenance-fixture")
        .expect("second canonical pattern must produce a finding");
    assert_eq!(finding.provenance.channel(), CandidateChannel::NamedPattern);
    let pattern = finding
        .provenance
        .pattern()
        .expect("named pattern provenance");
    assert_eq!(pattern.detector_index, 0);
    assert_eq!(pattern.pattern_index, 1);
}
/// WHY: typed source evidence must survive the same compact sidecar as pattern
/// identity. Parser abstention remains explicit rather than inventing a role.
#[test]
fn source_semantics_are_explicit_and_well_formed() {
    let source = r#"{"token":"CFGPROV_UNIT_123456"}"#;
    let start = source.find("CFGPROV_UNIT_123456").unwrap();
    let evidence = crate::source_semantics::classify_structured_candidate(
        source,
        Some("config.json"),
        start,
        start + "CFGPROV_UNIT_123456".len(),
    )
    .expect("structured source evidence");
    let parsed = CandidateProvenance::named(7, 11).with_source_semantics(evidence, None);
    assert_eq!(
        parsed.source_role(),
        SemanticSourceRole::StructuredAssignmentValue
    );
    assert_eq!(
        parsed.parser_confidence(),
        crate::source_semantics::SemanticParserConfidence::Parsed
    );
    assert!(parsed.is_well_formed());
    assert_eq!(
        CandidateProvenance::named(7, 11).source_role(),
        SemanticSourceRole::Unknown
    );
}

fn semantic_policy(
    anchor_role: AnchorSemanticRole,
    allowed_source_roles: Vec<SemanticSourceRole>,
    required_evidence: Vec<RequiredSemanticEvidence>,
) -> DetectorSemanticPolicySpec {
    DetectorSemanticPolicySpec {
        anchor_role,
        allowed_source_roles,
        required_evidence,
        ..Default::default()
    }
}

fn parsed_source_role(role: SemanticSourceRole) -> crate::source_semantics::SourceSemanticEvidence {
    crate::source_semantics::SourceSemanticEvidence::parsed(
        role,
        crate::source_semantics::SourceSpan::new(4, 12),
        crate::source_semantics::SourceSpan::new(0, 16),
    )
}

/// WHY: evidence policy is detector-owned and every proof requirement reaches
/// this choke point. Missing proof must fail to review while intrinsic proof
/// remains confirmed even in ambiguous source context.
#[test]
fn named_evidence_reason_precedence_is_fail_closed() {
    let exact = semantic_policy(
        AnchorSemanticRole::ExactKey,
        vec![SemanticSourceRole::StructuredAssignmentValue],
        Vec::new(),
    );
    let supported = CandidateProvenance::named(0, 0)
        .with_named_evidence(&exact, false, false, false)
        .with_source_semantics(
            parsed_source_role(SemanticSourceRole::StructuredAssignmentValue),
            Some(&exact),
        )
        .evidence(0);
    assert_eq!(supported.reason_code(), EvidenceReasonCode::VendorPattern);
    assert_eq!(supported.tier(), EvidenceTier::Likely);

    let mismatched = CandidateProvenance::named(0, 0)
        .with_named_evidence(&exact, false, false, false)
        .with_source_semantics(
            parsed_source_role(SemanticSourceRole::StringLiteral),
            Some(&exact),
        )
        .evidence(0);
    assert_eq!(
        mismatched.reason_code(),
        EvidenceReasonCode::SourceRoleMismatch
    );

    let weak = semantic_policy(AnchorSemanticRole::WeakContext, Vec::new(), Vec::new());
    assert_eq!(
        CandidateProvenance::named(0, 0)
            .with_named_evidence(&weak, false, false, false)
            .evidence(0)
            .reason_code(),
        EvidenceReasonCode::WeakAnchor
    );
    assert_eq!(
        CandidateProvenance::named(0, 0)
            .with_named_evidence(&exact, true, false, false)
            .evidence(0)
            .reason_code(),
        EvidenceReasonCode::GenericDetector
    );

    for requirement in [
        RequiredSemanticEvidence::Checksum,
        RequiredSemanticEvidence::RequiredCompanion,
        RequiredSemanticEvidence::PrivateKeyCompanion,
        RequiredSemanticEvidence::LiveVerification,
        RequiredSemanticEvidence::StructuralGrammar,
    ] {
        let policy = semantic_policy(AnchorSemanticRole::ExactKey, Vec::new(), vec![requirement]);
        assert_eq!(
            CandidateProvenance::named(0, 0)
                .with_named_evidence(&policy, false, false, false)
                .evidence(0)
                .reason_code(),
            EvidenceReasonCode::RequiredEvidenceMissing,
            "{requirement:?} must fail closed without proof"
        );
    }

    let checksum = semantic_policy(
        AnchorSemanticRole::ExactKey,
        Vec::new(),
        vec![RequiredSemanticEvidence::Checksum],
    );
    let confirmed = CandidateProvenance::named(0, 0)
        .with_named_evidence(&checksum, false, true, false)
        .with_source_semantics(
            parsed_source_role(SemanticSourceRole::TestFixture),
            Some(&checksum),
        )
        .evidence(0);
    assert_eq!(confirmed.reason_code(), EvidenceReasonCode::ChecksumValid);
    assert_eq!(confirmed.tier(), EvidenceTier::Confirmed);

    let companion = semantic_policy(
        AnchorSemanticRole::CompanionBound,
        Vec::new(),
        vec![RequiredSemanticEvidence::RequiredCompanion],
    );
    assert_eq!(
        CandidateProvenance::named(0, 0)
            .with_named_evidence(&companion, false, false, true)
            .evidence(0)
            .reason_code(),
        EvidenceReasonCode::RequiredCompanion
    );
}

/// WHY: synthetic discovery lanes have no detector pattern from which to infer
/// provider evidence. Their explicit review reasons must survive construction.
#[test]
fn synthetic_channels_emit_exact_review_reasons() {
    assert_eq!(
        CandidateProvenance::generic_assignment()
            .evidence(0)
            .reason_code(),
        EvidenceReasonCode::GenericAssignment
    );
    #[cfg(feature = "entropy")]
    assert_eq!(
        CandidateProvenance::entropy().evidence(0).reason_code(),
        EvidenceReasonCode::EntropyOnly
    );
    assert_eq!(
        CandidateProvenance::unattributed()
            .evidence(0)
            .reason_code(),
        EvidenceReasonCode::Unattributed
    );
}

/// WHY: provenance is diagnostic metadata only. Its debug form must contain no
/// credential or source bytes that could leak a scanned secret.
#[test]
fn provenance_debug_representation_is_secret_free() {
    let rendered = format!("{:?}", CandidateProvenance::named(7, 11));
    assert_eq!(
        rendered,
        "CandidateProvenance { detector_index: 7, pattern_index: 11, channel: NamedPattern, source_role: Unknown, parser_confidence: Abstained, evidence_reason: UnsupportedContext }"
    );
    assert!(!rendered.contains("credential"));
}

/// WHY: provenance is carried for every retained finding and pending ML row.
/// Layout growth would multiply across the one-million-finding hard cap.
#[test]
fn provenance_sidecar_stays_compact() {
    assert!(
        std::mem::size_of::<CandidateProvenance>() <= 16,
        "candidate provenance grew beyond its allocation-free compact contract"
    );
}
