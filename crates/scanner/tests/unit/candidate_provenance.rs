use crate::candidate_provenance::{CandidateChannel, CandidateProvenance};
use crate::compiler::compiler_build::build_compile_state;
use crate::scan_state::ScanState;
use keyhog_core::{
    Chunk, ChunkMetadata, CompanionMap, DetectorSpec, MatchLocation, PatternSpec, RawMatch,
    Severity,
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

/// WHY: candidate provenance is an internal sidecar. Heap ordering, identity
/// deduplication, capacity, and public `RawMatch` output must remain byte-for-byte
/// governed by the pre-existing `RawMatch` contract.
#[test]
fn provenance_sidecar_does_not_change_heap_or_public_output() {
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
    assert_eq!(
        retained
            .into_iter()
            .map(crate::scan_state::AttributedRawMatch::into_raw)
            .collect::<Vec<_>>(),
        public.into_matches()
    );
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

    let matches = scanner.debug_scan_phase2_with_provenance(&chunk);
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

/// WHY: provenance is diagnostic metadata only. Its debug form must contain no
/// credential or source bytes that could leak a scanned secret.
#[test]
fn provenance_debug_representation_is_secret_free() {
    let rendered = format!("{:?}", CandidateProvenance::named(7, 11));
    assert_eq!(
        rendered,
        "CandidateProvenance { detector_index: 7, pattern_index: 11, channel: NamedPattern }"
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
