use keyhog_core::{
    Chunk, ChunkMetadata, CompanionSpec, DetectorSpec, EvidenceDirection, EvidenceRequirement,
    PatternSpec, Severity,
};
use keyhog_scanner::execution_pack::{
    compose_policy_execution_pack, BackendPlan, CanonicalDetectorExecutionIr,
    CompiledRouteMatcherSections, ExecutionPack, ExecutionPackBackend, ExecutionPackIdentity,
    ExecutionPackPolicy, PolicyPlanSections, ScalarCpuExecutionProgram,
};
use keyhog_scanner::CompiledScanner;

fn detector(id: &str, pattern: PatternSpec, keywords: Vec<String>) -> DetectorSpec {
    DetectorSpec {
        id: id.to_owned(),
        name: format!("{id} matcher graph fixture"),
        service: "matcher-graph-fixture".to_owned(),
        severity: Severity::High,
        patterns: vec![pattern],
        keywords,
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|detector| detector.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn detectors() -> Vec<DetectorSpec> {
    let mut required = detector(
        "a-required-route",
        PatternSpec {
            regex: r"REQ_([A-Z0-9]{8})".to_owned(),
            group: Some(1),
            required_literals: vec!["REQ_".to_owned()],
            ..Default::default()
        },
        vec!["REQ_".to_owned()],
    );
    required.companions.push(CompanionSpec {
        name: "account".to_owned(),
        regex: r"account=([a-z0-9_-]+)".to_owned(),
        within_lines: 2,
        direction: EvidenceDirection::Before,
        requirement: EvidenceRequirement::Required,
        capture_group: Some(1),
        ..Default::default()
    });
    vec![
        required,
        detector(
            "b-prefix-route",
            PatternSpec {
                regex: r"PREFIX_[A-Z0-9]{8}".to_owned(),
                ..Default::default()
            },
            vec!["PREFIX_".to_owned()],
        ),
        detector(
            "c-phase2-route",
            PatternSpec {
                regex: r"[A-Z0-9]{4}-ANCHORLESS-[A-Z0-9]{4}".to_owned(),
                ..Default::default()
            },
            vec!["ANCHORLESS".to_owned()],
        ),
    ]
}

fn sections(detectors: &[DetectorSpec]) -> CompiledRouteMatcherSections {
    let ir = CanonicalDetectorExecutionIr::compile(detectors).expect("compile detector IR");
    CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu)
        .expect("compile packed matcher graph")
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.to_owned().into(),
        metadata: ChunkMetadata {
            path: Some("matcher-graph.txt".into()),
            ..Default::default()
        },
    }
}

fn replace_once(bytes: &mut Vec<u8>, old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len());
    let offset = bytes
        .windows(old.len())
        .position(|window| window == old)
        .expect("packed fixture contains field");
    bytes[offset..offset + old.len()].copy_from_slice(new);
}

/// WHY: install compilation must emit one deterministic canonical ownership graph so a mapped pack can be decoded without rebuilding routes.
#[test]
fn canonical_matcher_graph_round_trips_deterministically() {
    let detectors = detectors();
    let first = sections(&detectors);
    let second = sections(&detectors);
    first.validate_canonical().expect("canonical sections validate");
    assert_eq!(first, second);
    CompiledScanner::compile_from_packed_matchers(detectors, &first)
        .expect("canonical graph decodes into scanner ownership");
}

/// WHY: route bytes are an authenticated runtime boundary, so incompatible schemas, backend drift, and valid-JSON index corruption must all fail before scanner construction.
#[test]
fn packed_matcher_graph_rejects_version_backend_and_detector_index_corruption() {
    let detectors = detectors();

    let mut bad_version = sections(&detectors);
    replace_once(&mut bad_version.literal_index, b"\"version\":2", b"\"version\":9");
    assert!(bad_version
        .validate_canonical()
        .expect_err("unknown version must fail")
        .to_string()
        .contains("version or backend"));

    let mut bad_backend = sections(&detectors);
    replace_once(&mut bad_backend.regex_programs, b"\"backend\":\"Cpu\"", b"\"backend\":\"Sim\"");
    assert!(bad_backend
        .validate_canonical()
        .expect_err("backend drift must fail")
        .to_string()
        .contains("version or backend"));

    let mut bad_index = sections(&detectors);
    replace_once(
        &mut bad_index.regex_programs,
        b"\"detector_index\":0",
        b"\"detector_index\":9",
    );
    let error = match CompiledScanner::compile_from_packed_matchers(detectors, &bad_index) {
        Ok(_) => panic!("out-of-range detector route must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("references detector index 9"));
}

/// WHY: packed ownership is correct only when required-literal, extracted-prefix, phase-two, and required-companion decisions produce byte-for-byte equivalent findings.
#[test]
fn packed_matcher_graph_preserves_pattern_route_and_companion_findings() {
    let detectors = detectors();
    let packed = sections(&detectors);
    let ordinary = CompiledScanner::compile(detectors.clone()).expect("compile ordinary scanner");
    let packed_scanner = CompiledScanner::compile_from_packed_matchers(detectors, &packed)
        .expect("compile packed scanner");
    for text in [
        "account=tenant_7\ntoken=REQ_AB12CD34\nprefix=PREFIX_Z9Y8X7W6\nvalue=AB12-ANCHORLESS-CD34",
        "token=REQ_AB12CD34\nprefix=PREFIX_Z9Y8X7W6\nvalue=AB12-ANCHORLESS-CD34",
        "account=tenant_7\ntoken=REQ_AB12CD34\nvalue=AB12-NOTANCHOR-CD34",
    ] {
        let ordinary_findings = ordinary.scan(&chunk(text)).expect("ordinary scan");
        let packed_findings = packed_scanner.scan(&chunk(text)).expect("packed scan");
        assert_eq!(packed_findings, ordinary_findings, "input: {text}");
    }
    assert_eq!(
        packed_scanner.compiled_evidence_plan("a-required-route"),
        ordinary.compiled_evidence_plan("a-required-route")
    );
}

/// WHY: runtime pack loading must never call the detector route builder because the pack already owns every routing and homoglyph decision.
#[test]
fn packed_scanner_construction_bypasses_build_compile_state() {
    let detectors = detectors();
    let packed = sections(&detectors);
    let before_ordinary =
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations();
    CompiledScanner::compile(detectors.clone()).expect("ordinary scanner compiles");
    assert_eq!(
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations(),
        before_ordinary + 1
    );
    let before_packed =
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations();
    CompiledScanner::compile_from_packed_matchers(detectors, &packed)
        .expect("packed scanner construction consumes decoded graph directly");
    assert_eq!(
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations(),
        before_packed
    );
}

fn mapped_pack(
    detectors: &[DetectorSpec],
    backend_digest_override: Option<[u8; 32]>,
) -> (tempfile::TempDir, ExecutionPack) {
    let ir = CanonicalDetectorExecutionIr::compile(detectors).expect("compile detector IR");
    let matchers = CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Cpu)
        .expect("compile packed matchers");
    let program = ScalarCpuExecutionProgram::compile(&ir)
        .and_then(|program| program.canonical_bytes())
        .expect("compile scalar program");
    let identity = ExecutionPackIdentity::new(
        ir.digest(),
        [0x31; 32],
        [0x32; 32],
        [0x33; 32],
        [0x34; 32],
        backend_digest_override.unwrap_or(*blake3::hash(&program).as_bytes()),
        ExecutionPackPolicy::Default,
        ExecutionPackBackend::Cpu,
    );
    let compiled = compose_policy_execution_pack(
        identity,
        PolicyPlanSections {
            detector_ir: ir.as_bytes(),
            literal_index: &matchers.literal_index,
            regex_programs: &matchers.regex_programs,
            suppression_policy: &matchers.suppression_policy,
            backend_plan: BackendPlan::Cpu(&program),
        },
    )
    .expect("compose execution pack");
    let directory = tempfile::tempdir().expect("temporary pack directory");
    let path = directory.path().join("matcher-graph.khpack");
    std::fs::write(&path, compiled.as_bytes()).expect("write execution pack");
    let pack = ExecutionPack::open(&path, identity).expect("map execution pack");
    (directory, pack)
}

/// WHY: every packed scanner must own all runtime state after construction; keeping the authenticated mmap alive duplicates the selected policy and lets future borrowed-section dependencies hide until an installed long-lived process drops its source generation.
#[test]
fn mapped_execution_pack_constructs_scanner_from_borrowed_sections() {
    let detectors = detectors();
    let ordinary = CompiledScanner::compile(detectors.clone()).expect("compile ordinary scanner");
    let (directory, pack) = mapped_pack(&detectors, None);
    let before =
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations();
    let (packed, decoded_detectors) =
        CompiledScanner::compile_from_execution_pack_with_tuning_and_detectors(
            &pack,
            &Default::default(),
        )
        .expect("compile directly from mapped execution pack");
    assert_eq!(
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations(),
        before
    );
    assert_eq!(
        decoded_detectors
            .iter()
            .map(|detector| detector.id.as_str())
            .collect::<Vec<_>>(),
        detectors
            .iter()
            .map(|detector| detector.id.as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        decoded_detectors[0].patterns[0].regex,
        detectors[0].patterns[0].regex
    );
    let before_shared =
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations();
    let shared = CompiledScanner::compile_shared_from_execution_pack_with_tuning(
        std::sync::Arc::clone(&decoded_detectors),
        &pack,
        &Default::default(),
    )
    .expect("compile from the already decoded shared detector corpus");
    assert_eq!(
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations(),
        before_shared
    );
    let before_autoroute =
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations();
    let autoroute = CompiledScanner::
        compile_shared_matchers_from_execution_pack_with_gpu_policy_and_tuning(
            std::sync::Arc::clone(&decoded_detectors),
            &pack,
            keyhog_scanner::GpuInitPolicy::FromRuntimePolicy,
            &Default::default(),
        )
        .expect("hydrate autoroute matchers from the CPU correctness pack");
    assert_eq!(
        keyhog_scanner::execution_pack::matcher_sections::compile_state_builder_invocations(),
        before_autoroute
    );
    drop(pack);
    drop(directory);
    let input = chunk(
        "account=tenant_7\ntoken=REQ_AB12CD34\nprefix=PREFIX_Z9Y8X7W6\nvalue=AB12-ANCHORLESS-CD34",
    );
    assert_eq!(
        packed.scan(&input).expect("scan packed route"),
        ordinary.scan(&input).expect("scan ordinary route")
    );
    assert_eq!(
        shared.scan(&input).expect("scan shared packed route"),
        ordinary.scan(&input).expect("rescan ordinary route")
    );
    assert_eq!(
        autoroute.scan(&input).expect("scan autoroute packed route"),
        ordinary.scan(&input).expect("rescan ordinary autoroute route")
    );
}

/// WHY: a mapped pack whose backend program bytes do not match the authenticated header identity must fail before scanner ownership is materialized.
#[test]
fn mapped_execution_pack_rejects_backend_program_identity_corruption() {
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, Some([0x99; 32]));
    let error = match CompiledScanner::compile_from_execution_pack(&pack) {
        Ok(_) => panic!("backend identity drift must fail"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("BackendProgram identity does not match"));
}
