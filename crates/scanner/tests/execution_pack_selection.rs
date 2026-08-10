use keyhog_scanner::execution_pack::{
    compose_policy_execution_pack, select_execution_pack, BackendPlan,
    CanonicalDetectorExecutionIr, ExecutionPackBackend, ExecutionPackCandidate,
    ExecutionPackIdentity, ExecutionPackPolicy, ExecutionPackSigningKey, PersistedRouteDecision,
    PolicyPlanSections, RouteSelectionContext, ROUTE_DECISION_VERSION,
};
use std::fs;
use std::path::Path;

fn identity(backend: ExecutionPackBackend) -> ExecutionPackIdentity {
    let detector = keyhog_core::DetectorSpec {
        id: "selection-plan".to_owned(),
        name: "selection plan".to_owned(),
        service: "selection".to_owned(),
        ..Default::default()
    };
    let detector_digest = CanonicalDetectorExecutionIr::compile(&[detector])
        .expect("compile detector IR")
        .digest();
    ExecutionPackIdentity::new(
        detector_digest,
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
        [backend as u8; 32],
        ExecutionPackPolicy::Default,
        backend,
    )
}

fn signing_key() -> ExecutionPackSigningKey {
    ExecutionPackSigningKey::from_bytes([0x5a; 32]).expect("fixture signing key")
}

fn signature_path(path: &Path) -> std::path::PathBuf {
    path.with_extension("sig")
}

fn publish(path: &Path, backend: ExecutionPackBackend) -> ([u8; 32], [u8; 32]) {
    let detector = keyhog_core::DetectorSpec {
        id: "selection-plan".to_owned(),
        name: "selection plan".to_owned(),
        service: "selection".to_owned(),
        ..Default::default()
    };
    let ir = CanonicalDetectorExecutionIr::compile(&[detector]).expect("compile detector IR");
    let mut pack_identity = identity(backend);
    pack_identity.detector_digest = ir.digest();
    let backend_plan = match backend {
        ExecutionPackBackend::Cpu => BackendPlan::Cpu(b"cpu-program"),
        ExecutionPackBackend::Simd => BackendPlan::Simd(b"simd-program"),
        gpu => BackendPlan::VyreGpu {
            backend: gpu,
            orchestration_receipt: b"vyre-receipt",
        },
    };
    let compiled = compose_policy_execution_pack(
        pack_identity,
        PolicyPlanSections {
            detector_ir: ir.as_bytes(),
            literal_index: b"literal-index",
            regex_programs: b"regex-programs",
            suppression_policy: b"suppression-policy",
            backend_plan,
        },
    )
    .expect("compose pack");
    fs::write(path, compiled.as_bytes()).expect("publish pack");
    let signature = signing_key().sign(&compiled);
    fs::write(
        signature_path(path),
        signature.canonical_bytes().expect("encode signature"),
    )
    .expect("publish signature");
    (pack_identity.digest(), compiled.content_digest())
}

fn context() -> RouteSelectionContext {
    RouteSelectionContext {
        policy: ExecutionPackPolicy::Default,
        workload_digest: [0x71; 32],
        host_digest: [0x72; 32],
        calibration_digest: [0x73; 32],
        feature_schema_digest: [0x74; 32],
        quantized_model_digest: [0x75; 32],
    }
}

fn decision(
    backend: ExecutionPackBackend,
    pack_identity_digest: [u8; 32],
    pack_content_digest: [u8; 32],
) -> PersistedRouteDecision {
    let context = context();
    PersistedRouteDecision {
        version: ROUTE_DECISION_VERSION,
        policy: context.policy,
        backend,
        workload_digest: context.workload_digest,
        host_digest: context.host_digest,
        calibration_digest: context.calibration_digest,
        pack_identity_digest,
        pack_content_digest,
        feature_schema_digest: context.feature_schema_digest,
        quantized_model_digest: context.quantized_model_digest,
    }
}

/// WHY: autoroute must choose from manifest metadata before mapping; unavailable losing backends must not allocate, initialize, or break the selected route.
#[test]
fn selector_maps_only_the_persisted_winner() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let cpu_path = directory.path().join("cpu.khpack");
    let (identity_digest, content_digest) = publish(&cpu_path, ExecutionPackBackend::Cpu);
    let missing_simd = directory.path().join("simd-must-not-open.khpack");
    let candidates = [
        ExecutionPackCandidate::new(
            ExecutionPackBackend::Simd,
            &missing_simd,
            signature_path(&missing_simd),
            identity(ExecutionPackBackend::Simd),
        ),
        ExecutionPackCandidate::new(
            ExecutionPackBackend::Cpu,
            &cpu_path,
            signature_path(&cpu_path),
            identity(ExecutionPackBackend::Cpu),
        ),
    ];

    let selected = select_execution_pack(
        context(),
        decision(ExecutionPackBackend::Cpu, identity_digest, content_digest),
        &signing_key(),
        &candidates,
    )
    .expect("select CPU before mapping");
    assert_eq!(selected.decision().backend, ExecutionPackBackend::Cpu);
    assert_eq!(selected.pack().path(), cpu_path);
}

/// WHY: a missing calibrated winner is an invalid autoroute state, never permission to map a slower available backend.
#[test]
fn missing_selected_pack_fails_without_backend_fallback() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let cpu_path = directory.path().join("cpu.khpack");
    publish(&cpu_path, ExecutionPackBackend::Cpu);
    let candidates = [ExecutionPackCandidate::new(
        ExecutionPackBackend::Cpu,
        &cpu_path,
        signature_path(&cpu_path),
        identity(ExecutionPackBackend::Cpu),
    )];

    let error = select_execution_pack(
        context(),
        decision(ExecutionPackBackend::Simd, [0x91; 32], [0x92; 32]),
        &signing_key(),
        &candidates,
    )
    .err()
    .expect("missing selected pack must fail");
    assert!(error.to_string().contains("has no execution pack"));
    assert!(error.to_string().contains("reinstall and recalibrate"));
}

/// WHY: stale host, workload, policy, calibration, schema, or model evidence must be rejected before touching any backend path.
#[test]
fn stale_route_identity_fails_before_pack_open() {
    let missing = Path::new("/path/that/must/not/be/opened.khpack");
    let candidate = ExecutionPackCandidate::new(
        ExecutionPackBackend::Cpu,
        missing,
        signature_path(missing),
        identity(ExecutionPackBackend::Cpu),
    );
    let identity_digest = candidate.identity.digest();
    for (label, mutate) in [
        ("workload", 0_u8),
        ("host", 1_u8),
        ("calibration", 2_u8),
        ("feature schema", 3_u8),
        ("quantized model", 4_u8),
    ] {
        let mut route = decision(ExecutionPackBackend::Cpu, identity_digest, [0x93; 32]);
        match mutate {
            0 => route.workload_digest = [0; 32],
            1 => route.host_digest = [0; 32],
            2 => route.calibration_digest = [0; 32],
            3 => route.feature_schema_digest = [0; 32],
            _ => route.quantized_model_digest = [0; 32],
        }
        let error = select_execution_pack(
            context(),
            route,
            &signing_key(),
            std::slice::from_ref(&candidate),
        )
        .err()
        .expect("stale route must fail");
        assert!(error
            .to_string()
            .contains(&format!("autoroute {label} identity is stale")));
        assert!(!error.to_string().contains("failed to open"));
    }
}

/// WHY: calibration selects exact bytes, not merely a backend label; replacing that backend's pack invalidates the decision.
#[test]
fn selected_pack_content_must_match_calibrated_generation() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("cpu.khpack");
    let (identity_digest, _content_digest) = publish(&path, ExecutionPackBackend::Cpu);
    let candidate = ExecutionPackCandidate::new(
        ExecutionPackBackend::Cpu,
        &path,
        signature_path(&path),
        identity(ExecutionPackBackend::Cpu),
    );

    let error = select_execution_pack(
        context(),
        decision(ExecutionPackBackend::Cpu, identity_digest, [0x99; 32]),
        &signing_key(),
        &[candidate],
    )
    .err()
    .expect("stale content digest must fail");
    assert!(error
        .to_string()
        .contains("content does not match the calibrated route"));
}

/// WHY: a pack without its authenticated sidecar is incomplete and must never reach runtime section materialization.
#[test]
fn selected_pack_without_signature_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("cpu.khpack");
    let (identity_digest, content_digest) = publish(&path, ExecutionPackBackend::Cpu);
    fs::remove_file(signature_path(&path)).expect("remove signature");
    let candidate = ExecutionPackCandidate::new(
        ExecutionPackBackend::Cpu,
        &path,
        signature_path(&path),
        identity(ExecutionPackBackend::Cpu),
    );
    let error = select_execution_pack(
        context(),
        decision(ExecutionPackBackend::Cpu, identity_digest, content_digest),
        &signing_key(),
        &[candidate],
    )
    .err()
    .expect("unsigned selected pack must fail");
    assert!(error.to_string().contains("open signature"));
}

/// WHY: a sidecar with the correct shape but altered authenticator cannot authorize an otherwise valid pack.
#[test]
fn selected_pack_with_corrupt_signature_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("cpu.khpack");
    let (identity_digest, content_digest) = publish(&path, ExecutionPackBackend::Cpu);
    let signature_path = signature_path(&path);
    let mut signature = fs::read(&signature_path).expect("read signature");
    signature[111] ^= 0x40;
    fs::write(&signature_path, signature).expect("corrupt signature");
    let candidate = ExecutionPackCandidate::new(
        ExecutionPackBackend::Cpu,
        &path,
        &signature_path,
        identity(ExecutionPackBackend::Cpu),
    );
    let error = select_execution_pack(
        context(),
        decision(ExecutionPackBackend::Cpu, identity_digest, content_digest),
        &signing_key(),
        &[candidate],
    )
    .err()
    .expect("corrupt signature must fail");
    assert!(error.to_string().contains("signature verification failed"));
}

/// WHY: a signature generated by another installation cannot cross-authorize this installation's pack generation.
#[test]
fn selected_pack_with_foreign_signature_key_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("cpu.khpack");
    let (identity_digest, content_digest) = publish(&path, ExecutionPackBackend::Cpu);
    let candidate = ExecutionPackCandidate::new(
        ExecutionPackBackend::Cpu,
        &path,
        signature_path(&path),
        identity(ExecutionPackBackend::Cpu),
    );
    let foreign = ExecutionPackSigningKey::from_bytes([0x6b; 32]).expect("foreign key");
    let error = select_execution_pack(
        context(),
        decision(ExecutionPackBackend::Cpu, identity_digest, content_digest),
        &foreign,
        &[candidate],
    )
    .err()
    .expect("foreign signature key must fail");
    assert!(error.to_string().contains("key identity does not match"));
}
