#![cfg(feature = "gpu")]

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::execution_pack::{
    compose_policy_execution_pack, BackendPlan, CanonicalDetectorExecutionIr,
    CompiledRouteMatcherSections, ExecutionPack, ExecutionPackBackend, ExecutionPackIdentity,
    ExecutionPackPolicy, PolicyPlanSections, VyreExecutionIdentity, VyreOrchestrationProgram,
};
use keyhog_scanner::{
    gpu_literal_plan_compiler_invocations, install_compiled_gpu_literal_invocations,
    probe_hardware, runtime_gpu_literal_compiler_invocations, CompiledScanner, ScanBackend,
};
use std::sync::{Mutex, MutexGuard};

static GPU_PACK_TEST_LOCK: Mutex<()> = Mutex::new(());

fn serialized_tests() -> MutexGuard<'static, ()> {
    GPU_PACK_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn detectors() -> Vec<DetectorSpec> {
    vec![DetectorSpec {
        id: "packed-gpu-vyre".to_owned(),
        name: "Packed GPU VYRE fixture".to_owned(),
        service: "packed-gpu-vyre-fixture".to_owned(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: r"PACKED_GPU_[A-Z0-9]{8}".to_owned(),
            required_literals: vec!["PACKED_GPU_".to_owned()],
            ..Default::default()
        }],
        keywords: vec!["PACKED_GPU_".to_owned()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }]
}

fn current_wgpu_identity(
    detectors: &[DetectorSpec],
    target_digest: [u8; 32],
) -> VyreExecutionIdentity {
    let scanner = CompiledScanner::compile_for_backend(detectors.to_vec(), ScanBackend::GpuWgpu)
        .expect("census current WGPU peer");
    let status = scanner
        .gpu_backend_candidates()
        .into_iter()
        .find(|status| status.backend == ScanBackend::GpuWgpu)
        .expect("WGPU candidate status");
    assert!(
        status.is_eligible(),
        "the live GPU gate requires an eligible hardware WGPU peer: {status:?}"
    );
    VyreExecutionIdentity::for_selected_peer(
        ExecutionPackBackend::GpuWgpu,
        target_digest,
        status
            .runtime_identity
            .expect("eligible WGPU peer has runtime identity"),
        status
            .device_identity
            .expect("eligible WGPU peer has device identity"),
        &format!("{:?}", probe_hardware()),
    )
    .expect("derive exact selected-peer identity")
}

fn mapped_pack(
    detectors: &[DetectorSpec],
    mutate: impl FnOnce(&mut VyreOrchestrationProgram),
) -> (tempfile::TempDir, ExecutionPack) {
    let target_digest = [0x42; 32];
    let ir = CanonicalDetectorExecutionIr::compile(detectors).expect("compile detector IR");
    let matchers = CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::GpuWgpu)
        .expect("compile packed matcher sections");
    let identity = current_wgpu_identity(detectors, target_digest);
    let mut program =
        VyreOrchestrationProgram::compile(&ir, ExecutionPackBackend::GpuWgpu, identity)
            .expect("install-compile VYRE matcher");
    mutate(&mut program);
    let program_bytes = program.canonical_bytes().expect("encode VYRE program");
    let pack_identity = ExecutionPackIdentity::new(
        ir.digest(),
        [0x41; 32],
        target_digest,
        [0x43; 32],
        [0x44; 32],
        *blake3::hash(&program_bytes).as_bytes(),
        ExecutionPackPolicy::Default,
        ExecutionPackBackend::GpuWgpu,
    );
    let compiled = compose_policy_execution_pack(
        pack_identity,
        PolicyPlanSections {
            detector_ir: ir.as_bytes(),
            literal_index: &matchers.literal_index,
            regex_programs: &matchers.regex_programs,
            suppression_policy: &matchers.suppression_policy,
            backend_plan: BackendPlan::VyreGpu {
                backend: ExecutionPackBackend::GpuWgpu,
                orchestration_receipt: &program_bytes,
            },
        },
    )
    .expect("compose GPU execution pack");
    let directory = tempfile::tempdir().expect("temporary pack directory");
    let path = directory.path().join("packed-gpu-vyre.khpack");
    std::fs::write(&path, compiled.as_bytes()).expect("write GPU execution pack");
    let pack = ExecutionPack::open(&path, pack_identity).expect("map GPU execution pack");
    (directory, pack)
}

/// WHY: an authenticated GPU pack owns the complete immutable VYRE matcher, so construction and first use must install its bytes without rebuilding literal rows or invoking the runtime compiler.
#[test]
fn packed_gpu_installs_vyre_matcher_without_scan_time_compilation() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |_| {});
    let install_before = install_compiled_gpu_literal_invocations();
    let plan_before = gpu_literal_plan_compiler_invocations();
    let runtime_before = runtime_gpu_literal_compiler_invocations();

    let scanner = CompiledScanner::compile_from_execution_pack(&pack)
        .expect("construct scanner from packed VYRE matcher");
    assert_eq!(
        install_compiled_gpu_literal_invocations(),
        install_before + 1,
        "packed scanner must deserialize the authenticated matcher exactly once"
    );
    assert_eq!(gpu_literal_plan_compiler_invocations(), plan_before);
    assert_eq!(runtime_gpu_literal_compiler_invocations(), runtime_before);

    let findings = scanner
        .scan_with_backend(
            &Chunk {
                data: "prefix PACKED_GPU_ABCDEFGH suffix".to_owned().into(),
                metadata: ChunkMetadata {
                    path: Some("packed-gpu-vyre.txt".into()),
                    ..Default::default()
                },
            },
            ScanBackend::GpuWgpu,
        )
        .expect("scan with packed VYRE matcher");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].detector_id.as_ref(), "packed-gpu-vyre");
    assert_eq!(findings[0].location.offset, 7);
    assert_eq!(gpu_literal_plan_compiler_invocations(), plan_before);
    assert_eq!(runtime_gpu_literal_compiler_invocations(), runtime_before);
}

/// WHY: a signed pack for another device identity is not executable evidence for the acquired peer, and rejection must happen before any matcher installation or recompilation fallback.
#[test]
fn packed_gpu_rejects_selected_peer_identity_drift_before_install() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |program| {
        program
            .execution_identity
            .device_identity
            .push_str(":stale");
    });
    let install_before = install_compiled_gpu_literal_invocations();
    let plan_before = gpu_literal_plan_compiler_invocations();
    let runtime_before = runtime_gpu_literal_compiler_invocations();

    let error = match CompiledScanner::compile_from_execution_pack(&pack) {
        Ok(_) => panic!("selected-peer identity drift must fail scanner construction"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("execution identity does not match"));
    assert_eq!(install_compiled_gpu_literal_invocations(), install_before);
    assert_eq!(gpu_literal_plan_compiler_invocations(), plan_before);
    assert_eq!(runtime_gpu_literal_compiler_invocations(), runtime_before);
}
