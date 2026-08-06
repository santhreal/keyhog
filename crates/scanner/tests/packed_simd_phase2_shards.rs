#![cfg(feature = "simd")]

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::execution_pack::{
    compose_policy_execution_pack, BackendPlan, CanonicalDetectorExecutionIr,
    CompiledRouteMatcherSections, ExecutionPack, ExecutionPackBackend, ExecutionPackIdentity,
    ExecutionPackPolicy, HyperscanSimdExecutionProgram, PolicyPlanSections,
};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerTuningConfig};
use std::sync::{Mutex, MutexGuard};

static SIMD_TEST_LOCK: Mutex<()> = Mutex::new(());

fn serialized_tests() -> MutexGuard<'static, ()> {
    SIMD_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn detector(id: &str, regex: String) -> DetectorSpec {
    DetectorSpec {
        id: id.to_owned(),
        name: format!("{id} packed phase-two fixture"),
        service: "packed-phase-two-fixture".to_owned(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex,
            ..Default::default()
        }],
        keywords: Vec::new(),
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn detectors() -> Vec<DetectorSpec> {
    vec![
        detector(
            "packed-phase2-positive",
            r"[A-Z]{0,2}P2_NATIVE_[A-Z0-9]{8}".to_owned(),
        ),
        detector(
            "packed-phase2-host",
            r"^[A-Z]{0,2}P2_HOST_[A-Z0-9]{8}$".to_owned(),
        ),
        detector(
            "packed-phase2-unsupported",
            format!(
                "[A-Z]{{0,2}}{}P2_RECOVERY_[A-Z0-9]{{8}}",
                "(?:)".repeat(130)
            ),
        ),
    ]
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.to_owned().into(),
        metadata: ChunkMetadata {
            path: Some("packed-phase2.txt".into()),
            ..Default::default()
        },
    }
}

fn mapped_pack(
    detectors: &[DetectorSpec],
    mutate: impl FnOnce(&mut HyperscanSimdExecutionProgram),
) -> (tempfile::TempDir, ExecutionPack) {
    let ir = CanonicalDetectorExecutionIr::compile(detectors).expect("compile detector IR");
    let matchers = CompiledRouteMatcherSections::compile(&ir, ExecutionPackBackend::Simd)
        .expect("compile SIMD matcher sections");
    let mut program =
        HyperscanSimdExecutionProgram::compile(&ir).expect("compile native SIMD program");
    mutate(&mut program);
    let program_bytes = program.canonical_bytes().expect("encode SIMD program");
    let identity = ExecutionPackIdentity::new(
        ir.digest(),
        [0x51; 32],
        [0x52; 32],
        [0x53; 32],
        [0x54; 32],
        *blake3::hash(&program_bytes).as_bytes(),
        ExecutionPackPolicy::Default,
        ExecutionPackBackend::Simd,
    );
    let compiled = compose_policy_execution_pack(
        identity,
        PolicyPlanSections {
            detector_ir: ir.as_bytes(),
            literal_index: &matchers.literal_index,
            regex_programs: &matchers.regex_programs,
            suppression_policy: &matchers.suppression_policy,
            backend_plan: BackendPlan::Simd(&program_bytes),
        },
    )
    .expect("compose SIMD execution pack");
    let directory = tempfile::tempdir().expect("temporary pack directory");
    let path = directory.path().join("packed-phase2.khpack");
    std::fs::write(&path, compiled.as_bytes()).expect("write SIMD execution pack");
    let pack = ExecutionPack::open(&path, identity).expect("map SIMD execution pack");
    (directory, pack)
}

fn tuning(anchor: bool, localize_plain: bool) -> ScannerTuningConfig {
    ScannerTuningConfig {
        phase2_hs: Some(true),
        phase2_anchor: Some(anchor),
        homoglyph_gate: Some(localize_plain),
        ..Default::default()
    }
}

/// WHY: all three runtime ownership plans, host-only recovery, and Hyperscan-rejected recovery must come from signed native state without scan-time compilation or finding drift.
#[test]
fn packed_phase_two_all_scopes_preserve_findings_without_runtime_compilation() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let reference = CompiledScanner::compile_for_backend(detectors.clone(), ScanBackend::CpuFallback)
        .expect("compile scalar reference");
    let (_directory, pack) = mapped_pack(&detectors, |_| {});
    let after_install = HyperscanSimdExecutionProgram::compile_with_opts_invocations();

    for (anchor, localize_plain) in [(false, false), (true, false), (true, true)] {
        let packed = CompiledScanner::compile_from_execution_pack_with_tuning(
            &pack,
            &tuning(anchor, localize_plain),
        )
        .expect("hydrate packed phase-two shards");
        assert_eq!(
            HyperscanSimdExecutionProgram::compile_with_opts_invocations(),
            after_install,
            "packed scanner construction compiled a phase-two database"
        );
        for text in [
            "P2_NATIVE_ABCDEFGH",
            "XXP2_NATIVE_Z9Y8X7W6",
            "P2_HOST_1234ABCD",
            "P2_RECOVERY_A1B2C3D4",
            "P2_NATIVE_ABCDEFG",
            "unrelated text",
        ] {
            let input = chunk(text);
            let expected = reference
                .scan_with_backend(&input, ScanBackend::CpuFallback)
                .expect("scan scalar reference");
            let actual = packed
                .scan_with_backend(&input, ScanBackend::SimdCpu)
                .expect("scan packed SIMD route");
            assert_eq!(actual, expected, "finding drift for {text:?}");
        }
    }
    assert_eq!(
        HyperscanSimdExecutionProgram::compile_with_opts_invocations(),
        after_install,
        "a full, anchor-residual, localized-residual, or recovery scan compiled Hyperscan state"
    );
}

/// WHY: a valid native database paired with a different canonical phase-two index can mark the wrong detector, so authenticated mapping drift must fail before a scanner is exposed.
#[test]
fn packed_phase_two_rejects_native_mapping_identity_drift() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |program| {
        let full_scope = &mut program.phase2_scopes[0];
        let database = full_scope.full.as_mut().expect("full phase-two database");
        let host_only = full_scope
            .pattern_indices
            .iter()
            .copied()
            .find(|index| !database.pattern_indices.contains(index))
            .expect("host-only phase-two pattern");
        database.pattern_indices[0] = host_only;
        database.pattern_indices.sort_unstable();
    });
    let error = match CompiledScanner::compile_from_execution_pack(&pack) {
        Ok(_) => panic!("phase-two mapping drift must fail scanner construction"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("pattern mapping does not match"));
}

/// WHY: phase-two native shards are executed on scan input, so authenticated but invalid database bytes must fail closed during hydration and must never fall back to regex compilation.
#[test]
fn packed_phase_two_rejects_corrupt_native_shard_without_compilation() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |program| {
        let shard = program.phase2_scopes[0]
            .full
            .as_mut()
            .expect("full phase-two database")
            .serialized_shards
            .first_mut()
            .expect("full phase-two shard");
        std::sync::Arc::make_mut(shard)[0] ^= 0xff;
    });
    let before = HyperscanSimdExecutionProgram::compile_with_opts_invocations();
    let error = match CompiledScanner::compile_from_execution_pack(&pack) {
        Ok(_) => panic!("corrupt phase-two shard must fail scanner construction"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("incompatible or corrupt"));
    assert_eq!(
        HyperscanSimdExecutionProgram::compile_with_opts_invocations(),
        before,
        "corrupt packed phase-two shards triggered runtime compilation"
    );
}
