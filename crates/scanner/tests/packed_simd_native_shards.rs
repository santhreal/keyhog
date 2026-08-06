#![cfg(feature = "simd")]

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::execution_pack::{
    compose_policy_execution_pack, BackendPlan, CanonicalDetectorExecutionIr,
    CompiledRouteMatcherSections, ExecutionPack, ExecutionPackBackend, ExecutionPackIdentity,
    ExecutionPackPolicy, HyperscanSimdExecutionProgram, PolicyPlanSections,
};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::{Mutex, MutexGuard};

static SIMD_TEST_LOCK: Mutex<()> = Mutex::new(());

fn serialized_tests() -> MutexGuard<'static, ()> {
    SIMD_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn detector(id: &str, regex: String, literal: &str) -> DetectorSpec {
    DetectorSpec {
        id: id.to_owned(),
        name: format!("{id} packed SIMD fixture"),
        service: "packed-simd-fixture".to_owned(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex,
            required_literals: vec![literal.to_owned()],
            ..Default::default()
        }],
        keywords: vec![literal.to_owned()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn detectors() -> Vec<DetectorSpec> {
    let recovery_regex = format!(
        "{}RECOVERY_[A-Z0-9]{{8}}",
        "(?:)".repeat(130)
    );
    assert!(recovery_regex.len() > 500);
    vec![
        detector(
            "packed-alpha",
            r"PACKED_ALPHA_[A-Z0-9]{8}".to_owned(),
            "PACKED_ALPHA_",
        ),
        detector(
            "packed-beta",
            r"PACKED_BETA_[0-9]{4}".to_owned(),
            "PACKED_BETA_",
        ),
        detector("packed-recovery", recovery_regex, "RECOVERY_"),
    ]
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.to_owned().into(),
        metadata: ChunkMetadata {
            path: Some("packed-simd.txt".into()),
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
        [0x41; 32],
        [0x42; 32],
        [0x43; 32],
        [0x44; 32],
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
    let path = directory.path().join("packed-simd.khpack");
    std::fs::write(&path, compiled.as_bytes()).expect("write SIMD execution pack");
    let pack = ExecutionPack::open(&path, identity).expect("map SIMD execution pack");
    (directory, pack)
}

/// WHY: authenticated shard bytes are still native code-generation artifacts, so corruption must fail closed at first SIMD use without compiling regex source as a fallback.
#[test]
fn packed_simd_rejects_authenticated_but_invalid_native_shard_bytes() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |program| {
        let shard = program
            .serialized_shards
            .first_mut()
            .expect("fixture has a supported native shard");
        shard[0] ^= 0xff;
    });
    let scanner = CompiledScanner::compile_from_execution_pack(&pack)
        .expect("shard deserialization is deferred until first SIMD use");
    let before = HyperscanSimdExecutionProgram::compile_with_opts_invocations();
    let error = scanner
        .scan_with_backend(
            &chunk("PACKED_ALPHA_ABCDEFGH"),
            ScanBackend::SimdCpu,
        )
        .expect_err("corrupt native shard must fail closed");
    assert!(error.to_string().contains("incompatible or corrupt"));
    assert_eq!(
        HyperscanSimdExecutionProgram::compile_with_opts_invocations(),
        before,
        "corrupt packed shards must never trigger runtime Hyperscan compilation"
    );
}

/// WHY: AC ownership is finding routing, so swapping two valid in-range mapping identities must be rejected even when the program and outer pack are freshly authenticated.
#[test]
fn packed_simd_rejects_swapped_canonical_ac_mapping_identities() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |program| {
        let right = program
            .patterns
            .iter()
            .position(|pattern| pattern.regex.contains("PACKED_BETA_"))
            .expect("beta SIMD pattern");
        let left = program
            .patterns
            .iter()
            .position(|pattern| pattern.regex.contains("PACKED_ALPHA_"))
            .expect("alpha SIMD pattern");
        let left_index = program.patterns[left].ac_map_indices[0];
        let right_index = program.patterns[right].ac_map_indices[0];
        program.patterns[left].ac_map_indices[0] = right_index;
        program.patterns[right].ac_map_indices[0] = left_index;
        program.patterns[left].ac_map_indices.sort_unstable();
        program.patterns[right].ac_map_indices.sort_unstable();
    });
    let error = match CompiledScanner::compile_from_execution_pack(&pack) {
        Ok(_) => panic!("mapping identity drift must fail scanner construction"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("identity does not match canonical AC index"));
}

/// WHY: a native mapping cannot relabel a database row as another detector because that would silently attribute the same matched bytes to the wrong finding policy.
#[test]
fn packed_simd_rejects_detector_mapping_identity_drift() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |program| {
        program.patterns[0].detector_index =
            (program.patterns[0].detector_index + 1) % detectors.len() as u32;
    });
    let error = match CompiledScanner::compile_from_execution_pack(&pack) {
        Ok(_) => panic!("detector identity drift must fail scanner construction"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("detector identity does not match"));
}

/// WHY: install-compiled shards replace only database construction, so positive, negative, byte-boundary, and unsupported-pattern recovery findings must remain exactly equal to the ordinary scanner.
#[test]
fn packed_simd_native_shards_preserve_exact_findings_and_unsupported_recovery() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let ordinary = CompiledScanner::compile_for_backend(detectors.clone(), ScanBackend::CpuFallback)
        .expect("compile ordinary scalar scanner");
    let (_directory, pack) = mapped_pack(&detectors, |_| {});
    let packed = CompiledScanner::compile_from_execution_pack(&pack)
        .expect("construct scanner from native SIMD pack");

    for (text, expected_findings) in [
        (
            "PACKED_ALPHA_ABCDEFGH",
            &[("packed-alpha", 0usize)][..],
        ),
        (
            "prefix PACKED_BETA_1234 suffix",
            &[("packed-beta", 7usize)][..],
        ),
        (
            "RECOVERY_Z9Y8X7W6",
            &[("packed-recovery", 0usize)][..],
        ),
        ("PACKED_ALPHA_ABCDEFG", &[][..]),
        (
            "packed_alpha_abcdefgh",
            &[("packed-alpha", 0usize)][..],
        ),
        (
            "xPACKED_ALPHA_ABCDEFGHy",
            &[("packed-alpha", 1usize)][..],
        ),
        (
            "PACKED_BETA_0000\nRECOVERY_1234ABCD\nPACKED_ALPHA_ZYXWVUTS",
            &[
                ("packed-alpha", 35usize),
                ("packed-beta", 0usize),
                ("packed-recovery", 17usize),
            ][..],
        ),
    ] {
        let input = chunk(text);
        let expected = ordinary
            .scan_with_backend(&input, ScanBackend::CpuFallback)
            .expect("ordinary scan");
        let observed = expected
            .iter()
            .map(|finding| (finding.detector_id.as_ref(), finding.location.offset))
            .collect::<Vec<_>>();
        assert_eq!(observed, expected_findings, "ordinary fixture truth for {text:?}");
        let actual = packed
            .scan_with_backend(&input, ScanBackend::SimdCpu)
            .expect("packed SIMD scan");
        assert_eq!(actual, expected, "exact finding drift for input {text:?}");
    }
}

/// WHY: a valid mapped SIMD pack already owns native databases, so scanner construction and repeated first-use materialization must not call the runtime compiler.
#[test]
fn packed_simd_first_use_never_invokes_compile_with_opts() {
    let _guard = serialized_tests();
    let detectors = detectors();
    let (_directory, pack) = mapped_pack(&detectors, |_| {});
    let after_install_compile = HyperscanSimdExecutionProgram::compile_with_opts_invocations();
    let scanner = CompiledScanner::compile_from_execution_pack(&pack)
        .expect("construct scanner from native SIMD pack");
    assert_eq!(
        HyperscanSimdExecutionProgram::compile_with_opts_invocations(),
        after_install_compile
    );
    for text in ["PACKED_ALPHA_ABCDEFGH", "RECOVERY_Z9Y8X7W6"] {
        scanner
            .scan_with_backend(&chunk(text), ScanBackend::SimdCpu)
            .expect("scan packed native SIMD route");
    }
    assert_eq!(
        HyperscanSimdExecutionProgram::compile_with_opts_invocations(),
        after_install_compile,
        "packed SIMD scanner invoked compile_with_opts at scan time"
    );
}
