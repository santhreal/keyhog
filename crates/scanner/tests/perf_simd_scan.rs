//! Recall and parity tripwire for explicit CPU and SIMD execution plans.
//!
//! The two backends materialize different phase-one matchers. `CpuFallback`
//! uses the overlapping Aho-Corasick literal plan. `SimdCpu` uses Hyperscan plus
//! the install-time recovery matcher for patterns that Hyperscan cannot safely
//! own. A scanner compiled for one plan must never substitute the other plan.
//!
//! Several context-anchored detectors historically fired only through
//! Hyperscan. The current compiler supplies exact CPU recovery literals for
//! those detectors, so both plans must now find the same detector and credential
//! on those fixtures. This file guards both halves of that contract:
//!
//! 1. Former SIMD-only fixtures are detector-level findings on both plans.
//! 2. SIMD never drops a credential value found by the scalar plan.
//!
//! When the `simd` feature is absent there is no valid SIMD plan, so these
//! backend-differential assertions are skipped.

mod support;
use keyhog_core::{load_detectors, Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;

fn make_chunk(data: &str) -> Chunk {
    Chunk {
        data: data.to_string().into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "perf-tripwire".into(),
            path: Some("perf_simd_scan.txt".into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    }
}

fn finding_keys(ms: &[RawMatch]) -> BTreeSet<(String, String)> {
    ms.iter()
        .map(|m| (m.detector_id.to_string(), m.credential.as_str().to_string()))
        .collect()
}

/// The set of SECRET VALUES recovered, independent of which detector attributed
/// each. The recall contract between the SIMD and scalar paths is "no secret
/// value is lost", not "no (detector_id, value) pair changes" — see
/// `simd_findings_are_a_superset_of_scalar`.
fn credential_values(ms: &[RawMatch]) -> BTreeSet<String> {
    ms.iter().map(|m| m.credential.to_string()).collect()
}

/// Context-anchored fixtures that once exposed a gap between Hyperscan and the
/// CPU literal plan. Each backend must now recover the exact detector and
/// credential independently.
const HS_MINUS_AC_FIXTURES: &[(&str, &str, &str)] = &[
    (
        "datadog-api-key",
        "DD_API_KEY=7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
    ),
    (
        "twilio-auth-token",
        "TWILIO_ACCOUNT_SID=AC7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d\n\
         TWILIO_AUTH_TOKEN=4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f",
        "4c9a8f6e3b7d1a2c5e8f0b9d6a3c4e1f",
    ),
    (
        "africastalking-api-key",
        "africastalking_api_key=Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
        "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5",
    ),
];

/// Formerly SIMD-only fixtures must remain detector-level findings on both
/// independently materialized plans.
#[test]
fn formerly_simd_only_fixtures_have_backend_parity() {
    if !cfg!(feature = "simd") {
        eprintln!(
            "perf_simd_scan: `simd` feature not compiled; skipping the backend differential."
        );
        return;
    }

    let detectors = load_detectors(&detector_dir()).expect("load detectors");
    let simd_scanner =
        CompiledScanner::compile_for_backend(detectors.clone(), ScanBackend::SimdCpu)
            .expect("compile SIMD scanner");
    let cpu_scanner = CompiledScanner::compile_for_backend(detectors, ScanBackend::CpuFallback)
        .expect("compile CPU scanner");

    for &(detector_id, text, credential) in HS_MINUS_AC_FIXTURES {
        let chunk = make_chunk(text);
        let simd = simd_scanner
            .scan_with_backend(&chunk, ScanBackend::SimdCpu)
            .expect("selected SIMD scan succeeds");
        let cpu = cpu_scanner
            .scan_with_backend(&chunk, ScanBackend::CpuFallback)
            .expect("selected CPU scan succeeds");

        assert!(
            simd.iter().any(|m| {
                m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential
            }),
            "SimdCpu failed to find `{detector_id}` credential `{credential}`"
        );
        assert!(
            cpu.iter().any(|m| {
                m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential
            }),
            "CpuFallback failed to recover `{detector_id}` credential `{credential}`"
        );
    }
}

/// On every chunk, the SimdCpu finding values must be a superset of the
/// CpuFallback finding values. Each backend gets an independently materialized
/// scanner so backend substitution cannot make this test green by accident.
/// Fixtures stay in separate chunks because their credential substrings overlap.
#[test]
fn simd_findings_are_a_superset_of_scalar() {
    if !cfg!(feature = "simd") {
        eprintln!(
            "perf_simd_scan: `simd` feature not compiled. SimdCpu == CpuFallback; \
             superset assertion is vacuous, skipping."
        );
        return;
    }

    let detectors = load_detectors(&detector_dir()).expect("load detectors");
    let simd_scanner =
        CompiledScanner::compile_for_backend(detectors.clone(), ScanBackend::SimdCpu)
            .expect("compile SIMD scanner");
    let cpu_scanner = CompiledScanner::compile_for_backend(detectors, ScanBackend::CpuFallback)
        .expect("compile CPU scanner");

    // Literal-anchored control: a fixed-prefix secret (AKIA) is in the AC literal
    // set, so BOTH backends must find it. This proves the Hyperscan union did not
    // regress the scalar AC fast path while widening the candidate set.
    let control = make_chunk("const AWS_KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n");
    let control_simd = finding_keys(
        &simd_scanner
            .scan_with_backend(&control, ScanBackend::SimdCpu)
            .expect("selected backend scan succeeds"),
    );
    let control_cpu = finding_keys(
        &cpu_scanner
            .scan_with_backend(&control, ScanBackend::CpuFallback)
            .expect("selected backend scan succeeds"),
    );
    assert!(
        !control_cpu.is_empty() && control_cpu.is_subset(&control_simd),
        "literal-anchored control regressed: CpuFallback={control_cpu:?} must be non-empty \
         and a subset of SimdCpu={control_simd:?}."
    );

    // Compare credential values rather than detector labels. A more specific
    // detector may suppress a generic finding for the same value, which changes
    // attribution without losing the credential. Detector-level parity for
    // these fixtures is asserted above.
    for &(detector_id, text, _cred) in HS_MINUS_AC_FIXTURES {
        let chunk = make_chunk(text);
        let simd = credential_values(
            &simd_scanner
                .scan_with_backend(&chunk, ScanBackend::SimdCpu)
                .expect("SIMD fixture scan succeeds"),
        );
        let cpu = credential_values(
            &cpu_scanner
                .scan_with_backend(&chunk, ScanBackend::CpuFallback)
                .expect("CPU fixture scan succeeds"),
        );
        let dropped: Vec<_> = cpu.difference(&simd).collect();
        assert!(
            dropped.is_empty(),
            "on the `{detector_id}` fixture, SimdCpu lost a SECRET VALUE the scalar CpuFallback \
             path recovered: {dropped:?}. The SIMD path must never drop a credential value the \
             scalar path finds (detector re-attribution when a more-specific detector fires is \
             allowed; losing the value is not)."
        );
    }

    eprintln!(
        "perf_simd_scan: superset OK — control (AKIA) found by both backends; SimdCpu drops \
         no scalar SECRET VALUE on any HS\\AC fixture (specific-over-generic re-attribution \
         allowed). Detector-level union strictness proven by the load-bearing test."
    );
}
