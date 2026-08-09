//! Contracts for the scanner profiler extraction: collectors that migrated onto
//! the keyhog-profile public API must emit their measurements through the
//! profile runtime (and ONLY there), stay silent when no runtime is active, and
//! keep the documented `--perf-trace` decode-recursion line intact.
//!
//! Isolation notes: the span tests use `keyhog_profile::Runtime::new()` scopes
//! rather than `Session::start` because a session is a process-global singleton
//! and libtest runs these tests on parallel threads; a scoped runtime records
//! through the identical session machinery (worker shards, drained via the
//! public `take_stage_measurements`) without cross-test pollution. The one test
//! that flips the process-global detailed-profile switch holds the telemetry
//! serial lock, the established convention for process-global scanner state.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn chunk_of(text: &str, label: &str) -> Chunk {
    Chunk {
        data: text.to_owned().into(),
        metadata: ChunkMetadata {
            source_type: "profile-extraction".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// One literal-anchored detector, enough to drive prepare + phase 1 per chunk.
fn minimal_scanner() -> CompiledScanner {
    let detector = DetectorSpec {
        tests: Vec::new(),
        id: "profile-extraction-token".into(),
        name: "Profile Extraction Token".into(),
        service: "s".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "tok".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["tok".into()],
        min_confidence: None,
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    CompiledScanner::compile(vec![detector]).expect("minimal scanner compiles")
}

fn stage_measurement(
    measurements: &[keyhog_profile::StageMeasurement],
    stage: keyhog_profile::Stage,
) -> (u64, u64) {
    let found = measurements
        .iter()
        .find(|measurement| measurement.stage == stage);
    (
        found.map_or(0, |measurement| measurement.elapsed_ns),
        found.map_or(0, |measurement| measurement.calls),
    )
}

/// The deleted scan-inner atomic profiler (SCAN_PREPARE_NS / SCAN_PHASE1_NS /
/// SCAN_INNER_CALLS) duplicated exactly what the Preprocess and Phase1Triggers
/// stage spans already measure. This test locks the post-migration contract:
/// one scan of one chunk records exactly ONE Preprocess and ONE Phase1Triggers
/// call through the profile runtime, proving the timings flow through the
/// shared runtime AND that no duplicate scanner-side path double counts them.
#[test]
fn scan_inner_timings_flow_through_runtime_once_per_chunk() {
    let scanner = minimal_scanner();
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        for index in 0..3 {
            let chunk = chunk_of("tok=abc", &format!("chunk-{index}"));
            let _ = scanner
                .scan_with_backend(&chunk, ScanBackend::CpuFallback)
                .expect("selected backend scan succeeds");
        }
        let measurements = keyhog_profile::take_stage_measurements();
        let (preprocess_ns, preprocess_calls) =
            stage_measurement(&measurements, keyhog_profile::Stage::Preprocess);
        let (phase1_ns, phase1_calls) =
            stage_measurement(&measurements, keyhog_profile::Stage::Phase1Triggers);
        assert_eq!(
            preprocess_calls, 3,
            "exactly one Preprocess span per scanned chunk, no duplicate counter"
        );
        assert_eq!(
            phase1_calls, 3,
            "exactly one Phase1Triggers span per scanned chunk, no duplicate counter"
        );
        assert!(
            preprocess_ns > 0,
            "prepare_chunk wall time must be recorded"
        );
        assert!(phase1_ns > 0, "phase-1 wall time must be recorded");
    });
}

/// A scan with no active profile runtime (and the detailed switch off) must
/// record nothing: the disabled span path is one relaxed atomic load and every
/// stage drain comes back empty. Locks out a regression where a collector
/// writes to scanner-side or global state unconditionally.
#[test]
fn scan_is_silent_when_profiling_disabled() {
    let scanner = minimal_scanner();
    let chunk = chunk_of("tok=abc", "silent");
    let _ = scanner
        .scan_with_backend(&chunk, ScanBackend::CpuFallback)
        .expect("selected backend scan succeeds");
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        let measurements = keyhog_profile::take_stage_measurements();
        assert!(
            measurements.is_empty(),
            "a scan with profiling disabled must not emit stage measurements, got {measurements:?}"
        );
    });
}

/// Decode-through generation time is the profile runtime's `Decode` stage span
/// and sub-chunk rescan time is its decode-attributed share of leaf spans; the
/// duplicate DECODE_GEN_NS / DECODE_SCAN_NS atomics are gone. Scanning a chunk
/// whose only credential is base64-encoded proves the whole chain: the finding
/// can only come from a decoded sub-chunk rescan, `Decode` must record exactly
/// one generation call for the parent chunk, and the rescan must attribute
/// leaf time to decoded work.
#[cfg(feature = "decode")]
#[test]
fn decode_generation_and_rescan_flow_through_runtime() {
    use base64::Engine;
    let scanner = crate::support::compile_full_detector_scanner();
    let token = "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX";
    let encoded = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());
    let chunk = chunk_of(&format!("data = \"{encoded}\"\n"), "encoded");
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        let _ = scanner.scan(&chunk).expect("scan succeeds");
        let measurements = keyhog_profile::take_stage_measurements();
        let (decode_ns, decode_calls) =
            stage_measurement(&measurements, keyhog_profile::Stage::Decode);
        assert_eq!(
            decode_calls, 1,
            "exactly one decode-generation span per parent chunk"
        );
        assert!(
            decode_ns > 0,
            "decode generation wall time must be recorded"
        );
        let attributed_ns: u64 = measurements
            .iter()
            .map(|measurement| measurement.attributed_ns)
            .sum();
        assert!(
            attributed_ns > 0,
            "rescanning the decoded sub-chunk must attribute leaf time to decoded work"
        );
    });
}

/// The `--perf-trace` decode-recursion line keeps its exact shape after the
/// migration; only the gen/scan wall times changed owner (profile runtime
/// stage measurements instead of scanner-side atomics). Pure-format test, no
/// I/O, so the documented line is pinned byte for byte.
#[cfg(feature = "decode")]
#[test]
fn decode_recursion_line_format_is_preserved() {
    let line = crate::engine::scan_postprocess::format_decode_recursion(2, 5, 1024, 3.0, 1.0);
    assert_eq!(
        line,
        "decode-recursion: parents=2 subchunks=5 (2.5 sub/parent) bytes=1024 \
         gen=3.0ms scan=1.0ms (1.02 MB/s rescan)"
    );
    let empty = crate::engine::scan_postprocess::format_decode_recursion(0, 0, 0, 0.0, 0.0);
    assert_eq!(
        empty,
        "decode-recursion: parents=0 subchunks=0 (0.0 sub/parent) bytes=0 \
         gen=0.0ms scan=0.0ms (0.00 MB/s rescan)",
        "zero guards must render 0.0 ratios, never NaN"
    );
}

/// End-to-end `--perf-trace` path: the detailed switch (the legacy profiling
/// switch the CLI uses for `--perf-trace`) must record decode-recursion counts
/// exactly once per decode-through parent while the stage measurements drain
/// through the profile runtime. `parents == 1` for one decodable parent chunk
/// is the no-double-counting lock between the surviving count path and the
/// migrated span paths. Holds the telemetry serial lock because the detailed
/// switch and the count accumulators are process-global.
#[cfg(feature = "decode")]
#[test]
fn perf_trace_decode_recursion_counts_are_exact() {
    use base64::Engine;
    let _guard = super::telemetry_serial::lock();
    let scanner = crate::support::compile_full_detector_scanner();
    let token = "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX";
    let encoded = base64::engine::general_purpose::STANDARD.encode(token.as_bytes());
    let chunk = chunk_of(&format!("data = \"{encoded}\"\n"), "encoded");

    keyhog_scanner::set_profile_detail(keyhog_scanner::Detail::Diagnostic);
    keyhog_scanner::profile_reset();
    let _ = scanner.scan(&chunk).expect("scan succeeds");
    let mut gen_ns = 0;
    let mut rescan_ns = 0;
    for measurement in keyhog_profile::take_stage_measurements() {
        if measurement.stage == keyhog_profile::Stage::Decode {
            gen_ns = measurement.elapsed_ns;
        }
        rescan_ns += measurement.attributed_ns;
    }
    let typed = keyhog_profile::take_typed_metrics();
    let (parents, subchunks, bytes) =
        crate::engine::scan_postprocess::decode_recursion_from_typed(&typed);
    let gen_ms = gen_ns as f64 / 1e6;
    let scan_ms = rescan_ns as f64 / 1e6;
    keyhog_scanner::set_profile_detail(keyhog_scanner::Detail::Off);
    keyhog_scanner::profile_reset();

    assert_eq!(
        parents, 1,
        "one decodable parent chunk must record exactly one decode-through parent"
    );
    assert!(
        subchunks >= 1,
        "the decoded payload must produce at least one sub-chunk"
    );
    assert!(
        bytes >= token.len() as u64,
        "decoded sub-chunk bytes must cover the {}-byte payload, got {bytes}",
        token.len()
    );
    assert!(gen_ms > 0.0, "generation time comes from the Decode stage");
    assert!(scan_ms > 0.0, "rescan time comes from decode attribution");
}
