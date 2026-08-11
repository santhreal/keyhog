use crate::scanner_config::ScannerTuningConfig;
use crate::tuning::ScannerTuning;

/// WHY: runtime snapshots and configuration identity must resolve through one
/// owner. Equality on the complete resolved struct makes every added tuning
/// field fail this test until runtime ownership is explicit.
#[test]
fn runtime_snapshot_equals_canonical_effective_configuration() {
    let runtime = ScannerTuning::from_defaults();
    assert_eq!(
        runtime.resolve(),
        ScannerTuningConfig::default().effective()
    );

    let configured = ScannerTuningConfig {
        phase2_hs: Some(false),
        hs_prefilter_max_len: Some(8192),
        hs_shard_target: Some(777),
        phase2_anchor: Some(false),
        homoglyph_gate: Some(false),
        homoglyph_ascii_skip: Some(false),
        fallback_reverse: Some(true),
        prefilter_truncate: Some(false),
        fallback_prefix_gate: Some(true),
        decode_focus: Some(false),
        confirmed_suffix_gate: Some(false),
        confirmed_companion_gate: Some(false),
        no_candidate_gate: Some(false),
        fallback_localizer: Some(false),
        gpu_recall_floor: Some(true),
        chunk_lane_threshold: Some(2048),
    };
    runtime.apply_config(&configured).expect("valid tuning");
    assert_eq!(runtime.resolve(), configured.effective());
}
