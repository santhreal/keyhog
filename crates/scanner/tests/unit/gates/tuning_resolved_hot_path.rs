//! Gate scanner tuning hot paths: resolve atomics once, consume plain fields.

#[test]
fn phase2_prefilter_consumes_resolved_tuning_snapshot() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let prefilter = std::fs::read_to_string(root.join("src/engine/phase2_prefilter.rs"))
        .expect("phase2_prefilter source readable");
    let compiled = std::fs::read_to_string(root.join("src/engine/phase2_compiled.rs"))
        .expect("phase2_compiled source readable");

    assert!(
        prefilter.contains("use crate::scanner_config::ResolvedScannerTuningConfig;")
            && prefilter.contains("tuning: &ResolvedScannerTuningConfig"),
        "phase2 prefilter should consume a plain resolved tuning snapshot"
    );
    assert!(
        compiled.contains("let tuning = self.tuning.resolve();")
            && compiled.contains("prefilter.any_active_match(data, &tuning)")
            && compiled
                .contains("prefilter.mark_matches(match_text, scratch, localize_plain, &tuning)"),
        "phase2 scan path should resolve tuning before prefilter admission/marking"
    );
    assert!(
        !prefilter.contains("phase2_hs_enabled()")
            && !prefilter.contains("hs_prefilter_max_len()")
            && !prefilter.contains("no_candidate_gate_enabled()")
            && !prefilter.contains("prefilter_truncate_enabled()")
            && !prefilter.contains("homoglyph_ascii_skip_enabled()"),
        "phase2 prefilter must not reload atomic tuning/defaults inside the hot body"
    );
}

#[test]
fn gpu_moe_timeout_uses_resolved_tuning_config() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ml = std::fs::read_to_string(root.join("src/engine/scan_postprocess/ml.rs"))
        .expect("ML postprocess source readable");
    let tuning =
        std::fs::read_to_string(root.join("src/tuning.rs")).expect("tuning source readable");
    let scanner_config = std::fs::read_to_string(root.join("src/scanner_config.rs"))
        .expect("scanner_config source readable");

    assert!(
        tuning.contains("pub(crate) fn resolve(&self) -> ResolvedScannerTuningConfig")
            && scanner_config.contains("impl ResolvedScannerTuningConfig")
            && scanner_config.contains("gpu_moe_timeout(&self) -> Duration"),
        "resolved tuning config should own the plain GPU MoE timeout conversion"
    );
    assert!(
        ml.contains("let tuning = self.tuning.resolve();")
            && ml.contains("tuning.gpu_moe_timeout()")
            && !ml.contains("self.tuning.gpu_moe_timeout()"),
        "ML postprocess should use a resolved tuning snapshot for GPU MoE timeout"
    );
}
