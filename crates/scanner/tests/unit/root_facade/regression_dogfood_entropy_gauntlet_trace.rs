//! Regression: entropy fallback value-shape drops must name the adjudicator
//! stage in dogfood telemetry. A candidate that reaches the entropy gauntlet
//! and dies there is different from a candidate that never generated.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::sync::Arc;

fn scanner() -> CompiledScanner {
    let mut cfg = ScannerConfig::default();
    cfg.ml_enabled = false;
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detector corpus must load")
        .into_iter()
        .filter(keyhog_core::DetectorSpec::owns_entropy_policy)
        .collect();
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(cfg)
}

fn entropy_shape_reasons_for(
    scanner: &CompiledScanner,
    body: &str,
    path: &str,
    redact_prefix: &str,
    trace: &Arc<ScanTelemetry>,
) -> Vec<String> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    let _ = telemetry::with_scan_telemetry(trace, || {
        scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
    });
    trace
        .drain()
        .dogfood_events
        .into_iter()
        .filter_map(|event| match event {
            DogfoodEvent::ShapeSuppressed {
                reason,
                credential_redacted,
                ..
            } if credential_redacted.starts_with(redact_prefix) => Some(reason.into_owned()),
            _ => None,
        })
        .collect()
}

#[test]
fn entropy_gauntlet_i18n_path_drop_is_traced() {
    let _g = super::super::telemetry_serial::lock();
    let s = scanner();
    telemetry::testing::reset();

    let blob =
        "5OcKQwtmHw+SRJZ76bc4vwBhnVsM1ksLmOGTaHamLo6+MIF3IlZcNaWD3vhW7+3ID7UwSS6whDRWERI6756fzh06";
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let reasons = entropy_shape_reasons_for(
        &s,
        &format!("password hint\n{blob}\n"),
        "/repo/locale/messages.properties",
        "5OcK",
        &trace,
    );
    assert!(
        reasons.iter().any(|r| r == "entropy_i18n_file"),
        "entropy fallback i18n path drop must emit its adjudicator stage; got {reasons:?}"
    );

    telemetry::testing::reset();
    let trace = Arc::new(ScanTelemetry::new());
    let off = entropy_shape_reasons_for(
        &s,
        &format!("password hint\n{blob}\n"),
        "/repo/locale/messages.properties",
        "5OcK",
        &trace,
    );
    assert!(
        off.is_empty(),
        "with dogfood OFF the entropy-gauntlet recorder must emit nothing, got {off:?}"
    );
}
