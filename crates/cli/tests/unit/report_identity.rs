use super::{resolved_scan_manifest, scan_report_id, ScanReportMetadata};
use crate::args::ScanArgs;
use clap::Parser;
use keyhog_core::{ResolvedScanManifest, ScanCompletionStatus};
use std::collections::BTreeMap;

fn metadata() -> ScanReportMetadata {
    ScanReportMetadata {
        scan_id: String::new(),
        scan_status: ScanCompletionStatus::Success,
        backend_recoveries: Vec::new(),
        static_recovery: None,
        keyhog_version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: "test-git".to_string(),
        detector_digest: "test-detectors".to_string(),
        config_digest: Some("0000000000000001".to_string()),
        resolved_scan: None,
        generated_at: "2026-07-14T00:00:01".to_string(),
        scan_started_at: "2026-07-14T00:00:00".to_string(),
        scan_finished_at: "2026-07-14T00:00:01".to_string(),
        duration_ms: 1_000,
        targets: vec!["path:repo".to_string()],
        source_chunks_scanned: 2,
        source_bytes_scanned: 128,
        detector_count: 922,
    }
}

/// Regression: report identifiers must be deterministic while remaining bound to scan identity inputs.
#[test]
fn scan_report_id_is_stable_and_identity_bound() {
    let base = metadata();
    assert_eq!(scan_report_id(&base), scan_report_id(&base));
    assert_eq!(scan_report_id(&base).len(), 32);
    assert!(scan_report_id(&base)
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));

    let mut changed_config = base.clone();
    changed_config.config_digest = Some("0000000000000002".to_string());
    assert_ne!(scan_report_id(&base), scan_report_id(&changed_config));

    let mut changed_target = base;
    changed_target.targets = vec!["path:other-repo".to_string()];
    assert_ne!(
        scan_report_id(&changed_target),
        scan_report_id(&changed_config)
    );

    let mut changed_mode = changed_config.clone();
    changed_mode.resolved_scan = Some(ResolvedScanManifest {
        schema_version: 1,
        preset: "deep".to_string(),
        effective: BTreeMap::new(),
        overrides: Vec::new(),
    });
    assert_ne!(
        scan_report_id(&changed_mode),
        scan_report_id(&changed_config)
    );
}

/// Regression: resolved scan manifests must expose preset and override differences as stable operator-visible data.
#[test]
fn resolved_scan_manifest_is_diffable_across_presets_and_overrides() -> Result<(), serde_json::Error>
{
    let default_args = ScanArgs::parse_from(["keyhog"]);
    let deep_args = ScanArgs::parse_from(["keyhog", "--deep", "--decode-depth", "3"]);
    let default_manifest =
        resolved_scan_manifest(&default_args, &keyhog_scanner::ScannerConfig::default());
    let deep_manifest = resolved_scan_manifest(
        &deep_args,
        &crate::orchestrator_config::build_scanner_config(&deep_args),
    );

    assert_eq!(default_manifest.schema_version, 1);
    assert_eq!(default_manifest.preset, "default");
    assert_eq!(deep_manifest.preset, "deep");
    assert_ne!(default_manifest, deep_manifest);
    assert_eq!(deep_manifest.effective["max_decode_depth"], "3");
    assert!(deep_manifest
        .overrides
        .iter()
        .any(|key| key == "max_decode_depth"));

    let encoded = serde_json::to_string(&deep_manifest)?;
    assert!(encoded.contains("\"preset\":\"deep\""));
    assert!(encoded.contains("\"max_decode_depth\":\"3\""));
    Ok(())
}
