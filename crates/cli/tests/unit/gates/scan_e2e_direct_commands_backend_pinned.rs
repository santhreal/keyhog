#[test]
fn scan_e2e_direct_commands_backend_pinned() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = manifest_dir.join("tests/e2e");
    let mut scan_files = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read e2e dir") {
        let entry = entry.expect("read e2e entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            scan_files.push(path);
        }
    }
    for rel in [
        "tests/adversarial/huge_exclude_paths_glob_completes.rs",
        "tests/audit_arch_wiring.rs",
        "tests/audit_generalization.rs",
        "tests/audit_research_innovation.rs",
        "tests/audit_testing_dogfood.rs",
        "tests/config_hermetic.rs",
        "tests/lane5_sarif_schema_and_scale_matrix.rs",
        "tests/lane5_scan_flag_and_exit_matrix.rs",
        "tests/live_verify.rs",
        "tests/regression_scans_user_detectors_directory.rs",
        "tests/regression_self_scan_segment_suppression_visible.rs",
        "tests/sarif_github_compliance.rs",
    ] {
        scan_files.push(manifest_dir.join(rel));
    }

    let mut problems = Vec::new();
    for path in scan_files {
        let src = std::fs::read_to_string(&path).expect("read e2e source");
        let mut cursor = 0usize;
        while let Some(offset) = src[cursor..].find("Command::new(") {
            let start = cursor + offset;
            let rest = &src[start..];
            let end = [".output()", ".spawn()", ".status()"]
                .iter()
                .filter_map(|marker| rest.find(marker))
                .min()
                .map(|end| start + end)
                .unwrap_or(src.len());
            let block = &src[start..end];
            let is_scan = block.contains("\"scan\"") || block.contains(".arg(\"scan\")");
            // Explicit routing evidence the gate accepts: a pinned `--backend`, a
            // forced `--daemon=on`, an explicit `--daemon=auto`, or the
            // `--autoroute-calibrate` writer flag. The hazard this gate guards is a
            // BARE `scan` that silently rides the implicit default route with no
            // declared intent — an explicit `--daemon=auto` flag is a declared
            // intent, not that hazard, and is exactly what the daemon auto-route
            // contract tests must use to assert the in-process path reports
            // "autoroute calibration required". `--autoroute-calibrate` is the
            // strongest declared intent of all: it IS the calibration writer that
            // measures every backend to PICK the fastest, so pinning `--backend`
            // on it would be self-contradictory (you cannot calibrate a forced
            // backend) — the calibration path is exactly why auto exists.
            let pinned = block.contains("\"--backend\"")
                || block.contains("\"--daemon=on\"")
                || block.contains(".arg(\"--daemon=on\")")
                || block.contains("\"--daemon=auto\"")
                || block.contains(".arg(\"--daemon=auto\")")
                || block.contains("\"--autoroute-calibrate\"")
                || block.contains(".arg(\"--autoroute-calibrate\")");
            if is_scan && !pinned {
                problems.push(format!(
                    "{} has a direct keyhog scan subprocess without explicit backend evidence",
                    path.strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .unwrap_or(&path)
                        .display()
                ));
            }
            cursor = end.saturating_add(1);
        }
    }

    assert!(
        problems.is_empty(),
        "non-routing e2e scan tests must pin a diagnostic backend; default auto \
         is reserved for autoroute tests with persisted calibration evidence:\n{}",
        problems.join("\n")
    );
}
