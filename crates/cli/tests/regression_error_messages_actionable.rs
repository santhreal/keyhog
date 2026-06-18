use std::process::Command;

fn keyhog(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_keyhog"))
        .args(args)
        .output()
        .expect("spawn keyhog")
}

fn combined(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn dynamic_source_constructor_error_includes_fix() {
    let output = keyhog(&[
        "scan",
        "--no-daemon",
        "--backend",
        "simd",
        "--source",
        "gitlab-group",
    ]);
    assert!(
        !output.status.success(),
        "source construction without required params must fail"
    );
    let text = combined(&output);
    assert!(
        text.contains("failed to construct source 'gitlab-group'"),
        "source failure must name the source; output={text}"
    );
    assert!(
        text.contains("Fix: check the `--source gitlab-group:...` parameter format"),
        "source failure must include the exact fix; output={text}"
    );
}

#[test]
fn unknown_dynamic_source_error_includes_fix() {
    let output = keyhog(&[
        "scan",
        "--no-daemon",
        "--backend",
        "simd",
        "--source",
        "not-a-real-source",
    ]);
    assert!(!output.status.success(), "unknown dynamic source must fail");
    let text = combined(&output);
    assert!(
        text.contains("custom source 'not-a-real-source' not found"),
        "unknown source failure must name the source; output={text}"
    );
    assert!(
        text.contains("Fix: use a compiled-in source name"),
        "unknown source failure must include the fix; output={text}"
    );
}

#[test]
fn rare_setup_errors_are_actionable_in_source() {
    let watch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/watch.rs"
    ))
    .expect("watch source readable");
    let scan_system = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    ))
    .expect("scan-system source readable");
    let orchestrator_config = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator_config.rs"
    ))
    .expect("orchestrator_config source readable");

    assert!(
        !watch.contains("scanner compile failed: {e:?}")
            && !scan_system.contains("scanner compile failed: {e:?}"),
        "watch/scan-system must not expose bare scanner compile debug errors"
    );
    assert!(
        orchestrator_config.contains("keyhog detectors --audit --detectors"),
        "detector compile failures must point at the detector audit command"
    );
    assert!(
        watch.contains("fs.inotify.max_user_instances=1024")
            && watch.contains("fs.inotify.max_user_watches=524288")
            && watch.contains("keyhog scan {root}"),
        "watcher setup errors must include inotify fixes and one-shot scan fallback"
    );
}
