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
        "--daemon=off",
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
        "--daemon=off",
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
