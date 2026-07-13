//! E2E: Ghidra deep-analysis degradation includes actionable stderr.

#[cfg(feature = "binary")]
use crate::e2e::support::binary;

#[cfg(all(feature = "binary", feature = "git"))]
#[test]
fn binary_and_staged_modes_fail_instead_of_mixing_input_boundaries() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    assert!(std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .expect("git init")
        .success());
    std::fs::write(dir.path().join("staged.txt"), "staged content\n").expect("write fixture");
    assert!(std::process::Command::new("git")
        .args(["add", "staged.txt"])
        .current_dir(dir.path())
        .status()
        .expect("git add")
        .success());

    let output = std::process::Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--binary",
            "--git-staged",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn conflicting scan");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--binary cannot be combined with --git-staged")
            && stderr.contains("separate"),
        "input-boundary error must be actionable; stderr={stderr}"
    );
}

#[cfg(feature = "binary")]
#[test]
fn scan_binary_ghidra_failure_includes_stderr_excerpt() {
    let Some(fixture) = failing_ghidra_fixture() else {
        return;
    };

    let output = std::process::Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json",
            "--show-secrets",
            "--config",
        ])
        .arg(&fixture.config_path)
        .arg("--binary")
        .arg(&fixture.target)
        .output()
        .expect("spawn keyhog scan");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "binary strings fallback should still surface the planted AWS key; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("Ghidra decompiler analysis failed")
            && stderr.contains("ghidra stderr: GHIDRA_FAKE_REASON bad-project")
            && stderr.contains("falling back to shallow strings-only extraction")
            && stderr.contains("only SHALLOWLY scanned"),
        "Ghidra failure must include subprocess stderr and roll-up coverage warning; stderr={stderr}"
    );
    assert!(
        stdout.contains("aws-access-key")
            && stdout.contains("AKIAQYLPMN5HFIQR7XYA")
            && stdout.contains("binary:strings"),
        "scan should still report the strings-mode finding; stdout={stdout}; stderr={stderr}"
    );
}

#[cfg(feature = "binary")]
#[test]
fn scan_binary_ghidra_degradation_is_visible_in_sarif_notifications() {
    let Some(fixture) = failing_ghidra_fixture() else {
        return;
    };

    let output = std::process::Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "sarif",
            "--config",
        ])
        .arg(&fixture.config_path)
        .arg("--binary")
        .arg(&fixture.target)
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "binary strings fallback should still surface the planted AWS key; stderr={stderr}"
    );
    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("SARIF stdout must be JSON");
    let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("Ghidra degradation must create SARIF coverage notifications");
    assert!(
        notifications.iter().any(|notification| {
            notification["descriptor"]["id"].as_str() == Some("keyhog/coverage-gap")
                && notification["properties"]["reason"].as_str()
                    == Some(
                        "binary deep analysis degraded to strings-only (Ghidra failed or output too large)",
                    )
                && notification["properties"]["count"].as_u64() == Some(1)
        }),
        "SARIF notifications must include the binary deep-analysis degradation; sarif={sarif}; stderr={stderr}"
    );
}

#[cfg(feature = "binary")]
struct FailingGhidraFixture {
    _dir: tempfile::TempDir,
    config_path: std::path::PathBuf,
    target: std::path::PathBuf,
}

#[cfg(feature = "binary")]
fn failing_ghidra_fixture() -> Option<FailingGhidraFixture> {
    if default_system_analyze_headless_exists() {
        eprintln!(
            "SKIP (loud): a default trusted system analyzeHeadless exists ahead of \
             configured test dirs; keeping the system-first safe-bin contract"
        );
        return None;
    }

    let dir = tempfile::TempDir::new().expect("tempdir");
    let bin_dir = dir.path().join("trusted-bin");
    std::fs::create_dir_all(&bin_dir).expect("create trusted-bin");
    write_fake_ghidra(&bin_dir);

    let config_path = dir.path().join(".keyhog.toml");
    let trusted_dir = bin_dir.to_string_lossy().replace('\\', "\\\\");
    std::fs::write(
        &config_path,
        format!("[system]\ntrusted_bin_dirs = [\"{trusted_dir}\"]\n"),
    )
    .expect("write config");

    let target = dir.path().join("fixture.bin");
    std::fs::write(
        &target,
        concat!("\0\0AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\0\0"),
    )
    .expect("write binary fixture");

    Some(FailingGhidraFixture {
        _dir: dir,
        config_path,
        target,
    })
}

#[cfg(all(feature = "binary", unix))]
fn default_system_analyze_headless_exists() -> bool {
    [
        "/usr/bin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/sbin",
        "/bin",
        "/sbin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
    ]
    .iter()
    .any(|dir| std::path::Path::new(dir).join("analyzeHeadless").is_file())
}

#[cfg(all(feature = "binary", windows))]
fn default_system_analyze_headless_exists() -> bool {
    [
        r"C:\Windows\System32",
        r"C:\Windows",
        r"C:\Windows\System32\WindowsPowerShell\v1.0",
        r"C:\Program Files\Git\cmd",
        r"C:\Program Files\Git\bin",
    ]
    .iter()
    .any(|dir| {
        [".exe", ".com", ".bat", ".cmd"].iter().any(|suffix| {
            std::path::Path::new(dir)
                .join(format!("analyzeHeadless{suffix}"))
                .is_file()
        })
    })
}

#[cfg(all(feature = "binary", unix))]
fn write_fake_ghidra(bin_dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let path = bin_dir.join("analyzeHeadless");
    std::fs::write(
        &path,
        "#!/bin/sh\necho 'GHIDRA_FAKE_REASON bad-project' >&2\nexit 7\n",
    )
    .expect("write fake Ghidra");
    let mut permissions = std::fs::metadata(&path)
        .expect("fake Ghidra metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod fake Ghidra");
}

#[cfg(all(feature = "binary", windows))]
fn write_fake_ghidra(bin_dir: &std::path::Path) {
    let path = bin_dir.join("analyzeHeadless.bat");
    std::fs::write(
        &path,
        "@echo off\r\necho GHIDRA_FAKE_REASON bad-project 1>&2\r\nexit /b 7\r\n",
    )
    .expect("write fake Ghidra");
}
