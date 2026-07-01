//! Regression: a CPU-forced scan that fails during setup must terminate with an
//! exit CODE, never a signal.
//!
//! Root cause (2026-06-30 dogfood). `keyhog scan --backend cpu <early-error>`
//! printed the correct fail-closed diagnostic and then SIGSEGV'd (exit 139)
//! instead of `exit(2)`. `probe_hardware()` is memoised and calls `gpu_probe()`
//! on its first use; with a non-`Disabled` GPU runtime policy that creates a
//! wgpu/Vulkan instance whose mesa driver worker thread (`[vkps] Update`)
//! segfaults during teardown when the process exits fast — before the driver
//! finishes initialising — on an early setup error. An explicit `--backend cpu`
//! never uses the GPU, so the fix sets the runtime policy to `Disabled` from the
//! operator's flags BEFORE any probe (`ScanOrchestrator::new`'s first statement
//! + `gpu_runtime_policy_from_args` mapping an explicit CPU backend to
//! `Disabled`), so no Vulkan instance is created and there is no driver thread
//! to crash. This is a security-relevant contract: a wrapper that keys on
//! `$? == 2` for "policy error, do not proceed" would misread a 139 signal
//! death, and a fail-closed control that crashes is not trustworthy.
//!
//! The contract these tests pin is deliberately narrow and robust: the process
//! must exit with SOME status code (`status.code().is_some()`), i.e. it must not
//! die by signal. Where the exit code is deterministic (a documented user
//! error) they also pin `Some(2)`. They do NOT pin wall-clock or output bytes,
//! so they stay stable across hosts with and without a real GPU.

use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog scan --backend cpu --no-daemon <path>` and return the raw output.
fn scan_cpu(path: &std::path::Path) -> Output {
    Command::new(binary())
        .args(["scan", "--backend", "cpu", "--no-daemon"])
        .arg(path)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog scan")
}

fn combined(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A signal death reports `None` from `ExitStatus::code()` on Unix. This helper
/// makes the failure message name the signal so a regression is obvious.
fn assert_exited_by_code(output: &Output, context: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert!(
            output.status.code().is_some(),
            "{context}: process died by signal {:?} (a fail-closed path must \
             exit with a code, not crash); output:\n{}",
            output.status.signal(),
            combined(output)
        );
    }
    #[cfg(not(unix))]
    assert!(
        output.status.code().is_some(),
        "{context}: no exit code; output:\n{}",
        combined(output)
    );
}

/// Build a scan directory holding one real AWS key fixture so the scan has
/// something to do once setup succeeds (isolates the setup-error path).
fn dir_with_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("secret.env"),
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .expect("write fixture");
    dir
}

#[test]
fn expired_allowlist_exits_by_code_not_signal() {
    let dir = dir_with_fixture();
    std::fs::write(
        dir.path().join(".keyhogignore"),
        "detector:aws-access-key ; expires=1970-01-01 ; reason=\"old waiver\"\n",
    )
    .expect("write expired allowlist");
    let output = scan_cpu(dir.path());
    assert_exited_by_code(&output, "expired allowlist");
}

#[test]
fn expired_allowlist_is_exit_2() {
    let dir = dir_with_fixture();
    std::fs::write(
        dir.path().join(".keyhogignore"),
        "detector:aws-access-key ; expires=1970-01-01 ; reason=\"old waiver\"\n",
    )
    .expect("write expired allowlist");
    let output = scan_cpu(dir.path());
    assert_eq!(
        output.status.code(),
        Some(2),
        "expired allowlist is a user-error exit; output:\n{}",
        combined(&output)
    );
}

#[test]
fn nonexistent_path_exits_by_code_not_signal() {
    let missing = PathBuf::from("/keyhog-nonexistent-scan-target-xyz");
    let output = scan_cpu(&missing);
    assert_exited_by_code(&output, "nonexistent scan path");
}

#[test]
fn nonexistent_path_is_exit_2() {
    let missing = PathBuf::from("/keyhog-nonexistent-scan-target-xyz");
    let output = scan_cpu(&missing);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing scan path is a user error; output:\n{}",
        combined(&output)
    );
}

#[test]
fn nonexistent_path_diagnostic_is_operator_visible() {
    let missing = PathBuf::from("/keyhog-nonexistent-scan-target-xyz");
    let output = scan_cpu(&missing);
    let text = combined(&output);
    assert!(
        text.contains("does not exist"),
        "the missing-path error must explain the fix; got:\n{text}"
    );
}

#[test]
fn expired_allowlist_diagnostic_is_operator_visible() {
    let dir = dir_with_fixture();
    std::fs::write(
        dir.path().join(".keyhogignore"),
        "detector:aws-access-key ; expires=1970-01-01 ; reason=\"old waiver\"\n",
    )
    .expect("write expired allowlist");
    let output = scan_cpu(dir.path());
    let text = combined(&output);
    assert!(
        text.contains("expired allowlist policy")
            && text.contains("refusing to scan with stale suppressions"),
        "the expired-allowlist error must stay operator-visible even though the \
         scan now exits cleanly; got:\n{text}"
    );
}

#[test]
fn lockdown_required_without_flag_exits_by_code_not_signal() {
    let dir = dir_with_fixture();
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[lockdown]\nrequire = true\n",
    )
    .expect("write lockdown config");
    let output = scan_cpu(dir.path());
    assert_exited_by_code(&output, "lockdown required but --lockdown absent");
}

#[test]
fn empty_dir_scan_is_clean_success_baseline() {
    // Control: a well-formed CPU scan with no setup error must succeed cleanly
    // (exit 0), proving the Disabled-policy path did not break the happy path.
    let dir = TempDir::new().expect("tempdir");
    let output = scan_cpu(dir.path());
    assert_eq!(
        output.status.code(),
        Some(0),
        "an empty clean scan exits 0; output:\n{}",
        combined(&output)
    );
}

#[test]
fn content_scan_completes_cleanly_baseline() {
    // Control: a CPU scan over a real file completes with a clean exit code
    // (0 = no findings, 1 = findings) rather than crashing or erroring — proving
    // the GPU-probe short-circuit did not break the file-read/scan happy path.
    let dir = dir_with_fixture();
    let output = scan_cpu(dir.path());
    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "a clean content scan exits 0 or 1, not a crash or setup error; got \
         {:?}\n{}",
        output.status.code(),
        combined(&output)
    );
}

#[test]
fn repeated_error_scans_never_signal() {
    // The crash was a teardown race; run the error path several times to make a
    // flaky-signal regression fail deterministically rather than 1-in-N.
    let missing = PathBuf::from("/keyhog-nonexistent-scan-target-xyz");
    for i in 0..5 {
        let output = scan_cpu(&missing);
        assert_exited_by_code(&output, &format!("nonexistent scan path (iteration {i})"));
    }
}
