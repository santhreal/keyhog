//! Black-box contract for source-emitted composite-Action report receipts.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

fn scan(dir: &TempDir, format: &str, input: &Path) -> (PathBuf, PathBuf, Output) {
    let report = dir.path().join(format!("report.{format}"));
    let receipt = dir.path().join(format!("receipt.{format}"));
    let output = Command::new(binary())
        .args(["scan", "--backend", "cpu", "--no-verify", "--format", format, "--output"])
        .arg(&report)
        .arg("--action-receipt")
        .arg(&receipt)
        .arg("--path")
        .arg(input)
        .output()
        .expect("run receipt-producing scan");
    (report, receipt, output)
}

fn verify(report: &Path, receipt: &Path, format: &str, exit: i32) -> Output {
    Command::new(binary())
        .args(["action-report", "verify", "--receipt"])
        .arg(receipt)
        .arg("--report")
        .arg(report)
        .args(["--format", format, "--exit-code", &exit.to_string()])
        .output()
        .expect("verify Action receipt")
}

/// Every supported Action format emits one strict receipt after its report is
/// fully flushed; verification returns only the exact source finding count.
#[test]
fn source_receipt_binds_all_action_formats_and_exact_counts() {
    for format in ["sarif", "json", "jsonl", "text"] {
        let dir = TempDir::new().expect("format tempdir");
        let input = dir.path().join("clean.txt");
        fs::write(&input, "ordinary fixture content\n").expect("clean input");
        let (report, receipt, scan) = scan(&dir, format, &input);
        assert_eq!(scan.status.code(), Some(0), "{format} scan: {}", String::from_utf8_lossy(&scan.stderr));
        let verified = verify(&report, &receipt, format, 0);
        assert_eq!(verified.status.code(), Some(0), "{format} verify: {}", String::from_utf8_lossy(&verified.stderr));
        assert_eq!(verified.stdout, b"0\n");
        assert!(verified.stderr.is_empty());
        let body = fs::read_to_string(receipt).expect("read receipt");
        assert!(body.starts_with(&format!("schema=keyhog-action-report-v1\nformat={format}\nfindings=0\n")));
    }

    let dir = TempDir::new().expect("finding tempdir");
    let input = dir.path().join("secret.env");
    fs::write(&input, "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n").expect("finding input");
    let (report, receipt, scan) = scan(&dir, "json", &input);
    assert_eq!(scan.status.code(), Some(1), "finding scan: {}", String::from_utf8_lossy(&scan.stderr));
    let verified = verify(&report, &receipt, "json", 1);
    assert_eq!(verified.status.code(), Some(0), "finding verify: {}", String::from_utf8_lossy(&verified.stderr));
    assert_eq!(verified.stdout, b"1\n");
}

/// Report or receipt tampering, uppercase/noncanonical digests, and any
/// count/status/exit/format contradiction fail without publishing a count.
#[test]
fn receipt_verifier_rejects_tampering_and_semantic_contradictions() {
    let dir = TempDir::new().expect("tamper tempdir");
    let input = dir.path().join("clean.txt");
    fs::write(&input, "ordinary\n").expect("input");
    let (report, receipt, scan) = scan(&dir, "json", &input);
    assert_eq!(scan.status.code(), Some(0));
    let original_report = fs::read(&report).expect("report bytes");
    let original_receipt = fs::read_to_string(&receipt).expect("receipt text");

    fs::write(&report, b"[] \n").expect("tamper report");
    let rejected = verify(&report, &receipt, "json", 0);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    fs::write(&report, original_report).expect("restore report");

    for (name, body, requested_format, requested_exit) in [
        ("uppercase", original_receipt.replace("report-sha256=", "report-sha256=ABCDEF"), "json", 0),
        ("count", original_receipt.replace("findings=0", "findings=1"), "json", 0),
        ("status", original_receipt.replace("scan-status=success", "scan-status=partial"), "json", 0),
        ("exit", original_receipt.replace("exit-code=0", "exit-code=1"), "json", 0),
        ("format", original_receipt.replace("format=json", "format=sarif"), "json", 0),
    ] {
        let candidate = dir.path().join(format!("{name}.receipt"));
        fs::write(&candidate, body).expect("write tampered receipt");
        let rejected = verify(&report, &candidate, requested_format, requested_exit);
        assert_eq!(rejected.status.code(), Some(2), "{name}: {}", String::from_utf8_lossy(&rejected.stderr));
        assert!(rejected.stdout.is_empty(), "{name} must not publish a count");
    }
}

/// Receipt creation is create-new: stale regular files, symlinks, FIFOs, and
/// report/receipt aliases are rejected before scanning and never overwritten.
#[cfg(unix)]
#[test]
fn receipt_destination_rejects_precreated_and_alias_paths() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().expect("destination tempdir");
    let input = dir.path().join("clean.txt");
    fs::write(&input, "ordinary\n").expect("input");

    for kind in ["regular", "symlink", "fifo"] {
        let report = dir.path().join(format!("{kind}.json"));
        let receipt = dir.path().join(format!("{kind}.receipt"));
        match kind {
            "regular" => fs::write(&receipt, "sentinel").expect("regular receipt"),
            "symlink" => symlink(&input, &receipt).expect("symlink receipt"),
            "fifo" => {
                let status = Command::new("mkfifo").arg(&receipt).status().expect("mkfifo");
                assert!(status.success());
            }
            _ => unreachable!(),
        }
        let output = Command::new(binary())
            .args(["scan", "--backend", "cpu", "--no-verify", "--format", "json", "--output"])
            .arg(&report)
            .arg("--action-receipt")
            .arg(&receipt)
            .arg("--path")
            .arg(&input)
            .output()
            .expect("reject stale destination");
        assert_eq!(output.status.code(), Some(2), "{kind}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(!report.exists(), "{kind} must fail before report creation");
    }

    let alias = dir.path().join("same.json");
    let output = Command::new(binary())
        .args(["scan", "--backend", "cpu", "--no-verify", "--format", "json", "--output"])
        .arg(&alias)
        .arg("--action-receipt")
        .arg(&alias)
        .arg("--path")
        .arg(&input)
        .output()
        .expect("reject identical paths");
    assert_eq!(output.status.code(), Some(2));
    assert!(!alias.exists());
}

/// A real incomplete scan emits a verifiable partial receipt (exit 13), while a
/// setup failure emits no receipt at all; unsupported exits cannot orphan state.
#[test]
fn receipt_policy_covers_partial_and_excludes_failed_scans() {
    let dir = TempDir::new().expect("partial tempdir");
    let malformed = dir.path().join("broken.har");
    fs::write(&malformed, r#"{"log":{"entries":[{"request":{"url":"https://example.test"}"#).expect("malformed HAR");
    let (report, receipt, output) = scan(&dir, "json", &malformed);
    assert_eq!(output.status.code(), Some(13), "partial scan: {}", String::from_utf8_lossy(&output.stderr));
    let verified = verify(&report, &receipt, "json", 13);
    assert_eq!(verified.status.code(), Some(0), "partial receipt: {}", String::from_utf8_lossy(&verified.stderr));
    assert_eq!(verified.stdout, b"0\n");
    assert!(fs::read_to_string(&receipt).expect("partial receipt").contains("scan-status=partial\nexit-code=13\n"));

    let failed_receipt = dir.path().join("failed.receipt");
    let failed_report = dir.path().join("failed.json");
    let failed = Command::new(binary())
        .args(["scan", "--backend", "cpu", "--no-verify", "--format", "json", "--output"])
        .arg(&failed_report)
        .arg("--action-receipt")
        .arg(&failed_receipt)
        .arg("--path")
        .arg(dir.path().join("missing"))
        .output()
        .expect("failed scan");
    assert!(!failed.status.success());
    assert!(!failed_receipt.exists(), "failed scan must not publish an Action receipt");
}
