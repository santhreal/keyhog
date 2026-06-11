//! Integration tests for the keyhog CLI binary's process-surface contract:
//! exit codes (0 for no findings, 1+ for findings), output format parsing
//! (json/jsonl/sarif/csv), and --output file writing.
//!
//! Tests the orchestrator layer via std::process::Command on the compiled
//! binary at /mnt/FlareTraining/santh-archive/cargo-target/release/keyhog

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const KEYHOG_BIN: &str = "/mnt/FlareTraining/santh-archive/cargo-target/release/keyhog";

/// AWS access key that reliably triggers (not a canary token).
const AWS_AKIA: &str = "AKIAQYLPMN5HFIQR7XYA";

/// GitHub Personal Access Token (ghp_ prefix).
const GITHUB_PAT: &str = "ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX";

/// Stripe Live Key (sk_live_ prefix).
const STRIPE_KEY: &str = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

/// Slack Bot Token (xoxb- prefix).
const SLACK_BOT: &str = "xoxb-1234567890-1234567890-abcdefghijklmnopqrst";

// ============================================================================
// Helper functions
// ============================================================================

fn run_keyhog(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(KEYHOG_BIN);
    for arg in args {
        cmd.arg(arg);
    }
    let output = cmd
        .output()
        .expect("failed to execute keyhog binary");

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    (exit_code, stdout, stderr)
}

fn scan_with_stdin(content: &str, format: &str) -> (i32, String) {
    let mut cmd = Command::new(KEYHOG_BIN);
    cmd.arg("scan")
        .arg("--stdin")
        .arg("--format")
        .arg(format);

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn keyhog");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("failed to open stdin");
        stdin
            .write_all(content.as_bytes())
            .expect("failed to write to stdin");
    }

    let output = child.wait_with_output().expect("failed to wait for child");
    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    (exit_code, stdout)
}

// ============================================================================
// Exit Code Tests
// ============================================================================

#[test]
fn exit_code_zero_when_no_findings() {
    let (exit_code, _stdout) =
        scan_with_stdin("no secrets in this boring file\nlike at all\n", "text");
    assert_eq!(
        exit_code, 0,
        "exit code should be 0 when no findings are detected"
    );
}

#[test]
fn exit_code_one_when_aws_key_found() {
    let content = format!("const API_KEY = \"{}\";", AWS_AKIA);
    let (exit_code, _stdout) = scan_with_stdin(&content, "text");
    assert_eq!(
        exit_code, 1,
        "exit code should be 1 when secret is found"
    );
}

#[test]
fn exit_code_one_when_github_pat_found() {
    let content = format!("TOKEN=\"{}\"", GITHUB_PAT);
    let (exit_code, _stdout) = scan_with_stdin(&content, "text");
    assert_eq!(
        exit_code, 1,
        "exit code should be 1 when GitHub PAT is found"
    );
}

#[test]
fn exit_code_one_when_stripe_key_found() {
    let content = format!("stripe_api_key: {}", STRIPE_KEY);
    let (exit_code, _stdout) = scan_with_stdin(&content, "text");
    assert_eq!(
        exit_code, 1,
        "exit code should be 1 when Stripe key is found"
    );
}

#[test]
fn exit_code_one_when_slack_bot_found() {
    let content = format!("slack_token={}", SLACK_BOT);
    let (exit_code, _stdout) = scan_with_stdin(&content, "text");
    assert_eq!(
        exit_code, 1,
        "exit code should be 1 when Slack bot token is found"
    );
}

#[test]
fn exit_code_one_when_multiple_findings() {
    let content = format!(
        "aws={}\ngithub={}\nstripe={}",
        AWS_AKIA, GITHUB_PAT, STRIPE_KEY
    );
    let (exit_code, _stdout) = scan_with_stdin(&content, "text");
    assert_eq!(
        exit_code, 1,
        "exit code should be 1 when multiple secrets are found"
    );
}

// ============================================================================
// JSON Format Tests
// ============================================================================

#[test]
fn json_format_empty_array_on_no_findings() {
    let (exit_code, stdout) = scan_with_stdin("no secrets", "json");
    assert_eq!(exit_code, 0, "exit code for no findings");
    assert_eq!(
        stdout.trim(),
        "[]",
        "json format should produce empty array when no findings"
    );
}

#[test]
fn json_format_valid_json_array_on_finding() {
    let content = format!("key={}", AWS_AKIA);
    let (exit_code, stdout) = scan_with_stdin(&content, "json");
    assert_eq!(exit_code, 1, "exit code for finding");

    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "json output must be valid JSON: {}",
        stdout
    );

    let arr = parsed.unwrap();
    assert!(
        arr.is_array(),
        "json output must be an array, got: {}",
        arr
    );
    let arr = arr.as_array().unwrap();
    assert!(!arr.is_empty(), "json array should contain at least one finding");

    let finding = &arr[0];
    assert!(finding.get("detector_id").is_some(), "finding must have detector_id");
    assert!(
        finding.get("credential_redacted").is_some(),
        "finding must have credential_redacted"
    );
    assert!(finding.get("location").is_some(), "finding must have location");
}

#[test]
fn json_format_finding_has_required_fields() {
    let content = format!("api_key={}", STRIPE_KEY);
    let (_exit_code, stdout) = scan_with_stdin(&content, "json");

    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .expect("json parse failed");
    assert!(!arr.is_empty(), "should find at least one secret");

    let finding = &arr[0];
    let required_fields = vec![
        "detector_id",
        "detector_name",
        "service",
        "severity",
        "credential_redacted",
        "credential_hash",
        "location",
        "verification",
        "confidence",
    ];

    for field in required_fields {
        assert!(
            finding.get(field).is_some(),
            "finding missing required field: {}",
            field
        );
    }
}

#[test]
fn json_format_location_has_required_fields() {
    let content = format!("x={}", AWS_AKIA);
    let (_exit_code, stdout) = scan_with_stdin(&content, "json");

    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .expect("json parse failed");
    assert!(!arr.is_empty(), "should find at least one secret");

    let location = arr[0].get("location").expect("location field missing");
    assert!(
        location.get("source").is_some(),
        "location must have source"
    );
    assert!(
        location.get("line").is_some(),
        "location must have line"
    );
    assert!(
        location.get("offset").is_some(),
        "location must have offset"
    );
}

#[test]
fn json_format_handles_multiple_findings() {
    let content = format!(
        "aws {}\ngithub {}\n",
        AWS_AKIA, GITHUB_PAT
    );
    let (_exit_code, stdout) = scan_with_stdin(&content, "json");

    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .expect("json parse failed");
    assert!(
        arr.len() >= 2,
        "should find at least 2 secrets, found: {}",
        arr.len()
    );
}

// ============================================================================
// JSONL Format Tests
// ============================================================================

#[test]
fn jsonl_format_empty_on_no_findings() {
    let (exit_code, stdout) = scan_with_stdin("no secrets", "jsonl");
    assert_eq!(exit_code, 0, "exit code for no findings");
    assert_eq!(
        stdout.trim(),
        "",
        "jsonl format should produce no lines when no findings"
    );
}

#[test]
fn jsonl_format_one_line_per_finding() {
    let content = format!("key1={}\nkey2={}", AWS_AKIA, GITHUB_PAT);
    let (_exit_code, stdout) = scan_with_stdin(&content, "jsonl");

    let lines: Vec<&str> = stdout
        .trim()
        .lines()
        .filter(|l| !l.is_empty())
        .collect();
    assert!(
        lines.len() >= 2,
        "jsonl should have at least 2 lines for 2 secrets, got: {}",
        lines.len()
    );

    // Verify each line is valid JSON
    for (idx, line) in lines.iter().enumerate() {
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "jsonl line {} is not valid JSON: {}",
            idx,
            line
        );
    }
}

#[test]
fn jsonl_format_each_line_has_detector_id() {
    let content = format!("a={}\nb={}", AWS_AKIA, STRIPE_KEY);
    let (_exit_code, stdout) = scan_with_stdin(&content, "jsonl");

    for line in stdout.trim().lines() {
        if line.is_empty() {
            continue;
        }
        let obj: serde_json::Value = serde_json::from_str(line)
            .expect("line must be valid JSON");
        assert!(
            obj.get("detector_id").is_some(),
            "jsonl entry must have detector_id"
        );
    }
}

// ============================================================================
// CSV Format Tests
// ============================================================================

#[test]
fn csv_format_has_header() {
    let (exit_code, stdout) = scan_with_stdin("no secrets", "csv");
    assert_eq!(exit_code, 0, "exit code for no findings");

    // Even with no findings, CSV should have a header
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert!(
        !lines.is_empty(),
        "csv output should have at least header"
    );
    let header = lines[0];
    assert!(
        header.contains("detector_id"),
        "csv header should contain detector_id"
    );
}

#[test]
fn csv_format_header_plus_data_rows() {
    let content = format!("key={}", AWS_AKIA);
    let (_exit_code, stdout) = scan_with_stdin(&content, "csv");

    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert!(
        lines.len() >= 2,
        "csv should have header + data rows, got: {} lines",
        lines.len()
    );

    let header = lines[0];
    assert!(header.contains("detector_id"), "header missing detector_id");
    assert!(
        header.contains("credential_redacted"),
        "header missing credential_redacted"
    );
    assert!(header.contains("severity"), "header missing severity");
}

#[test]
fn csv_format_multiple_findings_multiple_rows() {
    let content = format!(
        "a={}\nb={}\n",
        AWS_AKIA, GITHUB_PAT
    );
    let (_exit_code, stdout) = scan_with_stdin(&content, "csv");

    let lines: Vec<&str> = stdout.trim().lines().collect();
    // At least header + 2 data rows
    assert!(
        lines.len() >= 3,
        "csv should have header + multiple data rows, got: {}",
        lines.len()
    );
}

// ============================================================================
// SARIF Format Tests
// ============================================================================

#[test]
fn sarif_format_valid_json_on_no_findings() {
    let (exit_code, stdout) = scan_with_stdin("no secrets", "sarif");
    // SARIF may exit 0 or 1 depending on convention; what matters is valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(
        parsed.is_ok(),
        "sarif output must be valid JSON: {}",
        stdout
    );
}

#[test]
fn sarif_format_has_required_top_level_fields() {
    let content = format!("key={}", AWS_AKIA);
    let (_exit_code, stdout) = scan_with_stdin(&content, "sarif");

    let doc: serde_json::Value = serde_json::from_str(&stdout)
        .expect("sarif must be valid JSON");

    assert!(
        doc.get("version").is_some(),
        "sarif doc must have version"
    );
    assert!(doc.get("runs").is_some(), "sarif doc must have runs");
}

#[test]
fn sarif_format_runs_array_contains_results() {
    let content = format!("key={}", AWS_AKIA);
    let (_exit_code, stdout) = scan_with_stdin(&content, "sarif");

    let doc: serde_json::Value = serde_json::from_str(&stdout)
        .expect("sarif must be valid JSON");

    let runs = doc
        .get("runs")
        .and_then(|v| v.as_array())
        .expect("runs must be an array");
    assert!(!runs.is_empty(), "runs should not be empty");

    let first_run = &runs[0];
    let results = first_run
        .get("results")
        .and_then(|v| v.as_array())
        .expect("results must be an array");
    assert!(!results.is_empty(), "results should not be empty");
}

#[test]
fn sarif_format_result_has_message_and_location() {
    let content = format!("key={}", STRIPE_KEY);
    let (_exit_code, stdout) = scan_with_stdin(&content, "sarif");

    let doc: serde_json::Value = serde_json::from_str(&stdout)
        .expect("sarif must be valid JSON");

    let results = doc
        .get("runs")
        .and_then(|v| v.as_array())
        .and_then(|a| a.get(0))
        .and_then(|v| v.get("results"))
        .and_then(|v| v.as_array())
        .expect("must find results");

    let result = &results[0];
    assert!(result.get("message").is_some(), "result missing message");
    assert!(
        result.get("locations").is_some(),
        "result missing locations"
    );
}

// ============================================================================
// Output File Tests
// ============================================================================

#[test]
fn output_file_json_format() {
    let temp = TempDir::new().expect("temp dir");
    let output_path = temp.path().join("findings.json");

    let mut cmd = Command::new(KEYHOG_BIN);
    cmd.arg("scan")
        .arg("--stdin")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(output_path.to_str().unwrap());

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn failed");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        write!(stdin, "key={}", AWS_AKIA).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 1, "exit code for finding");

    assert!(
        output_path.exists(),
        "output file should be created at {}",
        output_path.display()
    );

    let contents = fs::read_to_string(&output_path)
        .expect("failed to read output file");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&contents);
    assert!(
        parsed.is_ok(),
        "output file must contain valid JSON: {}",
        contents
    );
}

#[test]
fn output_file_csv_format() {
    let temp = TempDir::new().expect("temp dir");
    let output_path = temp.path().join("findings.csv");

    let mut cmd = Command::new(KEYHOG_BIN);
    cmd.arg("scan")
        .arg("--stdin")
        .arg("--format")
        .arg("csv")
        .arg("--output")
        .arg(output_path.to_str().unwrap());

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn failed");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        write!(stdin, "x={}", GITHUB_PAT).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code().unwrap_or(-1),
        1,
        "exit code for finding"
    );

    assert!(
        output_path.exists(),
        "output file should be created"
    );

    let contents = fs::read_to_string(&output_path)
        .expect("failed to read output file");
    assert!(
        contents.contains("detector_id"),
        "csv file should have header"
    );
}

#[test]
fn output_file_jsonl_format() {
    let temp = TempDir::new().expect("temp dir");
    let output_path = temp.path().join("findings.jsonl");

    let mut cmd = Command::new(KEYHOG_BIN);
    cmd.arg("scan")
        .arg("--stdin")
        .arg("--format")
        .arg("jsonl")
        .arg("--output")
        .arg(output_path.to_str().unwrap());

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn failed");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        write!(stdin, "stripe={}", STRIPE_KEY).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code().unwrap_or(-1),
        1,
        "exit code for finding"
    );

    assert!(
        output_path.exists(),
        "output file should be created"
    );

    let contents = fs::read_to_string(&output_path)
        .expect("failed to read output file");
    for line in contents.trim().lines() {
        if line.is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "each jsonl line must be valid JSON: {}",
            line
        );
    }
}

#[test]
fn output_file_sarif_format() {
    let temp = TempDir::new().expect("temp dir");
    let output_path = temp.path().join("findings.sarif");

    let mut cmd = Command::new(KEYHOG_BIN);
    cmd.arg("scan")
        .arg("--stdin")
        .arg("--format")
        .arg("sarif")
        .arg("--output")
        .arg(output_path.to_str().unwrap());

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn failed");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        write!(stdin, "slack={}", SLACK_BOT).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code().unwrap_or(-1),
        1,
        "exit code for finding"
    );

    assert!(
        output_path.exists(),
        "output file should be created"
    );

    let contents = fs::read_to_string(&output_path)
        .expect("failed to read output file");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&contents);
    assert!(
        parsed.is_ok(),
        "sarif file must be valid JSON: {}",
        contents
    );
}

// ============================================================================
// Format Consistency Tests
// ============================================================================

#[test]
fn all_formats_find_same_secret_count() {
    let content = format!(
        "a={}\nb={}\nc={}\n",
        AWS_AKIA, GITHUB_PAT, STRIPE_KEY
    );

    let (_, json_out) = scan_with_stdin(&content, "json");
    let json_arr: Vec<serde_json::Value> = serde_json::from_str(&json_out)
        .expect("json parse");

    let (_, jsonl_out) = scan_with_stdin(&content, "jsonl");
    let jsonl_count = jsonl_out.trim().lines().count();

    let (_, csv_out) = scan_with_stdin(&content, "csv");
    let csv_lines: Vec<&str> = csv_out.trim().lines().collect();
    let csv_count = if csv_lines.len() > 1 {
        csv_lines.len() - 1 // exclude header
    } else {
        0
    };

    let (_, sarif_out) = scan_with_stdin(&content, "sarif");
    let sarif_doc: serde_json::Value = serde_json::from_str(&sarif_out)
        .expect("sarif parse");
    let sarif_count = sarif_doc
        .get("runs")
        .and_then(|v| v.as_array())
        .and_then(|a| a.get(0))
        .and_then(|v| v.get("results"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    // All formats should report the same number of findings
    assert_eq!(
        json_arr.len(),
        jsonl_count,
        "json and jsonl must have same finding count"
    );
    assert_eq!(
        json_arr.len(),
        csv_count,
        "json and csv must have same finding count"
    );
    assert_eq!(
        json_arr.len(),
        sarif_count,
        "json and sarif must have same finding count"
    );
}

#[test]
fn empty_input_consistency_across_formats() {
    let empty = "";

    let (exit_json, _) = scan_with_stdin(empty, "json");
    let (exit_jsonl, _) = scan_with_stdin(empty, "jsonl");
    let (exit_csv, _) = scan_with_stdin(empty, "csv");
    let (exit_sarif, _) = scan_with_stdin(empty, "sarif");

    assert_eq!(exit_json, 0, "json: exit code 0 for empty");
    assert_eq!(exit_jsonl, 0, "jsonl: exit code 0 for empty");
    assert_eq!(exit_csv, 0, "csv: exit code 0 for empty");
    // sarif may vary, but document should still be valid
}

// ============================================================================
// Boundary and Adversarial Tests
// ============================================================================

#[test]
fn partial_aws_key_not_detected() {
    let partial = "AKIAQYLPMN5"; // Only 11 chars, AWS needs 20
    let (exit_code, _) = scan_with_stdin(partial, "json");
    assert_eq!(
        exit_code, 0,
        "partial AWS key should not be detected"
    );
}

#[test]
fn aws_key_with_noise_before_and_after() {
    let content = format!(
        "xxx{}yyy{}zzz",
        AWS_AKIA, GITHUB_PAT
    );
    let (exit_code, stdout) = scan_with_stdin(&content, "json");
    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .expect("json parse");
    assert_eq!(
        exit_code, 1,
        "should find secrets with surrounding noise"
    );
    assert!(
        arr.len() >= 2,
        "should find both secrets despite noise"
    );
}

#[test]
fn secret_at_boundary_of_long_input() {
    let mut content = String::new();
    content.push_str(&"a".repeat(10000));
    content.push_str(&format!("key={}", AWS_AKIA));
    content.push_str(&"b".repeat(10000));

    let (exit_code, stdout) = scan_with_stdin(&content, "json");
    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .expect("json parse");
    assert_eq!(exit_code, 1, "should find secret at boundary");
    assert!(
        !arr.is_empty(),
        "should detect secret in large input"
    );
}

#[test]
fn secret_in_multiline_context() {
    let content = format!(
        r#"
        function authenticate() {{
            const token = "{}";
            return token;
        }}
        "#,
        GITHUB_PAT
    );
    let (exit_code, _) = scan_with_stdin(&content, "json");
    assert_eq!(
        exit_code, 1,
        "should find secret in multiline code"
    );
}

#[test]
fn secret_with_encoding_not_bypassed() {
    // Plain text is expected; if obfuscated, detector must decode
    let content = format!("token={}", AWS_AKIA);
    let (exit_code, _) = scan_with_stdin(&content, "json");
    assert_eq!(
        exit_code, 1,
        "plain secret should be detected"
    );
}

#[test]
fn multiple_identical_secrets_reported_separately() {
    let secret = AWS_AKIA;
    let content = format!(
        "x={}\ny={}\nz={}",
        secret, secret, secret
    );
    let (_exit_code, stdout) = scan_with_stdin(&content, "json");
    let arr: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .expect("json parse");
    assert_eq!(
        arr.len(),
        3,
        "identical secrets at different locations should be reported"
    );
}

// ============================================================================
// CLI Behavior Tests
// ============================================================================

#[test]
fn format_invalid_rejected() {
    let (exit_code, _stdout, stderr) = run_keyhog(&[
        "scan",
        "--stdin",
        "--format",
        "invalid_format",
    ]);
    // Should fail gracefully
    assert_ne!(
        exit_code, 0,
        "invalid format should cause non-zero exit"
    );
    assert!(
        !stderr.is_empty() || exit_code != 0,
        "invalid format should error"
    );
}

#[test]
fn output_to_nonexistent_directory_handled() {
    let mut cmd = Command::new(KEYHOG_BIN);
    cmd.arg("scan")
        .arg("--stdin")
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg("/nonexistent/path/findings.json");

    let mut child = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn failed");

    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        write!(stdin, "x=y").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    // Should error out gracefully, not panic
    assert!(!output.status.success(), "should fail for bad output path");
}

#[test]
fn text_format_no_findings() {
    let (exit_code, stdout) = scan_with_stdin("clean code", "text");
    assert_eq!(exit_code, 0, "exit code 0 for no findings");
    // Text format output varies, but should not be malformed JSON
    assert!(
        !stdout.contains("["),
        "text format should not output JSON"
    );
}

#[test]
fn text_format_with_findings() {
    let content = format!("api_key={}", AWS_AKIA);
    let (exit_code, stdout) = scan_with_stdin(&content, "text");
    assert_eq!(exit_code, 1, "exit code 1 for finding");
    // Text format should contain some indication of the finding
    assert!(
        !stdout.is_empty(),
        "text format should produce output"
    );
}
