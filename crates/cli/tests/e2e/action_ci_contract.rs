//! E2E contract for the composite GitHub Action scan step.

use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use tempfile::TempDir;

fn action_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/actions/keyhog/run-scan.sh")
        .canonicalize()
        .expect("action run-scan.sh exists")
}

fn action_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/actions/keyhog/action.yml")
        .canonicalize()
        .expect("action.yml exists")
}

fn github_yaml_paths() -> Vec<PathBuf> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root exists");
    let mut paths = vec![action_manifest()];
    let workflow_dir = repo.join(".github/workflows");
    for entry in fs::read_dir(&workflow_dir).expect("read .github/workflows") {
        let path = entry.expect("workflow dir entry").path();
        if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        ) {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn github_workflow_paths() -> Vec<PathBuf> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root exists");
    let workflow_dir = repo.join(".github/workflows");
    let mut paths = Vec::new();
    for entry in fs::read_dir(&workflow_dir).expect("read .github/workflows") {
        let path = entry.expect("workflow dir entry").path();
        if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        ) {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

fn release_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/release.yml")
        .canonicalize()
        .expect("release.yml exists")
}

fn keyhog_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/keyhog.yml")
        .canonicalize()
        .expect("keyhog.yml exists")
}

fn keyhog_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn write_stub(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("keyhog");
    fs::write(&path, body).expect("write keyhog stub");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&path).expect("stub metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod stub");
    }
    path
}

fn run_action_with_path_prefix(dir: &TempDir, path_prefix: &str, envs: &[(&str, &str)]) -> Output {
    let output_path = dir.path().join("github-output.txt");
    let summary_path = dir.path().join("summary.md");
    let path = format!(
        "{}:{}:{}",
        path_prefix,
        dir.path().display(),
        env::var("PATH").expect("PATH is set")
    );

    let mut cmd = Command::new("bash");
    cmd.arg(action_script())
        .current_dir(dir.path())
        .env("PATH", path)
        .env("GITHUB_OUTPUT", &output_path)
        .env("GITHUB_STEP_SUMMARY", &summary_path)
        .env("KEYHOG_SCAN_PATH", ".")
        .env("KEYHOG_SEVERITY", "high")
        .env("KEYHOG_FORMAT", "sarif")
        .env("KEYHOG_VERIFY", "false")
        .env("KEYHOG_OUTPUT", "keyhog-results.sarif");

    for (key, value) in envs {
        cmd.env(key, value);
    }

    cmd.output().expect("run action script")
}

fn run_action(dir: &TempDir, envs: &[(&str, &str)]) -> Output {
    run_action_with_path_prefix(dir, dir.path().to_str().expect("utf-8 tempdir"), envs)
}

fn output_file(dir: &TempDir) -> String {
    fs::read_to_string(dir.path().join("github-output.txt")).expect("read GITHUB_OUTPUT")
}

fn summary_file(dir: &TempDir) -> String {
    fs::read_to_string(dir.path().join("summary.md")).expect("read GITHUB_STEP_SUMMARY")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn manifest_run_blocks(manifest: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in manifest.lines() {
        if line.starts_with("    - name:") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
        }
        if line.trim_start() == "run: |" {
            current = Some(String::new());
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }
    blocks
}

fn manifest_run_block_for_step(manifest: &str, step_name: &str) -> String {
    let lines: Vec<&str> = manifest.lines().collect();
    let needle = format!("- name: {step_name}");
    let mut idx = lines
        .iter()
        .position(|line| line.trim() == needle)
        .unwrap_or_else(|| panic!("manifest step '{step_name}' exists"));

    while idx < lines.len() && lines[idx].trim_start() != "run: |" {
        idx += 1;
    }
    assert!(
        idx < lines.len(),
        "manifest step '{step_name}' must have a literal run block"
    );

    let run_indent = lines[idx].len() - lines[idx].trim_start().len();
    let content_indent = run_indent + 2;
    idx += 1;
    let mut block = String::new();
    while idx < lines.len() {
        let line = lines[idx];
        if !line.trim().is_empty() {
            let indent = line.len() - line.trim_start().len();
            if indent <= run_indent {
                break;
            }
        }
        block.push_str(
            line.get(content_indent..)
                .unwrap_or_else(|| line.trim_start()),
        );
        block.push('\n');
        idx += 1;
    }
    block
}

fn run_manifest_bash_step(step_name: &str, envs: &[(&str, &str)]) -> Output {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let block = manifest_run_block_for_step(&manifest, step_name);
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(block);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("run manifest shell block")
}

fn yaml_literal_run_blocks(yaml: &str) -> Vec<String> {
    let lines: Vec<&str> = yaml.lines().collect();
    let mut blocks = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx];
        if line.trim_start() != "run: |" {
            idx += 1;
            continue;
        }

        let run_indent = line.len() - line.trim_start().len();
        idx += 1;
        let mut block = String::new();
        while idx < lines.len() {
            let block_line = lines[idx];
            if !block_line.trim().is_empty() {
                let indent = block_line.len() - block_line.trim_start().len();
                if indent <= run_indent {
                    break;
                }
            }
            block.push_str(block_line);
            block.push('\n');
            idx += 1;
        }
        blocks.push(block);
    }
    blocks
}

fn yaml_get<'a>(
    mapping: &'a serde_yaml::Mapping,
    key: impl Into<String>,
) -> Option<&'a serde_yaml::Value> {
    mapping.get(serde_yaml::Value::String(key.into()))
}

fn workflow_trigger<'a>(mapping: &'a serde_yaml::Mapping) -> Option<&'a serde_yaml::Value> {
    yaml_get(mapping, "on").or_else(|| mapping.get(serde_yaml::Value::Bool(true)))
}

#[test]
fn github_action_and_workflows_parse_as_yaml() {
    for path in github_yaml_paths() {
        let text = fs::read_to_string(&path).expect("read GitHub YAML");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|err| panic!("{} must parse as YAML: {err}", path.display()));
        assert!(
            matches!(parsed, serde_yaml::Value::Mapping(_)),
            "{} top-level YAML must be a mapping",
            path.display()
        );
    }
}

#[test]
fn github_workflows_keep_triggered_executable_job_shape() {
    for path in github_workflow_paths() {
        let text = fs::read_to_string(&path).expect("read workflow YAML");
        let parsed: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|err| panic!("{} must parse as YAML: {err}", path.display()));
        let root = parsed
            .as_mapping()
            .unwrap_or_else(|| panic!("{} top-level YAML must be a mapping", path.display()));

        let name = yaml_get(root, "name")
            .and_then(serde_yaml::Value::as_str)
            .unwrap_or("");
        assert!(
            !name.trim().is_empty(),
            "{} must name the workflow",
            path.display()
        );
        assert!(
            workflow_trigger(root).is_some(),
            "{} must declare at least one trigger",
            path.display()
        );

        let jobs = yaml_get(root, "jobs")
            .and_then(serde_yaml::Value::as_mapping)
            .unwrap_or_else(|| panic!("{} must declare a jobs mapping", path.display()));
        assert!(
            !jobs.is_empty(),
            "{} must declare at least one job",
            path.display()
        );

        for (job_name, job_value) in jobs {
            let job_name = job_name.as_str().unwrap_or("<non-string job name>");
            let job = job_value
                .as_mapping()
                .unwrap_or_else(|| panic!("{} job {job_name} must be a mapping", path.display()));
            let has_runner = yaml_get(job, "runs-on").is_some() || yaml_get(job, "uses").is_some();
            assert!(
                has_runner,
                "{} job {job_name} must declare runs-on or uses",
                path.display()
            );
            if let Some(steps) = yaml_get(job, "steps") {
                let steps = steps.as_sequence().unwrap_or_else(|| {
                    panic!("{} job {job_name} steps must be a sequence", path.display())
                });
                assert!(
                    !steps.is_empty(),
                    "{} job {job_name} must have at least one step",
                    path.display()
                );
                for (idx, step) in steps.iter().enumerate() {
                    let step = step.as_mapping().unwrap_or_else(|| {
                        panic!(
                            "{} job {job_name} step {} must be a mapping",
                            path.display(),
                            idx + 1
                        )
                    });
                    assert!(
                        yaml_get(step, "run").is_some() || yaml_get(step, "uses").is_some(),
                        "{} job {job_name} step {} must run a command or use an action",
                        path.display(),
                        idx + 1
                    );
                }
            } else {
                assert!(
                    yaml_get(job, "uses").is_some(),
                    "{} job {job_name} must declare steps unless it calls a reusable workflow",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn composite_action_manifest_keeps_composite_runs_shape() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&manifest).expect("action.yml parses as YAML");
    let root = parsed.as_mapping().expect("action.yml is a mapping");
    let runs = root
        .get(serde_yaml::Value::String("runs".to_string()))
        .and_then(serde_yaml::Value::as_mapping)
        .expect("action.yml declares runs");
    assert_eq!(
        runs.get(serde_yaml::Value::String("using".to_string()))
            .and_then(serde_yaml::Value::as_str),
        Some("composite"),
        "action.yml must remain a composite action"
    );
    let steps = runs
        .get(serde_yaml::Value::String("steps".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("composite action declares steps");
    assert!(
        !steps.is_empty(),
        "composite action must have at least one executable step"
    );
}

#[test]
fn action_runs_real_keyhog_and_counts_sarif_findings() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).expect("create repo");
    fs::write(
        repo.join("secret.env"),
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n",
    )
    .expect("write planted secret");

    let binary = keyhog_binary();
    let binary_dir = binary
        .parent()
        .expect("binary parent")
        .to_str()
        .expect("utf-8 binary dir");
    let output = run_action_with_path_prefix(
        &dir,
        binary_dir,
        &[
            ("KEYHOG_SCAN_PATH", "repo"),
            ("KEYHOG_FORMAT", "sarif"),
            ("KEYHOG_OUTPUT", "real-keyhog.sarif"),
            ("KEYHOG_SEVERITY", "high"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "real keyhog findings exit must remain on action findings path; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let gh_output = output_file(&dir);
    assert!(
        gh_output.contains("findings=1"),
        "real SARIF report count must surface through GITHUB_OUTPUT; got {gh_output}"
    );

    let sarif = fs::read_to_string(dir.path().join("real-keyhog.sarif")).expect("read SARIF");
    assert!(
        sarif.contains("\"runs\""),
        "SARIF report must contain runs: {sarif}"
    );
    assert!(
        sarif.contains("aws"),
        "SARIF report should carry the planted AWS finding: {sarif}"
    );
}

#[test]
fn action_runs_real_keyhog_and_counts_text_findings() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path().join("repo");
    fs::create_dir(&repo).expect("create repo");
    fs::write(
        repo.join("secret.env"),
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n",
    )
    .expect("write planted secret");

    let binary = keyhog_binary();
    let binary_dir = binary
        .parent()
        .expect("binary parent")
        .to_str()
        .expect("utf-8 binary dir");
    let output = run_action_with_path_prefix(
        &dir,
        binary_dir,
        &[
            ("KEYHOG_SCAN_PATH", "repo"),
            ("KEYHOG_FORMAT", "text"),
            ("KEYHOG_OUTPUT", "real-keyhog.txt"),
            ("KEYHOG_SEVERITY", "high"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "real keyhog text findings exit must remain on action findings path; output={}",
        combined_output(&output)
    );

    let gh_output = output_file(&dir);
    assert!(
        gh_output.contains("findings=1"),
        "real text report count must surface through GITHUB_OUTPUT; got {gh_output}"
    );

    let report = fs::read_to_string(dir.path().join("real-keyhog.txt")).expect("read text report");
    assert!(
        report.contains("Secret:"),
        "text report must carry the stable finding field counted by the action; report={report}"
    );
    assert!(
        report.contains("AWS Access Key") || report.contains("aws"),
        "text report should carry the planted AWS finding: {report}"
    );
}

#[test]
fn action_counts_sarif_findings_and_writes_ci_summary() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
cat > "$out" <<'JSON'
{"runs":[{"results":[{},{}]}]}
JSON
exit 1
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "findings exit must allow artifact/upload/fail steps to run; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let gh_output = output_file(&dir);
    assert!(
        gh_output.contains("findings=2"),
        "SARIF result count must be exposed; got {gh_output}"
    );
    assert!(
        gh_output.contains("exit-code=1"),
        "raw scanner exit must be exposed; got {gh_output}"
    );
    assert!(
        gh_output
            .lines()
            .any(|line| line.starts_with("duration-ms=")
                && line["duration-ms=".len()..].parse::<u64>().is_ok()),
        "scan duration must be exposed as milliseconds; got {gh_output}"
    );

    let summary = summary_file(&dir);
    assert!(summary.contains("| Findings | `2` |"), "summary={summary}");
    assert!(summary.contains("| Exit code | `1` |"), "summary={summary}");
    assert!(
        summary.contains("| Duration | `"),
        "summary must expose scan duration; summary={summary}"
    );
    assert!(
        summary.contains("| Fail on findings | `true` |"),
        "summary={summary}"
    );
    assert!(
        summary.contains("| Upload SARIF | `true` |"),
        "summary={summary}"
    );
}

#[test]
fn action_treats_malformed_findings_report_as_at_least_one_finding() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{not-json\n' > "$out"
exit 1
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "malformed findings report should keep CI on findings path; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_file(&dir).contains("findings=1"),
        "parse failure after findings exit must not become zero findings"
    );
}

#[test]
fn action_treats_live_malformed_report_as_at_least_one_finding() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{not-json\n' > "$out"
exit 10
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "malformed live report should keep CI on findings path; output={}",
        combined_output(&output)
    );
    assert!(
        output_file(&dir).contains("findings=1"),
        "parse failure after live exit must not become zero findings"
    );
    assert!(
        combined_output(&output).contains("LIVE credential(s) confirmed by --verify (exit 10)."),
        "live verification exit must remain operator-visible"
    );
}

#[test]
fn action_rejects_malformed_clean_report() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{not-json\n' > "$out"
exit 0
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "malformed clean report must fail closed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn action_rejects_object_shaped_clean_json_report() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{"findings":[{"detector_id":"one"}]}\n' > "$out"
exit 0
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "json"),
            ("KEYHOG_OUTPUT", "keyhog-results.json"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "object-shaped clean json report must fail closed; output={}",
        combined_output(&output)
    );
}

#[test]
fn action_rejects_sarif_with_non_array_results() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{"runs":[{"results":{"not":"an array"}}]}\n' > "$out"
exit 0
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "SARIF results must be arrays; output={}",
        combined_output(&output)
    );
}

#[test]
fn action_rejects_findings_exit_without_report() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
exit 1
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "findings exit without report must fail closed; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn action_rejects_clean_exit_without_report() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
exit 0
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "clean exit without report must fail closed; output={}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output)
            .contains("keyhog exited 0 but did not write 'keyhog-results.sarif'."),
        "missing clean report must be operator-visible; output={}",
        combined_output(&output)
    );
}

#[test]
fn action_validates_format_before_invoking_scanner() {
    let dir = TempDir::new().expect("tempdir");
    let invoked = dir.path().join("invoked");
    write_stub(
        &dir,
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
printf invoked > '{}'
exit 0
"#,
            invoked.display()
        ),
    );

    let output = run_action(&dir, &[("KEYHOG_FORMAT", "xml")]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid action format should be a usage error; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !invoked.exists(),
        "invalid format must fail before running keyhog"
    );
}

#[test]
fn action_validates_severity_and_verify_before_invoking_scanner() {
    let dir = TempDir::new().expect("tempdir");
    let invoked = dir.path().join("invoked");
    write_stub(
        &dir,
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
printf invoked > '{}'
exit 0
"#,
            invoked.display()
        ),
    );

    for (key, value) in [("KEYHOG_SEVERITY", "emergency"), ("KEYHOG_VERIFY", "yes")] {
        let output = run_action(&dir, &[(key, value)]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{key}={value} should be a usage error; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !invoked.exists(),
            "{key}={value} must fail before running keyhog"
        );
    }
}

#[test]
fn action_validates_policy_booleans_before_invoking_scanner() {
    let dir = TempDir::new().expect("tempdir");
    let invoked = dir.path().join("invoked");
    write_stub(
        &dir,
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
printf invoked > '{}'
exit 0
"#,
            invoked.display()
        ),
    );

    for (key, value) in [
        ("KEYHOG_FAIL_ON_FINDINGS", "maybe"),
        ("KEYHOG_UPLOAD_SARIF", "maybe"),
    ] {
        let output = run_action(&dir, &[(key, value)]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{key}={value} should be a usage error; output={}",
            combined_output(&output)
        );
        assert!(
            !invoked.exists(),
            "{key}={value} must fail before running keyhog"
        );
    }
}

#[test]
fn action_escapes_workflow_command_values() {
    let dir = TempDir::new().expect("tempdir");
    let invoked = dir.path().join("invoked");
    write_stub(
        &dir,
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
printf invoked > '{}'
exit 0
"#,
            invoked.display()
        ),
    );

    let injected = "bad\n::warning title=Owned::forged";
    let output = run_action(&dir, &[("KEYHOG_SEVERITY", injected)]);
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid severity should be a usage error; output={combined}"
    );
    assert!(
        combined.contains("Invalid severity 'bad%0A::warning title=Owned::forged'"),
        "workflow command value must encode newlines; output={combined}"
    );
    assert!(
        !combined.contains("bad\n::warning title=Owned::forged"),
        "workflow command value must not allow a second command line; output={combined}"
    );
    assert!(
        !invoked.exists(),
        "invalid severity must fail before running keyhog"
    );
}

#[test]
fn composite_action_passes_policy_inputs_to_scanner_script() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        manifest.contains("KEYHOG_FAIL_ON_FINDINGS: ${{ inputs.fail-on-findings }}"),
        "composite action must validate fail-on-findings in the tested script"
    );
    assert!(
        manifest.contains("KEYHOG_UPLOAD_SARIF: ${{ inputs.upload-sarif }}"),
        "composite action must validate upload-sarif in the tested script"
    );
}

#[test]
fn composite_action_exposes_scan_duration_output() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        manifest.contains("duration-ms:"),
        "composite action must expose scan duration for CI performance tracking"
    );
    assert!(
        manifest.contains("value: ${{ steps.scan.outputs.duration-ms }}"),
        "duration output must come from the tested scan script"
    );
}

#[test]
fn composite_action_artifact_name_is_job_scoped() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        !manifest.contains("name: keyhog-report\n"),
        "workflow artifacts must not use one constant name; matrix CI jobs would collide"
    );
    assert!(
        manifest.contains(
            "name: keyhog-report-${{ github.job }}-${{ steps.scan.outputs.duration-ms || 'unknown-duration' }}"
        ),
        "artifact name must include job and scan-duration context to avoid common matrix/retry collisions"
    );
}

#[test]
fn composite_action_sarif_upload_fails_closed_on_trusted_runs() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let upload_step = manifest
        .split("- name: Upload SARIF to code-scanning")
        .nth(1)
        .and_then(|rest| rest.split("    - name:").next())
        .expect("SARIF upload step exists");

    assert!(
        upload_step.contains("uses: github/codeql-action/upload-sarif@v3"),
        "SARIF upload must use the GitHub Code Scanning action"
    );
    assert!(
        upload_step.contains(
            "continue-on-error: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}"
        ),
        "SARIF upload may be advisory only for fork PR permission failures; trusted CI uploads must fail closed"
    );
    assert!(
        !upload_step.contains("continue-on-error: true"),
        "unconditional SARIF upload tolerance hides broken production Code Scanning integrations"
    );
}

#[test]
fn composite_action_live_credentials_fail_even_when_findings_are_advisory() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        manifest.contains("steps.scan.outputs.exit-code == '10'"),
        "verified-live credentials must fail the composite Action even when fail-on-findings is false"
    );
    assert!(
        manifest.contains("KEYHOG_EXIT_CODE: ${{ steps.scan.outputs.exit-code }}"),
        "fail step must receive the raw scanner exit code through env"
    );
    assert!(
        manifest.contains("LIVE credential(s) confirmed by --verify (exit 10)."),
        "fail step must make the live-credential reason operator-visible"
    );
    assert!(
        manifest.contains("exit 10"),
        "verified-live credentials should preserve the scanner's exit-10 semantics"
    );
}

#[test]
fn composite_action_fail_step_exits_ten_for_live_credentials() {
    let output = run_manifest_bash_step(
        "Fail when findings reported",
        &[
            ("KEYHOG_FINDINGS", "1"),
            ("KEYHOG_EXIT_CODE", "10"),
            ("KEYHOG_SEVERITY", "high"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(10),
        "live verified credentials must preserve scanner exit 10; output={combined}"
    );
    assert!(
        combined.contains("LIVE credential(s) confirmed by --verify (exit 10)."),
        "live failure reason must be operator-visible; output={combined}"
    );
    assert!(
        !combined.contains("Set fail-on-findings:false"),
        "live credentials must not be described as advisory findings; output={combined}"
    );
}

#[test]
fn composite_action_fail_step_exits_one_for_advisory_findings() {
    let output = run_manifest_bash_step(
        "Fail when findings reported",
        &[
            ("KEYHOG_FINDINGS", "2"),
            ("KEYHOG_EXIT_CODE", "1"),
            ("KEYHOG_SEVERITY", "critical"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "ordinary findings must preserve the existing fail-on-findings contract; output={combined}"
    );
    assert!(
        combined.contains("2 finding(s) at or above 'critical' severity"),
        "ordinary findings failure must include count and severity; output={combined}"
    );
}

#[test]
fn composite_action_fail_step_rejects_invalid_exit_code_without_reflection() {
    let injected = "10\n::warning title=Owned::forged";
    let output = run_manifest_bash_step(
        "Fail when findings reported",
        &[
            ("KEYHOG_FINDINGS", "1"),
            ("KEYHOG_EXIT_CODE", injected),
            ("KEYHOG_SEVERITY", "high"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(3),
        "invalid exit-code output must fail closed; output={combined}"
    );
    assert!(
        combined.contains("Invalid exit-code output."),
        "invalid exit-code failure must be actionable; output={combined}"
    );
    assert!(
        !combined.contains("::warning title=Owned::forged"),
        "invalid exit-code value must not be reflected into workflow commands; output={combined}"
    );
}

#[test]
fn composite_action_shell_blocks_do_not_inline_untrusted_expressions() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let mut offenders = Vec::new();
    for block in manifest_run_blocks(&manifest) {
        for line in block.lines() {
            if line.contains("${{ inputs.") || line.contains("${{ steps.") {
                offenders.push(line.trim().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "composite action shell blocks must receive inputs/step outputs through env, not direct interpolation: {offenders:#?}"
    );
}

#[test]
fn composite_action_version_output_is_validated_before_github_output() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        manifest.contains("KEYHOG_ACTION_VERSION: ${{ inputs.version }}"),
        "version input must enter shell through env"
    );
    assert!(
        manifest.contains("*[!A-Za-z0-9._/-]*"),
        "version resolver must reject chars that can inject GITHUB_OUTPUT or shell syntax"
    );
    assert!(
        manifest.contains("Invalid version. Use only letters"),
        "version resolver must not reflect rejected input into a workflow command"
    );
    assert!(
        !manifest.contains("Invalid version '$v'"),
        "version resolver must not echo the rejected version value"
    );
    assert!(
        manifest.contains("printf 'version=%s\\n' \"$v\" >> \"$GITHUB_OUTPUT\""),
        "version resolver must write a single validated output line"
    );
    assert!(
        !manifest.contains("echo \"version=$v\" >> \"$GITHUB_OUTPUT\""),
        "version resolver must not echo an unvalidated output assignment"
    );
}

#[test]
fn composite_action_error_commands_do_not_reflect_untrusted_env_values() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        !manifest.contains("Invalid findings output '${KEYHOG_FINDINGS:-}'"),
        "fail step must not echo an invalid findings output into a workflow command"
    );
    assert!(
        manifest.contains("Invalid findings output."),
        "fail step should still explain invalid findings output"
    );
}

#[test]
fn composite_action_verifies_downloaded_release_asset() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        manifest.contains("Install Vectorscan/Hyperscan runtime (Linux prebuilt)"),
        "Linux release binary path must install the runtime library it links against"
    );
    assert!(
        manifest.contains("libhyperscan5"),
        "Linux prebuilt path must install libhyperscan5 before executing the release asset"
    );
    assert!(
        manifest.contains("curl -fL --retry 2 \"$url.sha256\""),
        "prebuilt download must fetch the matching release checksum"
    );
    assert!(
        manifest.contains("sha256sum -c \"$asset.sha256\"")
            || manifest.contains("shasum -a 256 -c \"$asset.sha256\""),
        "prebuilt download must verify the checksum before adding keyhog to PATH"
    );
    assert!(
        manifest.contains("Release asset or checksum missing"),
        "missing checksum must fall back to source build instead of running an unchecked binary"
    );
}

#[test]
fn keyhog_workflow_dogfoods_local_composite_action() {
    let workflow = fs::read_to_string(keyhog_workflow()).expect("read keyhog.yml");
    assert!(
        workflow.contains("uses: ./.github/actions/keyhog"),
        "repo CI must dogfood the bundled composite action, not a divergent inline scanner"
    );
    assert!(
        workflow.contains("fail-on-findings: 'false'"),
        "repo CI should preserve strict-marker gating while still uploading findings"
    );
    assert!(
        workflow.contains("KEYHOG_FINDINGS: ${{ steps.keyhog.outputs.findings }}"),
        "strict-marker step must receive action findings through env"
    );
    assert!(
        workflow.contains("KEYHOG_EXIT_CODE: ${{ steps.keyhog.outputs.exit-code }}"),
        "strict-marker step must receive action exit code through env"
    );

    let mut offenders = Vec::new();
    for block in yaml_literal_run_blocks(&workflow) {
        for line in block.lines() {
            if line.contains("${{ steps.keyhog.outputs.") {
                offenders.push(line.trim().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "keyhog workflow shell blocks must receive action outputs through env, not direct interpolation: {offenders:#?}"
    );
}

#[test]
fn release_workflow_validates_manual_tag_before_shell_outputs() {
    let workflow = fs::read_to_string(release_workflow()).expect("read release.yml");
    let mut offenders = Vec::new();
    for block in yaml_literal_run_blocks(&workflow) {
        for line in block.lines() {
            if line.contains("${{ inputs.tag }}") {
                offenders.push(line.trim().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "release workflow shell blocks must receive workflow_dispatch tag through env, not direct interpolation: {offenders:#?}"
    );
    assert!(
        workflow.contains("KEYHOG_RELEASE_INPUT_TAG: ${{ inputs.tag }}"),
        "manual release tag must enter shell through a named env var"
    );
    assert!(
        workflow.contains("v[0-9]*)"),
        "release tag resolver must require a v-prefixed numeric release tag"
    );
    assert!(
        workflow.contains("*[!A-Za-z0-9._-]*)"),
        "release tag resolver must reject shell metacharacters, spaces, and newlines"
    );
    assert!(
        workflow.contains("printf 'tag=%s\\n' \"$tag\" >> \"$GITHUB_OUTPUT\""),
        "release tag resolver must write a single validated output line"
    );
    assert!(
        !workflow.contains("echo \"tag=$tag\" >> \"$GITHUB_OUTPUT\""),
        "release tag resolver must not echo an unvalidated output assignment"
    );
    assert!(
        workflow.contains("KEYHOG_RELEASE_TAG: ${{ steps.tag.outputs.tag }}"),
        "validated release tag output should enter follow-up shell steps through env"
    );
}

#[test]
fn action_wires_verify_baseline_and_paths_as_single_arguments() {
    let dir = TempDir::new().expect("tempdir");
    let args_path = dir.path().join("args.txt");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  printf '<%s>\n' "$arg"
done > "$KEYHOG_STUB_ARGS"
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '[]\n' > "$out"
exit 0
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_STUB_ARGS", args_path.to_str().expect("utf-8 path")),
            ("KEYHOG_SCAN_PATH", "src path/with space"),
            ("KEYHOG_FORMAT", "json"),
            ("KEYHOG_OUTPUT", "report.json"),
            ("KEYHOG_VERIFY", "true"),
            ("KEYHOG_BASELINE", "baseline path/with space.json"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "argument wiring stub must pass; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let args = fs::read_to_string(args_path).expect("read args");
    assert!(
        args.contains("<--path>\n<src path/with space>\n"),
        "args={args}"
    );
    assert!(args.contains("<--verify>\n"), "args={args}");
    assert!(
        args.contains("<--baseline>\n<baseline path/with space.json>\n"),
        "args={args}"
    );
}

#[test]
fn action_counts_text_reports_without_box_drawing_grep() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
cat > "$out" <<'TXT'
  Secret:     [REDACTED]
  Location:   a:1
  Secret:     [REDACTED]
  Location:   b:2
TXT
exit 1
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "text"),
            ("KEYHOG_OUTPUT", "keyhog-results.txt"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "text findings exit should stay on findings path; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_file(&dir).contains("findings=2"),
        "text report count must use stable field labels"
    );
}

#[test]
fn action_counts_jsonl_reports_by_valid_json_lines() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
cat > "$out" <<'JSONL'
{"detector_id":"one"}

{"detector_id":"two"}
JSONL
exit 1
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "jsonl"),
            ("KEYHOG_OUTPUT", "keyhog-results.jsonl"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "jsonl findings exit should stay on findings path; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_file(&dir).contains("findings=2"),
        "jsonl report count must ignore blank lines and parse JSON values"
    );
}

#[test]
fn action_rejects_malformed_clean_jsonl_report() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{not-json}\n' > "$out"
exit 0
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "jsonl"),
            ("KEYHOG_OUTPUT", "keyhog-results.jsonl"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "malformed clean jsonl report must fail closed; output={}",
        combined_output(&output)
    );
}

#[test]
fn action_rejects_non_object_clean_jsonl_report() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '"not-a-finding-object"\n' > "$out"
exit 0
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "jsonl"),
            ("KEYHOG_OUTPUT", "keyhog-results.jsonl"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "non-object clean jsonl report must fail closed; output={}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output).contains("Could not parse clean scan report"),
        "non-object JSONL must be operator-visible as report corruption; output={}",
        combined_output(&output)
    );
}

#[test]
fn action_treats_non_object_findings_jsonl_as_at_least_one_finding() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '"not-a-finding-object"\n' > "$out"
exit 1
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "jsonl"),
            ("KEYHOG_OUTPUT", "keyhog-results.jsonl"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "non-object findings jsonl should keep CI on findings path; output={}",
        combined_output(&output)
    );
    assert!(
        output_file(&dir).contains("findings=1"),
        "parse failure after findings exit must not become zero findings"
    );
}

#[test]
fn action_sanitizes_markdown_summary_cells() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '[]\n' > "$out"
exit 0
"#,
    );

    let output = run_action(
        &dir,
        &[
            ("KEYHOG_FORMAT", "json"),
            ("KEYHOG_OUTPUT", "report.json"),
            ("KEYHOG_SCAN_PATH", "src|`name\nsecond"),
            ("KEYHOG_BASELINE", "base|`line\nthird"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "summary sanitization stub must pass; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let summary = summary_file(&dir);
    assert!(
        summary.contains("| Path | `src\\|\\`name second` |"),
        "path cell must escape pipes/backticks/newlines; summary={summary}"
    );
    assert!(
        summary.contains("| Baseline | `base\\|\\`line third` |"),
        "baseline cell must escape pipes/backticks/newlines; summary={summary}"
    );
}
