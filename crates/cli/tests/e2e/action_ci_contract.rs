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

fn release_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/release.yml")
        .canonicalize()
        .expect("release.yml exists")
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

    let summary = summary_file(&dir);
    assert!(summary.contains("| Findings | `2` |"), "summary={summary}");
    assert!(summary.contains("| Exit code | `1` |"), "summary={summary}");
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
