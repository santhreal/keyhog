//! Behavioral fixture for the manual GitHub Actions workflow in the CI guide.
//!
//! The fixture executes the documented capture and enforcement shell blocks.
//! A local upload stand-in copies the produced SARIF between those phases, so
//! every public nonzero scan status must survive report production and upload.

#![cfg(unix)]

use serde_yaml::{Mapping, Value};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const PUBLIC_NONZERO_EXIT_CODES: [i32; 7] = [1, 2, 3, 10, 11, 12, 13];

struct DocumentedWorkflow {
    capture: String,
    enforce: String,
    report: PathBuf,
}

fn docs_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/workflows/ci.md")
}

fn yaml_fences(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current = None;
    for line in markdown.lines() {
        if line.trim() == "```yaml" {
            current = Some(String::new());
            continue;
        }
        if line.trim() == "```" {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
    }
    blocks
}

fn fenced_block_after_heading(markdown: &str, heading: &str, language: &str) -> String {
    let section = markdown
        .split_once(heading)
        .unwrap_or_else(|| panic!("CI guide contains {heading}"))
        .1;
    let opening = format!("```{language}");
    let body = section
        .split_once(&opening)
        .unwrap_or_else(|| panic!("{heading} contains a {language} fence"))
        .1;
    body.split_once("```")
        .unwrap_or_else(|| panic!("{heading} closes its {language} fence"))
        .0
        .trim()
        .to_string()
}

fn dedent(block: &str) -> String {
    let indent = block
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    block
        .lines()
        .map(|line| line.get(indent..).unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn field<'a>(mapping: &'a Mapping, name: &str) -> Option<&'a Value> {
    mapping.get(Value::String(name.to_string()))
}

fn documented_workflow() -> DocumentedWorkflow {
    let markdown = fs::read_to_string(docs_path()).expect("read CI guide");
    let block = yaml_fences(&markdown)
        .into_iter()
        .find(|block| {
            block.contains("id: keyhog")
                && block.contains("github/codeql-action/upload-sarif")
                && block.contains("KEYHOG_EXIT")
        })
        .expect("CI guide contains the manual capture, upload, and enforce workflow");
    let parsed: Value = serde_yaml::from_str(&dedent(&block)).expect("manual workflow parses");
    let steps = parsed
        .as_sequence()
        .expect("manual workflow fence is a step sequence");

    let capture = steps
        .iter()
        .filter_map(Value::as_mapping)
        .find(|step| field(step, "id").and_then(Value::as_str) == Some("keyhog"))
        .and_then(|step| field(step, "run"))
        .and_then(Value::as_str)
        .expect("manual workflow has an executable capture step")
        .to_string();

    let upload = steps
        .iter()
        .filter_map(Value::as_mapping)
        .find(|step| {
            field(step, "uses")
                .and_then(Value::as_str)
                .is_some_and(|uses| uses.starts_with("github/codeql-action/upload-sarif@"))
        })
        .expect("manual workflow has a SARIF upload step");
    let report = field(upload, "with")
        .and_then(Value::as_mapping)
        .and_then(|with| field(with, "sarif_file"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .expect("SARIF upload names its report");

    let enforce = steps
        .iter()
        .filter_map(Value::as_mapping)
        .find(|step| field(step, "name").and_then(Value::as_str) == Some("Enforce scan result"))
        .and_then(|step| field(step, "run"))
        .and_then(Value::as_str)
        .expect("manual workflow has an executable enforcement step")
        .to_string();

    DocumentedWorkflow {
        capture,
        enforce,
        report,
    }
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write fixture executable");
    let mut permissions = fs::metadata(path).expect("fixture metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make fixture executable");
}

fn run_shell(script: &str, cwd: &Path, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new("bash");
    command.arg("-c").arg(script).current_dir(cwd);
    for (name, value) in envs {
        command.env(name, value);
    }
    command.output().expect("execute documented shell step")
}

fn run_posix_shell(script: &str, cwd: &Path, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new("sh");
    command.arg("-c").arg(script).current_dir(cwd);
    for (name, value) in envs {
        command.env(name, value);
    }
    command
        .output()
        .expect("execute documented POSIX shell step")
}

fn upload_report(report: &Path, destination: &Path) -> Output {
    Command::new("bash")
        .arg("-c")
        .arg(
            r#"set -euo pipefail
test -s "$SARIF_FILE"
cp -- "$SARIF_FILE" "$UPLOAD_DESTINATION"
cmp -- "$SARIF_FILE" "$UPLOAD_DESTINATION"
"#,
        )
        .env("SARIF_FILE", report)
        .env("UPLOAD_DESTINATION", destination)
        .output()
        .expect("execute SARIF upload stand-in")
}

#[test]
fn documented_capture_upload_enforce_preserves_every_public_nonzero_exit() {
    let workflow = documented_workflow();

    for exit_code in PUBLIC_NONZERO_EXIT_CODES {
        let case = TempDir::new().expect("case tempdir");
        let bin_dir = case.path().join("bin");
        fs::create_dir(&bin_dir).expect("create fixture bin directory");
        write_executable(
            &bin_dir.join("keyhog"),
            r#"#!/usr/bin/env bash
set -euo pipefail
report=""
while (( $# )); do
  case "$1" in
    --output)
      report="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
test -n "$report"
printf '{"version":"2.1.0","runs":[{"results":[{"ruleId":"fixture-exit-%s"}]}]}\n' "$KEYHOG_FIXTURE_EXIT" > "$report"
exit "$KEYHOG_FIXTURE_EXIT"
"#,
        );

        let github_output = case.path().join("github-output.txt");
        let path = format!(
            "{}:{}",
            bin_dir.display(),
            env::var("PATH").expect("PATH is set")
        );
        let exit_text = exit_code.to_string();
        let capture = run_shell(
            &workflow.capture,
            case.path(),
            &[
                ("PATH", &path),
                (
                    "GITHUB_OUTPUT",
                    github_output.to_str().expect("output path"),
                ),
                ("KEYHOG_FIXTURE_EXIT", &exit_text),
            ],
        );
        assert_eq!(
            capture.status.code(),
            Some(0),
            "capture must release the workflow for upload after keyhog exit {exit_code}; stdout={} stderr={}",
            String::from_utf8_lossy(&capture.stdout),
            String::from_utf8_lossy(&capture.stderr)
        );
        assert_eq!(
            fs::read_to_string(&github_output).expect("capture wrote GITHUB_OUTPUT"),
            format!("exit-code={exit_code}\n"),
            "capture must preserve the exact keyhog status"
        );

        let report = case.path().join(&workflow.report);
        let expected_report = format!(
            "{{\"version\":\"2.1.0\",\"runs\":[{{\"results\":[{{\"ruleId\":\"fixture-exit-{exit_code}\"}}]}}]}}\n"
        );
        assert_eq!(
            fs::read_to_string(&report).expect("capture produced SARIF"),
            expected_report,
            "capture must leave the report available to upload"
        );

        let uploaded = case.path().join(format!("uploaded-{exit_code}.sarif"));
        let upload = upload_report(&report, &uploaded);
        assert!(
            upload.status.success(),
            "SARIF upload must complete before enforcement for exit {exit_code}; stdout={} stderr={}",
            String::from_utf8_lossy(&upload.stdout),
            String::from_utf8_lossy(&upload.stderr)
        );
        assert_eq!(
            fs::read_to_string(&uploaded).expect("uploaded SARIF exists"),
            expected_report,
            "upload must preserve the report bytes"
        );

        let enforce = run_shell(
            &workflow.enforce,
            case.path(),
            &[("KEYHOG_EXIT", &exit_text)],
        );
        assert_eq!(
            enforce.status.code(),
            Some(exit_code),
            "enforcement must restore keyhog exit {exit_code} after upload; stdout={} stderr={}",
            String::from_utf8_lossy(&enforce.stdout),
            String::from_utf8_lossy(&enforce.stderr)
        );
        assert_eq!(
            fs::read_to_string(&uploaded).expect("uploaded SARIF remains available"),
            expected_report,
            "enforcement must not remove the uploaded evidence"
        );
    }
}

#[test]
fn documented_generic_shell_preserves_report_stderr_and_exact_exit() {
    let markdown = fs::read_to_string(docs_path()).expect("read CI guide");
    let script = fenced_block_after_heading(&markdown, "## Generic shell", "sh");

    for exit_code in std::iter::once(0).chain(PUBLIC_NONZERO_EXIT_CODES) {
        let case = TempDir::new().expect("case tempdir");
        let bin_dir = case.path().join("bin");
        fs::create_dir(&bin_dir).expect("create fixture bin directory");
        write_executable(
            &bin_dir.join("keyhog"),
            r#"#!/bin/sh
report=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      report=$2
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [ "$KEYHOG_FIXTURE_EXIT" -le 1 ]; then
  printf '[{"detector_id":"fixture-exit-%s"}]\n' "$KEYHOG_FIXTURE_EXIT" > "$report"
fi
printf 'fixture stderr %s\n' "$KEYHOG_FIXTURE_EXIT" >&2
exit "$KEYHOG_FIXTURE_EXIT"
"#,
        );

        let path = format!(
            "{}:{}",
            bin_dir.display(),
            env::var("PATH").expect("PATH is set")
        );
        let exit_text = exit_code.to_string();
        let output = run_posix_shell(
            &script,
            case.path(),
            &[("PATH", &path), ("KEYHOG_FIXTURE_EXIT", &exit_text)],
        );
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "generic shell must restore KeyHog exit {exit_code}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(case.path().join("keyhog.exit-code")).expect("saved exit status"),
            format!("{exit_code}\n")
        );
        assert_eq!(
            fs::read_to_string(case.path().join("keyhog.stderr")).expect("saved stderr"),
            format!("fixture stderr {exit_code}\n")
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            format!("fixture stderr {exit_code}\n"),
            "saved stderr must also remain visible in the job log"
        );
        let report = fs::read_to_string(case.path().join("keyhog.json"))
            .expect("generic shell always leaves valid JSON");
        if exit_code <= 1 {
            assert_eq!(
                report,
                format!("[{{\"detector_id\":\"fixture-exit-{exit_code}\"}}]\n")
            );
        } else {
            assert_eq!(
                report, "[]\n",
                "an operational failure before report generation must preserve the initialized report"
            );
        }
        serde_json::from_str::<serde_json::Value>(&report).expect("report parses as JSON");
    }
}
