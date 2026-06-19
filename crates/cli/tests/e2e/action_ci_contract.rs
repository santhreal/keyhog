//! E2E contract for the composite GitHub Action scan step.

use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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

fn ci_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/ci.yml")
        .canonicalize()
        .expect("ci.yml exists")
}

fn differential_bench_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/differential-bench.yml")
        .canonicalize()
        .expect("differential-bench.yml exists")
}

fn keyhog_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).expect("write executable test stub");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path).expect("stub metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod stub");
    }
}

fn write_stub(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("keyhog");
    write_executable(&path, body);
    path
}

fn push_script_arg(args: &mut Vec<String>, flag: &str, value: &str) {
    args.push(flag.to_string());
    args.push(value.to_string());
}

fn action_script_args(script_args: &[&str], inputs: &[(&str, &str)]) -> Vec<String> {
    let mut args = Vec::new();
    push_script_arg(&mut args, "--path", ".");
    push_script_arg(&mut args, "--severity", "high");
    push_script_arg(&mut args, "--format", "sarif");
    push_script_arg(&mut args, "--output", "keyhog-results.sarif");
    push_script_arg(&mut args, "--verify", "false");
    push_script_arg(&mut args, "--fail-on-findings", "true");
    push_script_arg(&mut args, "--upload-sarif", "true");

    for (key, value) in inputs {
        match *key {
            "ACTION_INPUT_SCAN_PATH" => push_script_arg(&mut args, "--path", value),
            "ACTION_INPUT_SEVERITY" => push_script_arg(&mut args, "--severity", value),
            "ACTION_INPUT_FORMAT" => push_script_arg(&mut args, "--format", value),
            "ACTION_INPUT_OUTPUT" => push_script_arg(&mut args, "--output", value),
            "ACTION_INPUT_VERIFY" => push_script_arg(&mut args, "--verify", value),
            "ACTION_INPUT_BASELINE" => push_script_arg(&mut args, "--baseline", value),
            "ACTION_INPUT_BACKEND" => push_script_arg(&mut args, "--backend", value),
            "ACTION_INPUT_FAIL_ON_FINDINGS" => {
                push_script_arg(&mut args, "--fail-on-findings", value)
            }
            "ACTION_INPUT_UPLOAD_SARIF" => push_script_arg(&mut args, "--upload-sarif", value),
            _ => {}
        }
    }

    args.extend(script_args.iter().map(|arg| (*arg).to_string()));
    args
}

fn is_action_input_key(key: &str) -> bool {
    matches!(
        key,
        "ACTION_INPUT_SCAN_PATH"
            | "ACTION_INPUT_SEVERITY"
            | "ACTION_INPUT_FORMAT"
            | "ACTION_INPUT_OUTPUT"
            | "ACTION_INPUT_VERIFY"
            | "ACTION_INPUT_BASELINE"
            | "ACTION_INPUT_BACKEND"
            | "ACTION_INPUT_FAIL_ON_FINDINGS"
            | "ACTION_INPUT_UPLOAD_SARIF"
    )
}

fn run_action_with_script_args_and_path_prefix(
    dir: &TempDir,
    script_args: &[&str],
    path_prefix: &str,
    envs: &[(&str, &str)],
) -> Output {
    let output_path = dir.path().join("github-output.txt");
    let summary_path = dir.path().join("summary.md");
    let path = format!(
        "{}:{}:{}",
        path_prefix,
        dir.path().display(),
        env::var("PATH").expect("PATH is set")
    );

    let script_args = action_script_args(script_args, envs);
    let mut cmd = Command::new("bash");
    cmd.arg(action_script())
        .args(&script_args)
        .current_dir(dir.path())
        .env("PATH", path)
        .env("GITHUB_OUTPUT", &output_path)
        .env("GITHUB_STEP_SUMMARY", &summary_path);

    for (key, value) in envs {
        if !is_action_input_key(key) {
            cmd.env(key, value);
        }
    }

    cmd.output().expect("run action script")
}

fn run_action_with_path_prefix(dir: &TempDir, path_prefix: &str, envs: &[(&str, &str)]) -> Output {
    run_action_with_script_args_and_path_prefix(dir, &[], path_prefix, envs)
}

fn run_action_with_script_args(
    dir: &TempDir,
    script_args: &[&str],
    envs: &[(&str, &str)],
) -> Output {
    run_action_with_script_args_and_path_prefix(
        dir,
        script_args,
        dir.path().to_str().expect("utf-8 tempdir"),
        envs,
    )
}

fn run_action(dir: &TempDir, envs: &[(&str, &str)]) -> Output {
    run_action_with_path_prefix(dir, dir.path().to_str().expect("utf-8 tempdir"), envs)
}

fn run_action_raw_with_script_args(
    dir: &TempDir,
    script_args: &[&str],
    envs: &[(&str, &str)],
) -> Output {
    let output_path = dir.path().join("github-output.txt");
    let summary_path = dir.path().join("summary.md");
    let path = format!(
        "{}:{}",
        dir.path().display(),
        env::var("PATH").expect("PATH is set")
    );

    let mut cmd = Command::new("bash");
    cmd.arg(action_script())
        .args(script_args)
        .current_dir(dir.path())
        .env("PATH", path)
        .env("GITHUB_OUTPUT", &output_path)
        .env("GITHUB_STEP_SUMMARY", &summary_path);

    for (key, value) in envs {
        cmd.env(key, value);
    }

    cmd.output().expect("run raw action script")
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
fn ci_workflow_runs_standalone_cli_suites() {
    let workflow = fs::read_to_string(ci_workflow()).expect("read ci.yml");
    assert!(
        workflow.contains("cargo test -p keyhog --test property"),
        "CI must run the standalone CLI property suite instead of relying on all_tests"
    );
    assert!(
        workflow.contains("cargo test -p keyhog --test adversarial"),
        "CI must run the standalone CLI adversarial suite instead of relying on all_tests"
    );
    assert!(
        workflow.contains("--test-threads=4"),
        "adversarial CI must bound test parallelism because each test spawns keyhog"
    );
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
            ("ACTION_INPUT_SCAN_PATH", "repo"),
            ("ACTION_INPUT_FORMAT", "sarif"),
            ("ACTION_INPUT_OUTPUT", "real-keyhog.sarif"),
            ("ACTION_INPUT_SEVERITY", "high"),
            ("ACTION_INPUT_BACKEND", "simd"),
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
            ("ACTION_INPUT_SCAN_PATH", "repo"),
            ("ACTION_INPUT_FORMAT", "text"),
            ("ACTION_INPUT_OUTPUT", "real-keyhog.txt"),
            ("ACTION_INPUT_SEVERITY", "high"),
            ("ACTION_INPUT_BACKEND", "simd"),
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
fn action_prints_effective_config_before_real_scan_when_enabled() {
    let dir = TempDir::new().expect("tempdir");
    let calls = dir.path().join("calls.txt");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
printf '%s\n' "$cmd" >> "$CALLS_FILE"
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
if [[ "$cmd" == "config" ]]; then
  printf '[effective-config]\nmin_confidence = 0.4\n'
  exit 0
fi
if [[ "$cmd" != "scan" ]]; then
  echo "expected scan command after preflight, got $cmd" >&2
  exit 42
fi
cat > "$out" <<'JSON'
{"runs":[{"results":[]}]}
JSON
exit 0
"#,
    );

    let calls_path = calls.to_string_lossy().into_owned();
    let output = run_action_with_script_args(
        &dir,
        &["--print-effective-config"],
        &[("CALLS_FILE", calls_path.as_str())],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "effective-config preflight must not replace the real scan; output={}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output).contains("[effective-config]"),
        "CI log must include the resolved effective config; output={}",
        combined_output(&output)
    );
    assert_eq!(
        fs::read_to_string(&calls).expect("read calls"),
        "config\nscan\n",
        "action must run print-only preflight first, then the real scan"
    );
    assert!(
        output_file(&dir).contains("findings=0"),
        "real scan report must still be parsed after preflight"
    );
}

#[test]
fn action_effective_config_preflight_is_advisory_and_never_verifies() {
    let dir = TempDir::new().expect("tempdir");
    let calls = dir.path().join("calls.txt");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
out=""
has_verify=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output)
      shift
      out="$1"
      ;;
    --verify)
      has_verify=true
      ;;
  esac
  shift || true
done
printf '%s verify=%s\n' "$cmd" "$has_verify" >> "$CALLS_FILE"
if [[ "$cmd" == "config" ]]; then
  if [[ "$has_verify" == "true" ]]; then
    echo "preflight must not run live verification" >&2
    exit 43
  fi
  echo "config preflight failed" >&2
  exit 1
fi
if [[ "$cmd" != "scan" ]]; then
  echo "expected scan command after preflight, got $cmd" >&2
  exit 42
fi
if [[ "$has_verify" != "true" ]]; then
  echo "real scan must preserve --verify" >&2
  exit 44
fi
cat > "$out" <<'JSON'
{"runs":[{"results":[]}]}
JSON
exit 0
"#,
    );

    let calls_path = calls.to_string_lossy().into_owned();
    let output = run_action_with_script_args(
        &dir,
        &["--print-effective-config"],
        &[
            ("CALLS_FILE", calls_path.as_str()),
            ("ACTION_INPUT_VERIFY", "true"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "preflight failures must not block report-producing scans; output={combined}"
    );
    assert!(
        combined
            .contains("keyhog effective-config preflight exited 1; continuing with the real scan"),
        "preflight fallback warning must be operator-visible; output={combined}"
    );
    assert_eq!(
        fs::read_to_string(&calls).expect("read calls"),
        "config verify=false\nscan verify=true\n",
        "preflight must skip --verify, while the real scan preserves it"
    );
    assert!(
        output_file(&dir).contains("findings=0"),
        "real scan report must still be parsed after advisory preflight"
    );
}

#[test]
fn action_effective_config_preflight_cannot_mask_real_scan_missing_report() {
    let dir = TempDir::new().expect("tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    let calls = dir.path().join("calls.txt");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '%s output=%s\n' "$cmd" "$out" >> "$CALLS_FILE"
if [[ "$cmd" == "config" ]]; then
  if [[ -n "$out" ]]; then
    echo "config preflight must not receive --output" >&2
    exit 43
  fi
  exit 0
fi
if [[ "$cmd" != "scan" ]]; then
  echo "expected scan command after preflight, got $cmd" >&2
  exit 42
fi
exit 1
"#,
    );

    let calls_path = calls.to_string_lossy().into_owned();
    let runner_temp_path = runner_temp.to_string_lossy().into_owned();
    let output = run_action_with_script_args(
        &dir,
        &["--print-effective-config"],
        &[
            ("CALLS_FILE", calls_path.as_str()),
            ("RUNNER_TEMP", runner_temp_path.as_str()),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a stale preflight report must not hide a real findings exit without a report; output={combined}"
    );
    assert!(
        combined.contains("keyhog exited 1 but did not write 'keyhog-results.sarif'"),
        "missing real report must be operator-visible; output={combined}"
    );

    let calls_text = fs::read_to_string(&calls).expect("read calls");
    let mut lines = calls_text.lines();
    let preflight = lines.next().expect("preflight call");
    let real_scan = lines.next().expect("real scan call");
    assert!(
        lines.next().is_none(),
        "action should invoke exactly one preflight and one real scan; calls={calls_text}"
    );
    assert_eq!(
        preflight, "config output=",
        "config preflight must not receive any report output path"
    );
    assert_eq!(
        real_scan, "scan output=keyhog-results.sarif",
        "real scan must own the final report path"
    );
    assert!(
        !dir.path().join("keyhog-results.sarif").exists(),
        "test stub never wrote the real report"
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
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.json"),
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

    let output = run_action(&dir, &[("ACTION_INPUT_FORMAT", "xml")]);
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

    for (key, value) in [
        ("ACTION_INPUT_SEVERITY", "emergency"),
        ("ACTION_INPUT_VERIFY", "yes"),
    ] {
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
        ("ACTION_INPUT_FAIL_ON_FINDINGS", "maybe"),
        ("ACTION_INPUT_UPLOAD_SARIF", "maybe"),
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
fn action_ignores_removed_keyhog_env_transport() {
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

    let output = run_action_raw_with_script_args(
        &dir,
        &[
            "--path",
            ".",
            "--severity",
            "high",
            "--format",
            "json",
            "--output",
            "explicit.json",
            "--verify",
            "false",
            "--fail-on-findings",
            "true",
            "--upload-sarif",
            "true",
        ],
        &[
            ("KEYHOG_SCAN_PATH", "wrong-path"),
            ("KEYHOG_SEVERITY", "emergency"),
            ("KEYHOG_FORMAT", "xml"),
            ("KEYHOG_OUTPUT", "env-selected.json"),
            ("KEYHOG_VERIFY", "yes"),
            ("KEYHOG_BASELINE", "env-baseline.json"),
            ("KEYHOG_BACKEND", "broken"),
            ("KEYHOG_FAIL_ON_FINDINGS", "maybe"),
            ("KEYHOG_UPLOAD_SARIF", "maybe"),
        ],
    );

    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "removed KEYHOG_* transport env must not affect the action wrapper; output={combined}"
    );
    assert!(
        dir.path().join("explicit.json").is_file(),
        "explicit argv report path must be used"
    );
    assert!(
        !dir.path().join("env-selected.json").exists(),
        "removed KEYHOG_OUTPUT env must not select the report path"
    );
    assert!(
        output_file(&dir).contains("findings=0"),
        "clean explicit JSON report must be parsed through GITHUB_OUTPUT"
    );
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
    let output = run_action(&dir, &[("ACTION_INPUT_SEVERITY", injected)]);
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
        manifest.contains("ACTION_FAIL_ON_FINDINGS: ${{ inputs.fail-on-findings }}"),
        "composite action must validate fail-on-findings in the tested script"
    );
    assert!(
        manifest.contains("ACTION_UPLOAD_SARIF: ${{ inputs.upload-sarif }}"),
        "composite action must validate upload-sarif in the tested script"
    );
    assert!(
        manifest.contains("--print-effective-config"),
        "composite action must print the resolved scanner config before the real scan"
    );
    assert!(
        manifest.contains("--fail-on-findings \"$ACTION_FAIL_ON_FINDINGS\""),
        "fail-on-findings must reach the tested script through argv"
    );
    assert!(
        manifest.contains("--upload-sarif \"$ACTION_UPLOAD_SARIF\""),
        "upload-sarif must reach the tested script through argv"
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
fn composite_action_artifact_name_is_matrix_scoped() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let artifact_step = manifest
        .split("- name: Upload scan report as workflow artifact")
        .nth(1)
        .and_then(|rest| rest.split("    - name:").next())
        .expect("artifact upload step exists");

    assert!(
        artifact_step.contains("if: always() && steps.report-check.outputs.exists == 'true'"),
        "report artifact upload must still run after scan/SARIF failures so CI users can inspect the report"
    );
    assert!(
        !manifest.contains("name: keyhog-report\n"),
        "workflow artifacts must not use one constant name; matrix CI jobs would collide"
    );
    assert!(
        artifact_step.contains(
            "name: keyhog-report-${{ github.job }}-${{ strategy.job-index || '0' }}-${{ github.run_attempt }}-${{ steps.scan.outputs.duration-ms || 'unknown-duration' }}"
        ),
        "artifact name must include job, matrix index, run attempt, and scan-duration context to avoid matrix/retry collisions"
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
        upload_step.contains(
            "uses: github/codeql-action/upload-sarif@dd903d2e4f5405488e5ef1422510ee31c8b32357 # v3"
        ),
        "SARIF upload must use a SHA-pinned GitHub Code Scanning action"
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
        manifest.contains("ACTION_EXIT_CODE: ${{ steps.scan.outputs.exit-code }}"),
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
fn composite_action_fail_step_waits_for_scan_outputs() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let fail_step = manifest
        .split("- name: Fail when findings reported")
        .nth(1)
        .and_then(|rest| rest.split("    - name:").next())
        .expect("final fail step exists");

    assert!(
        fail_step.contains("steps.scan.outputs.findings != ''"),
        "final findings failure must not run when the scan wrapper failed before writing findings output"
    );
    assert!(
        fail_step.contains("steps.scan.outputs.exit-code != ''"),
        "final findings failure must not run when the scan wrapper failed before writing exit-code output"
    );
    assert!(
        fail_step.contains("steps.scan.outputs.exit-code == '10'"),
        "live credential failures must still run through the final fail step"
    );
}

#[test]
fn composite_action_fail_step_exits_ten_for_live_credentials() {
    let output = run_manifest_bash_step(
        "Fail when findings reported",
        &[
            ("ACTION_FINDINGS", "1"),
            ("ACTION_EXIT_CODE", "10"),
            ("ACTION_SEVERITY", "high"),
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
            ("ACTION_FINDINGS", "2"),
            ("ACTION_EXIT_CODE", "1"),
            ("ACTION_SEVERITY", "critical"),
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
            ("ACTION_FINDINGS", "1"),
            ("ACTION_EXIT_CODE", injected),
            ("ACTION_SEVERITY", "high"),
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
        manifest.contains("ACTION_VERSION: ${{ inputs.version }}"),
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
        manifest.contains(
            "printf 'release_required=%s\\n' \"$release_required\" >> \"$GITHUB_OUTPUT\""
        ),
        "version resolver must expose whether source-build fallback is allowed"
    );
    assert!(
        manifest.contains("ACTION_RELEASE_REQUIRED: ${{ steps.version.outputs.release_required }}"),
        "download step must receive the release-required decision through env"
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
        !manifest.contains("Invalid findings output '${ACTION_FINDINGS:-}'"),
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
        manifest.contains("startsWith(steps.asset.outputs.name, 'keyhog-linux-x86_64')"),
        "both CPU and CUDA Linux prebuilts must install the Hyperscan runtime they link against"
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
        manifest.contains("refusing source-build fallback for a required release"),
        "missing required release assets/checksums must fail closed instead of source-building silently"
    );
}

#[test]
fn composite_action_required_release_download_failure_fails_closed() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin");
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
exit 22
"#,
    );
    let output_path = dir.path().join("github-output.txt");
    let output_path_str = output_path.to_string_lossy().into_owned();
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("create runner temp");
    let runner_temp_str = runner_temp.to_string_lossy().into_owned();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let output = run_manifest_bash_step(
        "Try downloading prebuilt binary",
        &[
            ("PATH", path.as_str()),
            ("GITHUB_OUTPUT", output_path_str.as_str()),
            ("RUNNER_TEMP", runner_temp_str.as_str()),
            ("ACTION_ASSET_NAME", "keyhog-linux-x86_64"),
            ("ACTION_RESOLVED_VERSION", "0.5.37"),
            ("ACTION_RELEASE_REQUIRED", "true"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "required release download miss must fail closed; output={combined}"
    );
    assert!(
        combined.contains("refusing source-build fallback for a required release"),
        "failure must explain that source-build fallback is forbidden for release refs; output={combined}"
    );
}

#[test]
fn composite_action_branch_ref_download_failure_allows_source_build() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin");
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
exit 22
"#,
    );
    let output_path = dir.path().join("github-output.txt");
    let output_path_str = output_path.to_string_lossy().into_owned();
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("create runner temp");
    let runner_temp_str = runner_temp.to_string_lossy().into_owned();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let output = run_manifest_bash_step(
        "Try downloading prebuilt binary",
        &[
            ("PATH", path.as_str()),
            ("GITHUB_OUTPUT", output_path_str.as_str()),
            ("RUNNER_TEMP", runner_temp_str.as_str()),
            ("ACTION_ASSET_NAME", "keyhog-linux-x86_64"),
            ("ACTION_RESOLVED_VERSION", "main"),
            ("ACTION_RELEASE_REQUIRED", "false"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "branch/SHA download miss may continue to source build; output={combined}"
    );
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    assert!(
        github_output.contains("found=false"),
        "branch/SHA miss must advertise source-build path; output={github_output}"
    );
}

#[test]
fn composite_action_detects_cuda_linux_release_asset() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin");
    write_executable(
        &fake_bin.join("uname"),
        r#"#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 2 ;;
esac
"#,
    );
    write_executable(
        &fake_bin.join("nvidia-smi"),
        r#"#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -L) printf 'GPU 0: NVIDIA GeForce RTX 5090 (UUID: GPU-test)\n' ;;
  *) printf 'NVIDIA GeForce RTX 5090\n' ;;
esac
"#,
    );
    write_executable(
        &fake_bin.join("ldconfig"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf 'libcuda.so.1 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libcuda.so.1\n'
"#,
    );
    write_executable(
        &fake_bin.join("nvcc"),
        r#"#!/usr/bin/env bash
set -euo pipefail
exit 0
"#,
    );
    let output_path = dir.path().join("github-output.txt");
    let output_path_str = output_path.to_string_lossy().into_owned();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let output = run_manifest_bash_step(
        "Detect platform asset name",
        &[
            ("PATH", path.as_str()),
            ("GITHUB_OUTPUT", output_path_str.as_str()),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "CUDA Linux asset detection must run under bash; output={combined}"
    );
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    assert!(
        github_output.contains("name=keyhog-linux-x86_64-cuda"),
        "CUDA-ready Linux runners must use the published CUDA prebuilt asset; output={github_output}"
    );
}

#[test]
fn composite_action_source_build_preserves_cuda_feature_request() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    let source_root = dir.path().join("source");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&fake_bin).expect("create fake bin");
    fs::create_dir(&source_root).expect("create source root");
    fs::create_dir(&runner_temp).expect("create runner temp");
    let cargo_args = dir.path().join("cargo-args.txt");
    write_executable(
        &fake_bin.join("uname"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf 'Linux\n'
"#,
    );
    write_executable(
        &fake_bin.join("cargo"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$CARGO_ARGS_FILE"
mkdir -p target/release
printf 'fake-keyhog' > target/release/keyhog
chmod +x target/release/keyhog
"#,
    );
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let source_root_str = source_root.to_string_lossy().into_owned();
    let runner_temp_str = runner_temp.to_string_lossy().into_owned();
    let cargo_args_str = cargo_args.to_string_lossy().into_owned();
    let output = run_manifest_bash_step(
        "Build keyhog from source (fallback)",
        &[
            ("PATH", path.as_str()),
            ("ACTION_SOURCE_ROOT", source_root_str.as_str()),
            ("RUNNER_TEMP", runner_temp_str.as_str()),
            ("ACTION_ASSET_NAME", "keyhog-linux-x86_64-cuda"),
            ("CARGO_ARGS_FILE", cargo_args_str.as_str()),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "CUDA source-build fallback must run with fake cargo; output={combined}"
    );
    let args = fs::read_to_string(&cargo_args).expect("read cargo args");
    assert!(
        args.contains("--locked\n"),
        "source fallback must build against the committed lockfile; args={args}"
    );
    assert!(
        args.contains("--features\ncuda\n"),
        "CUDA source fallback must preserve the requested CUDA feature; args={args}"
    );
    assert!(
        runner_temp.join("keyhog").is_file(),
        "source-build fallback must still install the built binary into RUNNER_TEMP"
    );
}

#[test]
fn composite_action_detects_windows_release_asset() {
    let dir = TempDir::new().expect("tempdir");
    write_executable(
        &dir.path().join("uname"),
        r#"#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -s) printf 'MINGW64_NT-10.0\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 2 ;;
esac
"#,
    );
    let output_path = dir.path().join("github-output.txt");
    let output_path_str = output_path.to_string_lossy().into_owned();
    let path = format!(
        "{}:{}",
        dir.path().display(),
        env::var("PATH").expect("PATH is set")
    );
    let output = run_manifest_bash_step(
        "Detect platform asset name",
        &[
            ("PATH", path.as_str()),
            ("GITHUB_OUTPUT", output_path_str.as_str()),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "Windows asset detection must run under bash; output={combined}"
    );
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    assert!(
        github_output.contains("name=keyhog-windows-x86_64.exe"),
        "Windows GitHub runners must use the published prebuilt asset; output={github_output}"
    );
}

#[test]
fn composite_action_download_preserves_windows_exe_name() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin");
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
if [[ -z "$out" ]]; then
  exit 9
fi
case "$out" in
  *.sha256) printf 'fake  keyhog-windows-x86_64.exe\n' > "$out" ;;
  *) printf 'windows-binary' > "$out" ;;
esac
"#,
    );
    write_executable(
        &fake_bin.join("sha256sum"),
        r#"#!/usr/bin/env bash
set -euo pipefail
exit 0
"#,
    );
    let output_path = dir.path().join("github-output.txt");
    let output_path_str = output_path.to_string_lossy().into_owned();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let runner_temp = dir.path().join("runner-temp");
    let runner_temp_str = runner_temp.to_string_lossy().into_owned();
    fs::create_dir(&runner_temp).expect("create runner temp");
    let output = run_manifest_bash_step(
        "Try downloading prebuilt binary",
        &[
            ("PATH", path.as_str()),
            ("GITHUB_OUTPUT", output_path_str.as_str()),
            ("RUNNER_TEMP", runner_temp_str.as_str()),
            ("ACTION_ASSET_NAME", "keyhog-windows-x86_64.exe"),
            ("ACTION_RESOLVED_VERSION", "0.5.37"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "Windows prebuilt download path must complete with local fake tools; output={combined}"
    );
    assert!(
        runner_temp.join("keyhog.exe").is_file(),
        "Windows prebuilt must be installed as keyhog.exe so PATH lookup can execute it"
    );
    assert!(
        !runner_temp.join("keyhog").exists(),
        "Windows prebuilt must not be renamed to an extensionless binary"
    );
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    assert!(
        github_output.contains("found=true"),
        "verified Windows prebuilt download must advertise found=true; output={github_output}"
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
        workflow.contains("ACTION_FINDINGS: ${{ steps.keyhog.outputs.findings }}"),
        "strict-marker step must receive action findings through env"
    );
    assert!(
        workflow.contains("ACTION_EXIT_CODE: ${{ steps.keyhog.outputs.exit-code }}"),
        "strict-marker step must receive action exit code through env"
    );
    assert!(
        !workflow.contains("KEYHOG_FINDINGS") && !workflow.contains("KEYHOG_EXIT_CODE"),
        "strict-marker workflow must not resurrect KEYHOG_* internal env transport"
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
fn differential_bench_smoke_fails_closed_before_scoring() {
    let workflow =
        fs::read_to_string(differential_bench_workflow()).expect("read differential-bench.yml");
    let smoke = workflow
        .split("- name: keyhog smoke check (broken binary != F1 regression)")
        .nth(1)
        .and_then(|tail| tail.split("- name: generate mirror corpus").next())
        .expect("keyhog smoke step exists");
    assert!(
        smoke.contains("--format json --output \"$report\""),
        "smoke scan must write a parseable report artifact"
    );
    assert!(
        smoke.contains("case \"$rc\" in") && smoke.contains("1 | 10) ;;"),
        "smoke scan must accept only findings/live-findings exit codes"
    );
    assert!(
        smoke.contains("json.loads(report.read_text())"),
        "smoke scan must parse JSON directly from the report file"
    );
    for retired in [
        "|| echo 0",
        "2>/dev/null || true",
        "d=json.loads(t) if t else []",
    ] {
        assert!(
            !smoke.contains(retired),
            "smoke scan must not convert scanner/report failures into zero findings: {retired}"
        );
    }
}

#[test]
fn differential_bench_installs_verified_keyhog_release_binary() {
    let workflow =
        fs::read_to_string(differential_bench_workflow()).expect("read differential-bench.yml");
    let install = workflow
        .split("- name: install keyhog (release binary)")
        .nth(1)
        .and_then(|tail| tail.split("- name: install trufflehog").next())
        .expect("keyhog release install step exists");
    assert!(
        install.contains("asset=\"keyhog-linux-x86_64\""),
        "differential bench must name the release asset once and verify that exact file"
    );
    assert!(
        install.contains("\"$url.sha256\""),
        "differential bench must download the matching release checksum"
    );
    assert!(
        install.contains("sha256sum -c \"$asset.sha256\""),
        "differential bench must verify the release checksum before PATH install"
    );
    assert!(
        install.contains("install -m 0755 \"$RUNNER_TEMP/$asset\" \"$HOME/.local/bin/keyhog\""),
        "differential bench must install only the verified temporary asset"
    );
    assert!(
        !install.contains("-o \"$HOME/.local/bin/keyhog\""),
        "differential bench must not curl a release binary straight into PATH"
    );
}

#[test]
fn ci_install_from_build_proof_requires_expect_setup() {
    let workflow = fs::read_to_string(ci_workflow()).expect("read ci.yml");
    let install = workflow
        .split("- name: install-from-build proof (Linux)")
        .nth(1)
        .and_then(|tail| tail.split("- name: Dogfood self-scan").next())
        .expect("Linux install-from-build proof step exists");
    assert!(
        install.contains("sudo apt-get install -y --no-install-recommends expect"),
        "Linux install proof must install expect before exercising interactive installer paths"
    );
    for retired in [
        "expect || true",
        "apt-get install -y --no-install-recommends expect || true",
    ] {
        assert!(
            !install.contains(retired),
            "Linux install proof must fail closed if expect cannot be installed: {retired}"
        );
    }
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
            ("ACTION_INPUT_SCAN_PATH", "src path/with space"),
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "report.json"),
            ("ACTION_INPUT_VERIFY", "true"),
            ("ACTION_INPUT_BASELINE", "baseline path/with space.json"),
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
            ("ACTION_INPUT_FORMAT", "text"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.txt"),
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
    let scan = fs::read_to_string(action_script()).expect("read run-scan.sh");
    assert!(
        !scan.contains("grep -c 'Secret:' \"$report_path\" 2>/dev/null || true"),
        "text report counter must not turn grep/read errors into zero findings"
    );
    assert!(
        scan.contains("grep_status=$?") && scan.contains("0 | 1)"),
        "text report counter must distinguish no matches from grep/read errors"
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
            ("ACTION_INPUT_FORMAT", "jsonl"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.jsonl"),
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
            ("ACTION_INPUT_FORMAT", "jsonl"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.jsonl"),
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
            ("ACTION_INPUT_FORMAT", "jsonl"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.jsonl"),
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
            ("ACTION_INPUT_FORMAT", "jsonl"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.jsonl"),
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
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "report.json"),
            ("ACTION_INPUT_SCAN_PATH", "src|`name\nsecond"),
            ("ACTION_INPUT_BASELINE", "base|`line\nthird"),
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
