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

fn normalize_doc_text(text: &str) -> String {
    text.replace("<code>", " ")
        .replace("</code>", " ")
        .replace('`', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

fn integration_smoke_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/integration-smoke.yml")
        .canonicalize()
        .expect("integration-smoke.yml exists")
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
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root exists");
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(block);
    cmd.env("ACTION_SOURCE_ROOT", source_root);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("run manifest shell block")
}

fn run_release_download_harness(
    tar_entry: &str,
    tar_kind: &str,
    artifact_extension: &str,
    checksum_exit: &str,
    signature_exit: &str,
    preplant_programs_symlink: bool,
) -> (TempDir, Output) {
    let dir = TempDir::new().expect("release download harness tempdir");
    let fake_bin = dir.path().join("bin");
    let runner_temp = dir.path().join("runner-temp");
    let cache_root = dir.path().join("cache");
    fs::create_dir(&fake_bin).expect("create fake bin");
    fs::create_dir(&runner_temp).expect("create runner temp");
    if preplant_programs_symlink {
        #[cfg(unix)]
        {
            let keyhog_cache = cache_root.join("keyhog");
            let redirected = dir.path().join("redirected-programs");
            fs::create_dir_all(&keyhog_cache).expect("create keyhog cache root");
            fs::create_dir(&redirected).expect("create symlink target");
            std::os::unix::fs::symlink(&redirected, keyhog_cache.join("programs"))
                .expect("preplant programs symlink");
        }
        #[cfg(not(unix))]
        panic!("programs symlink harness requires Unix");
    }
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
url=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -o) shift; out="$1" ;;
    http*) url="$1" ;;
  esac
  shift || true
done
[[ -n "$out" && -n "$url" ]]
printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
case "$out" in
  *.sha256)
    target="$(basename "${out%.sha256}")"
    printf '%064d  %s\n' 0 "$target" > "$out"
    ;;
  *) printf 'payload' > "$out" ;;
esac
"#,
    );
    write_executable(
        &fake_bin.join("sha256sum"),
        r#"#!/usr/bin/env bash
set -euo pipefail
exit "$FAKE_SHA_EXIT"
"#,
    );
    write_executable(
        &fake_bin.join("minisign"),
        r#"#!/usr/bin/env bash
set -euo pipefail
exit "$FAKE_SIGNATURE_EXIT"
"#,
    );
    write_executable(
        &fake_bin.join("tar"),
        r#"#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -tzf) printf '%s\n' "$FAKE_TAR_ENTRY" ;;
  -tvzf) printf '%s rw-r--r-- 0/0 1 Jan 1 00:00 %s\n' "$FAKE_TAR_KIND" "$FAKE_TAR_ENTRY" ;;
  -xzf)
    destination=""
    while [[ "$#" -gt 0 ]]; do
      if [[ "$1" == "-C" ]]; then shift; destination="$1"; fi
      shift || true
    done
    [[ -n "$destination" ]]
    printf 'matcher' > "$destination/literal-program.$FAKE_ARTIFACT_EXTENSION"
    ;;
  *) exit 9 ;;
esac
"#,
    );

    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let output_path = dir.path().join("github-output.txt");
    let curl_log = dir.path().join("curl.log");
    let output = run_manifest_bash_step(
        "Try downloading prebuilt binary",
        &[
            ("PATH", path.as_str()),
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("UTF-8 temp path"),
            ),
            (
                "GITHUB_OUTPUT",
                output_path.to_str().expect("UTF-8 output path"),
            ),
            ("ACTION_ASSET_NAME", "keyhog-linux-x86_64"),
            ("ACTION_RESOLVED_VERSION", "0.5.41"),
            ("ACTION_RELEASE_REQUIRED", "true"),
            ("RUNNER_OS", "Linux"),
            (
                "XDG_CACHE_HOME",
                cache_root.to_str().expect("UTF-8 cache path"),
            ),
            ("FAKE_CURL_LOG", curl_log.to_str().expect("UTF-8 curl log")),
            ("FAKE_TAR_ENTRY", tar_entry),
            ("FAKE_TAR_KIND", tar_kind),
            ("FAKE_ARTIFACT_EXTENSION", artifact_extension),
            ("FAKE_SHA_EXIT", checksum_exit),
            ("FAKE_SIGNATURE_EXIT", signature_exit),
            ("KEYHOG_MINISIGN_PUBLIC_KEY", "test-public-key"),
        ],
    );
    (dir, output)
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
fn action_quick_start_scans_the_checked_out_workspace_by_default() {
    let checked_out = TempDir::new().expect("checked-out workspace tempdir");
    fs::write(
        checked_out.path().join("secret.env"),
        "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\n",
    )
    .expect("write planted secret");

    let binary = keyhog_binary();
    let binary_dir = binary
        .parent()
        .expect("binary parent")
        .to_str()
        .expect("utf-8 binary dir");
    let finding =
        run_action_with_path_prefix(&checked_out, binary_dir, &[("ACTION_INPUT_BACKEND", "cpu")]);
    assert_eq!(
        finding.status.code(),
        Some(0),
        "quick-start finding must use the action findings path; output={}",
        combined_output(&finding)
    );
    assert!(
        output_file(&checked_out).contains("findings=1"),
        "default action path must scan the checked-out workspace"
    );

    let no_checkout = TempDir::new().expect("empty workspace tempdir");
    let clean =
        run_action_with_path_prefix(&no_checkout, binary_dir, &[("ACTION_INPUT_BACKEND", "cpu")]);
    assert_eq!(
        clean.status.code(),
        Some(0),
        "an empty no-checkout workspace should remain clean; output={}",
        combined_output(&clean)
    );
    assert!(
        output_file(&no_checkout).contains("findings=0"),
        "the action must not claim repository coverage without checked-out content"
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
    assert!(
        output_file(&dir).contains("scan-status=failed\n"),
        "malformed findings reports must publish a failed completion state"
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
        output_file(&dir).contains("scan-status=failed\n"),
        "malformed live reports must publish a failed completion state"
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
    let receipt = output_file(&dir);
    assert!(
        receipt.contains("exit-code=0\n")
            && receipt.contains("scan-status=failed\n")
            && receipt.contains("report-present=false\n"),
        "missing clean reports must publish an honest failed receipt; receipt={receipt}"
    );
}

#[test]
fn action_publishes_receipt_before_invalid_config_exit() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(&dir, "#!/usr/bin/env bash\nexit 2\n");

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid config must preserve the scanner exit code; output={}",
        combined_output(&output)
    );
    let receipt = output_file(&dir);
    assert!(
        receipt.contains("exit-code=2\n"),
        "invalid config must publish the raw scanner exit code; receipt={receipt}"
    );
    assert!(
        receipt.contains("scan-status=failed\n"),
        "invalid config must publish a failed typed completion state; receipt={receipt}"
    );
    assert!(
        receipt.contains("report-present=false\n"),
        "invalid config without a report must publish report presence; receipt={receipt}"
    );
    assert!(
        receipt
            .lines()
            .find_map(|line| line.strip_prefix("duration-ms="))
            .and_then(|value| value.parse::<u64>().ok())
            .is_some(),
        "invalid config must publish a numeric duration; receipt={receipt}"
    );
    let summary = summary_file(&dir);
    assert!(
        summary.contains("| Completion status | `failed` |")
            && summary.contains("| Report present | `false` |"),
        "failure summary must retain typed state and report presence; summary={summary}"
    );
}

#[test]
fn action_publishes_partial_receipt_before_incomplete_coverage_exit() {
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
printf '{"runs":[{"results":[]}]}' > "$out"
exit 13
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(13),
        "incomplete coverage must preserve the scanner exit code; output={}",
        combined_output(&output)
    );
    let receipt = output_file(&dir);
    assert!(
        receipt.contains("exit-code=13\n") && receipt.contains("scan-status=partial\n"),
        "incomplete coverage must publish raw code and partial state; receipt={receipt}"
    );
    assert!(
        receipt.contains("report-present=true\n"),
        "incomplete coverage with a report must publish report presence; receipt={receipt}"
    );
    let summary = summary_file(&dir);
    assert!(
        summary.contains("| Completion status | `partial` |")
            && summary.contains("| Exit code | `13` |"),
        "incomplete coverage summary must distinguish the partial terminal class; summary={summary}"
    );
}

#[test]
fn action_publishes_failure_receipt_before_internal_scanner_exit() {
    let dir = TempDir::new().expect("tempdir");
    write_stub(&dir, "#!/usr/bin/env bash\nexit 11\n");

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(11),
        "internal scanner failure must preserve the scanner exit code; output={}",
        combined_output(&output)
    );
    let receipt = output_file(&dir);
    assert!(
        receipt.contains("exit-code=11\n")
            && receipt.contains("scan-status=failed\n")
            && receipt.contains("report-present=false\n"),
        "internal scanner failure must publish a complete failure receipt; receipt={receipt}"
    );
    let summary = summary_file(&dir);
    assert!(
        summary.contains("| Completion status | `failed` |")
            && summary.contains("| Exit code | `11` |"),
        "internal scanner failure summary must retain the panic exit class; summary={summary}"
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
fn action_accepts_client_safe_severity_and_forwards_it_exactly() {
    let dir = TempDir::new().expect("tempdir");
    let seen = dir.path().join("severity");
    write_stub(
        &dir,
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --severity) shift; printf '%s' "$1" > '{}' ;;
    --output) shift; out="$1" ;;
  esac
  shift
done
printf '[]\n' > "$out"
"#,
            seen.display()
        ),
    );

    let output = run_action(
        &dir,
        &[
            ("ACTION_INPUT_SEVERITY", "client-safe"),
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "results.json"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "client-safe must be accepted by the Action wrapper: {}",
        combined_output(&output)
    );
    assert_eq!(
        fs::read_to_string(seen).expect("recorded severity"),
        "client-safe"
    );
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
    assert!(
        manifest.contains("scan-status:")
            && manifest.contains("value: ${{ steps.scan.outputs.scan-status }}"),
        "typed scan status output must come from the tested scan script"
    );
    assert!(
        manifest.contains("report-present:")
            && manifest.contains("value: ${{ steps.scan.outputs.report-present }}"),
        "report presence output must come from the tested scan script"
    );
}

#[test]
fn composite_action_analysis_categories_produce_distinct_report_identities() {
    let dir = TempDir::new().expect("tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    for (index, (category, format, expected_name)) in [
        ("services-api", "sarif", "keyhog-results-services-api.sarif"),
        ("services-web", "json", "keyhog-results-services-web.json"),
    ]
    .into_iter()
    .enumerate()
    {
        let github_output = dir.path().join(format!("output-{index}"));
        let output = run_manifest_bash_step(
            "Compute output filename",
            &[
                ("ACTION_ANALYSIS_CATEGORY", category),
                ("ACTION_FORMAT", format),
                (
                    "GITHUB_OUTPUT",
                    github_output.to_str().expect("utf-8 output path"),
                ),
                (
                    "RUNNER_TEMP",
                    runner_temp.to_str().expect("utf-8 runner temp"),
                ),
                ("GITHUB_RUN_ID", "42"),
                ("GITHUB_RUN_ATTEMPT", "1"),
                ("GITHUB_JOB", "scan"),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "valid category must resolve: {}",
            combined_output(&output)
        );
        let resolved = fs::read_to_string(github_output).expect("identity outputs written");
        assert_eq!(
            resolved,
            format!("category={category}\nname={expected_name}\n")
        );
    }

    let duplicate_output = dir.path().join("duplicate-output");
    let duplicate = run_manifest_bash_step(
        "Compute output filename",
        &[
            ("ACTION_ANALYSIS_CATEGORY", "services-api"),
            ("ACTION_FORMAT", "sarif"),
            (
                "GITHUB_OUTPUT",
                duplicate_output.to_str().expect("utf-8 output path"),
            ),
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("utf-8 runner temp"),
            ),
            ("GITHUB_RUN_ID", "42"),
            ("GITHUB_RUN_ATTEMPT", "1"),
            ("GITHUB_JOB", "scan"),
        ],
    );
    let combined = combined_output(&duplicate);
    assert_eq!(duplicate.status.code(), Some(2), "{combined}");
    assert!(
        combined.contains("Conflicting analysis-category"),
        "duplicate category must fail with an actionable diagnostic: {combined}"
    );
    assert!(!duplicate_output.exists());
}

#[test]
fn composite_action_rejects_ambiguous_analysis_categories_before_writing_identity() {
    let dir = TempDir::new().expect("tempdir");
    let too_long = "a".repeat(65);
    for (index, category) in [
        "",
        "Services-api",
        "services/api",
        "services api",
        ".hidden",
        "-flag",
        "api.",
        "api\nforged=value",
        too_long.as_str(),
    ]
    .into_iter()
    .enumerate()
    {
        let github_output = dir.path().join(format!("invalid-output-{index}"));
        let output = run_manifest_bash_step(
            "Compute output filename",
            &[
                ("ACTION_ANALYSIS_CATEGORY", category),
                ("ACTION_FORMAT", "sarif"),
                (
                    "GITHUB_OUTPUT",
                    github_output.to_str().expect("utf-8 output path"),
                ),
            ],
        );
        let combined = combined_output(&output);
        assert_eq!(
            output.status.code(),
            Some(2),
            "invalid category must fail before scan identity is written: {combined}"
        );
        assert!(
            combined.contains("Invalid analysis-category"),
            "category failure must be actionable: {combined}"
        );
        assert!(
            !github_output.exists(),
            "invalid category must not write a report or SARIF identity"
        );
    }
}

#[test]
fn composite_action_artifact_name_is_partition_and_matrix_scoped() {
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
            "name: keyhog-report-${{ steps.outfile.outputs.category }}-${{ github.job }}-${{ strategy.job-index || '0' }}-${{ github.run_attempt }}"
        ),
        "artifact name must include the stable analysis category, job, matrix index, and run attempt"
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
    assert!(
        upload_step.contains("category: ${{ steps.outfile.outputs.category }}"),
        "Code Scanning must receive the same validated partition identity as the report"
    );
}

#[test]
fn keyhog_workflow_covers_trusted_and_fork_sarif_permission_matrix() {
    let workflow_text = fs::read_to_string(keyhog_workflow()).expect("read keyhog.yml");
    let workflow: serde_yaml::Value =
        serde_yaml::from_str(&workflow_text).expect("keyhog.yml parses as YAML");
    let root = workflow.as_mapping().expect("keyhog.yml is a mapping");
    let jobs = yaml_get(root, "jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("keyhog.yml declares jobs");
    let scan = yaml_get(jobs, "scan")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("keyhog.yml declares the scan job");
    let permissions = yaml_get(scan, "permissions")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("trusted scan fixture declares job permissions");
    assert_eq!(
        yaml_get(permissions, "contents").and_then(serde_yaml::Value::as_str),
        Some("read"),
        "trusted SARIF scans must keep repository contents read-only"
    );
    assert_eq!(
        yaml_get(permissions, "security-events").and_then(serde_yaml::Value::as_str),
        Some("write"),
        "trusted scan fixture must grant the least privilege needed for SARIF upload"
    );

    let steps = yaml_get(scan, "steps")
        .and_then(serde_yaml::Value::as_sequence)
        .expect("scan job declares steps");
    let action_step = steps
        .iter()
        .find_map(|step| {
            let step = step.as_mapping()?;
            (yaml_get(step, "uses").and_then(serde_yaml::Value::as_str)
                == Some("./.github/actions/keyhog"))
            .then_some(step)
        })
        .expect("scan job invokes the bundled composite action");
    let action_inputs = yaml_get(action_step, "with")
        .and_then(serde_yaml::Value::as_mapping)
        .expect("scan action fixture declares inputs");
    assert_eq!(
        yaml_get(action_inputs, "format").and_then(serde_yaml::Value::as_str),
        Some("sarif"),
        "the trusted fixture must exercise the SARIF upload path"
    );
    assert_eq!(
        yaml_get(action_inputs, "upload-sarif").and_then(serde_yaml::Value::as_str),
        Some("true"),
        "the trusted fixture must leave SARIF upload enabled"
    );

    let action_text = fs::read_to_string(action_manifest()).expect("read action.yml");
    let action: serde_yaml::Value =
        serde_yaml::from_str(&action_text).expect("action.yml parses as YAML");
    let action_steps = action
        .get("runs")
        .and_then(|runs| runs.get("steps"))
        .and_then(serde_yaml::Value::as_sequence)
        .expect("composite action declares steps");
    let upload_step = action_steps
        .iter()
        .find_map(|step| {
            let step = step.as_mapping()?;
            (yaml_get(step, "name").and_then(serde_yaml::Value::as_str)
                == Some("Upload SARIF to code-scanning"))
            .then_some(step)
        })
        .expect("composite action declares a SARIF upload step");
    let continue_on_error = yaml_get(upload_step, "continue-on-error")
        .and_then(serde_yaml::Value::as_str)
        .expect("SARIF upload declares its permission fallback explicitly");
    assert_eq!(
        continue_on_error,
        "${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}",
        "only fork pull requests may turn a restricted-token upload failure into an advisory result"
    );

    // This local event fixture mirrors GitHub's trusted and restricted-token
    // contexts. It makes the permission contract executable without requiring
    // a networked Code Scanning upload from a unit-test runner.
    let fixtures = [
        ("push", "santhreal/keyhog", false),
        ("pull_request", "santhreal/keyhog", false),
        ("pull_request", "contributor/keyhog", true),
    ];
    for (event_name, head_repo, advisory) in fixtures {
        let is_fork_pr = event_name == "pull_request" && head_repo != "santhreal/keyhog";
        assert_eq!(
            is_fork_pr, advisory,
            "permission fixture must classify {event_name} from {head_repo} correctly"
        );
    }

    let action_readme = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.github/actions/keyhog/README.md"),
    )
    .expect("read composite action README");
    assert!(
        action_readme.contains("Set `upload-sarif: 'false'`"),
        "the action must document the upload-disabled alternative for workflows without write permission"
    );
    assert!(
        action_readme.contains("Fork PRs can\nlack `security-events: write`"),
        "the action must document that restricted fork uploads remain advisory"
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
        manifest.contains("Invalid version. Use only letters")
            && manifest.contains("Explicit version must be MAJOR.MINOR.PATCH"),
        "version resolver must not reflect rejected input into a workflow command"
    );
    assert!(
        manifest.contains(
            "bash \"$ACTION_SOURCE_ROOT/scripts/release-version.sh\" \"$ACTION_VERSION\""
        ) && !manifest.contains("[-+][A-Za-z0-9._-]+"),
        "the Action must use the shared release grammar and reject build metadata"
    );
    assert!(
        manifest.contains("v=\"${normalized_tag#v}\"")
            && manifest.contains("releases/download/v${version}")
            && manifest.contains("\"$release_url/$name\""),
        "an explicit version must normalize one optional v prefix before building the release URL"
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
fn composite_action_version_resolver_matches_publishable_tag_forms() {
    for (input, expected) in [
        ("0.5.41", "0.5.41"),
        ("v0.5.41", "0.5.41"),
        ("0.5.41-rc.1", "0.5.41-rc.1"),
    ] {
        let dir = TempDir::new().expect("version output tempdir");
        let output_path = dir.path().join("github-output.txt");
        let output = run_manifest_bash_step(
            "Resolve KeyHog version",
            &[
                ("ACTION_VERSION", input),
                (
                    "GITHUB_OUTPUT",
                    output_path.to_str().expect("UTF-8 output path"),
                ),
            ],
        );
        assert!(
            output.status.success(),
            "publishable version {input:?} must resolve: {}",
            combined_output(&output)
        );
        let resolved = fs::read_to_string(output_path).expect("read version output");
        assert_eq!(
            resolved,
            format!("version={expected}\nrelease_required=true\n")
        );
    }

    for rejected in ["0.5.41+build.7", "0.5.41-", "0.5", "main\nversion=owned"] {
        let dir = TempDir::new().expect("version output tempdir");
        let output_path = dir.path().join("github-output.txt");
        let output = run_manifest_bash_step(
            "Resolve KeyHog version",
            &[
                ("ACTION_VERSION", rejected),
                (
                    "GITHUB_OUTPUT",
                    output_path.to_str().expect("UTF-8 output path"),
                ),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "unpublishable version {rejected:?} must fail"
        );
        assert!(
            !output_path.exists()
                || fs::read_to_string(&output_path)
                    .expect("read rejected output")
                    .is_empty(),
            "a rejected version must not write workflow outputs"
        );
    }
}

#[test]
fn composite_action_floating_major_ref_resolves_exact_signed_release() {
    let dir = TempDir::new().expect("version output tempdir");
    let output_path = dir.path().join("github-output.txt");
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root exists");
    let output = run_manifest_bash_step(
        "Resolve KeyHog version",
        &[
            ("ACTION_VERSION", ""),
            ("GITHUB_ACTION_REF", "v0"),
            (
                "ACTION_SOURCE_ROOT",
                repo.to_str().expect("UTF-8 repository path"),
            ),
            (
                "GITHUB_OUTPUT",
                output_path.to_str().expect("UTF-8 output path"),
            ),
        ],
    );
    assert!(
        output.status.success(),
        "floating release ref must resolve the exact version from its checked-out source: {}",
        combined_output(&output)
    );
    assert_eq!(
        fs::read_to_string(output_path).expect("read version output"),
        format!(
            "version={}\nrelease_required=true\n",
            env!("CARGO_PKG_VERSION")
        )
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
        manifest.contains("Install release runtime and verifier (Linux prebuilt)"),
        "Linux release binary path must install its runtime and signature verifier"
    );
    assert!(
        manifest.contains("libhyperscan5") && manifest.contains("minisign"),
        "Linux prebuilt path must install libhyperscan5 and minisign before executing the release asset"
    );
    assert!(
        manifest.contains("startsWith(steps.asset.outputs.name, 'keyhog-linux-x86_64')"),
        "both CPU and CUDA Linux prebuilts must install the Hyperscan runtime they link against"
    );
    assert!(
        manifest.contains("$asset.minisig")
            && manifest.contains("$sidecar.minisig")
            && manifest.contains("KEYHOG_MINISIGN_PUBLIC_KEY"),
        "prebuilt download must authenticate the binary and GPU literal sidecar with the pinned key"
    );
    assert!(
        manifest.contains("sha256sum -c \"$asset.sha256\"")
            && manifest.contains("sha256sum -c \"$sidecar.sha256\"")
            || manifest.contains("shasum -a 256 -c \"$asset.sha256\"")
                && manifest.contains("shasum -a 256 -c \"$sidecar.sha256\""),
        "prebuilt download must verify both checksums before adding keyhog to PATH"
    );
    assert!(
        manifest.contains("GPU literal sidecar contains an unsafe path")
            && manifest.contains("GPU literal sidecar contains a link entry")
            && manifest.contains("GPU literal sidecar contains no matcher artifacts"),
        "the Action must validate and seed the authenticated sidecar rather than compile shipped matchers"
    );
    assert!(
        manifest.contains("refusing source-build fallback for a release ref"),
        "missing required release payloads must fail closed instead of source-building silently"
    );
}

#[test]
fn composite_action_authenticated_bundle_executes_all_six_exact_downloads() {
    let (dir, output) = run_release_download_harness("literal.bin", "-", "bin", "0", "0", false);
    assert!(
        output.status.success(),
        "valid authenticated bundle must install: {}",
        combined_output(&output)
    );
    let urls = fs::read_to_string(dir.path().join("curl.log")).expect("read curl log");
    let base = "https://github.com/santhreal/keyhog/releases/download/v0.5.41/";
    let expected = [
        "keyhog-linux-x86_64",
        "keyhog-linux-x86_64.sha256",
        "keyhog-linux-x86_64.minisig",
        "keyhog-linux-x86_64.gpu-literals.tar.gz",
        "keyhog-linux-x86_64.gpu-literals.tar.gz.sha256",
        "keyhog-linux-x86_64.gpu-literals.tar.gz.minisig",
    ]
    .map(|name| format!("{base}{name}"))
    .join("\n");
    assert_eq!(urls, format!("{expected}\n"));
    assert!(
        dir.path()
            .join("cache/keyhog/programs/literal-program.bin")
            .is_file(),
        "validated sidecar artifact must reach the platform cache"
    );
}

#[test]
fn composite_action_release_bundle_proofs_fail_closed() {
    for (checksum_exit, signature_exit, expected) in
        [("1", "0", "checksum"), ("0", "1", "signature")]
    {
        let (_dir, output) = run_release_download_harness(
            "literal.bin",
            "-",
            "bin",
            checksum_exit,
            signature_exit,
            false,
        );
        assert!(
            !output.status.success(),
            "invalid {expected} must stop release installation"
        );
    }
}

#[test]
fn composite_action_rejects_cross_platform_archive_traversal() {
    for unsafe_entry in [
        "../escape.bin",
        r"\escape.bin",
        "C:escape.bin",
        "nested/.. /escape.bin",
        "nested/.../escape.bin",
    ] {
        let (_dir, output) =
            run_release_download_harness(unsafe_entry, "-", "bin", "0", "0", false);
        let combined = combined_output(&output);
        assert_eq!(
            output.status.code(),
            Some(2),
            "unsafe entry {unsafe_entry:?} must fail closed: {combined}"
        );
        assert!(
            combined.contains("unsafe path"),
            "unsafe entry {unsafe_entry:?} must have an operator-visible reason: {combined}"
        );
    }
}

#[test]
fn composite_action_rejects_links_special_entries_and_empty_matcher_sets() {
    for (kind, extension, reason) in [
        ("l", "bin", "link entry"),
        ("p", "bin", "unsupported entry type"),
        ("-", "txt", "no matcher artifacts"),
    ] {
        let (_dir, output) =
            run_release_download_harness("literal.bin", kind, extension, "0", "0", false);
        let combined = combined_output(&output);
        assert_eq!(
            output.status.code(),
            Some(2),
            "invalid sidecar ({reason}) must fail closed: {combined}"
        );
        assert!(
            combined.contains(reason),
            "invalid sidecar must surface {reason:?}: {combined}"
        );
    }
}

#[cfg(unix)]
#[test]
fn composite_action_rejects_owned_cache_directory_symlinks() {
    let (dir, output) = run_release_download_harness("literal.bin", "-", "bin", "0", "0", true);
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "pre-planted programs symlink must fail closed: {combined}"
    );
    assert!(
        combined.contains("unsafe owned-directory symlink"),
        "cache rejection must be operator-visible: {combined}"
    );
    assert!(
        fs::read_dir(dir.path().join("redirected-programs"))
            .expect("read redirected target")
            .next()
            .is_none(),
        "Action must not stage through the owned programs symlink"
    );
}

#[test]
fn consumer_docs_state_release_assets_fail_closed_before_source_build() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root exists");
    let docs = [
        repo.join("README.md"),
        repo.join(".github/actions/keyhog/README.md"),
        repo.join("docs/src/workflows/ci.md"),
    ];
    let retired_claims = [
        "Auto-downloads a prebuilt binary; falls back to cargo build when no release asset matches",
        "falls back to source build if no prebuilt binary matches",
        "Auto-built binaries with source fallback",
        "falls back to a cargo build when no asset matches the host triple",
    ];

    for path in docs {
        let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!("read {}: {err}", path.display());
        });
        let normalized = normalize_doc_text(&raw);
        let lower = normalized.to_ascii_lowercase();
        for claim in retired_claims {
            assert!(
                !lower.contains(&claim.to_ascii_lowercase()),
                "{} still advertises the retired source-build fallback claim: {claim}",
                path.display()
            );
        }
        assert!(
            lower.contains("release tags"),
            "{} must describe release-tag behavior",
            path.display()
        );
        assert!(
            lower.contains("fail closed") || lower.contains("fails closed"),
            "{} must say missing release assets fail closed",
            path.display()
        );
        assert!(
            lower.contains("branch/sha"),
            "{} must scope source builds to branch/SHA action refs",
            path.display()
        );
        assert!(
            lower.contains("build from source") || lower.contains("source builds"),
            "{} must still document the allowed branch/SHA source-build path",
            path.display()
        );
    }
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
        combined.contains("refusing source-build fallback for a release ref"),
        "failure must explain that source-build fallback is forbidden for release refs; output={combined}"
    );
}

#[test]
fn composite_action_wires_resolved_asset_into_download_step() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action manifest");
    assert!(
        manifest.contains("ACTION_ASSET_NAME: ${{ steps.asset.outputs.name }}"),
        "the download step must receive the platform asset selected by the preceding asset step"
    );
}

#[test]
fn composite_action_calibrates_exact_workload_without_forcing_a_backend() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let step = manifest
        .split("- name: Calibrate autoroute for this scan")
        .nth(1)
        .and_then(|tail| tail.split("- name:").next())
        .expect("Calibrate autoroute step exists");
    assert!(
        step.contains("if: inputs.backend == '' || inputs.backend == 'auto'")
            && step.contains("--autoroute-calibrate")
            && step.contains("--autoroute-gpu")
            && step.contains("--path \"$ACTION_SCAN_PATH\"")
            && step.contains("--severity \"$ACTION_SEVERITY\"")
            && step.contains("config_args=(")
            && step.contains("  --effective")
            && step.contains("args+=(--baseline \"$ACTION_BASELINE\")")
            && step.contains("config_args+=(--baseline \"$ACTION_BASELINE\")")
            && step.contains("keyhog \"${args[@]}\""),
        "fresh and explicit-auto Action scans must calibrate the exact requested workload and policy"
    );
    assert!(
        !step.contains("--backend")
            && !step.contains("--no-autoroute-gpu")
            && !step.contains("calibration_passes")
            && !step.contains("for ((pass"),
        "Action calibration must measure eligible peers, not choose a route"
    );
}

#[test]
fn composite_action_calibration_executes_exact_argv_once_for_every_incremental_mode() {
    for incremental in ["false", "true"] {
        let dir = TempDir::new().expect("tempdir");
        let runner_temp = dir.path().join("runner-temp");
        fs::create_dir(&runner_temp).expect("runner temp");
        let call_log = dir.path().join("calls.bin");
        let config_log = dir.path().join("config.log");
        write_executable(
            &dir.path().join("keyhog"),
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "config" ]]; then
  printf '%s\0' "$@" > "$KEYHOG_CONFIG_LOG"
  printf '[effective-config]\nincremental = %s\n' "$STUB_INCREMENTAL"
  exit "${STUB_CONFIG_EXIT:-0}"
fi
printf '__CALL__\0' >> "$KEYHOG_CALL_LOG"
printf '%s\0' "$@" >> "$KEYHOG_CALL_LOG"
previous=""
for arg in "$@"; do
  if [[ "$previous" == "--output" ]]; then
    printf '[]\n' > "$arg"
  fi
  previous="$arg"
done
"#,
        );
        let path = format!(
            "{}:{}",
            dir.path().display(),
            env::var("PATH").expect("PATH")
        );
        let output = run_manifest_bash_step(
            "Calibrate autoroute for this scan",
            &[
                ("ACTION_SCAN_PATH", "repo slice"),
                ("ACTION_SEVERITY", "critical"),
                ("ACTION_BASELINE", "baseline file.json"),
                (
                    "RUNNER_TEMP",
                    runner_temp.to_str().expect("utf-8 runner temp"),
                ),
                ("GITHUB_RUN_ID", "42"),
                ("GITHUB_RUN_ATTEMPT", "3"),
                (
                    "KEYHOG_CALL_LOG",
                    call_log.to_str().expect("utf-8 call log"),
                ),
                (
                    "KEYHOG_CONFIG_LOG",
                    config_log.to_str().expect("utf-8 config log"),
                ),
                ("STUB_INCREMENTAL", incremental),
                ("PATH", &path),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "calibration step failed: {}",
            combined_output(&output)
        );
        let config_args = fs::read(&config_log)
            .expect("config invocation logged")
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .map(|field| String::from_utf8(field.to_vec()).expect("utf-8 config argument"))
            .collect::<Vec<_>>();
        assert_eq!(
            config_args,
            [
                "config",
                "--effective",
                "--path",
                "repo slice",
                "--severity",
                "critical",
                "--format",
                "json",
                "--baseline",
                "baseline file.json",
            ]
        );

        let fields = fs::read(&call_log)
            .expect("calibration calls logged")
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .map(|field| String::from_utf8(field.to_vec()).expect("utf-8 argument"))
            .collect::<Vec<_>>();
        let probe = runner_temp.join("keyhog-autoroute-probe-42-3.json");
        let expected = vec![
            "scan".to_string(),
            "--autoroute-calibrate".to_string(),
            "--autoroute-gpu".to_string(),
            "--path".to_string(),
            "repo slice".to_string(),
            "--severity".to_string(),
            "critical".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--output".to_string(),
            probe.display().to_string(),
            "--baseline".to_string(),
            "baseline file.json".to_string(),
        ];
        let calls = fields
            .split(|field| field == "__CALL__")
            .filter(|call| !call.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 1, "calibration must run exactly once");
        for call in calls {
            assert_eq!(call, expected.as_slice());
        }
        assert!(
            !probe.exists(),
            "throwaway calibration report must be removed"
        );
    }
}

#[test]
fn composite_action_calibration_fails_before_scanning_when_config_is_unresolved() {
    let dir = TempDir::new().expect("tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    let call_log = dir.path().join("calls.bin");
    let config_log = dir.path().join("config.log");
    write_executable(
        &dir.path().join("keyhog"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "config" ]]; then
  printf 'config\n' >> "$KEYHOG_CONFIG_LOG"
  exit 7
fi
printf 'scan\n' >> "$KEYHOG_CALL_LOG"
"#,
    );
    let path = format!(
        "{}:{}",
        dir.path().display(),
        env::var("PATH").expect("PATH")
    );
    let output = run_manifest_bash_step(
        "Calibrate autoroute for this scan",
        &[
            ("ACTION_SCAN_PATH", "."),
            ("ACTION_SEVERITY", "high"),
            ("ACTION_BASELINE", ""),
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("utf-8 runner temp"),
            ),
            (
                "KEYHOG_CALL_LOG",
                call_log.to_str().expect("utf-8 call log"),
            ),
            (
                "KEYHOG_CONFIG_LOG",
                config_log.to_str().expect("utf-8 config log"),
            ),
            ("PATH", &path),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(output.status.code(), Some(7), "{combined}");
    assert!(
        combined.contains("Could not resolve the exact scan configuration"),
        "config failure must be actionable: {combined}"
    );
    assert!(!call_log.exists(), "scan must not run after config failure");
}

#[test]
fn release_floating_tags_advance_only_after_signed_newest_stable_release() {
    let workflow = fs::read_to_string(release_workflow()).expect("read release.yml");
    let docker = workflow.split("\n  docker:").nth(1).expect("docker job");
    let major = workflow
        .split("\n  major-tag:")
        .nth(1)
        .expect("major-tag job");
    for (name, job) in [("docker", docker), ("major-tag", major)] {
        assert!(
            job.contains("needs: sign"),
            "{name} must wait for signatures"
        );
        assert!(
            job.contains("Decide whether this is the newest stable release")
                && job.contains("grep -E '^v[0-9]+\\.[0-9]+\\.[0-9]+$'")
                && job.contains("steps.floating.outputs.advance == 'true'"),
            "{name} must reject prereleases and older manual reruns before moving a floating tag"
        );
    }
    assert!(
        docker.contains("ghcr.io/${{ github.repository }}:${{ steps.tag.outputs.version }}")
            && !docker
                .split("- name: Build and push")
                .nth(1)
                .and_then(|tail| tail.split("- name:").next())
                .expect("build-and-push step")
                .contains(":latest"),
        "the immutable version image must publish before latest is conditionally advanced"
    );
}

#[test]
fn composite_action_branch_ref_skips_release_lookup_and_builds_source() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin");
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
touch "$CURL_CALLED"
exit 22
"#,
    );
    let curl_called = dir.path().join("curl-called");
    let curl_called_str = curl_called.to_string_lossy().into_owned();
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
            ("CURL_CALLED", curl_called_str.as_str()),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "branch/SHA refs must continue directly to a source build; output={combined}"
    );
    assert!(
        combined.contains("skipping release lookup"),
        "branch/SHA refs must report that no release request was made; output={combined}"
    );
    assert!(!curl_called.exists(), "branch/SHA refs must not call curl");
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    assert!(
        github_output.contains("found=false"),
        "branch/SHA path must advertise source build; output={github_output}"
    );
}

#[test]
fn composite_action_detects_unified_linux_release_asset() {
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
        "Linux asset detection must run under bash; output={combined}"
    );
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    assert!(
        github_output.contains("name=keyhog-linux-x86_64"),
        "Linux runners must use the unified accelerator-capable asset; output={github_output}"
    );
}

#[test]
fn composite_action_source_build_uses_default_linux_features() {
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
            ("CARGO_ARGS_FILE", cargo_args_str.as_str()),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "Linux source-build fallback must run with fake cargo; output={combined}"
    );
    let args = fs::read_to_string(&cargo_args).expect("read cargo args");
    assert!(
        args.contains("--locked\n"),
        "source fallback must build against the committed lockfile; args={args}"
    );
    assert!(
        !args.contains("--features\ncuda\n"),
        "removed CUDA alias must not return; args={args}"
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
  *.gpu-literals.tar.gz)
    payload="$(mktemp -d)"
    printf 'gpu-program' > "$payload/literal-program.bin"
    tar -czf "$out" -C "$payload" literal-program.bin
    rm -rf "$payload"
    ;;
  *.sha256)
    target="$(basename "${out%.sha256}")"
    printf '%064d  %s\n' 0 "$target" > "$out"
    ;;
  *.minisig) printf 'fake-signature\n' > "$out" ;;
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
    write_executable(
        &fake_bin.join("minisign"),
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
    let cache_root = dir.path().join("cache");
    let cache_root_str = cache_root.to_string_lossy().into_owned();
    #[cfg(unix)]
    {
        let programs = cache_root.join("keyhog/programs");
        fs::create_dir_all(&programs).expect("create programs cache");
        let victim = dir.path().join("symlink-victim");
        fs::write(&victim, "unchanged").expect("write symlink victim");
        std::os::unix::fs::symlink(&victim, programs.join("literal-program.bin"))
            .expect("preplant destination symlink");
    }
    let output = run_manifest_bash_step(
        "Try downloading prebuilt binary",
        &[
            ("PATH", path.as_str()),
            ("GITHUB_OUTPUT", output_path_str.as_str()),
            ("RUNNER_TEMP", runner_temp_str.as_str()),
            ("ACTION_ASSET_NAME", "keyhog-windows-x86_64.exe"),
            ("ACTION_RESOLVED_VERSION", "0.5.37"),
            ("ACTION_RELEASE_REQUIRED", "true"),
            ("RUNNER_OS", "Linux"),
            ("XDG_CACHE_HOME", cache_root_str.as_str()),
            ("KEYHOG_MINISIGN_PUBLIC_KEY", "test-public-key"),
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
    assert!(
        cache_root
            .join("keyhog/programs/literal-program.bin")
            .is_file(),
        "authenticated GPU literal artifacts must be seeded into the platform cache"
    );
    #[cfg(unix)]
    {
        let installed = cache_root.join("keyhog/programs/literal-program.bin");
        assert!(
            fs::symlink_metadata(&installed)
                .expect("installed artifact metadata")
                .file_type()
                .is_file(),
            "atomic installation must replace a pre-planted destination symlink"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("symlink-victim")).expect("read symlink victim"),
            "unchanged",
            "artifact installation must never write through a destination symlink"
        );
    }
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
fn differential_bench_scanner_versions_fail_closed() {
    let workflow =
        fs::read_to_string(differential_bench_workflow()).expect("read differential-bench.yml");
    let versions = workflow
        .split("- name: scanner versions")
        .nth(1)
        .and_then(|tail| tail.split("- name: keyhog smoke check").next())
        .expect("scanner versions step exists");
    assert!(
        versions.contains("set -euo pipefail"),
        "scanner version proof must fail the workflow on command failures"
    );
    assert!(
        versions.contains("keyhog --version") && versions.contains("trufflehog --version"),
        "scanner version proof must exercise the installed keyhog/trufflehog binaries"
    );
    assert!(
        !versions.contains("set +e") && !versions.contains("|| true"),
        "scanner version proof must not hide broken competitor installs"
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
        workflow
            .matches("bash scripts/release-version.sh \"$tag\"")
            .count()
            >= 5,
        "every release job must use the shared exact semantic-version parser"
    );
    assert!(
        workflow.contains("scripts/release-version.sh")
            && workflow.contains("Release tag must be exact semver"),
        "release tag resolver must constrain the entire tag through the shared parser"
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
    assert!(
        workflow.contains("Prove the release ref is a tag")
            && workflow.contains("git/ref/tags/$KEYHOG_RELEASE_TAG")
            && workflow.contains("ref: refs/tags/${{ steps.tag.outputs.tag }}")
            && workflow.contains("ref: ${{ github.ref }}"),
        "manual releases must prove and checkout the exact validated tag, never a same-named branch"
    );
}

#[test]
fn shared_release_version_parser_accepts_prereleases_and_rejects_build_metadata() {
    let parser = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/release-version.sh")
        .canonicalize()
        .expect("shared release-version.sh exists");
    for (input, expected) in [("1.2.3", "v1.2.3"), ("v1.2.3-rc.1", "v1.2.3-rc.1")] {
        let output = Command::new(&parser)
            .arg(input)
            .output()
            .expect("run shared release parser");
        assert!(
            output.status.success(),
            "valid release version {input} rejected: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            expected,
            "parser must normalize release versions to v-prefixed tags"
        );
    }
    let output = Command::new(&parser)
        .arg("v1.2.3+build.7")
        .output()
        .expect("run shared release parser for build metadata");
    assert!(
        !output.status.success(),
        "release build metadata must be rejected because no asset namespace is published for it"
    );
}

#[test]
fn release_stages_privately_and_publishes_only_the_exact_signed_manifest() {
    let workflow = fs::read_to_string(release_workflow()).expect("read release.yml");
    let build = workflow
        .split("\n  build:")
        .nth(1)
        .and_then(|tail| tail.split("\n  sign:").next())
        .expect("build job exists");
    let publish = workflow
        .split("- name: Sign, validate, and publish the exact release manifest")
        .nth(1)
        .and_then(|tail| tail.split("\n  docker:").next())
        .expect("signed publish step exists");
    assert!(
        build.contains("Stage unsigned release bundle")
            && build.contains("actions/upload-artifact@")
            && !build.contains("gh release upload"),
        "matrix jobs must stage privately instead of exposing unsigned release assets"
    );
    assert!(
        publish.contains("gh release create \"$tag\" \"${create_args[@]}\"")
            && publish.contains("create_args=(--draft")
            && publish.contains("gh release edit \"$tag\" --draft=true")
            && publish.contains(
                "republish=true\n            is_draft=\"$(gh release view \"$tag\""
            )
            && publish.contains("gh release edit \"$tag\" --draft=false"),
        "new, published-rerun, and interrupted-draft releases must remain private until the signed manifest is complete, then publish"
    );
    assert!(
        publish.contains("staged release manifest is missing")
            && publish.contains("actual[*]")
            && publish.contains("wanted[*]")
            && publish.contains("published release manifest does not equal"),
        "publication must fail closed on missing, extra, or mismatched assets"
    );
}

#[test]
fn integration_smoke_defaults_to_latest_stable_without_a_version_literal() {
    let workflow =
        fs::read_to_string(integration_smoke_workflow()).expect("read integration-smoke.yml");
    let input = workflow
        .split("      version:")
        .nth(1)
        .and_then(|tail| tail.split("\n\njobs:").next())
        .expect("version workflow input exists");
    assert!(
        input.contains("default: \"\"") && input.contains("leave blank for latest stable"),
        "the smoke workflow must not drift behind the latest published stable release"
    );
    assert!(
        workflow.contains("if [[ -n \"$KEYHOG_SMOKE_VERSION\" ]]")
            && workflow.contains("install_args+=(--version=\"$KEYHOG_SMOKE_VERSION\")")
            && workflow.contains("IsNullOrWhiteSpace($env:KEYHOG_SMOKE_VERSION)"),
        "Unix and Windows smokes must pin only when the operator supplied a version"
    );
}

#[test]
fn integration_smoke_can_execute_the_fail_closed_verified_installer() {
    let workflow =
        fs::read_to_string(integration_smoke_workflow()).expect("read integration-smoke.yml");
    assert!(
        workflow.contains("libhyperscan5 minisign")
            && workflow.contains("brew install minisign"),
        "Linux and macOS smoke lanes must install the runtime and signature verifier required by the release installer"
    );
    assert!(
        workflow.contains("winget install -e --id jedisct1.minisign")
            && workflow.contains("Get-Command minisign.exe"),
        "Windows smoke must install minisign and prove the executable is available before running the installer"
    );
}

#[test]
fn integration_smoke_daemon_path_fails_closed() {
    let workflow =
        fs::read_to_string(integration_smoke_workflow()).expect("read integration-smoke.yml");
    let daemon = workflow
        .split("- name: Daemon start/status/stop")
        .nth(1)
        .and_then(|tail| tail.split("- name: Backend probe").next())
        .expect("daemon smoke step exists");
    assert!(
        daemon.contains("if: runner.os != 'Windows'") && daemon.contains("set -euo pipefail"),
        "daemon lifecycle smoke must be Unix-only and fail the workflow on command failures"
    );
    assert!(
        daemon.contains("keyhog daemon start &") && daemon.contains("daemon_pid=$!"),
        "daemon smoke step must manage the foreground daemon process explicitly"
    );
    assert!(
        daemon.contains("if keyhog daemon status; then")
            && daemon.contains("FAIL: daemon did not become ready")
            && daemon.contains("exit 1"),
        "daemon smoke step must fail if status never succeeds"
    );
    assert!(
        daemon.contains("keyhog daemon stop") && daemon.contains("wait \"$daemon_pid\""),
        "daemon smoke step must prove stop and daemon process exit"
    );
    for retired in ["best-effort", "do not fail", "failure logged, not fatal"] {
        assert!(
            !daemon.contains(retired),
            "daemon smoke step must not advertise advisory daemon coverage: {retired}"
        );
    }
    let windows = workflow
        .split("- name: Daemon is rejected on Windows")
        .nth(1)
        .and_then(|tail| tail.split("- name: Backend probe").next())
        .expect("Windows daemon contract step exists");
    assert!(
        windows.contains("if: runner.os == 'Windows'")
            && windows.contains("$code -ne 2")
            && windows.contains("unix-only"),
        "Windows smoke must assert exit 2 and the Unix-only remedy"
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
fn action_accepts_only_canonical_gpu_backend_names() {
    for backend in ["gpu-cuda", "gpu-wgpu"] {
        let dir = TempDir::new().expect("tempdir");
        let args_path = dir.path().join("args.txt");
        write_stub(
            &dir,
            r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$KEYHOG_STUB_ARGS"
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '[]\n' > "$out"
"#,
        );
        let output = run_action(
            &dir,
            &[
                ("KEYHOG_STUB_ARGS", args_path.to_str().expect("utf-8 path")),
                ("ACTION_INPUT_FORMAT", "json"),
                ("ACTION_INPUT_OUTPUT", "report.json"),
                ("ACTION_INPUT_BACKEND", backend),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "canonical backend {backend} must reach keyhog: {}",
            combined_output(&output)
        );
        let args = fs::read_to_string(args_path).expect("read args");
        assert!(
            args.contains(&format!("--backend\n{backend}\n")),
            "canonical backend was not preserved: {args}"
        );
    }

    let dir = TempDir::new().expect("tempdir");
    write_stub(&dir, "#!/usr/bin/env bash\nexit 99\n");
    let output = run_action(&dir, &[("ACTION_INPUT_BACKEND", "gpu")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        combined_output(&output).contains("gpu-cuda, gpu-wgpu"),
        "retired alias must fail with canonical replacements: {}",
        combined_output(&output)
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
