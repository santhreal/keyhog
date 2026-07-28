//! E2E contract for the composite GitHub Action scan step.

use std::env;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
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

fn action_e2e_workflow() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.github/workflows/action-e2e.yml")
        .canonicalize()
        .expect("action-e2e.yml exists")
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
    let scanner = dir.path().join("keyhog-scan-stub");
    write_executable(&scanner, body);
    let real_keyhog = dir.path().join("keyhog-real");
    #[cfg(unix)]
    std::os::unix::fs::symlink(keyhog_binary(), &real_keyhog).expect("link real Action verifier");
    #[cfg(not(unix))]
    fs::copy(keyhog_binary(), &real_keyhog).expect("copy real Action verifier");
    let path = dir.path().join("keyhog");
    write_executable(
        &path,
        r#"#!/usr/bin/env bash
set -uo pipefail
root="${0%/*}"
if [[ "${1:-}" == "action-report" ]]; then
  exec "$root/keyhog-real" "$@"
fi
receipt=""
report=""
format=""
previous=""
for arg in "$@"; do
  case "$previous" in
    --action-receipt) receipt="$arg" ;;
    --output) report="$arg" ;;
    --format) format="$arg" ;;
  esac
  previous="$arg"
done
set +e
"$root/keyhog-scan-stub" "$@"
scanner_exit=$?
set -e
if [[ -n "$receipt" && -f "$report" && "$scanner_exit" =~ ^(0|1|10|13)$ ]]; then
  count=""
  if [[ "$format" == "json" ]]; then
    mapfile -t json_lines < "$report"
    if [[ "${#json_lines[@]}" == "1" && "${json_lines[0]}" == "[]" ]]; then count=0; fi
  fi
  if [[ -z "$count" ]] && command -v python3 >/dev/null 2>&1; then
    count="$(python3 - "$format" "$report" <<'PY'
import json, sys
fmt, path = sys.argv[1:]
try:
    if fmt == "json":
        value = json.load(open(path, encoding="utf-8"))
        assert isinstance(value, list)
        print(len(value))
    elif fmt == "jsonl":
        rows = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
        assert all(isinstance(row, dict) for row in rows)
        print(len(rows))
    elif fmt == "sarif":
        value = json.load(open(path, encoding="utf-8"))
        assert isinstance(value, dict) and isinstance(value.get("runs"), list)
        print(sum(len(run["results"]) for run in value["runs"]))
    elif fmt == "text":
        lines = open(path, encoding="utf-8").read().splitlines()
        summaries = [line.strip().split()[0] for line in lines if line.strip().endswith("unverified") and line.strip().split()[0].isdigit()]
        assert len(summaries) == 1
        print(summaries[0])
except Exception:
    raise SystemExit(1)
PY
)" || count=""
  fi
  if [[ "$count" =~ ^[0-9]+$ ]]; then
    read -r report_sha _ < <(sha256sum "$report")
    report_bytes="$(wc -c < "$report")"
    report_bytes="${report_bytes//[[:space:]]/}"
    status=success
    [[ "$scanner_exit" == "13" ]] && status=partial
    {
      printf 'schema=keyhog-action-report-v1\n'
      printf 'format=%s\n' "$format"
      printf 'findings=%s\n' "$count"
      printf 'report-bytes=%s\n' "$report_bytes"
      printf 'report-sha256=%s\n' "$report_sha"
      printf 'scan-status=%s\n' "$status"
      printf 'exit-code=%s\n' "$scanner_exit"
    } > "$receipt"
    if [[ "${KEYHOG_TEST_TAMPER_RECEIPT:-}" == "uppercase-sha" ]]; then
      receipt_text="$(<"$receipt")"
      receipt_text="${receipt_text/report-sha256=$report_sha/report-sha256=${report_sha^^}}"
      printf '%s\n' "$receipt_text" > "$receipt"
    fi
    if [[ "${KEYHOG_TEST_TAMPER_REPORT_AFTER_RECEIPT:-}" == "true" ]]; then
      printf ' ' >> "$report"
    fi
  fi
fi
exit "$scanner_exit"
"#,
    );
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
    push_script_arg(&mut args, "--preset", "default");
    push_script_arg(&mut args, "--lockdown", "false");
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
            "ACTION_INPUT_PRESET" => push_script_arg(&mut args, "--preset", value),
            "ACTION_INPUT_LOCKDOWN" => push_script_arg(&mut args, "--lockdown", value),
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
            | "ACTION_INPUT_PRESET"
            | "ACTION_INPUT_LOCKDOWN"
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
    fs::create_dir_all(dir.path().join("runner-temp")).expect("runner temp");
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
        .env("GITHUB_STEP_SUMMARY", &summary_path)
        .env("RUNNER_TEMP", dir.path().join("runner-temp"));
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
    fs::create_dir_all(dir.path().join("runner-temp")).expect("runner temp");
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
        .env("GITHUB_STEP_SUMMARY", &summary_path)
        .env("RUNNER_TEMP", dir.path().join("runner-temp"));

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
    let runner_temp = envs
        .iter()
        .find_map(|(key, value)| (*key == "RUNNER_TEMP").then(|| PathBuf::from(value)))
        .unwrap_or_else(|| source_root.join("target/action-contract-runner-temp"));
    fs::create_dir_all(&runner_temp).expect("create manifest harness runner temp");
    let runtime = tempfile::Builder::new()
        .prefix("keyhog-action-runtime.")
        .tempdir_in(&runner_temp)
        .expect("create manifest harness runtime")
        .keep();
    fs::create_dir(runtime.join("bin")).expect("create manifest harness bin");
    let path_value = envs
        .iter()
        .find_map(|(key, value)| (*key == "PATH").then_some(*value))
        .unwrap_or("");
    let resolve_tool = |name: &str| {
        env::split_paths(path_value)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
            .unwrap_or_else(|| PathBuf::from(name))
    };
    let verifier_source = resolve_tool("minisign");
    let private_verifier = runtime.join("private-minisign");
    if verifier_source.is_file() {
        fs::copy(&verifier_source, &private_verifier).expect("copy private verifier");
    }
    let mut cmd = Command::new("bash");
    cmd.arg("-c").arg(block);
    cmd.env("ACTION_SOURCE_ROOT", source_root);
    cmd.env("ACTION_RUNNER_EXIT_CODE", "0");
    cmd.env("RUNNER_TEMP", &runner_temp);
    cmd.env("ACTION_RUNTIME", &runtime);
    cmd.env("ACTION_CACHE_HOME", runtime.join("cache"));
    cmd.env("ACTION_KEYHOG", resolve_tool("keyhog"));
    cmd.env(
        "ACTION_VERIFIER",
        if private_verifier.is_file() {
            private_verifier
        } else {
            verifier_source
        },
    );
    cmd.env("ACTION_RESOLVED_VERSION", "0.5.48");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().expect("run manifest shell block")
}

#[cfg(unix)]
fn preplant_destination(path: &Path, victim: &Path, kind: &str) {
    fs::write(victim, "victim-unchanged").expect("victim");
    match kind {
        "symlink" => std::os::unix::fs::symlink(victim, path).expect("preplant symlink"),
        "hardlink" => fs::hard_link(victim, path).expect("preplant hardlink"),
        "fifo" => {
            let status = Command::new("mkfifo").arg(path).status().expect("mkfifo");
            assert!(status.success());
        }
        "regular" => fs::write(path, "preplanted-regular").expect("preplant regular"),
        _ => panic!("unknown preplant kind {kind}"),
    }
}

fn run_release_download_harness(
    tar_entry: &str,
    tar_kind: &str,
    artifact_extension: &str,
    checksum_exit: &str,
    signature_exit: &str,
    preplant_programs_symlink: bool,
    action_lockdown: bool,
    preplant_binary: Option<&str>,
) -> (TempDir, Output) {
    let dir = TempDir::new().expect("release download harness tempdir");
    let fake_bin = dir.path().join("bin");
    let runner_temp = dir.path().join("runner-temp");
    let action_cache_home = runner_temp.join("keyhog-action-cache");
    let cache_root = action_cache_home.join("xdg");
    fs::create_dir(&fake_bin).expect("create fake bin");
    fs::create_dir(&runner_temp).expect("create runner temp");
    #[cfg(unix)]
    if let Some(kind) = preplant_binary {
        preplant_destination(
            &runner_temp.join("keyhog"),
            &dir.path().join("predictable-binary-victim"),
            kind,
        );
    }
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
if [[ "${1:-}" == "-c" ]]; then
  exit "$FAKE_SHA_EXIT"
fi
exec /usr/bin/sha256sum "$@"
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
            ("ACTION_RESOLVED_VERSION", "0.5.45"),
            ("ACTION_RELEASE_REQUIRED", "true"),
            (
                "ACTION_LOCKDOWN",
                if action_lockdown { "true" } else { "false" },
            ),
            ("RUNNER_OS", "Linux"),
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

fn private_action_runtime(dir: &TempDir) -> PathBuf {
    fs::read_dir(dir.path().join("runner-temp"))
        .expect("read runner temp")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("keyhog-action-runtime."))
        })
        .expect("private Action runtime")
}

fn yaml_get<'a>(
    mapping: &'a serde_yaml::Mapping,
    key: impl Into<String>,
) -> Option<&'a serde_yaml::Value> {
    mapping.get(serde_yaml::Value::String(key.into()))
}

fn workflow_job<'a>(workflow: &'a serde_yaml::Mapping, name: &str) -> &'a serde_yaml::Mapping {
    yaml_get(workflow, "jobs")
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|jobs| yaml_get(jobs, name))
        .and_then(serde_yaml::Value::as_mapping)
        .unwrap_or_else(|| panic!("workflow declares the {name} job"))
}

fn workflow_job_needs(job: &serde_yaml::Mapping) -> Vec<&str> {
    match yaml_get(job, "needs") {
        Some(serde_yaml::Value::String(need)) => vec![need],
        Some(serde_yaml::Value::Sequence(needs)) => needs
            .iter()
            .map(|need| need.as_str().expect("job need is a string"))
            .collect(),
        Some(_) => panic!("job needs must be a string or sequence"),
        None => Vec::new(),
    }
}

fn workflow_job_steps(job: &serde_yaml::Mapping) -> &[serde_yaml::Value] {
    yaml_get(job, "steps")
        .and_then(serde_yaml::Value::as_sequence)
        .map(Vec::as_slice)
        .expect("workflow job declares steps")
}

fn workflow_run_step_containing<'a>(
    job: &'a serde_yaml::Mapping,
    command: &str,
) -> &'a serde_yaml::Mapping {
    workflow_job_steps(job)
        .iter()
        .filter_map(serde_yaml::Value::as_mapping)
        .find(|step| {
            yaml_get(step, "run")
                .and_then(serde_yaml::Value::as_str)
                .is_some_and(|run| run.contains(command))
        })
        .unwrap_or_else(|| panic!("workflow job has a run step containing {command:?}"))
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

/// Regression: hosted E2E once exercised only the root Action with forced CPU
/// defaults, leaving the nested mirror and auto+lockdown policy path unexecuted.
#[test]
fn hosted_action_e2e_splits_source_and_authenticated_release_modes() {
    let workflow =
        fs::read_to_string(action_e2e_workflow()).expect("read action-e2e workflow");
    serde_yaml::from_str::<serde_yaml::Value>(&workflow)
        .expect("action-e2e workflow parses as YAML");

    for runner in [
        "ubuntu-24.04",
        "windows-2025",
        "macos-15-intel",
        "macos-15",
    ] {
        assert!(
            workflow
                .lines()
                .any(|line| line.trim() == format!("- runner: {runner}")),
            "hosted release E2E matrix must name {runner} explicitly"
        );
    }
    assert_eq!(
        workflow.matches("        uses: ./\n").count(),
        3,
        "hosted and provisioned source/release modes must invoke the root composite"
    );
    assert_eq!(
        workflow.matches("        uses: ./.github/actions/keyhog\n").count(),
        5,
        "hosted policy and provisioned lockdown modes must invoke the nested mirror"
    );
    assert_eq!(
        workflow
            .matches("version: ${{ env.KEYHOG_ACTION_E2E_VERSION }}")
            .count(),
        3,
        "only workflow_dispatch release invocations may force the authenticated asset path"
    );
    for step_name in [
        "Invoke root composite from branch/SHA source",
        "Invoke nested composite with precision finding policy from branch/SHA source",
        "Reject unsupported hosted CPU lockdown from branch/SHA source",
    ] {
        let step = workflow
            .split(&format!("- name: {step_name}"))
            .nth(1)
            .and_then(|tail| tail.split("\n      - name:").next())
            .unwrap_or_else(|| panic!("source step {step_name} exists"));
        assert!(
            step.contains("if: github.event_name != 'workflow_dispatch'")
                && !step.contains("\n          version:"),
            "PR/main source proof must never require an unpublished release asset: {step}"
        );
    }
    for step_name in [
        "Invoke root composite against authenticated release asset",
        "Invoke nested composite with precision finding policy from authenticated release asset",
        "Reject unsupported hosted auto lockdown from authenticated release asset",
    ] {
        let step = workflow
            .split(&format!("- name: {step_name}"))
            .nth(1)
            .and_then(|tail| tail.split("\n      - name:").next())
            .unwrap_or_else(|| panic!("release step {step_name} exists"));
        assert!(
            step.contains("if: github.event_name == 'workflow_dispatch'")
                && step.contains("version: ${{ env.KEYHOG_ACTION_E2E_VERSION }}"),
            "release-asset proof must be explicit and may never silently source-build: {step}"
        );
    }
    let clean_source = workflow
        .split("- name: Invoke root composite from branch/SHA source")
        .nth(1)
        .and_then(|tail| tail.split("\n      - name:").next())
        .expect("clean source step exists");
    assert!(
        clean_source.contains("\n          backend: cpu")
            && !clean_source.contains("\n          preset:")
            && !clean_source.contains("\n          lockdown:"),
        "portable source smoke must request CPU explicitly rather than silently treating auto as CPU"
    );
    let source_precision = workflow
        .split("- name: Invoke nested composite with precision finding policy from branch/SHA source")
        .nth(1)
        .and_then(|tail| tail.split("\n      - name:").next())
        .expect("source precision step exists");
    assert!(
        source_precision.contains("preset: precision")
            && source_precision.contains("lockdown: 'false'")
            && source_precision.contains("\n          backend: cpu"),
        "portable precision source smoke must select CPU explicitly"
    );
    let release_precision = workflow
        .split("- name: Invoke nested composite with precision finding policy from authenticated release asset")
        .nth(1)
        .and_then(|tail| tail.split("\n      - name:").next())
        .expect("release precision step exists");
    assert!(
        release_precision.contains("preset: precision")
            && release_precision.contains("lockdown: 'false'")
            && !release_precision.contains("\n          backend:"),
        "authenticated production binary smoke must prove default proof-backed backend:auto"
    );
    for (name, explicit_cpu) in [
        ("Reject unsupported hosted CPU lockdown from branch/SHA source", true),
        (
            "Reject unsupported hosted auto lockdown from authenticated release asset",
            false,
        ),
    ] {
        let step = workflow
            .split(&format!("- name: {name}"))
            .nth(1)
            .and_then(|tail| tail.split("\n      - name:").next())
            .expect("lockdown validation step exists");
        assert!(step.contains("lockdown: 'true'"));
        assert_eq!(
            step.contains("\n          backend: cpu"),
            explicit_cpu,
            "source lockdown must select CPU explicitly while release proves default auto"
        );
    }
    assert!(
        !workflow.contains("cargo build"),
        "workflow must exercise composite install paths rather than inline builds"
    );

    for contract in [
        "steps.clean_release.outputs.findings",
        "steps.clean_source.outputs.findings",
        "steps.finding_release.outputs.exit-code",
        "steps.finding_source.outputs.exit-code",
        "steps.finding_release.outcome",
        "steps.finding_source.outcome",
        "steps.lockdown_release.outcome",
        "steps.lockdown_source.outcome",
        "command -v keyhog",
        "compgen -G \"$programs_glob\"",
        "Download clean report artifact",
        "Download findings report artifact",
        "missing-receipt.txt",
        "missing-report.txt",
        "tampered-report-receipt.txt",
        "scan-status=failed",
        "security-events: write",
        "cargo test -p keyhog --test action_root_mirror_parity",
        "cargo test -p keyhog --test e2e_all -- action_",
        "uses: ./.github/actions/keyhog",
    ] {
        assert!(
            workflow.contains(contract),
            "hosted Action E2E must execute and assert `{contract}`"
        );
    }

    for line in workflow.lines().map(str::trim) {
        let Some(target) = line.strip_prefix("uses: ") else {
            continue;
        };
        if matches!(target, "./" | "./.github/actions/keyhog") {
            continue;
        }
        let target = target.split_whitespace().next().expect("action target");
        let (_, revision) = target
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("external Action must be SHA-pinned: {target}"));
        assert!(
            matches!(revision.len(), 40 | 64)
                && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "external Action revision must be a full commit SHA: {target}"
        );
    }
}

/// Regression: a hosted negative lane cannot prove lockdown works. Maintain a
/// pinned, provisioned container that executes both real composite entrypoints:
/// source push/PR uses explicit portable CPU, while authenticated release
/// dispatch uses proof-backed backend:auto.
#[test]
fn action_e2e_maintains_provisioned_positive_lockdown_lane() {
    let workflow =
        fs::read_to_string(action_e2e_workflow()).expect("read action-e2e workflow");
    let job = workflow
        .split("  positive-lockdown:")
        .nth(1)
        .and_then(|tail| tail.split("\n  release-asset:").next())
        .expect("positive-lockdown job exists");
    for contract in [
        "image: rust:1.89.0-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff",
        "options: --cap-add IPC_LOCK --ulimit memlock=-1:-1",
        "uses: ./",
        "uses: ./.github/actions/keyhog",
        "version: ${{ github.event_name == 'workflow_dispatch' && env.KEYHOG_ACTION_E2E_VERSION || '' }}",
        "backend: ${{ github.event_name == 'workflow_dispatch' && 'auto' || 'cpu' }}",
        "lockdown: 'true'",
        "steps.root_lockdown.outputs.findings",
        "steps.nested_lockdown.outputs.findings",
        "[[ \"$ACTION_REPORT_PRESENT\" == \"true\" ]]",
        "$RUNNER_TEMP/keyhog-autoroute-cache-*",
        "literal_bins=(\"$RUNNER_TEMP\"/keyhog-action-runtime.*/cache/**/*.bin)",
        "authenticated-release-auto",
        "portable-source-cpu",
        "installed_keyhog=\"$(command -v keyhog)\"",
        "[[ \"$(keyhog --version)\" == *\"$KEYHOG_ACTION_E2E_VERSION\"* ]]",
    ] {
        assert!(
            job.contains(contract),
            "positive real-mlock lane must assert `{contract}`"
        );
    }
    assert_eq!(
        job.matches("lockdown: 'true'").count(),
        2,
        "root and nested composites must both execute real positive lockdown"
    );
    assert_eq!(
        job.matches("backend: ${{ github.event_name == 'workflow_dispatch' && 'auto' || 'cpu' }}")
            .count(),
        2,
        "root and nested must select portable source CPU or authenticated release auto explicitly"
    );
    assert_eq!(
        job.matches("ACTION_MODE: ${{ github.event_name == 'workflow_dispatch' && 'authenticated-release-auto' || 'portable-source-cpu' }}")
            .count(),
        2,
        "each invocation must assert its selected install and routing mode"
    );
    assert_eq!(
        job.matches("[[ \"$ACTION_FINDINGS\" == \"0\" ]]").count(),
        2,
        "both composite receipts must prove an exact clean finding count"
    );
    assert!(
        !job.contains("sudo") && !job.contains("apt-get") && !job.contains("jq"),
        "positive lockdown must use immutable provisioned inputs without mutable bootstrap"
    );
}

/// Regression: Marketplace examples and hosted release smoke must track the
/// workspace version so the Action never advertises or tests a stale asset.
#[test]
fn action_examples_and_hosted_release_default_follow_workspace_version() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = fs::read_to_string(repo.join("Cargo.toml")).expect("read workspace Cargo.toml");
    let workspace_package = cargo
        .split("[workspace.package]")
        .nth(1)
        .and_then(|tail| tail.split("\n[").next())
        .expect("workspace.package section");
    let version = workspace_package
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("version = \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .expect("workspace package version");

    let workflow =
        fs::read_to_string(action_e2e_workflow()).expect("read action-e2e workflow");
    assert!(
        workflow.contains(&format!("default: '{version}'"))
            && workflow.contains(&format!("inputs.version || '{version}'")),
        "hosted release E2E manual and automatic paths must use workspace version {version}"
    );
    let action = fs::read_to_string(action_manifest()).expect("read action manifest");
    assert!(
        action.contains(&format!("Published final KeyHog version v{version} or newer")),
        "Action version example must follow workspace version {version}"
    );
}

#[test]
fn root_and_nested_action_entrypoints_differ_only_by_relative_paths() {
    let root =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../action.yml"))
            .expect("read root action.yml");
    let nested = fs::read_to_string(action_manifest()).expect("read nested action.yml");
    let normalized_root = root
        .replace(
            "ACTION_SOURCE_ROOT: ${{ github.action_path }}",
            "ACTION_SOURCE_ROOT: ${{ github.action_path }}/../../..",
        )
        .replace(
            "${{ github.action_path }}/.github/actions/keyhog/run-scan.sh",
            "${{ github.action_path }}/run-scan.sh",
        );
    assert_eq!(
        normalized_root, nested,
        "both published action entrypoints must execute one behavior"
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
        Some(1),
        "standalone action runner must fail on real findings; stdout={} stderr={}",
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
        Some(1),
        "quick-start standalone runner must fail on findings; output={}",
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
        Some(1),
        "standalone action runner must fail on real text findings; output={}",
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
{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[{"ruleId":"one"},{"ruleId":"two"}],"tool":{"driver":{"name":"keyhog"}}}]}
JSON
exit 1
"#,
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "standalone findings exit must fail after publishing receipt outputs; stderr={}",
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
    assert!(summary.contains("| Findings | <code>2</code> |"), "summary={summary}");
    assert!(summary.contains("| Exit code | <code>1</code> |"), "summary={summary}");
    assert!(
        summary.contains("| Duration | <code>"),
        "summary must expose scan duration; summary={summary}"
    );
    assert!(
        summary.contains("| Fail on findings | <code>true</code> |"),
        "summary={summary}"
    );
    assert!(
        summary.contains("| Upload SARIF | <code>true</code> |"),
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
{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[],"tool":{"driver":{"name":"keyhog"}}}]}
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
fn action_effective_config_preflight_reflects_verification_and_backend_inputs() {
    let dir = TempDir::new().expect("tempdir");
    let calls = dir.path().join("calls.txt");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
out=""
has_verify=false
backend=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output)
      shift
      out="$1"
      ;;
    --verify)
      has_verify=true
      ;;
    --backend)
      shift
      backend="$1"
      ;;
  esac
  shift || true
done
printf '%s verify=%s backend=%s\n' "$cmd" "$has_verify" "$backend" >> "$CALLS_FILE"
if [[ "$cmd" == "config" ]]; then
  echo "config preflight failed" >&2
  exit 1
fi
if [[ "$cmd" != "scan" ]]; then
  echo "expected scan command after preflight, got $cmd" >&2
  exit 42
fi
if [[ "$has_verify" != "true" || "$backend" != "cpu" ]]; then
  echo "real scan must preserve --verify and --backend cpu" >&2
  exit 44
fi
cat > "$out" <<'JSON'
{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[],"tool":{"driver":{"name":"keyhog"}}}]}
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
            ("ACTION_INPUT_BACKEND", "cpu"),
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
        "config verify=true backend=cpu\nscan verify=true backend=cpu\n",
        "`config --effective` and `scan` must receive the same verification and backend policy"
    );
    assert!(
        output_file(&dir).contains("findings=0"),
        "real scan report must still be parsed after advisory preflight"
    );
}

/// Regression: Action `verify: false` was once only a default and committed
/// `verify=true` could re-enable live provider network calls in both CLI phases.
#[test]
fn action_verify_false_forces_no_verify_in_preflight_and_scan() {
    let dir = TempDir::new().expect("tempdir");
    let calls = dir.path().join("calls.txt");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
out=""
has_verify=false
has_no_verify=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output) shift; out="$1" ;;
    --verify) has_verify=true ;;
    --no-verify) has_no_verify=true ;;
  esac
  shift || true
done
printf '%s verify=%s no-verify=%s\n' "$cmd" "$has_verify" "$has_no_verify" >> "$CALLS_FILE"
if [[ "$cmd" == "config" ]]; then
  printf '[effective-config]\nverify = false\n'
  exit 0
fi
printf '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[],"tool":{"driver":{"name":"keyhog"}}}]}\n' > "$out"
"#,
    );
    fs::write(dir.path().join(".keyhog.toml"), "verify = true\n")
        .expect("write committed verify policy");

    let calls_path = calls.to_string_lossy().into_owned();
    let output = run_action_with_script_args(
        &dir,
        &["--print-effective-config"],
        &[
            ("CALLS_FILE", calls_path.as_str()),
            ("ACTION_INPUT_VERIFY", "false"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "verify=false must remain report-producing and offline: {}",
        combined_output(&output)
    );
    assert_eq!(
        fs::read_to_string(&calls).expect("read calls"),
        "config verify=false no-verify=true\nscan verify=false no-verify=true\n",
        "Action false must explicitly override committed verification in both invocations"
    );
}

/// Regression: preset and lockdown inputs were documented but not forwarded
/// consistently to effective-config preflight and the real scan.
#[test]
fn action_composes_presets_and_lockdown_for_preflight_and_scan() {
    const POLICY_FLAGS: [&str; 4] = ["--fast", "--deep", "--precision", "--lockdown"];

    for (preset, lockdown, expected_flags) in [
        ("default", "false", Vec::<&str>::new()),
        ("fast", "false", vec!["--fast"]),
        ("deep", "true", vec!["--deep", "--lockdown"]),
        ("precision", "true", vec!["--precision", "--lockdown"]),
        ("fast", "true", vec!["--fast", "--lockdown"]),
    ] {
        let dir = TempDir::new().expect("tempdir");
        let calls = dir.path().join("calls.txt");
        write_stub(
            &dir,
            r#"#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
printf '%s' "$cmd" >> "$CALLS_FILE"
for arg in "${@:2}"; do
  printf '|%s' "$arg" >> "$CALLS_FILE"
done
printf '\n' >> "$CALLS_FILE"
if [[ "$cmd" == "config" ]]; then
  printf '[effective-config]\n'
  exit 0
fi
out=''
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == '--output' ]]; then
    shift
    out="$1"
  fi
  shift || true
done
printf '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[],"tool":{"driver":{"name":"keyhog"}}}]}\n' > "$out"
"#,
        );

        let calls_path = calls.to_string_lossy().into_owned();
        let output = run_action_with_script_args(
            &dir,
            &["--print-effective-config"],
            &[
                ("CALLS_FILE", calls_path.as_str()),
                ("ACTION_INPUT_PRESET", preset),
                ("ACTION_INPUT_LOCKDOWN", lockdown),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "preset={preset} lockdown={lockdown} must complete both invocations: {}",
            combined_output(&output)
        );

        let calls = fs::read_to_string(&calls).expect("read policy calls");
        let calls = calls.lines().collect::<Vec<_>>();
        assert_eq!(
            calls.len(),
            2,
            "preset={preset} lockdown={lockdown} must run config then scan"
        );
        assert!(
            calls[0].starts_with("config|--effective|"),
            "policy preflight invocation missing: {}",
            calls[0]
        );
        assert!(
            calls[1].starts_with("scan|"),
            "policy scan invocation missing: {}",
            calls[1]
        );
        for call in calls {
            let selected = call
                .split('|')
                .filter(|arg| POLICY_FLAGS.contains(arg))
                .collect::<Vec<_>>();
            assert_eq!(
                selected, expected_flags,
                "preset={preset} lockdown={lockdown} must preserve orthogonal CLI flags in `{call}`"
            );
        }
    }
}

/// Regression: preset and lockdown forwarding must compose in the production
/// CLI rather than only appearing correct under argument-recording stubs.
#[test]
fn action_real_cli_preserves_preset_lockdown_composition() {
    let binary = keyhog_binary();

    for preset in ["deep", "precision", "fast"] {
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("safe.txt"), "ordinary fixture content\n")
            .expect("write safe fixture");
        let output = Command::new(&binary)
            .args([
                "config",
                "--effective",
                "--backend",
                "cpu",
                "--path",
                ".",
                "--severity",
                "high",
                "--format",
                "json",
            ])
            .arg(format!("--{preset}"))
            .arg("--lockdown")
            .current_dir(dir.path())
            .env("XDG_CACHE_HOME", dir.path().join("cache"))
            .output()
            .expect("run real effective-config command");
        assert_eq!(
            output.status.code(),
            Some(0),
            "the real CLI must decide preset={preset} + lockdown composition without wrapper overrides: {}",
            combined_output(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("lockdown = true"),
            "effective config must reflect lockdown for preset={preset}"
        );
    }
}

/// Regression: `backend:auto + lockdown:true` must either reuse one ephemeral
/// routing receipt or fail closed when the host cannot apply memory protections.
#[test]
fn action_real_cli_lockdown_auto_reuses_receipt_or_fails_closed() {
    let binary = keyhog_binary();
    let dir = TempDir::new().expect("tempdir");
    fs::write(dir.path().join("safe.txt"), "ordinary fixture content\n")
        .expect("write safe fixture");
    let route_cache = dir.path().join("autoroute.json");
    let probe = dir.path().join("probe.json");
    let report = dir.path().join("report.json");
    let cache_home = dir.path().join("cache");

    let calibration = Command::new(&binary)
        .args([
            "scan",
            "--autoroute-calibrate",
            "--autoroute-gpu",
            "--no-verify",
            "--lockdown",
            "--autoroute-cache",
        ])
        .arg(&route_cache)
        .args(["--path", ".", "--format", "json", "--output"])
        .arg(&probe)
        .current_dir(dir.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .output()
        .expect("run production calibration");
    if !calibration.status.success() {
        assert_eq!(
            calibration.status.code(),
            Some(2),
            "unsupported lockdown capability must be a configuration failure"
        );
        assert!(
            combined_output(&calibration)
                .contains("lockdown mode requested but protections failed to apply"),
            "production CLI must explain the failed lockdown guarantee: {}",
            combined_output(&calibration)
        );
        return;
    }
    assert!(
        route_cache.is_file() && fs::metadata(&route_cache).expect("route metadata").len() > 0,
        "calibration must publish a nonempty ephemeral routing receipt"
    );

    let scan = Command::new(&binary)
        .args([
            "scan",
            "--no-verify",
            "--lockdown",
            "--autoroute-cache",
        ])
        .arg(&route_cache)
        .args(["--path", ".", "--format", "json", "--output"])
        .arg(&report)
        .current_dir(dir.path())
        .env("XDG_CACHE_HOME", &cache_home)
        .output()
        .expect("run production scan with calibration receipt");
    assert_eq!(
        scan.status.code(),
        Some(0),
        "production auto scan must consume the lockdown calibration receipt: {}",
        combined_output(&scan)
    );
    assert!(report.is_file(), "production scan must publish its report");
    fs::remove_file(&route_cache).expect("delete ephemeral routing receipt");
    assert!(
        !route_cache.exists(),
        "Action cleanup contract requires the routing receipt to be deletable"
    );
}

/// Regression: the Action must preserve CLI-over-config precedence for an
/// explicit preset instead of inventing a second conflict policy.
#[test]
fn action_defers_committed_preset_conflicts_to_cli_precedence() {
    let dir = TempDir::new().expect("tempdir");
    fs::write(
        dir.path().join(".keyhog.toml"),
        "fast = true\nprecision = true\n",
    )
    .expect("write conflicting committed config");
    let binary = keyhog_binary();
    let binary_dir = binary
        .parent()
        .expect("binary parent")
        .to_str()
        .expect("utf-8 binary dir");
    let cache = dir.path().join("cache");
    let cache = cache.to_string_lossy().into_owned();

    let unresolved = run_action_with_script_args_and_path_prefix(
        &dir,
        &["--print-effective-config"],
        binary_dir,
        &[
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "unresolved.json"),
            ("ACTION_INPUT_BACKEND", "cpu"),
            ("XDG_CACHE_HOME", cache.as_str()),
        ],
    );
    assert_eq!(
        unresolved.status.code(),
        Some(2),
        "default preset must not hide a committed preset conflict: {}",
        combined_output(&unresolved)
    );
    assert!(
        combined_output(&unresolved).contains("choose only one scan preset"),
        "the CLI's committed-config conflict diagnostic must remain visible"
    );

    let explicit = run_action_with_script_args_and_path_prefix(
        &dir,
        &["--print-effective-config"],
        binary_dir,
        &[
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "explicit.json"),
            ("ACTION_INPUT_BACKEND", "cpu"),
            ("ACTION_INPUT_PRESET", "deep"),
            ("XDG_CACHE_HOME", cache.as_str()),
        ],
    );
    assert_eq!(
        explicit.status.code(),
        Some(0),
        "an explicit CLI preset must retain its existing precedence over committed preset keys: {}",
        combined_output(&explicit)
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

/// Regression: malformed reports accompanying a findings exit once fabricated
/// findings=1; unreadable evidence must instead fail with an unavailable count.
#[test]
fn action_rejects_malformed_findings_report_even_when_findings_are_advisory() {
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

    let output = run_action(&dir, &[("ACTION_INPUT_FAIL_ON_FINDINGS", "false")]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "malformed findings report must fail independently of findings policy; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_file(&dir).contains("findings=\n"),
        "parse failure after findings exit must publish an unavailable count"
    );
    assert!(
        output_file(&dir).contains("scan-status=failed\n"),
        "malformed findings reports must publish a failed completion state"
    );
}

/// Regression: a live-verification exit with an unreadable report must not be
/// treated as proven live evidence or assigned a fabricated finding count.
#[test]
fn action_rejects_live_exit_with_malformed_report() {
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
        Some(3),
        "malformed live report must fail report validation; output={}",
        combined_output(&output)
    );
    assert!(
        output_file(&dir).contains("findings=\n"),
        "parse failure after live exit must publish an unavailable count"
    );
    assert!(
        output_file(&dir).contains("scan-status=failed\n"),
        "malformed live reports must publish a failed completion state"
    );
    assert!(
        combined_output(&output).contains("refusing to infer a finding count from exit 10"),
        "invalid live evidence must be operator-visible without claiming confirmation"
    );
}

/// Regression: wrapper receipts once trusted either process exit or report
/// count independently, allowing contradictory clean/findings states to pass.
#[test]
fn action_rejects_source_receipt_semantic_contradictions() {
    for (exit_code, report_has_finding, label) in [
        ("1", false, "findings exit with empty report"),
        ("10", false, "live exit with empty report"),
        ("0", true, "clean exit with nonempty report"),
    ] {
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
if [[ "$STUB_REPORT_HAS_FINDING" == "true" ]]; then
  printf '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[{"ruleId":"detector"}],"tool":{"driver":{"name":"keyhog"}}}]}' > "$out"
else
  printf '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[],"tool":{"driver":{"name":"keyhog"}}}]}' > "$out"
fi
exit "$STUB_EXIT"
"#,
        );
        let output = run_action(
            &dir,
            &[
                ("ACTION_INPUT_FAIL_ON_FINDINGS", "false"),
                ("STUB_EXIT", exit_code),
                (
                    "STUB_REPORT_HAS_FINDING",
                    if report_has_finding { "true" } else { "false" },
                ),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(3),
            "{label} must fail closed even when findings are advisory: {}",
            combined_output(&output)
        );
        assert!(
            combined_output(&output).contains("Could not verify scan report receipt"),
            "{label} must reject a source receipt contradiction: {}",
            combined_output(&output)
        );
        assert!(
            output_file(&dir).contains("scan-status=failed\n"),
            "{label} must publish a failed receipt"
        );
    }
}

/// Regression: report bytes replaced after KeyHog emits its valid source
/// receipt must fail exact-byte verification without fabricating a clean count.
#[test]
fn action_rejects_report_bytes_changed_after_source_receipt() {
    let dir = TempDir::new().expect("report tamper tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then shift; out="$1"; fi
  shift || true
done
printf '[]\n' > "$out"
"#,
    );
    let output = run_action(
        &dir,
        &[
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.json"),
            ("KEYHOG_TEST_TAMPER_REPORT_AFTER_RECEIPT", "true"),
        ],
    );
    assert_eq!(output.status.code(), Some(3), "tampered report must fail closed");
    assert!(
        combined_output(&output).contains("Could not verify scan report receipt"),
        "exact-byte verification failure must be operator-visible: {}",
        combined_output(&output)
    );
    assert!(output_file(&dir).contains("findings=\n"));
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

/// Regression: a stale valid report once let a scanner that wrote nothing
/// publish success, so the wrapper must remove prior output before invocation.
#[test]
fn action_never_accepts_a_stale_report_as_current_scan_output() {
    let dir = TempDir::new().expect("tempdir");
    fs::write(
        dir.path().join("keyhog-results.sarif"),
        r#"{"runs":[{"results":[]}]}"#,
    )
    .expect("seed stale report");
    write_stub(&dir, "#!/usr/bin/env bash\nexit 0\n");

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a scanner that publishes no report must fail despite stale valid output: {}",
        combined_output(&output)
    );
    assert!(
        !dir.path().join("keyhog-results.sarif").exists(),
        "stale report must be removed before the scanner starts"
    );
    assert!(
        output_file(&dir).contains("report-present=false\n"),
        "receipt must describe the current invocation only"
    );
}

/// Regression: report writers followed a workspace-owned output symlink and
/// could overwrite an unrelated victim before the Action uploaded the result.
#[cfg(unix)]
#[test]
fn action_refuses_symlink_report_output_before_invoking_scanner() {
    let dir = TempDir::new().expect("tempdir");
    let victim = dir.path().join("victim");
    fs::write(&victim, "unchanged").expect("write victim");
    std::os::unix::fs::symlink(&victim, dir.path().join("keyhog-results.sarif"))
        .expect("seed report symlink");
    let invoked = dir.path().join("invoked");
    write_stub(
        &dir,
        &format!(
            "#!/usr/bin/env bash\nprintf invoked > '{}'\nexit 0\n",
            invoked.display()
        ),
    );

    let output = run_action(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "symlink output must fail before scanning: {}",
        combined_output(&output)
    );
    assert!(!invoked.exists(), "scanner must not run for a symlink report");
    assert_eq!(
        fs::read_to_string(victim).expect("read victim"),
        "unchanged",
        "report preparation must not follow the symlink"
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
        summary.contains("| Completion status | <code>failed</code> |")
            && summary.contains("| Report present | <code>false</code> |"),
        "failure summary must retain typed state and report presence; summary={summary}"
    );
}

/// Regression: unexpected exit 13 once published findings=0 before parsing a
/// valid partial report, hiding findings produced before incomplete coverage.
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
printf '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[{"ruleId":"partial"}],"tool":{"driver":{"name":"keyhog"}}}]}' > "$out"
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
        receipt.contains("findings=1\n"),
        "partial reports must publish their readable finding count; receipt={receipt}"
    );
    assert!(
        receipt.contains("report-present=true\n"),
        "incomplete coverage with a report must publish report presence; receipt={receipt}"
    );
    let summary = summary_file(&dir);
    assert!(
        summary.contains("| Completion status | <code>partial</code> |")
            && summary.contains("| Exit code | <code>13</code> |"),
        "incomplete coverage summary must distinguish the partial terminal class; summary={summary}"
    );
}

/// Regression: exit 13 is partial only when KeyHog's final source receipt
/// verifies; an untrusted receipt preserves the raw exit but publishes failure.
#[test]
fn action_rejects_untrusted_partial_receipt_without_inventing_count() {
    let dir = TempDir::new().expect("untrusted partial tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then shift; out="$1"; fi
  shift || true
done
printf '[]\n' > "$out"
exit 13
"#,
    );
    let output = run_action(
        &dir,
        &[
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "partial.json"),
            ("KEYHOG_TEST_TAMPER_RECEIPT", "uppercase-sha"),
        ],
    );
    assert_eq!(output.status.code(), Some(13), "raw partial exit is preserved");
    let receipt = output_file(&dir);
    assert!(
        receipt.contains("findings=\n")
            && receipt.contains("exit-code=13\n")
            && receipt.contains("scan-status=failed\n"),
        "untrusted partial source receipt must fail closed: {receipt}"
    );
    let runner_temp = dir.path().join("runner-temp");
    assert!(
        fs::read_dir(runner_temp)
            .expect("read runner temp")
            .all(|entry| !entry
                .expect("runner temp entry")
                .file_name()
                .to_string_lossy()
                .starts_with("keyhog-action-report-")),
        "untrusted partial receipt must be cleaned only while unchanged"
    );
}

/// Regression: cancellation exit 130 has no completed source receipt, so the
/// count stays unavailable while cancellation state and cleanup remain truthful.
#[test]
fn action_cancellation_publishes_receipt_and_cleans_autoroute_cache() {
    let dir = TempDir::new().expect("tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    let route_cache = runner_temp.join("route.json");
    fs::write(&route_cache, r#"{"schema_version":1}"#).expect("seed route cache");
    let route_lock = runner_temp.join("route.json.lock");
    fs::write(&route_lock, "owned lock").expect("seed route lock");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then shift; out="$1"; fi
  shift || true
done
printf '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json","runs":[{"results":[{"ruleId":"before-cancel"}],"tool":{"driver":{"name":"keyhog"}}}]}' > "$out"
exit 130
"#,
    );
    let route = route_cache.to_string_lossy().into_owned();
    let runner_temp_value = runner_temp.to_string_lossy().into_owned();
    let output = run_action_with_script_args(
        &dir,
        &["--autoroute-cache", route.as_str(), "--cleanup-autoroute-cache"],
        &[("RUNNER_TEMP", runner_temp_value.as_str())],
    );
    assert_eq!(
        output.status.code(),
        Some(130),
        "cancellation must preserve the scanner exit code: {}",
        combined_output(&output)
    );
    let receipt = output_file(&dir);
    assert!(
        receipt.contains("findings=\n")
            && receipt.contains("exit-code=130\n")
            && receipt.contains("scan-status=cancelled\n")
            && receipt.contains("report-present=false\n")
            && receipt.contains("report=\n"),
        "cancellation must not publish an unverified report snapshot: {receipt}"
    );
    assert!(
        !route_cache.exists() && !route_lock.exists(),
        "cancellation must delete the ephemeral autoroute receipt and lock"
    );
    assert!(
        fs::read_dir(&runner_temp)
            .expect("read runner temp")
            .all(|entry| !entry
                .expect("runner temp entry")
                .file_name()
                .to_string_lossy()
                .starts_with("keyhog-action-report-")),
        "cancellation must not leave an incomplete source receipt"
    );
}

/// Regression: unexpected scanner failures must publish a typed failed receipt
/// and never be mislabeled as successful findings completion.
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
        summary.contains("| Completion status | <code>failed</code> |")
            && summary.contains("| Exit code | <code>11</code> |"),
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

/// Regression: invalid authoritative Action policy values must fail before any
/// scanner invocation so malformed inputs cannot fall through to defaults.
#[test]
fn action_validates_severity_verify_preset_and_lockdown_before_invoking_scanner() {
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
        ("ACTION_INPUT_PRESET", "turbo"),
        ("ACTION_INPUT_LOCKDOWN", "sometimes"),
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
    assert!(
        manifest.contains("ACTION_PRESET: ${{ inputs.preset }}")
            && manifest.contains("ACTION_LOCKDOWN: ${{ inputs.lockdown }}")
            && manifest.contains("--preset \"$ACTION_PRESET\"")
            && manifest.contains("--lockdown \"$ACTION_LOCKDOWN\"")
            && manifest.contains("description: 'Scan preset: default | fast | deep | precision.'")
            && manifest.contains("default: 'false'"),
        "orthogonal preset and lockdown inputs must reach the tested script through argv"
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
fn composite_action_uploads_receipts_before_enforcing_findings_failure() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    let scan_step = manifest
        .split("- name: Run scan")
        .nth(1)
        .and_then(|rest| rest.split("    - name:").next())
        .expect("scan step exists");

    assert!(
        scan_step.contains("continue-on-error: true"),
        "the standalone runner's expected findings failure must not skip report uploads"
    );
    assert!(
        manifest.contains("- name: Fail when findings reported"),
        "the composite must convert the published receipt into its final findings failure"
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
            (yaml_get(step, "uses").and_then(serde_yaml::Value::as_str) == Some("./"))
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
    assert!(
        fail_step.contains("steps.scan.outputs.runner-exit-code != '0'"),
        "a tolerated runner failure must be restored after report uploads"
    );
    assert!(
        fail_step.contains("steps.scan.outcome == 'failure'"),
        "malformed or missing scan-step outputs must fail closed even when runner-exit-code is unavailable"
    );
    assert!(
        fail_step.contains("ACTION_RUNNER_EXIT_CODE: ${{ steps.scan.outputs.runner-exit-code }}"),
        "the final gate must receive the exact standalone runner status"
    );
    assert!(
        fail_step.contains("ACTION_SCAN_STATUS: ${{ steps.scan.outputs.scan-status }}"),
        "the final gate must receive the wrapper's report-validation status"
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
fn composite_action_fail_step_preserves_pre_receipt_runner_failure() {
    let output = run_manifest_bash_step(
        "Fail when findings reported",
        &[
            ("ACTION_RUNNER_EXIT_CODE", "2"),
            ("ACTION_FINDINGS", ""),
            ("ACTION_EXIT_CODE", ""),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an early runner usage failure must survive report-upload choreography; output={combined}"
    );
    assert!(
        combined.contains("before publishing its receipt"),
        "the early runner failure must remain actionable; output={combined}"
    );
}

#[test]
fn composite_action_fail_step_preserves_post_receipt_runner_failure() {
    let output = run_manifest_bash_step(
        "Fail when findings reported",
        &[
            ("ACTION_RUNNER_EXIT_CODE", "3"),
            ("ACTION_FINDINGS", "1"),
            ("ACTION_EXIT_CODE", "1"),
            ("ACTION_SCAN_STATUS", "failed"),
            ("ACTION_SEVERITY", "high"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a tolerated wrapper failure must be restored after uploads; output={combined}"
    );
    assert!(
        combined.contains("after publishing a failed receipt"),
        "the post-receipt runner failure must remain actionable; output={combined}"
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

/// Regression: explicit Action versions once accepted old binaries and
/// noncanonical SemVer spellings that could resolve ambiguous release assets.
#[test]
fn composite_action_version_resolver_accepts_only_compatible_publishable_tags() {
    for (input, expected) in [
        ("0.5.48", "0.5.48"),
        ("v0.5.48", "0.5.48"),
        ("1.0.0", "1.0.0"),
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

    for rejected in ["0.5.47", "0.5.48-rc.1", "0.5.49-rc.1", "0.5.48+build.7", "0.5.48-", "0.5", "00.5.48", "0.5.49-rc..1", "0.5.49-rc.", "main\nversion=owned"] {
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
        if matches!(rejected, "0.5.47" | "0.5.48-rc.1" | "0.5.49-rc.1") {
            assert!(
                combined_output(&output).contains("older than final v0.5.48"),
                "incompatible binary must fail with an actionable final minimum-version diagnostic"
            );
        }
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

/// Regression: portable source refs must reject default/auto at the resolver
/// boundary rather than failing indirectly in autoroute calibration.
#[test]
fn composite_action_version_resolver_enforces_source_cpu_boundary() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    for backend in ["", "auto"] {
        let dir = TempDir::new().expect("source boundary tempdir");
        let output_path = dir.path().join("output");
        let output = run_manifest_bash_step(
            "Resolve KeyHog version",
            &[
                ("ACTION_VERSION", ""),
                ("GITHUB_ACTION_REF", "main"),
                ("ACTION_BACKEND", backend),
                ("ACTION_SOURCE_ROOT", repo.to_str().expect("repo")),
                ("GITHUB_OUTPUT", output_path.to_str().expect("output")),
            ],
        );
        assert_eq!(output.status.code(), Some(2), "source backend {backend:?}");
        assert!(combined_output(&output).contains("require backend: cpu"));
        assert!(!output_path.exists() || fs::read(&output_path).expect("output").is_empty());
    }
    let source_dir = TempDir::new().expect("source CPU tempdir");
    let source_output = source_dir.path().join("output");
    let source = run_manifest_bash_step(
        "Resolve KeyHog version",
        &[
            ("ACTION_VERSION", ""),
            ("GITHUB_ACTION_REF", "main"),
            ("ACTION_BACKEND", "cpu"),
            ("ACTION_SOURCE_ROOT", repo.to_str().expect("repo")),
            ("GITHUB_OUTPUT", source_output.to_str().expect("output")),
        ],
    );
    assert!(source.status.success(), "explicit source CPU: {}", combined_output(&source));
    assert!(fs::read_to_string(source_output)
        .expect("source output")
        .contains("release_required=false"));
    for backend in ["", "auto"] {
        let dir = TempDir::new().expect("release boundary tempdir");
        let output_path = dir.path().join("output");
        let release = run_manifest_bash_step(
            "Resolve KeyHog version",
            &[
                ("ACTION_VERSION", "0.5.48"),
                ("ACTION_BACKEND", backend),
                ("GITHUB_OUTPUT", output_path.to_str().expect("output")),
            ],
        );
        assert!(release.status.success(), "release backend {backend:?}");
        assert!(fs::read_to_string(output_path)
            .expect("release output")
            .contains("release_required=true"));
    }
    for manifest_path in [
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../action.yml"),
        action_manifest(),
    ] {
        let manifest = fs::read_to_string(manifest_path).expect("manifest");
        assert!(manifest.contains("ACTION_BACKEND: ${{ inputs.backend }}"));
        assert!(manifest.contains("Portable branch and commit source refs require backend: cpu"));
    }
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

/// Regression: Action release bootstrap once trusted floating package-manager
/// state, so this locks the verifier archive hashes, exact source toolchain,
/// portable source profile, and HTTPS-only authenticated release downloads.
#[test]
fn composite_action_pins_release_verifier_and_source_dependencies() {
    let manifest = fs::read_to_string(action_manifest()).expect("read action.yml");
    assert!(
        manifest.contains("- name: Install pinned release verifier")
            && manifest.contains("verifier_version=\"0.11\"")
            && manifest.contains("f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0")
            && manifest.contains("e7c410ae8b8960d7087392472b040bda9b2f307c76df0384ac37f9ad103fc893")
            && manifest.contains("b9c31c2c3034f81f0e5f5d92cbcc20e67a9671b6e5455661588638848dc58031"),
        "every supported runner must use an exact byte-authenticated minisign archive"
    );
    assert!(
        manifest.contains("toolchain: '1.89.0'")
            && manifest.contains("--no-default-features --features portable")
            && !manifest.contains("apt-get")
            && !manifest.contains("brew install")
            && !manifest.contains("choco install"),
        "source fallback must not depend on floating toolchains or native package-manager state"
    );
    assert!(
        manifest.contains("curl --proto '=https' --tlsv1.2 --fail --location"),
        "verifier and release downloads must require HTTPS with TLS 1.2 or newer"
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

/// Regression: a compromised or replaced minisign download must fail before
/// extraction or PATH mutation rather than bootstrapping a forged verifier.
#[test]
fn composite_action_rejects_pinned_verifier_archive_hash_mismatch() {
    let dir = TempDir::new().expect("verifier bootstrap tempdir");
    let fake_bin = dir.path().join("bin");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&fake_bin).expect("fake bin");
    fs::create_dir(&runner_temp).expect("runner temp");
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf 'attacker-controlled verifier archive' > "$out"
"#,
    );
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        env::var("PATH").expect("PATH is set")
    );
    let github_path = dir.path().join("github-path");
    let output = run_manifest_bash_step(
        "Install pinned release verifier",
        &[
            ("PATH", path.as_str()),
            ("RUNNER_OS", "Linux"),
            ("RUNNER_ARCH", "X64"),
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("UTF-8 runner temp"),
            ),
            (
                "GITHUB_PATH",
                github_path.to_str().expect("UTF-8 GITHUB_PATH"),
            ),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "wrong verifier bytes must fail closed: {}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output).contains("Pinned minisign archive SHA-256 mismatch"),
        "hash mismatch must be operator-visible: {}",
        combined_output(&output)
    );
    assert!(
        !github_path.exists()
            || fs::read_to_string(github_path)
                .expect("read GITHUB_PATH")
                .is_empty(),
        "failed verifier bootstrap must not mutate PATH"
    );
}

/// Regression: verifier bootstrap must fail closed on redirect/download and
/// archive extraction errors, never publishing a partial verifier to PATH.
#[test]
fn composite_action_verifier_redirect_and_extraction_fail_closed() {
    for mode in ["redirect", "extract"] {
        let dir = TempDir::new().expect("verifier bootstrap tempdir");
        let fake_bin = dir.path().join("bin");
        let runner_temp = dir.path().join("runner-temp");
        fs::create_dir(&fake_bin).expect("fake bin");
        fs::create_dir(&runner_temp).expect("runner temp");
        write_executable(
            &fake_bin.join("curl"),
            r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$BOOTSTRAP_FAILURE_MODE" == "redirect" ]]; then exit 22; fi
out=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf 'archive-with-authenticated-test-hash' > "$out"
"#,
        );
        write_executable(
            &fake_bin.join("sha256sum"),
            r#"#!/usr/bin/env bash
printf 'f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0  %s\n' "$1"
"#,
        );
        write_executable(&fake_bin.join("tar"), "#!/usr/bin/env bash\nexit 9\n");
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            env::var("PATH").expect("PATH is set")
        );
        let github_path = dir.path().join("github-path");
        let output = run_manifest_bash_step(
            "Install pinned release verifier",
            &[
                ("PATH", path.as_str()),
                ("RUNNER_OS", "Linux"),
                ("RUNNER_ARCH", "X64"),
                ("BOOTSTRAP_FAILURE_MODE", mode),
                (
                    "RUNNER_TEMP",
                    runner_temp.to_str().expect("UTF-8 runner temp"),
                ),
                (
                    "GITHUB_PATH",
                    github_path.to_str().expect("UTF-8 GITHUB_PATH"),
                ),
            ],
        );
        assert!(
            !output.status.success(),
            "{mode} failure must stop verifier bootstrap"
        );
        assert!(
            !runner_temp.join("minisign").exists(),
            "{mode} failure must not install a verifier"
        );
        assert!(
            !github_path.exists()
                || fs::read_to_string(&github_path)
                    .expect("read GITHUB_PATH")
                    .is_empty(),
            "{mode} failure must not mutate PATH"
        );
    }
}

/// Regression: authenticated release installation must fetch exactly the six
/// required payloads and stage only the verified matcher into its isolated cache.
#[test]
fn composite_action_authenticated_bundle_executes_all_six_exact_downloads() {
    let (dir, output) =
        run_release_download_harness("literal.bin", "-", "bin", "0", "0", false, false, None);
    assert!(
        output.status.success(),
        "valid authenticated bundle must install: {}",
        combined_output(&output)
    );
    let urls = fs::read_to_string(dir.path().join("curl.log")).expect("read curl log");
    let base = "https://github.com/santhreal/keyhog/releases/download/v0.5.45/";
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
    let runtime = private_action_runtime(&dir);
    assert!(
        runtime
            .join("cache/xdg/keyhog/programs/literal-program.bin")
            .is_file(),
        "validated sidecar artifact must reach the invocation-private platform cache"
    );
}

/// Regression: the historical predictable release destination could be
/// preplanted as any filesystem type and `cp` followed symlinks into victims.
#[cfg(unix)]
#[test]
fn composite_action_release_binary_ignores_all_predictable_preplants() {
    for kind in ["symlink", "hardlink", "fifo", "regular"] {
        let (dir, output) = run_release_download_harness(
            "literal.bin",
            "-",
            "bin",
            "0",
            "0",
            false,
            false,
            Some(kind),
        );
        assert!(
            output.status.success(),
            "{kind} preplant must not block private install: {}",
            combined_output(&output)
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("predictable-binary-victim"))
                .expect("victim contents"),
            "victim-unchanged",
            "{kind} preplant must not mutate victim"
        );
        let outputs = fs::read_to_string(dir.path().join("github-output.txt")).expect("outputs");
        let binary = outputs
            .lines()
            .find_map(|line| line.strip_prefix("binary-path="))
            .expect("private binary");
        let metadata = fs::symlink_metadata(binary).expect("private binary metadata");
        assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
        let old = dir.path().join("runner-temp/keyhog");
        let old_type = fs::symlink_metadata(&old).expect("old preplant").file_type();
        match kind {
            "symlink" => assert!(old_type.is_symlink()),
            "fifo" => assert!(old_type.is_fifo()),
            "hardlink" => assert_eq!(fs::read_to_string(old).expect("hardlink"), "victim-unchanged"),
            "regular" => assert_eq!(fs::read_to_string(old).expect("regular"), "preplanted-regular"),
            _ => unreachable!(),
        }
    }
}

/// Regression: lockdown once seeded persistent GPU artifacts despite claiming
/// cache refusal, so authenticated sidecars must remain unstaged in this mode.
#[test]
fn composite_action_lockdown_authenticates_bundle_without_creating_disk_cache() {
    let (dir, output) =
        run_release_download_harness("literal.bin", "-", "bin", "0", "0", false, true, None);
    assert!(
        output.status.success(),
        "lockdown must still authenticate the complete release bundle: {}",
        combined_output(&output)
    );
    let runtime = private_action_runtime(&dir);
    let outputs = fs::read_to_string(dir.path().join("github-output.txt")).expect("outputs");
    let binary_path = outputs
        .lines()
        .find_map(|line| line.strip_prefix("binary-path="))
        .expect("private binary output");
    assert!(Path::new(binary_path).is_file(), "authenticated release binary must be private");
    assert!(
        !runtime.join("cache/xdg/keyhog").exists(),
        "invocation-private GPU cache must remain unseeded so CLI lockdown can apply"
    );
    assert!(
        combined_output(&output).contains("lockdown did not seed the isolated Action cache"),
        "lockdown cache behavior must be operator-visible"
    );
}

#[test]
fn composite_action_release_bundle_proofs_fail_closed() {
    for (checksum_exit, signature_exit, expected) in
        [("1", "0", "checksum"), ("0", "1", "signature")]
    {
        let (_dir, output) = run_release_download_harness("literal.bin", "-", "bin", checksum_exit, signature_exit, false, false, None);
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
            run_release_download_harness(unsafe_entry, "-", "bin", "0", "0", false, false, None);
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
            run_release_download_harness("literal.bin", kind, extension, "0", "0", false, false, None);
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

/// Regression: a preplanted predictable cache symlink from an earlier Action
/// must remain untouched while this invocation stages into its private runtime.
#[cfg(unix)]
#[test]
fn composite_action_resets_isolated_cache_without_following_symlinks() {
    let (dir, output) =
        run_release_download_harness("literal.bin", "-", "bin", "0", "0", true, false, None);
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "private cache must ignore a stale predictable programs symlink: {combined}"
    );
    assert!(
        private_action_runtime(&dir)
            .join("cache/xdg/keyhog/programs/literal-program.bin")
            .is_file(),
        "the authenticated matcher must be installed only into the private cache"
    );
    assert!(
        fs::read_dir(dir.path().join("redirected-programs"))
            .expect("read redirected target")
            .next()
            .is_none(),
        "Action must not stage through the owned programs symlink"
    );
}

/// Regression: release refs must never silently source-build after an
/// authenticated asset failure, while branch/commit refs retain that path.
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
            lower.contains("branch/sha")
                || lower.contains("branch and commit")
                || lower.contains("branch or commit"),
            "{} must scope source builds to branch/SHA or branch/commit Action refs",
            path.display()
        );
        assert!(
            lower.contains("build from source")
                || lower.contains("source builds")
                || lower.contains("build their checked-out source"),
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

/// Regression: default and explicit-auto Action scans once calibrated a
/// throwaway report but discarded routing evidence before the real scan.
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
            && step.contains("ACTION_PRESET: ${{ inputs.preset }}")
            && step.contains("ACTION_LOCKDOWN: ${{ inputs.lockdown }}")
            && step.contains("config_args+=(\"$preset_flag\")")
            && step.contains("args+=(\"$preset_flag\")")
            && step.contains("config_args+=(--lockdown)")
            && step.contains("args+=(--lockdown)")
            && step.contains("\"$ACTION_KEYHOG\" \"${args[@]}\"")
            && step.matches("--no-verify").count() == 2,
        "fresh and explicit-auto Action scans must calibrate the exact requested workload and policy"
    );
    assert!(
        !step.contains("--backend")
            && !step.contains("--verify")
            && !step.contains("--no-autoroute-gpu")
            && !step.contains("calibration_passes")
            && !step.contains("for ((pass"),
        "Action calibration must measure eligible peers without live verification or choosing a route"
    );
}

/// Regression: non-Linux runners cannot honor core lockdown's `mlockall`
/// guarantee, so the Action must reject them before invoking calibration.
#[test]
fn composite_action_lockdown_requires_linux() {
    for runner_os in ["macOS", "Windows"] {
        let dir = TempDir::new().expect("lockdown preflight tempdir");
        let runner_temp = dir.path().join("runner-temp");
        fs::create_dir(&runner_temp).expect("runner temp");
        let output = run_manifest_bash_step(
            "Calibrate autoroute for this scan",
            &[
                ("RUNNER_OS", runner_os),
                ("ACTION_LOCKDOWN", "true"),
                ("ACTION_PRESET", "default"),
                ("ACTION_SCAN_PATH", "."),
                ("ACTION_SEVERITY", "high"),
                (
                    "RUNNER_TEMP",
                    runner_temp.to_str().expect("UTF-8 runner temp"),
                ),
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "{runner_os} lockdown must fail during Action validation: {}",
            combined_output(&output)
        );
        let combined = combined_output(&output);
        assert!(
            combined.contains("requires a Linux runner with sufficient locked-memory capacity")
                && combined.contains("sufficient memlock limit")
                && combined.contains("--cap-add IPC_LOCK")
                && combined.contains("--ulimit memlock=-1:-1")
                && combined.contains("lockdown:false"),
            "lockdown rejection must give exact Linux provisioning guidance: {combined}"
        );
    }
}

/// Regression: a finite soft memlock limit can be sufficient. Execute the
/// composite calibration step under a finite limit and prove the Action
/// delegates the protection decision to KeyHog instead of rejecting heuristically.
#[test]
fn composite_action_accepts_finite_memlock_and_invokes_keyhog() {
    let dir = TempDir::new().expect("finite memlock tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    let bash_env = dir.path().join("finite-memlock.sh");
    fs::write(&bash_env, "ulimit -l 64\n").expect("finite memlock Bash environment");
    let call_log = dir.path().join("calls.log");
    let limit_log = dir.path().join("limit.log");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$(ulimit -l)" > "$KEYHOG_LIMIT_LOG"
printf '%s\n' "$1" >> "$KEYHOG_CALL_LOG"
if [[ "$1" == "config" ]]; then
  printf '[effective-config]\nincremental = false\n'
  exit 0
fi
previous=""
for arg in "$@"; do
  if [[ "$previous" == "--output" ]]; then printf '[]\n' > "$arg"; fi
  if [[ "$previous" == "--autoroute-cache" ]]; then
    printf '{"schema_version":1}\n' > "$arg"
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
    let github_output = dir.path().join("github-output");
    let output = run_manifest_bash_step(
        "Calibrate autoroute for this scan",
        &[
            ("BASH_ENV", bash_env.to_str().expect("UTF-8 BASH_ENV")),
            ("RUNNER_OS", "Linux"),
            ("ACTION_LOCKDOWN", "true"),
            ("ACTION_PRESET", "default"),
            ("ACTION_SCAN_PATH", "."),
            ("ACTION_SEVERITY", "high"),
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("UTF-8 runner temp"),
            ),
            (
                "GITHUB_OUTPUT",
                github_output.to_str().expect("UTF-8 GITHUB_OUTPUT"),
            ),
            (
                "KEYHOG_CALL_LOG",
                call_log.to_str().expect("UTF-8 call log"),
            ),
            (
                "KEYHOG_LIMIT_LOG",
                limit_log.to_str().expect("UTF-8 limit log"),
            ),
            ("PATH", path.as_str()),
        ],
    );
    assert!(
        output.status.success(),
        "finite memlock must reach and trust KeyHog's real protection checks: {}",
        combined_output(&output)
    );
    assert_eq!(
        fs::read_to_string(&limit_log).expect("record finite memlock"),
        "64\n",
        "the behavioral probe must execute under a finite memlock limit"
    );
    assert_eq!(
        fs::read_to_string(&call_log).expect("read KeyHog calls"),
        "config\nscan\n",
        "the Action must delegate both effective-config and calibration to KeyHog"
    );
    assert!(
        fs::read_to_string(github_output)
            .expect("read calibration outputs")
            .contains("cache-sha256="),
        "successful finite-memlock calibration must publish a bound receipt"
    );
}

/// Regression: backend:auto may never silently degrade to CPU when calibration
/// has not persisted the exact decision consumed by the scan.
#[test]
fn composite_action_rejects_missing_autoroute_receipt() {
    let dir = TempDir::new().expect("missing autoroute receipt tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    write_executable(
        &dir.path().join("keyhog"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "config" ]]; then exit 0; fi
previous=""
for arg in "$@"; do
  if [[ "$previous" == "--output" ]]; then printf '[]\n' > "$arg"; fi
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
            ("RUNNER_OS", "Linux"),
            ("ACTION_LOCKDOWN", "false"),
            ("ACTION_PRESET", "default"),
            ("ACTION_SCAN_PATH", "."),
            ("ACTION_SEVERITY", "high"),
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("UTF-8 runner temp"),
            ),
            ("PATH", path.as_str()),
        ],
    );
    assert_eq!(output.status.code(), Some(3), "missing route must fail closed");
    assert!(
        combined_output(&output).contains("did not publish a trusted routing receipt"),
        "missing route must explain that auto requires a bound decision: {}",
        combined_output(&output)
    );
}


/// Regression: lockdown autoroute must remove stale global state, calibrate
/// exactly once without verification, and publish only a fresh ephemeral receipt.
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
  previous=""
  for arg in "$@"; do
    if [[ "$previous" == "--autoroute-cache" && -e "$arg" ]]; then
      echo "stale autoroute receipt reached config preflight" >&2
      exit 71
    fi
    previous="$arg"
  done
  printf '[effective-config]\nincremental = %s\n' "$STUB_INCREMENTAL"
  exit "${STUB_CONFIG_EXIT:-0}"
fi
printf '__CALL__\0' >> "$KEYHOG_CALL_LOG"
printf '%s\0' "$@" >> "$KEYHOG_CALL_LOG"
previous=""
for arg in "$@"; do
  if [[ "$previous" == "--output" ]]; then
    printf '[]\n' > "$arg"
  elif [[ "$previous" == "--autoroute-cache" ]]; then
    printf '{"schema_version":1}\n' > "$arg"
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
                ("ACTION_PRESET", "precision"),
                ("ACTION_LOCKDOWN", "true"),
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
        let runtime = private_action_runtime(&dir);
        let route_cache = runtime.join("autoroute/route.json");
        let probe = runtime.join("autoroute/probe.json");
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
                "--no-verify",
                "--path",
                "repo slice",
                "--severity",
                "critical",
                "--format",
                "json",
                "--autoroute-cache",
                route_cache.to_str().expect("UTF-8 route cache"),
                "--precision",
                "--lockdown",
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
        let expected = vec![
            "scan".to_string(),
            "--autoroute-calibrate".to_string(),
            "--autoroute-gpu".to_string(),
            "--no-verify".to_string(),
            "--path".to_string(),
            "repo slice".to_string(),
            "--severity".to_string(),
            "critical".to_string(),
            "--format".to_string(),
            "json".to_string(),
            "--output".to_string(),
            probe.display().to_string(),
            "--autoroute-cache".to_string(),
            route_cache.display().to_string(),
            "--precision".to_string(),
            "--lockdown".to_string(),
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
        assert!(
            !route_cache.exists() && !runtime.join("autoroute/route.json.lock").exists(),
            "unpublished private calibration receipt and lock must be removed"
        );
    }
}

/// Regression: a background process could replace the deterministic autoroute
/// pathname after calibration; the scan must bind and reject substituted bytes.
#[test]
fn composite_action_rejects_substituted_autoroute_receipt_before_scan() {
    let dir = TempDir::new().expect("route substitution tempdir");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    let route_cache = runner_temp.join("route.json");
    fs::write(&route_cache, "substituted-route").expect("write substituted route");
    let output = run_manifest_bash_step(
        "Run scan",
        &[
            (
                "RUNNER_TEMP",
                runner_temp.to_str().expect("UTF-8 runner temp"),
            ),
            (
                "ACTION_AUTOROUTE_CACHE",
                route_cache.to_str().expect("UTF-8 route cache"),
            ),
            (
                "ACTION_AUTOROUTE_CACHE_SHA256",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("ACTION_LOCKDOWN", "false"),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "substituted routing state must fail before wrapper execution: {}",
        combined_output(&output)
    );
    assert!(
        combined_output(&output)
            .contains("Autoroute calibration receipt changed after calibration"),
        "receipt substitution must be operator-visible: {}",
        combined_output(&output)
    );
    assert!(
        !route_cache.exists(),
        "substituted Action-owned receipt must still be cleaned on failure"
    );
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

/// Locks out floating image/action tags advancing before the authenticated CI
/// verdict, signed candidate smoke, immutable container, and public transition.
#[test]
fn release_floating_tags_advance_only_after_atomic_publication_gates() {
    let source = fs::read_to_string(release_workflow()).expect("read release.yml");
    let workflow: serde_yaml::Value =
        serde_yaml::from_str(&source).expect("release.yml must parse");
    let workflow = workflow
        .as_mapping()
        .expect("release workflow is a mapping");
    let docker = workflow_job(workflow, "docker");
    let publish = workflow_job(workflow, "publish");
    let major = workflow_job(workflow, "major-tag");
    let crates = workflow_job(workflow, "crates");

    let mut docker_needs = workflow_job_needs(docker);
    docker_needs.sort_unstable();
    assert_eq!(
        docker_needs,
        ["ci-verdict", "smoke"],
        "the immutable container must wait for authenticated CI and signed candidate smoke"
    );
    let mut publish_needs = workflow_job_needs(publish);
    publish_needs.sort_unstable();
    assert_eq!(
        publish_needs,
        ["ci-verdict", "docker", "sign", "smoke"],
        "public release transition must explicitly wait for authenticated CI, the signed receipt, immutable container, and candidate smoke"
    );
    let mut major_needs = workflow_job_needs(major);
    major_needs.sort_unstable();
    assert_eq!(
        major_needs,
        ["ci-verdict", "publish"],
        "major-tag must wait for authenticated CI and the exact public release"
    );
    assert_eq!(
        workflow_job_needs(crates),
        ["publish"],
        "crates must not advance until the exact immutable release is public"
    );

    // Regression: prereleases and older manual reruns must never move either
    // floating namespace, even though the immutable image is a publish prerequisite.
    for (name, job) in [("docker", docker), ("major-tag", major)] {
        let floating = workflow_run_step_containing(job, "is-newest-stable-tag.sh");
        let run = yaml_get(floating, "run")
            .and_then(serde_yaml::Value::as_str)
            .expect("floating-tag predicate is a run step");
        assert!(
            run.contains("\"$KEYHOG_RELEASE_TAG\""),
            "{name} must evaluate the exact validated release tag"
        );
        assert!(
            workflow_job_steps(job)
                .iter()
                .filter_map(serde_yaml::Value::as_mapping)
                .any(|step| {
                    yaml_get(step, "if").and_then(serde_yaml::Value::as_str)
                        == Some("steps.floating.outputs.advance == 'true'")
                }),
            "{name} must gate its floating mutation on the shared stable-tag predicate"
        );
    }

    let image = workflow_job_steps(docker)
        .iter()
        .filter_map(serde_yaml::Value::as_mapping)
        .find(|step| {
            yaml_get(step, "uses")
                .and_then(serde_yaml::Value::as_str)
                .is_some_and(|uses| uses.starts_with("docker/build-push-action@"))
        })
        .expect("docker job builds the immutable image");
    let tags = yaml_get(image, "with")
        .and_then(serde_yaml::Value::as_mapping)
        .and_then(|with| yaml_get(with, "tags"))
        .and_then(serde_yaml::Value::as_str)
        .expect("container build declares tags");
    assert!(
        tags.contains("steps.tag.outputs.version") && !tags.contains(":latest"),
        "the build step must publish only the immutable version tag; latest advances separately"
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

/// Regression: source fallback once depended on floating Linux Hyperscan
/// packages; every runner must now build the lockfile-backed portable profile.
#[test]
fn composite_action_source_build_uses_portable_locked_features() {
    let dir = TempDir::new().expect("tempdir");
    let fake_bin = dir.path().join("bin");
    let source_root = dir.path().join("source");
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&fake_bin).expect("create fake bin");
    fs::create_dir(&source_root).expect("create source root");
    fs::create_dir(&runner_temp).expect("create runner temp");
    let source_output = dir.path().join("source-output.txt");
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
    let source_output_str = source_output.to_string_lossy().into_owned();
    let cargo_args_str = cargo_args.to_string_lossy().into_owned();
    let output = run_manifest_bash_step(
        "Build keyhog from source (fallback)",
        &[
            ("PATH", path.as_str()),
            ("ACTION_SOURCE_ROOT", source_root_str.as_str()),
            ("RUNNER_TEMP", runner_temp_str.as_str()),
            ("GITHUB_OUTPUT", source_output_str.as_str()),
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
        args.contains("--no-default-features\n--features\nportable\n"),
        "source fallback must use one deterministic no-native-dependency feature profile; args={args}"
    );
    let outputs = fs::read_to_string(&source_output).expect("source outputs");
    let binary_path = outputs
        .lines()
        .find_map(|line| line.strip_prefix("binary-path="))
        .expect("source binary path");
    assert!(
        Path::new(binary_path).is_file() && !runner_temp.join("keyhog").exists(),
        "source fallback must publish only into its invocation-private digest directory"
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

/// Regression: cross-platform release installation must retain the `.exe`
/// identity while atomically replacing stale matcher destinations in isolation.
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
if [[ "${1:-}" == "-c" ]]; then exit 0; fi
exec /usr/bin/sha256sum "$@"
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
    let action_cache_home = runner_temp.join("keyhog-action-cache");
    let cache_root = action_cache_home.join("xdg");
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
            ("KEYHOG_MINISIGN_PUBLIC_KEY", "test-public-key"),
        ],
    );
    let combined = combined_output(&output);
    assert_eq!(
        output.status.code(),
        Some(0),
        "Windows prebuilt download path must complete with local fake tools; output={combined}"
    );
    let github_output = fs::read_to_string(&output_path).expect("read GITHUB_OUTPUT");
    let binary_path = github_output
        .lines()
        .find_map(|line| line.strip_prefix("binary-path="))
        .expect("private Windows binary");
    assert!(
        binary_path.ends_with("/keyhog.exe") && Path::new(binary_path).is_file(),
        "Windows prebuilt must retain keyhog.exe in its invocation-private digest directory"
    );
    assert!(
        !runner_temp.join("keyhog.exe").exists() && !runner_temp.join("keyhog").exists(),
        "Windows prebuilt must not publish to predictable RUNNER_TEMP paths"
    );
    let private_cache = private_action_runtime(&dir).join("cache/xdg");
    assert!(
        private_cache
            .join("keyhog/programs/literal-program.bin")
            .is_file(),
        "authenticated GPU literal artifacts must be seeded into the invocation-private cache"
    );
    #[cfg(unix)]
    {
        let installed = private_cache.join("keyhog/programs/literal-program.bin");
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
    assert!(
        github_output.contains("found=true"),
        "verified Windows prebuilt download must advertise found=true; output={github_output}"
    );
}

#[test]
fn keyhog_workflow_dogfoods_local_composite_action() {
    let workflow = fs::read_to_string(keyhog_workflow()).expect("read keyhog.yml");
    assert!(
        workflow.contains("uses: ./"),
        "repo CI must dogfood the bundled composite action, not a divergent inline scanner"
    );
    assert!(
        workflow.contains("backend: simd"),
        "hosted one-shot dogfood must pin SIMD instead of spending the job on autoroute calibration"
    );
    let root_action =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../action.yml"))
            .expect("read root action.yml");
    assert!(
        root_action.contains("continue-on-error: true")
            && root_action
                .contains("bash \"${{ github.action_path }}/.github/actions/keyhog/run-scan.sh\"",)
            && root_action.contains("steps.scan.outputs.runner-exit-code != '0'"),
        "the root action must upload reports before restoring the standalone runner status"
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
fn differential_bench_builds_checked_out_keyhog_release_binary() {
    let source =
        fs::read_to_string(differential_bench_workflow()).expect("read differential-bench.yml");
    let workflow: serde_yaml::Value =
        serde_yaml::from_str(&source).expect("differential-bench.yml must parse");
    let gate = workflow_job(
        workflow
            .as_mapping()
            .expect("differential benchmark workflow is a mapping"),
        "gate",
    );
    let build = workflow_run_step_containing(
        gate,
        "cargo build --locked --release -p keyhog --bin keyhog",
    );
    let run = yaml_get(build, "run")
        .and_then(serde_yaml::Value::as_str)
        .expect("checked-out build step runs shell commands");

    // Regression: selecting a step by its display name let harmless wording
    // changes hide whether the benchmark still executes the checked-out binary.
    assert!(
        run.contains("install -m 0755 target/release/keyhog \"$HOME/.local/bin/keyhog\""),
        "differential bench must install only the release artifact it just built"
    );
    assert!(
        run.contains("git rev-parse HEAD"),
        "differential evidence must disclose the exact checked-out KeyHog commit"
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
        versions.contains("keyhog --version")
            && versions.contains("betterleaks --version")
            && versions.contains("kingfisher --version"),
        "scanner version proof must exercise every required installed competitor"
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

/// Locks out direct dispatch-input interpolation or emitting a release identity
/// before actor, annotated tag, signer, main ancestry, and exact CI are proven.
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
        workflow.contains("KEYHOG_MANUAL_TAG: ${{ inputs.tag }}"),
        "manual release tag must enter shell through the named KEYHOG_MANUAL_TAG env var"
    );
    let verifier = workflow
        .find("automation/scripts/verify_release_tag.py")
        .expect("authenticated tag verifier");
    let ci_verdict = workflow
        .find("(.total_count == (.jobs | length))")
        .expect("exact complete CI verdict");
    let output = workflow
        .find("printf 'tag=%s\\n' \"$tag\" >> \"$GITHUB_OUTPUT\"")
        .expect("validated tag output");
    assert!(
        verifier < ci_verdict && ci_verdict < output,
        "release outputs must follow signed-tag and exact-CI verification"
    );
    assert!(
        workflow.contains("release source must name an exact semantic-version tag")
            && workflow.contains("--authorized-key")
            && workflow.contains("--authorized-fingerprint")
            && workflow.contains("--main-ref-json")
            && workflow.contains("--compare-json"),
        "release boundary must fail closed on malformed SemVer, signer, or main ancestry"
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
        workflow.contains("KEYHOG_RELEASE_TAG: ${{ needs.ci-verdict.outputs.tag }}"),
        "validated release tag output should enter downstream shell steps through env"
    );
    assert!(
        workflow.contains("git/ref/tags/$tag")
            && workflow.contains("git/tags/$tag_object")
            && workflow.contains("ref: ${{ needs.ci-verdict.outputs.commit }}")
            && !workflow.contains("ref: refs/tags/${{ inputs.tag }}"),
        "manual releases must authenticate the annotated tag then checkout only its validated commit"
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

/// Locks out public release mutation before authenticated CI, every private
/// payload, signed candidate smoke, and immutable container provenance.
#[test]
fn release_stages_privately_then_publishes_the_signed_immutable_receipt() {
    let source = fs::read_to_string(release_workflow()).expect("read release.yml");
    let workflow: serde_yaml::Value =
        serde_yaml::from_str(&source).expect("release.yml must parse");
    let workflow = workflow
        .as_mapping()
        .expect("release workflow is a mapping");
    let build = workflow_job(workflow, "build");
    let sign = workflow_job(workflow, "sign");
    let smoke = workflow_job(workflow, "smoke");
    let publish = workflow_job(workflow, "publish");

    assert!(
        workflow_job_steps(build)
            .iter()
            .filter_map(serde_yaml::Value::as_mapping)
            .any(|step| {
                yaml_get(step, "uses")
                    .and_then(serde_yaml::Value::as_str)
                    .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                    && yaml_get(step, "name").and_then(serde_yaml::Value::as_str)
                        == Some("Stage unsigned release bundle")
            }),
        "matrix jobs must stage unsigned bundles privately"
    );
    let mut sign_needs = workflow_job_needs(sign);
    sign_needs.sort_unstable();
    assert_eq!(
        sign_needs,
        ["build", "ci-verdict", "installers"],
        "the sole signing job must wait for authenticated CI and every privately staged payload"
    );
    let mut smoke_needs = workflow_job_needs(smoke);
    smoke_needs.sort_unstable();
    assert_eq!(
        smoke_needs,
        ["ci-verdict", "sign"],
        "candidate smoke must explicitly retain authenticated CI and signed private artifacts"
    );

    let prepare = workflow_run_step_containing(sign, "publish_release_assets.py\" prepare");
    let prepare = yaml_get(prepare, "run")
        .and_then(serde_yaml::Value::as_str)
        .expect("private preparation runs shell commands");
    assert!(
        prepare.contains("--receipt \"$workdir/release-publication.json\"")
            && prepare.contains("\"$workdir/release-publication.json\" </dev/null")
            && !prepare.contains("publish_release_assets.py\" publish"),
        "signing must produce and sign an immutable-ID receipt without making the release public"
    );

    let transition = workflow_run_step_containing(publish, "publish_release_assets.py\" publish");
    let transition = yaml_get(transition, "run")
        .and_then(serde_yaml::Value::as_str)
        .expect("public transition runs shell commands");
    assert!(
        transition.contains("--receipt \"$GITHUB_WORKSPACE/proof/release-publication.json\""),
        "the final job must publish only the downloaded signed immutable-ID receipt"
    );

    // Regression: publication is atomic only when both externally visible
    // prerequisites and the exact private receipt are proven first.
    let mut needs = workflow_job_needs(publish);
    needs.sort_unstable();
    assert_eq!(needs, ["ci-verdict", "docker", "sign", "smoke"]);
    let proof = workflow_run_step_containing(publish, "minisign -Vm");
    let proof = yaml_get(proof, "run")
        .and_then(serde_yaml::Value::as_str)
        .expect("publication proof runs shell commands");
    assert!(
        proof.contains("release-publication.json")
            && proof.contains("KEYHOG_CONTAINER_DIGEST")
            && proof.contains("git rev-parse HEAD"),
        "final publication must verify the receipt signature, container digest, and source commit"
    );
}

#[test]
fn integration_smoke_sarif_path_requires_the_findings_exit_code() {
    let workflow =
        fs::read_to_string(integration_smoke_workflow()).expect("read integration-smoke.yml");
    let sarif = workflow
        .split("- name: SARIF output")
        .nth(1)
        .and_then(|tail| tail.split("- name: Empty dir scan").next())
        .expect("SARIF smoke step exists");
    assert!(
        sarif.contains("code=$?")
            && sarif.contains("if [ \"$code\" != \"1\" ]; then")
            && sarif.contains("FAIL: expected exit 1 (secrets found), got $code"),
        "SARIF smoke must require the findings exit code as well as validating the report"
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
  ┌ HIGH ─── first
  │ Secret:     [REDACTED]
  └─────────────────────────────────────────────
  ┌ HIGH ─── second
  │ Secret:     [REDACTED]
  └─────────────────────────────────────────────
  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  2 secrets found · 2 unverified
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
        Some(1),
        "standalone text findings must fail after counting the report; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output_file(&dir).contains("findings=2"),
        "text report count must use stable field labels"
    );
    let scan = fs::read_to_string(action_script()).expect("read run-scan.sh");
    assert!(
        scan.contains("\"$keyhog_bin\" action-report verify")
            && scan.contains("--receipt \"$action_receipt\"")
            && !scan.contains("command -v jq")
            && !scan.contains("python3")
            && !scan.contains("grep -c"),
        "the Action must verify KeyHog's source-emitted receipt without ambient parsers"
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
        Some(1),
        "standalone JSONL findings must fail after counting the report; stderr={}",
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

/// Regression: a clean exit with structurally invalid JSONL once produced an
/// uploadable receipt; report corruption must remain fail-closed and visible.
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
        combined_output(&output).contains("Could not verify scan report receipt"),
        "non-KeyHog JSONL must be operator-visible as untrusted emission: output={}",
        combined_output(&output)
    );
}

/// Regression: malformed JSONL on a findings exit must not fabricate one
/// finding merely to reconcile the process status.
#[test]
fn action_rejects_non_object_findings_jsonl() {
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
        Some(3),
        "non-object findings JSONL must fail report validation; output={}",
        combined_output(&output)
    );
    assert!(
        output_file(&dir).contains("findings=\n"),
        "parse failure after findings exit must publish an unavailable count"
    );
}

/// Regression: the composite must validate and count reports with only Bash
/// and the KeyHog binary available; jq and Python are not runtime dependencies.
#[cfg(unix)]
#[test]
fn action_counts_report_with_minimal_path_without_jq_or_python() {
    let dir = TempDir::new().expect("minimal PATH tempdir");
    write_stub(
        &dir,
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then shift; out="$1"; fi
  shift || true
done
printf '[]\n' > "$out"
"#,
    );
    std::os::unix::fs::symlink("/bin/bash", dir.path().join("bash"))
        .expect("provide only Bash beside KeyHog");
    for tool in ["sha256sum", "wc", "rm", "mktemp", "cat", "chmod", "basename"] {
        std::os::unix::fs::symlink(format!("/usr/bin/{tool}"), dir.path().join(tool))
            .unwrap_or_else(|error| panic!("provide {tool} in minimal PATH: {error}"));
    }
    let runner_temp = dir.path().join("runner-temp");
    fs::create_dir(&runner_temp).expect("runner temp");
    let output_path = dir.path().join("github-output.txt");
    let summary_path = dir.path().join("summary.md");
    let args = action_script_args(
        &[],
        &[
            ("ACTION_INPUT_FORMAT", "json"),
            ("ACTION_INPUT_OUTPUT", "keyhog-results.json"),
        ],
    );
    let output = Command::new("bash")
        .arg(action_script())
        .args(args)
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", dir.path())
        .env("GITHUB_OUTPUT", &output_path)
        .env("GITHUB_STEP_SUMMARY", &summary_path)
        .env("RUNNER_TEMP", &runner_temp)
        .output()
        .expect("run Action with minimal PATH");
    assert!(
        output.status.success(),
        "KeyHog-owned parser must work without jq/python: {}",
        combined_output(&output)
    );
    assert!(
        fs::read_to_string(output_path)
            .expect("read receipt")
            .contains("findings=0\n"),
        "minimal dependency receipt must carry the exact count"
    );
    assert!(!dir.path().join("jq").exists() && !dir.path().join("python3").exists());
}

/// Regression: untrusted summary values containing Markdown/HTML delimiters
/// must remain inside one HTML-escaped code cell without table or line injection.
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
            ("ACTION_INPUT_SCAN_PATH", "src|`name\n<second>&"),
            ("ACTION_INPUT_BASELINE", "<base>|`line\nthird&"),
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
        summary.contains("| Path | <code>src&#124;`name&#10;&lt;second&gt;&amp;</code> |"),
        "path cell must HTML-escape delimiters and encode newlines without treating backticks as Markdown; summary={summary}"
    );
    assert!(
        summary.contains("| Baseline | <code>&lt;base&gt;&#124;`line&#10;third&amp;</code> |"),
        "baseline cell must HTML-escape delimiters and encode newlines without treating backticks as Markdown; summary={summary}"
    );
}
/// Regression: cleanup ownership is established before policy validation so an
/// early invalid argument cannot leak the caller-owned autoroute receipt.
#[cfg(unix)]
#[test]
fn action_cleans_autoroute_receipt_on_early_validation_failure() {
    for kind in ["symlink", "fifo", "regular"] {
        let dir = TempDir::new().expect("early cleanup tempdir");
        let runner_temp = dir.path().join("runner-temp");
        fs::create_dir(&runner_temp).expect("runner temp");
        let route = runner_temp.join("route.json");
        let lock = runner_temp.join("route.json.lock");
        let victim = dir.path().join("lock-victim");
        fs::write(&route, "owned route").expect("route");
        preplant_destination(&lock, &victim, kind);
        let output = Command::new("bash")
            .arg(action_script())
            .args([
                "--format",
                "invalid",
                "--autoroute-cache",
                route.to_str().expect("route path"),
                "--cleanup-autoroute-cache",
            ])
            .env("RUNNER_TEMP", &runner_temp)
            .output()
            .expect("run invalid wrapper");
        assert_eq!(output.status.code(), Some(2), "{kind}: {}", combined_output(&output));
        assert!(!route.exists() && !lock.exists(), "{kind} cleanup must remove route + lock");
        assert_eq!(
            fs::read_to_string(victim).expect("victim"),
            "victim-unchanged",
            "{kind} lock cleanup must not mutate victim"
        );
    }
}

/// Regression: a snapshot replaced after wrapper verification must stop both
/// internal uploads rather than degrading to a warning-only clean job.
#[test]
fn composite_action_report_check_rejects_changed_private_snapshot() {
    let dir = TempDir::new().expect("snapshot tamper tempdir");
    let runner_temp = dir.path().join("runner-temp");
    let runtime = runner_temp.join("keyhog-action-runtime.test");
    let snapshot_dir = runtime.join("report-snapshot.test");
    fs::create_dir_all(&snapshot_dir).expect("snapshot dir");
    let snapshot = snapshot_dir.join("report.sarif");
    fs::write(&snapshot, "verified bytes").expect("snapshot");
    let digest_output = Command::new("/usr/bin/sha256sum")
        .arg(&snapshot)
        .output()
        .expect("snapshot digest");
    let digest_text = String::from_utf8(digest_output.stdout).expect("digest UTF-8");
    let digest = digest_text.split_whitespace().next().expect("digest");
    fs::write(&snapshot, "tampered bytes").expect("tamper snapshot");
    let github_output = dir.path().join("report-check-output");
    let output = run_manifest_bash_step(
        "Check receipt-bound report snapshot before upload",
        &[
            ("RUNNER_TEMP", runner_temp.to_str().expect("runner temp")),
            ("ACTION_RUNTIME", runtime.to_str().expect("runtime")),
            ("ACTION_REPORT_NAME", snapshot.to_str().expect("snapshot")),
            ("ACTION_REPORT_SHA256", digest),
            ("ACTION_SCAN_REPORT_PRESENT", "true"),
            ("GITHUB_OUTPUT", github_output.to_str().expect("output")),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "changed private snapshot must fail closed: {}",
        combined_output(&output)
    );
    assert!(combined_output(&output).contains("missing or changed after verification"));
}

/// Regression: the shared duplicate-category registry must reject symlink
/// redirection without mutating its victim and still reject a real duplicate.
#[cfg(unix)]
#[test]
fn composite_action_category_registry_rejects_symlink_and_duplicate() {
    let dir = TempDir::new().expect("category registry tempdir");
    let runner_temp = dir.path().join("runner-temp");
    let categories = runner_temp.join("keyhog-analysis-categories");
    let victim = dir.path().join("victim");
    fs::create_dir_all(&categories).expect("categories root");
    fs::create_dir(&victim).expect("victim");
    std::os::unix::fs::symlink(&victim, categories.join("7-1-job")).expect("identity symlink");
    let output_path = dir.path().join("category-output");
    let envs = [
        ("RUNNER_TEMP", runner_temp.to_str().expect("runner temp")),
        ("GITHUB_RUN_ID", "7"),
        ("GITHUB_RUN_ATTEMPT", "1"),
        ("GITHUB_JOB", "job"),
        ("ACTION_ANALYSIS_CATEGORY", "slice"),
        ("ACTION_FORMAT", "sarif"),
        ("GITHUB_OUTPUT", output_path.to_str().expect("output")),
    ];
    let redirected = run_manifest_bash_step("Compute output filename", &envs);
    assert_eq!(redirected.status.code(), Some(2));
    assert!(fs::read_dir(&victim).expect("victim entries").next().is_none());
    fs::remove_file(categories.join("7-1-job")).expect("remove symlink");
    let first = run_manifest_bash_step("Compute output filename", &envs);
    assert!(first.status.success(), "first category claim: {}", combined_output(&first));
    let duplicate = run_manifest_bash_step("Compute output filename", &envs);
    assert_eq!(duplicate.status.code(), Some(2));
    assert!(combined_output(&duplicate).contains("Conflicting analysis-category"));
}

/// Regression: verifier bootstrap must never touch the historical predictable
/// `$RUNNER_TEMP/minisign` destination regardless of its filesystem type.
#[cfg(unix)]
#[test]
fn composite_action_minisign_ignores_all_predictable_preplants() {
    for kind in ["symlink", "hardlink", "fifo", "regular"] {
        let dir = TempDir::new().expect("minisign preplant tempdir");
        let runner_temp = dir.path().join("runner-temp");
        let fake_bin = dir.path().join("bin");
        fs::create_dir(&runner_temp).expect("runner temp");
        fs::create_dir(&fake_bin).expect("fake bin");
        preplant_destination(
            &runner_temp.join("minisign"),
            &dir.path().join("verifier-victim"),
            kind,
        );
        write_executable(
            &fake_bin.join("curl"),
            r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "--output" ]]; then shift; out="$1"; fi
  shift || true
done
printf 'archive' > "$out"
"#,
        );
        write_executable(
            &fake_bin.join("sha256sum"),
            r#"#!/usr/bin/env bash
printf 'f0a0954413df8531befed169e447a66da6868d79052ed7e892e50a4291af7ae0  %s\n' "$1"
"#,
        );
        write_executable(
            &fake_bin.join("tar"),
            r#"#!/usr/bin/env bash
set -euo pipefail
dest=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == "-C" ]]; then shift; dest="$1"; fi
  shift || true
done
mkdir -p "$dest/minisign-linux/x86_64"
cat > "$dest/minisign-linux/x86_64/minisign" <<'SH'
#!/usr/bin/env bash
printf 'minisign 0.11\n'
SH
chmod +x "$dest/minisign-linux/x86_64/minisign"
"#,
        );
        let path = format!("{}:{}", fake_bin.display(), env::var("PATH").expect("PATH"));
        let github_output = dir.path().join("verifier-output");
        let output = run_manifest_bash_step(
            "Install pinned release verifier",
            &[
                ("PATH", path.as_str()),
                ("RUNNER_TEMP", runner_temp.to_str().expect("runner temp")),
                ("RUNNER_OS", "Linux"),
                ("RUNNER_ARCH", "X64"),
                ("GITHUB_OUTPUT", github_output.to_str().expect("output")),
            ],
        );
        assert!(output.status.success(), "{kind}: {}", combined_output(&output));
        assert_eq!(
            fs::read_to_string(dir.path().join("verifier-victim")).expect("victim"),
            "victim-unchanged"
        );
        let outputs = fs::read_to_string(github_output).expect("verifier outputs");
        let verifier = outputs
            .lines()
            .find_map(|line| line.strip_prefix("path="))
            .expect("private verifier");
        let metadata = fs::symlink_metadata(verifier).expect("verifier metadata");
        assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
    }
}

/// Regression: source fallback must ignore every preplanted old predictable
/// binary destination and publish only its invocation-private digest copy.
#[cfg(unix)]
#[test]
fn composite_action_source_binary_ignores_all_predictable_preplants() {
    for kind in ["symlink", "hardlink", "fifo", "regular"] {
        let dir = TempDir::new().expect("source preplant tempdir");
        let runner_temp = dir.path().join("runner-temp");
        let source_root = dir.path().join("source");
        let fake_bin = dir.path().join("bin");
        fs::create_dir(&runner_temp).expect("runner temp");
        fs::create_dir(&source_root).expect("source");
        fs::create_dir(&fake_bin).expect("fake bin");
        preplant_destination(
            &runner_temp.join("keyhog"),
            &dir.path().join("source-victim"),
            kind,
        );
        write_executable(
            &fake_bin.join("cargo"),
            r#"#!/usr/bin/env bash
set -euo pipefail
mkdir -p target/release
printf '#!/usr/bin/env bash\nexit 0\n' > target/release/keyhog
chmod +x target/release/keyhog
"#,
        );
        let path = format!("{}:{}", fake_bin.display(), env::var("PATH").expect("PATH"));
        let github_output = dir.path().join("source-output");
        let output = run_manifest_bash_step(
            "Build keyhog from source (fallback)",
            &[
                ("PATH", path.as_str()),
                ("RUNNER_TEMP", runner_temp.to_str().expect("runner temp")),
                ("ACTION_SOURCE_ROOT", source_root.to_str().expect("source")),
                ("ACTION_RESOLVED_VERSION", "0.5.48"),
                ("GITHUB_OUTPUT", github_output.to_str().expect("output")),
            ],
        );
        assert!(output.status.success(), "{kind}: {}", combined_output(&output));
        assert_eq!(
            fs::read_to_string(dir.path().join("source-victim")).expect("victim"),
            "victim-unchanged"
        );
        let outputs = fs::read_to_string(github_output).expect("source outputs");
        let binary = outputs
            .lines()
            .find_map(|line| line.strip_prefix("binary-path="))
            .expect("private source binary");
        let metadata = fs::symlink_metadata(binary).expect("source metadata");
        assert!(metadata.file_type().is_file() && !metadata.file_type().is_symlink());
    }
}
