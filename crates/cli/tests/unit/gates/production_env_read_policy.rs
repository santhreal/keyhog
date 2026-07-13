use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read source directory {}: {error}", root.display()));
    for entry in entries {
        let entry = entry
            .unwrap_or_else(|error| panic!("read dir entry under {}: {error}", root.display()));
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn env_call_name(line: &str) -> Option<Option<String>> {
    for call in [
        "std::env::var(",
        "std::env::var_os(",
        "env::var(",
        "env::var_os(",
    ] {
        let Some(start) = line.find(call) else {
            continue;
        };
        let rest = line[start + call.len()..].trim_start();
        let Some(rest) = rest.strip_prefix('"') else {
            return Some(None);
        };
        let Some(end) = rest.find('"') else {
            return Some(None);
        };
        return Some(Some(rest[..end].to_string()));
    }
    None
}

fn allowed_env_read(rel: &str, name: &str) -> bool {
    match name {
        // `PATH`: doctor health check locates the keyhog binary.
        "PATH" => rel == "crates/cli/src/subcommands/doctor.rs",
        "NO_COLOR" => matches!(
            rel,
            "crates/cli/src/lib.rs"
                | "crates/cli/src/style.rs"
                | "crates/cli/src/orchestrator/run.rs"
        ),
        "TERM" | "COLORTERM" => rel == "crates/core/src/report/banner.rs",
        "XDG_RUNTIME_DIR" => rel == "crates/cli/src/daemon/server.rs",
        "AWS_ACCESS_KEY_ID"
        | "AWS_SECRET_ACCESS_KEY"
        | "AWS_REGION"
        | "AWS_DEFAULT_REGION"
        | "AWS_SESSION_TOKEN" => rel.starts_with("crates/sources/src/s3/"),
        "GOOGLE_OAUTH_ACCESS_TOKEN" | "GCS_BEARER_TOKEN" => rel == "crates/sources/src/gcs.rs",
        "KEYHOG_GITHUB_TOKEN"
        | "KEYHOG_GITLAB_TOKEN"
        | "KEYHOG_BITBUCKET_USERNAME"
        | "KEYHOG_BITBUCKET_TOKEN" => rel == "crates/cli/src/sources.rs",
        _ => false,
    }
}

/// Files where reading an env var through a *variable* name (rather than a
/// string literal) is justified: cloud credential discovery iterates a fixed,
/// provider-standard set of env var names (`AWS_*`, GCS bearer tokens) through
/// one small helper, so the name reaches `var_os`/`var` as a parameter. Those
/// names are themselves on the static allowlist above; the dynamic form is a
/// code-structure detail, not an unaudited behavior knob.
fn allowed_dynamic_env_read(rel: &str) -> bool {
    rel.starts_with("crates/sources/src/s3/") || rel == "crates/sources/src/gcs.rs"
}

#[test]
fn env_policy_parser_catches_aliases_and_dynamic_names() {
    assert_eq!(
        env_call_name(r#"let path = std::env::var("PATH");"#),
        Some(Some("PATH".to_string()))
    );
    assert_eq!(
        env_call_name(r#"let color = std::env::var_os("NO_COLOR");"#),
        Some(Some("NO_COLOR".to_string()))
    );
    assert_eq!(
        env_call_name(r#"let path = env::var("PATH");"#),
        Some(Some("PATH".to_string()))
    );
    assert_eq!(
        env_call_name(r#"let dynamic = env::var(name);"#),
        Some(None)
    );
}

#[test]
fn env_policy_allowlist_is_path_scoped() {
    assert!(allowed_env_read(
        "crates/cli/src/subcommands/doctor.rs",
        "PATH"
    ));
    assert!(!allowed_env_read("crates/scanner/src/lib.rs", "PATH"));
    assert!(allowed_env_read(
        "crates/sources/src/s3/auth.rs",
        "AWS_ACCESS_KEY_ID"
    ));
    assert!(!allowed_env_read(
        "crates/sources/src/http.rs",
        "AWS_ACCESS_KEY_ID"
    ));
    assert!(allowed_env_read(
        "crates/core/src/report/banner.rs",
        "COLORTERM"
    ));
    assert!(!allowed_env_read(
        "crates/cli/src/orchestrator/run.rs",
        "COLORTERM"
    ));
}

#[test]
fn production_env_reads_stay_on_the_allowlist() {
    let root = repo_root();
    let mut files = Vec::new();
    for rel in [
        "crates/cli/src",
        "crates/core/src",
        "crates/scanner/src",
        "crates/sources/src",
        "crates/verifier/src",
    ] {
        collect_rs_files(&root.join(rel), &mut files);
    }

    let mut offenders = Vec::new();
    for path in files {
        let rel_path = path
            .strip_prefix(&root)
            .unwrap_or_else(|error| panic!("strip repo root from {}: {error}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read production source {}: {error}", path.display()));
        // This gate audits PRODUCTION env reads, so `#[cfg(test)]` items (e.g.
        // git child-process test seams gated on `KEYHOG_TEST_*`) are skipped:
        // they never compile into the shipped binary.
        let mut test_block_depth: Option<i32> = None;
        let mut pending_cfg_test = false;
        for (line_no, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if let Some(depth) = test_block_depth.as_mut() {
                *depth += brace_delta(line);
                if *depth <= 0 {
                    test_block_depth = None;
                }
                continue;
            }
            if trimmed == "#[cfg(test)]" {
                pending_cfg_test = true;
                continue;
            }
            if pending_cfg_test {
                // Stay pending across stacked attributes (e.g. `#[cfg(test)]`
                // then `#[test]`); the first non-attribute line is the item.
                if trimmed.starts_with("#[") {
                    continue;
                }
                pending_cfg_test = false;
                if line.contains('{') {
                    test_block_depth = Some(brace_delta(line));
                }
                continue;
            }

            let Some(call) = env_call_name(line) else {
                continue;
            };
            match call {
                Some(name) if allowed_env_read(&rel_path, &name) => {}
                Some(name) => offenders.push(format!("{rel_path}:{} reads {name}", line_no + 1)),
                None if allowed_dynamic_env_read(&rel_path) => {}
                None => offenders.push(format!(
                    "{rel_path}:{} reads a dynamic env var: {}",
                    line_no + 1,
                    line.trim()
                )),
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "production env reads must be explicit and justified; behavior/config KEYHOG_* env knobs are banned:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn production_gpu_policy_names_do_not_resurrect_retired_env_model() {
    let root = repo_root();
    for retired_path in [
        "crates/cli/src/backend_env.rs",
        "crates/scanner/src/gpu/env.rs",
    ] {
        assert!(
            !root.join(retired_path).exists(),
            "{retired_path} must stay removed; scan/GPU behavior is resolved policy, not env"
        );
    }

    let mut files = Vec::new();
    for rel in ["crates/cli/src", "crates/scanner/src"] {
        collect_rs_files(&root.join(rel), &mut files);
    }

    let forbidden = [
        "backend_env",
        "validate_scan_runtime_env",
        "env_no_gpu",
        "env_require_gpu",
        "FromEnvironment",
    ];
    let mut offenders = Vec::new();
    for path in files {
        let rel_path = path
            .strip_prefix(&root)
            .unwrap_or_else(|error| panic!("strip repo root from {}: {error}", path.display()))
            .to_string_lossy()
            .replace('\\', "/");
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read production source {}: {error}", path.display()));
        for retired in forbidden {
            if src.contains(retired) {
                offenders.push(format!(
                    "{rel_path} contains retired env-policy name {retired}"
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "production GPU/runtime policy names must not imply ambient-env control:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn docker_surfaces_do_not_reintroduce_retired_detector_env() {
    let root = repo_root();
    for rel in [
        "Dockerfile",
        "tests/docker/Dockerfile.glibc",
        "tests/docker/Dockerfile.musl",
    ] {
        let path = root.join(rel);
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read docker surface {}: {error}", path.display()));
        assert!(
            !src.contains("KEYHOG_DETECTORS"),
            "{rel} must not advertise the retired detector-directory env knob; use the default auto-discovered directory or explicit --detectors"
        );
        assert!(
            src.contains("/usr/share/keyhog/detectors"),
            "{rel} must place shipped detector TOMLs in the auto-discovered system detector directory"
        );
    }

    let scenarios_path = root.join("tests/docker/scenarios.sh");
    let scenarios = fs::read_to_string(&scenarios_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", scenarios_path.display()));
    for retired in [
        "KEYHOG_ENTROPY_STRICT",
        "KEYHOG_NOISE_STRICT",
        "KEYHOG_UNICODE_STRICT",
        "KEYHOG_WHITESPACE_STRICT",
        "KEYHOG_LINE_LEN_STRICT",
        "KEYHOG_COMPOUND_STRICT",
        "KEYHOG_ENCODING_STRICT",
        "KEYHOG_MULTI_STRICT",
        "KEYHOG_PATH_SHAPE_STRICT",
        "KEYHOG_COMMENT_STRICT",
        "KEYHOG_ADVERSARIAL_STRICT",
    ] {
        assert!(
            !scenarios.contains(retired),
            "docker scenario matrix must exercise real CLI/TOML controls, not retired no-op env profile {retired}"
        );
    }
    assert!(
        scenarios.contains("CLI_PROFILES=(")
            && scenarios.contains("--backend cpu")
            && scenarios.contains("--backend simd")
            && scenarios.contains("--precision"),
        "docker scenario matrix must keep explicit CLI profile coverage"
    );
}

fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}
