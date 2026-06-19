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
    for call in ["std::env::var(", "std::env::var_os("] {
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
    const EXTERNAL_ENV: &[&str] = &[
        "PATH",
        "NO_COLOR",
        "TERM",
        "COLORTERM",
        "XDG_RUNTIME_DIR",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_SESSION_TOKEN",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "GCS_BEARER_TOKEN",
    ];

    if EXTERNAL_ENV.contains(&name) {
        return true;
    }

    let _ = rel; // keep the signature useful for future path-scoped external allowances.
    false
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
        for (line_no, line) in src.lines().enumerate() {
            let Some(call) = env_call_name(line) else {
                continue;
            };
            match call {
                Some(name) if allowed_env_read(&rel_path, &name) => {}
                Some(name) => offenders.push(format!("{rel_path}:{} reads {name}", line_no + 1)),
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
