//! Gate: scanner detector-id literals and family predicates have one owner.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{} not readable: {e}", dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn uncommented_code(src: &str) -> String {
    src.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("#[cfg") {
                None
            } else {
                Some(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn detector_ids_module_owns_scanner_detector_identity() {
    let src = scanner_src();
    let owner = read(&src.join("detector_ids.rs"));
    for expected in [
        "GENERIC_SECRET",
        "GENERIC_API_KEY",
        "ENTROPY_API_KEY",
        "AWS_ACCESS_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_CLASSIC_PAT",
        "SLACK_BOT_TOKEN",
        "STRIPE_SECRET_KEY",
        "is_generic_detector",
        "is_entropy_detector",
        "is_service_anchored_detector",
        "RESIDUAL_WEAK_ANCHORED",
    ] {
        assert!(
            owner.contains(expected),
            "detector_ids.rs must own `{expected}`"
        );
    }

    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    let mut offenders = Vec::new();
    let forbidden_literals = [
        "\"generic-secret\"",
        "\"generic-keyword-secret\"",
        "\"generic-api-key\"",
        "\"generic-password\"",
        "\"generic-database-url\"",
        "\"generic-private-key\"",
        "\"entropy-generic\"",
        "\"entropy-password\"",
        "\"entropy-token\"",
        "\"entropy-api-key\"",
        "\"ssh-private-key\"",
        "\"github-app-private-key\"",
        "\"aws-access-key\"",
        "\"anthropic-api-key\"",
        "\"github-classic-pat\"",
        "\"github-fine-grained-pat\"",
        "\"gitlab-token\"",
        "\"npm-access-token\"",
        "\"pypi-api-token\"",
        "\"openai-api-key\"",
        "\"sendgrid-api-key\"",
        "\"slack-bot-token\"",
        "\"slack-token\"",
        "\"slack-user-token\"",
        "\"stripe-api-key\"",
        "\"stripe-secret-key\"",
        "\"hot-square_secret\"",
    ];
    let forbidden_family_checks = [
        ".starts_with(\"generic-\")",
        ".starts_with(\"entropy-\")",
        "== \"private-key\"",
        "!= \"private-key\"",
    ];

    for path in files {
        if path.file_name().and_then(|name| name.to_str()) == Some("detector_ids.rs") {
            continue;
        }
        let rel = path.strip_prefix(&src).unwrap_or(&path);
        let code = uncommented_code(&read(&path));
        for forbidden in forbidden_literals
            .iter()
            .chain(forbidden_family_checks.iter())
        {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", rel.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "detector ids and detector-family checks must route through detector_ids.rs: {offenders:#?}"
    );
}
