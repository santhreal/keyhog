//! Gate: scanner detector-id literals and family predicates have one owner.

use super::support::*;
// This gate must also ignore `#[cfg(...)]`-gated blocks, so it binds the
// stricter shared stripper under the local name its call sites use.
use super::support::uncommented_code_strip_cfg as uncommented_code;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("scanner crate must live under crates/scanner")
        .to_path_buf()
}

#[test]
fn detector_ids_module_owns_scanner_detector_identity() {
    let src = scanner_src();
    let owner = read(&src.join("detector_ids.rs"));
    for expected in [
        "GENERIC_SECRET",
        "GENERIC_API_KEY",
        "ENTROPY_API_KEY",
        "GITHUB_CLASSIC_PAT",
        "SLACK_BOT_TOKEN",
        "STRIPE_SECRET_KEY",
        "is_generic_detector",
        "is_entropy_detector",
        "is_service_anchored_detector",
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
        // Historical phantom validator labels kept forbidden so they can't be
        // reintroduced as hardcoded literals; the real detectors they were meant
        // to name are `github-pat-fine-grained` / `gitlab-personal-access-token`
        // (owned below).
        "\"github-fine-grained-pat\"",
        "\"github-pat-fine-grained\"",
        "\"gitlab-token\"",
        "\"gitlab-personal-access-token\"",
        "\"npm-access-token\"",
        "\"pypi-api-token\"",
        "\"openai-api-key\"",
        "\"sendgrid-api-key\"",
        "\"slack-bot-token\"",
        "\"slack-token\"",
        "\"slack-user-token\"",
        "\"square-access-token\"",
        "\"stripe-api-key\"",
        "\"stripe-secret-key\"",
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

    let classification = read(&src.join("detector_classification.rs"));
    let rules = read(&repo_root().join("rules/detector-classification.toml"));
    let spec = read(&repo_root().join("crates/core/src/spec.rs"));
    let confirmed_extract = read(
        &src.join("engine")
            .join("scan_postprocess")
            .join("confirmed_extract.rs"),
    );
    // DET-0 architecture law: `weak_anchor` and `private_key_block` are PER-DETECTOR
    // `DetectorSpec` flags declared in each detector's own TOML, one file tells the
    // whole story of one detector. They are NOT hardcoded in detector_ids.rs and are
    // NO LONGER centralized id lists in the Tier-B classification rules. Exact family
    // membership is pinned by `weak_anchor_family_is_toml_declared` /
    // `private_key_block_family_is_toml_declared` (detector_ids.rs). The old
    // `is_residual_weak_anchor` / classification `is_private_key_block_detector`
    // query fns are gone; the private-key-block predicate now reads `spec.private_key_block`
    // and lives in detector_ids.rs (the family-predicate owner).
    assert!(
        spec.contains("pub weak_anchor: bool")
            && !owner.contains("RESIDUAL_WEAK_ANCHORED")
            && !owner.contains("is_residual_weak_anchored")
            && !classification.contains("fn is_residual_weak_anchor")
            && !rules.contains("weak_anchor = ["),
        "weak-anchor classification must be the per-detector `DetectorSpec::weak_anchor` flag (DET-0), not a detector_ids.rs / classification-rules id list"
    );
    assert!(
        spec.contains("pub private_key_block: bool")
            && !owner.contains("PRIVATE_KEY | SSH_PRIVATE_KEY | GITHUB_APP_PRIVATE_KEY")
            && owner.contains("fn is_private_key_block_detector")
            && owner.contains("spec.private_key_block")
            && !classification.contains("fn is_private_key_block_detector")
            && !rules.contains("private_key_block = ["),
        "private-key-block classification must be the per-detector `DetectorSpec::private_key_block` flag read by detector_ids.rs (DET-0), not a classification-rules id list"
    );
    assert!(
        classification.contains("stripe_hot_confirmed_prefix")
            && classification
                .contains("include_str!(\"../../../rules/detector-classification.toml\")")
            && rules.contains("stripe_hot_confirmed_prefix = [")
            && !confirmed_extract.contains("sk_live_")
            && !confirmed_extract.contains("rk_test_")
            && confirmed_extract.contains("stripe_hot_confirmed_by_pattern"),
        "Stripe confirmed hot-prefix classification must be Tier-B data precomputed on the scanner, not an inline extraction list"
    );
}
