//! KH-GAP-076: nightly job exports every multiplier strict env var.

use std::path::PathBuf;

const STRICT_ENV_VARS: [&str; 11] = [
    "KEYHOG_ADVERSARIAL_STRICT",
    "KEYHOG_ENCODING_STRICT",
    "KEYHOG_PATH_SHAPE_STRICT",
    "KEYHOG_NOISE_STRICT",
    "KEYHOG_UNICODE_STRICT",
    "KEYHOG_WHITESPACE_STRICT",
    "KEYHOG_LINE_LEN_STRICT",
    "KEYHOG_ENTROPY_STRICT",
    "KEYHOG_MULTI_STRICT",
    "KEYHOG_COMPOUND_STRICT",
    "KEYHOG_COMMENT_STRICT",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn runners_nightly_exports_all_multiplier_strict_env_vars() {
    let text = std::fs::read_to_string(repo_root().join(".github/workflows/runners-nightly.yml"))
        .expect("read runners-nightly.yml");

    let missing: Vec<&str> = STRICT_ENV_VARS
        .iter()
        .copied()
        .filter(|var| !text.contains(var))
        .collect();

    assert!(
        missing.is_empty(),
        "runners-nightly.yml must export all multiplier strict env vars; missing: {missing:?}"
    );
}
