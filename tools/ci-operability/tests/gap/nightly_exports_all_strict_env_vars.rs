//! KH-GAP-076: nightly job exports every multiplier strict env var.

use super::support::read_workflow;

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

#[test]
fn runners_nightly_exports_all_multiplier_strict_env_vars() {
    let text = read_workflow("runners-nightly.yml");

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
