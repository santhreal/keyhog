/// Canonical list of well-known service-credential prefixes.
///
/// This is the single source of truth for the prefix set. Two consumers:
///
/// 1. [`known_prefix_confidence_floor`] (this module) lifts any credential
///    starting with one of these to a 0.8 confidence floor.
/// 2. `context::inference::{is_sequential_placeholder, is_hex_sequential_placeholder}`
///    strip these prefixes before sequence-detection so a `ghp_aaaaaaaaaa`
///    placeholder still triggers the all-same-char suppression on the
///    BODY, not on the prefix.
///
/// Pre-2026-05-24 state: this list was duplicated three times across
/// `confidence/prefixes.rs` + `context/inference.rs` × 2, and the copies
/// had already drifted (KNOWN_PREFIXES missed `glcbt-`, `glrt-`,
/// `xoxs-`, `vercel_`, `sbp_`, `0x`, `rk_test_`, `sk-`; the inference
/// copies missed `PRIVATE KEY`, `-----BEGIN`, `TESTKEY_`). Consolidated
/// here (kimi-dedup audit rows #12-13).
pub const KNOWN_PREFIXES: &[&str] = &[
    // GitHub PATs (every documented variant)
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    // Stripe live + test for all key families
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "rk_live_",
    "rk_test_",
    // AWS access key ID prefixes
    "AKIA",
    "ASIA",
    // Slack (full variant set)
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    // OpenAI / Anthropic / generic sk-
    "sk-proj-",
    "sk-ant-",
    "sk-",
    // SendGrid
    "SG.",
    // HuggingFace
    "hf_",
    // npm
    "npm_",
    // PyPI
    "pypi-",
    // GitLab PAT variants
    "glpat-",
    "glcbt-",
    "glrt-",
    // DigitalOcean
    "dop_v1_",
    // JWT shape (base64url of `{"alg":...}`)
    "eyJ",
    // Vercel
    "vercel_",
    // Supabase project
    "sbp_",
    // Hex-prefixed credentials (Ethereum-style addresses + a few API
    // keys that ship as 0x<hex>).
    "0x",
    // Bare keyword used as a credential - the upstream detector already
    // gated on `PRIVATE KEY` substring so this floor only lifts captured
    // bodies, not arbitrary PEM blocks.
    "PRIVATE KEY",
    // PEM-framed private key blocks captured by the `private-key`
    // detector start with `-----BEGIN` (e.g. `-----BEGIN RSA-PRIVATE-KEY-----`).
    "-----BEGIN",
    // Test-fixture marker used by the bundled suppression list.
    "TESTKEY_",
];

/// Return a minimum confidence floor for credentials with well-known literal prefixes.
///
/// Credentials carrying a placeholder word (`EXAMPLE`, `PLACEHOLDER`, `DUMMY`,
/// `FAKE`, `SAMPLE`, `CHANGEME`) do NOT get the floor. A `ghp_EXAMPLE_…`
/// or `sk_live_PLACEHOLDER_…` is a doc sample, not a credential - the
/// placeholder penalty in `apply_post_ml_penalties` had already slammed
/// these to ~0.05, but the unconditional `final_score.max(0.8)` in
/// `scan_postprocess` then lifted them straight back. Mirror corpus
/// 2026-05-29: 154 docs-example FPs across `ghp_`/`AKIA`/`xoxb-`/`sk_live_`
/// all surfaced through this exact path; this single guard kills them.
#[must_use]
pub fn known_prefix_confidence_floor(credential: &str) -> Option<f64> {
    if super::penalties::contains_placeholder_word(credential)
        || crate::decode_structure::decoded_contains_placeholder(credential)
    {
        return None;
    }
    if KNOWN_PREFIXES
        .iter()
        .any(|prefix| credential.starts_with(prefix))
    {
        Some(0.8)
    } else {
        None
    }
}
