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
pub(crate) const KNOWN_PREFIXES: &[&str] = &[
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
    // Google API keys
    "AIza",
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
    // Distinctive-prefix vendor tokens whose BODY is pure lowercase hex
    // (`[a-f0-9]{N}`). A pure-hex body earns almost no entropy/shape signal, so
    // `compute_confidence` normalizes a bare-token match (literal-prefix weight
    // only) below the 0.40 floor and `apply_post_ml_penalties` crushes it
    // further — the exact "lift-back defeated" path this floor exists to survive.
    // Without the floor these critical/high-severity vendor tokens were dropped
    // as `below_min_confidence` (a real recall bug: e.g. `API_TOKEN=shpat_<32hex>`
    // reported nothing while `sk-<32hex>` reported deepseek, purely because `sk-`
    // was floored and `shpat_` was not). Only DISTINCTIVE prefixes go here — the
    // generic hex-body prefixes (`api-`, `key-`, `sdk-`, `ck_`, `pub-c-`) are
    // deliberately excluded because flooring them would lift ordinary
    // `key-<hex>` identifiers to findings; those detectors must earn a keyword
    // context anchor instead. Each prefix below is proven to surface an
    // exact-shape token on both CPU backends by
    // `regression_hexbody_vendor_prefix_floor`.
    // Shopify (admin / custom-app / storefront)
    "shpat_",
    "shpca_",
    "shpss_",
    // Brevo (Sendinblue)
    "xkeysib-",
    // RubyGems
    "rubygems_",
    // Postman
    "PMAK-",
    // Shippo (live)
    "shippo_live_",
    // Flipt
    "flipt_",
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
    // PuTTY `.ppk` private-key files captured by the `putty-private-key`
    // detector start with `PuTTY-User-Key-File-<version>:`. Same class as the
    // PEM `-----BEGIN` floor: the distinctive header marker is the
    // high-confidence signal, so the captured key file is floored to 0.8 rather
    // than scored on the low-entropy header lines that precede the base64 body.
    "PuTTY-User-Key-File-",
    // RFC 4716 / ssh.com SSH2 private-key blocks captured by the
    // `ssh2-private-key` detector start with the 4-dash spaced framing
    // `---- BEGIN SSH2 [ENCRYPTED ]PRIVATE KEY ----`. Same class as the PEM
    // `-----BEGIN` and PuTTY floors: the distinctive header is the high-confidence
    // signal, so the whole captured block is floored to 0.8 rather than scored on
    // the (possibly low-entropy) base64 body, which would otherwise drop a real
    // key whose body happens to be short or repetitive.
    "---- BEGIN SSH2",
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
/// 2026-05-29: 154 docs-example FPs across the GitHub PAT, AWS access
/// key, Slack bot token, and Stripe secret key prefix families all
/// surfaced through this exact path; this single guard kills them.
///
/// The same lift-back defeated the degenerate-repeat penalty: a known-prefix
/// placeholder like `AKIAXXXXXXXXXXXXXXXX` (16-char `X` run) was crushed to
/// ~0.08 by `apply_post_ml_penalties` and then floored back to 0.8 here. The
/// `is_degenerate_repeat` skip (CredData dogfood 2026-06-03) closes that hole
/// the same way - a 10+ identical-char run is never a real key body.
#[must_use]
pub(crate) fn known_prefix_confidence_floor(credential: &str) -> Option<f64> {
    if super::penalties::contains_placeholder_word(credential)
        || crate::decode_structure::evidence(credential).decoded_contains_placeholder()
        || super::penalties::is_degenerate_repeat(credential)
    {
        return None;
    }
    if let Some(body) = known_prefix_body(credential) {
        if crate::placeholder_words::bytes_contain_placeholder_word(body.as_bytes()) {
            return None;
        }
        return Some(0.8);
    }
    None
}

pub(crate) fn known_prefix_body(credential: &str) -> Option<&str> {
    KNOWN_PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
}
