const KNOWN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "rk_live_",
    "AKIA",
    "ASIA",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "sk-proj-",
    "sk-ant-",
    "SG.",
    "hf_",
    "npm_",
    "pypi-",
    "glpat-",
    "dop_v1_",
    "PRIVATE KEY",
    // PEM-framed private key blocks captured by the `private-key`
    // detector start with `-----BEGIN` (e.g. `-----BEGIN RSA PRIVATE KEY-----`)
    // so the literal `PRIVATE KEY` prefix above doesn't match the
    // full-block credential. Add the PEM frame explicitly — the
    // upstream regex already gated on `…PRIVATE KEY…` so this
    // confidence floor doesn't lift non-credential PEM blocks
    // (certificates, public keys) since those aren't captured at all.
    "-----BEGIN",
    "eyJ",
    "TESTKEY_",
];

/// Return a minimum confidence floor for credentials with well-known literal prefixes.
pub fn known_prefix_confidence_floor(credential: &str) -> Option<f64> {
    if KNOWN_PREFIXES
        .iter()
        .any(|prefix| credential.starts_with(prefix))
    {
        Some(0.8)
    } else {
        None
    }
}
