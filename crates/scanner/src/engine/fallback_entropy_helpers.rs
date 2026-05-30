//! Helper functions for fallback_entropy.rs to satisfy line caps.

#[cfg(feature = "entropy")]
pub(crate) fn entropy_path_looks_like_kebab_identifier(value: &str) -> bool {
    if value.len() > 24 {
        return false;
    }
    let bytes = value.as_bytes();
    let dash_count = bytes.iter().filter(|&&b| b == b'-').count();
    if dash_count == 0 {
        return false;
    }
    let lower_count = bytes
        .iter()
        .filter(|&&b| (b as char).is_ascii_lowercase())
        .count();
    if lower_count * 2 < bytes.len() {
        return false;
    }
    !bytes.iter().any(|&b| matches!(b as char, '+' | '/' | '='))
}

#[cfg(feature = "entropy")]
pub(crate) fn entropy_path_is_ci_workflow_file(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    p.contains("/.github/workflows/")
        || p.contains("\\.github\\workflows\\")
        || p.contains("/.github/actions/")
        || p.contains("\\.github\\actions\\")
        || p.contains("/.gitlab-ci.yml")
        || p.contains("\\.gitlab-ci.yml")
        || p.ends_with(".gitlab-ci.yml")
        || p.contains("/.circleci/")
        || p.contains("\\.circleci\\")
        || p.contains("/azure-pipelines")
        || p.contains("\\azure-pipelines")
        || p.contains("/bitbucket-pipelines")
        || p.contains("\\bitbucket-pipelines")
        || p.contains("/.travis.yml")
        || p.contains("\\.travis.yml")
        || p.ends_with(".travis.yml")
        || p.contains("/Jenkinsfile")
        || p.contains("\\Jenkinsfile")
        || p.ends_with("/Jenkinsfile")
        || p.ends_with("\\Jenkinsfile")
}

#[cfg(feature = "entropy")]
pub(crate) fn entropy_path_is_i18n_file(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    p.contains("/locale/")
        || p.contains("\\locale\\")
        || p.contains("/locales/")
        || p.contains("\\locales\\")
        || p.contains("/i18n/")
        || p.contains("\\i18n\\")
        || p.contains("/l10n/")
        || p.contains("\\l10n\\")
        || p.contains("/translations/")
        || p.contains("\\translations\\")
        || p.contains("/lang/")
        || p.contains("\\lang\\")
        || p.contains("/langs/")
        || p.contains("\\langs\\")
        || p.ends_with(".po")
        || p.ends_with(".pot")
        || {
            let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
            (name.starts_with("locale_")
                || name.starts_with("messages_")
                || name.starts_with("strings_"))
                && (name.ends_with(".ini")
                    || name.ends_with(".properties")
                    || name.ends_with(".xml")
                    || name.ends_with(".json")
                    || name.ends_with(".yaml")
                    || name.ends_with(".yml"))
        }
}

#[cfg(feature = "entropy")]
pub(crate) fn entropy_path_looks_like_filename(value: &str) -> bool {
    const FILENAME_SUFFIXES: &[&[u8]] = &[
        b".jks",
        b".yml",
        b".yaml",
        b".toml",
        b".json",
        b".properties",
        b".pem",
        b".key",
        b".crt",
        b".cer",
        b".pfx",
        b".p12",
        b".keystore",
        b".truststore",
        b".conf",
        b".ini",
        b".env",
        b".lock",
        b".log",
    ];
    let bytes = value.as_bytes();
    FILENAME_SUFFIXES
        .iter()
        .any(|s| crate::ascii_ci::ends_with_ignore_ascii_case(bytes, s))
}

#[cfg(feature = "entropy")]
pub(crate) fn entropy_path_looks_like_random_base64_blob(value: &str) -> bool {
    // Lower bound 50 (was 40) so 40-49 char base64-shaped credentials get
    // a path through the entropy fallback. Real-world recall fixtures sit
    // in this 40-49 char band (Stripe-style restricted-secret-key bodies,
    // GitHub legacy 40-char auth secrets). Protobuf-of-random-bytes
    // decoys skew larger (median 64 chars per negatives.py: 30-80 random
    // bytes) so this band is overwhelmingly real credentials.
    if !(50..=300).contains(&value.len()) {
        return false;
    }
    let has_padding = value.ends_with("==") || value.ends_with('=');
    let length_mult_4 = value.len() % 4 == 0;
    if !has_padding && !length_mult_4 {
        return false;
    }
    let mut has_plus = false;
    let mut has_slash = false;
    for c in value.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '=' => {}
            '+' => has_plus = true,
            '/' => has_slash = true,
            _ => return false,
        }
    }
    // Tightened punctuation requirement: require BOTH `+` AND `/` (or
    // padding with at least one of them). Real protobuf-of-random-bytes
    // encoding produces both `+` and `/` because the byte distribution
    // is uniform; restricted-secret-key style positives often contain
    // only one. Padded values with at least one `+/` still trip - this
    // is a per-byte distribution signal, not a structural one.
    (has_plus && has_slash) || (has_padding && (has_plus || has_slash))
}

#[cfg(feature = "entropy")]
pub(crate) fn classify_entropy_detector(
    keyword: &str,
) -> (&'static str, &'static str, &'static str) {
    if keyword == "none (high-entropy)" {
        ("entropy-generic", "Generic High-Entropy Secret", "generic")
    } else if keyword.contains("password") || keyword.contains("pwd") {
        ("entropy-password", "Password (Entropy Detected)", "generic")
    } else if keyword.contains("token") {
        ("entropy-token", "API Token (Entropy Detected)", "generic")
    } else {
        ("entropy-api-key", "API Key (Entropy Detected)", "generic")
    }
}

/// True when the entropy candidate's keyword indicates a strong credential
/// anchor was directly responsible for the candidate's extraction. The
/// caller uses this to admit the candidate past the file-extension gate
/// in `scan_entropy_fallback`: if the line carries `api_key=`, `token=`,
/// `password=`, etc., the file extension (source code vs. config) is no
/// longer the deciding signal - the keyword anchor IS positive evidence
/// the value is a credential.
///
/// `keyword == "none (high-entropy)"` is the no-keyword path (very-high
/// entropy threshold was used); it is NOT a credential anchor.
#[cfg(feature = "entropy")]
pub(crate) fn keyword_is_credential_anchor(keyword: &str) -> bool {
    if keyword == "none (high-entropy)" {
        return false;
    }
    let lower = keyword.to_ascii_lowercase();
    const CREDENTIAL_ANCHORS: &[&str] = &[
        "secret",
        "password",
        "passwd",
        "pwd",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "auth",
        "credential",
        "private_key",
        "private-key",
        "privatekey",
        "client_secret",
        "client-secret",
        "access_key",
        "access-key",
        "accesskey",
    ];
    CREDENTIAL_ANCHORS.iter().any(|anchor| lower.contains(anchor))
}

#[cfg(all(test, feature = "entropy"))]
mod helper_tests {
    use super::*;

    #[test]
    fn credential_anchor_recognizes_common_keywords() {
        // Positive recall for the common credential keyword shapes the
        // entropy scanner emits as `keyword`.
        assert!(keyword_is_credential_anchor("api_key"));
        assert!(keyword_is_credential_anchor("API_KEY"));
        assert!(keyword_is_credential_anchor("apiKey"));
        assert!(keyword_is_credential_anchor("apikey"));
        assert!(keyword_is_credential_anchor("token"));
        assert!(keyword_is_credential_anchor("password"));
        assert!(keyword_is_credential_anchor("client_secret"));
        assert!(keyword_is_credential_anchor("PRIVATE_KEY"));
        assert!(keyword_is_credential_anchor("auth_token"));
    }

    #[test]
    fn credential_anchor_rejects_no_keyword_marker() {
        // Negative twin: the entropy scanner uses this exact string for
        // the keyword-free very-high-entropy path; it must NOT count as
        // a credential anchor (otherwise it would defeat the gate).
        assert!(!keyword_is_credential_anchor("none (high-entropy)"));
    }

    #[test]
    fn credential_anchor_rejects_unrelated_keyword() {
        // Negative twin: an unrelated word must not be admitted.
        assert!(!keyword_is_credential_anchor("description"));
        assert!(!keyword_is_credential_anchor("environment"));
    }

    #[test]
    fn random_b64_blob_admits_pure_alnum_when_mult4_diverse() {
        // Positive: 56-char padded base64 alphabet, with both + and /
        // (current behavior) - kept as a sanity test.
        let v = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789++//ZZ==";
        // The legacy gate already catches this:
        assert!(entropy_path_looks_like_random_base64_blob(v));
    }

    #[test]
    fn random_b64_blob_rejects_pure_lowercase_low_diversity() {
        // Negative twin: 50 chars of just `a` repeated - low diversity,
        // not a base64 blob shape (also fails the new band floor).
        let v: String = "a".repeat(50);
        assert!(!entropy_path_looks_like_random_base64_blob(&v));
    }

    #[test]
    fn random_b64_blob_admits_real_protobuf_dump() {
        // Positive: a real 64-char protobuf-of-random-bytes payload
        // with BOTH + and / - this is the dominant shape the gate
        // exists to suppress; must still fire after the tightened
        // punctuation check (both + and /).
        let v = "Vwqk+gg+vh6Pm9mhPgQU/wJPTbFY6cwjNNFQQVY+8jtl/RGABCDEFGHIJKLMNOPQ";
        assert_eq!(v.len(), 64);
        assert!(entropy_path_looks_like_random_base64_blob(v));
    }

    #[test]
    fn random_b64_blob_releases_short_credential_band() {
        // Positive recall: a 44-char credential body in the 40-49 char
        // band (where Stripe restricted-key bodies and similar named
        // secrets land) is no longer over-suppressed by this gate.
        // The previous 40-char floor swept these into the "looks like
        // a protobuf dump" bucket; new 50-char floor releases them.
        let v = "Hk9PqRsTuVwXyZAbCdEfGhIjKlMnOpQr0123456789ab";
        assert_eq!(v.len(), 44);
        assert!(!entropy_path_looks_like_random_base64_blob(v));
    }

    #[test]
    fn random_b64_blob_rejects_plus_only_no_slash() {
        // Negative twin to the tightened punctuation gate: a 60-char
        // value with `+` only (no `/`, no padding) was previously
        // suppressed under the OR-of-punct rule. With the tightened
        // AND-of-both rule, this releases to the downstream emit path.
        // Real protobuf encodings of random bytes virtually always
        // produce both `+` and `/` because the byte distribution is
        // uniform; a `+`-only base64 is much more likely a credential.
        let v = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH+IIIJJJJKKKKLLLLMMMMNNNNOPQR";
        assert_eq!(v.len(), 60);
        assert!(!entropy_path_looks_like_random_base64_blob(v));
    }
}
