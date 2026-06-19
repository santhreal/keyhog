//! Focused shape helpers for fallback entropy filtering.

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
            let name = p.rsplit(['/', '\\']).next().unwrap_or(p); // LAW10: split yields >=1 element; unwrap_or is the never-taken total default, recall-safe
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
    // Band 50..=300: lower bound 50 (was 40) so 40-49 char base64-shaped
    // credentials get a path through the entropy fallback. Real-world recall
    // fixtures sit in this 40-49 char band (Stripe-style restricted-secret-key
    // bodies, GitHub legacy 40-char auth secrets). Protobuf-of-random-bytes
    // decoys skew larger (median 64 chars per negatives.py: 30-80 random bytes)
    // so this band is overwhelmingly real credentials.
    //
    // The band + padding + standard-base64-alphabet + BOTH-`+`-AND-`/` skeleton
    // is the shared `is_byte_distribution_base64_blob` canonical (MC-12); this
    // path composes only its band on top.
    crate::decode_structure::is_byte_distribution_base64_blob(value, 50, 300)
}

/// The four synthetic entropy-fallback metadata triples, index-parallel with
/// [`classify_entropy_detector_index`]. Single source of truth: the scanner
/// pre-interns this exact table into `entropy_metadata_by_index` at
/// construction so the emit path clones an `Arc<str>` by index instead of
/// re-interning these constants per finding (PERF-locality_intern-1).
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_DETECTOR_METADATA: [(&str, &str, &str); 4] = [
    ("entropy-generic", "Generic High-Entropy Secret", "generic"),
    ("entropy-password", "Password (Entropy Detected)", "generic"),
    ("entropy-token", "API Token (Entropy Detected)", "generic"),
    ("entropy-api-key", "API Key (Entropy Detected)", "generic"),
];

/// Classify an entropy candidate's keyword into the index of its metadata
/// triple in [`ENTROPY_DETECTOR_METADATA`]. The branch order matches the
/// historical keyword→detector mapping, so the resolved detector
/// id/name/service are unchanged; the scanner clones the pre-interned triple
/// at this index at the emit site (PERF-locality_intern-1).
#[cfg(feature = "entropy")]
#[inline]
pub(crate) fn classify_entropy_detector_index(keyword: &str) -> usize {
    if keyword == "none (high-entropy)" {
        0
    } else if keyword.contains("password") || keyword.contains("pwd") {
        1
    } else if keyword.contains("token") {
        2
    } else {
        3
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
    if crate::engine::phase2_generic::keywords::normalize_assignment_keyword(keyword)
        .as_deref()
        .is_some_and(crate::entropy::keywords::normalized_assignment_keyword_is_credential)
    {
        return true;
    }
    super::scan_filters::GENERIC_ASSIGNMENT_KEYWORDS
        .iter()
        .any(|anchor| lower.contains(anchor))
        || lower.contains("bearer")
}
