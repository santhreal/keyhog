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
    if !(40..=300).contains(&value.len()) {
        return false;
    }
    let has_padding = value.ends_with("==") || value.ends_with('=');
    let length_mult_4 = value.len() % 4 == 0;
    if !has_padding && !length_mult_4 {
        return false;
    }
    let mut has_b64_punct = false;
    for c in value.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '=' => {}
            '+' | '/' => has_b64_punct = true,
            _ => return false,
        }
    }
    has_b64_punct || has_padding
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
