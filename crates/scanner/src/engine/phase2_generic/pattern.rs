//! Construction of the generic assignment bridge regex.

const GENERIC_VALUE_CHARS: &str = r"a-zA-Z0-9/+=_.:!@#$%^&*-";

/// Structural group-1 arm for bounded vendor-prefixed key names.
pub(crate) const GENERIC_RE_VENDOR_SUFFIX_ARM: &str =
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,2}[._-](?:key|secret|token)";

/// Build group 1 from the single derived assignment-keyword vocabulary.
pub(crate) fn generic_keyword_alternation() -> String {
    generic_keyword_alternation_from(crate::assignment_keywords::assignment_keywords())
}

pub(crate) fn generic_keyword_alternation_from(keywords: &[String]) -> String {
    generic_keyword_alternation_from_with_vendor_fallback(keywords, true)
}

pub(crate) fn generic_keyword_alternation_from_with_vendor_fallback(
    keywords: &[String],
    include_vendor_fallback: bool,
) -> String {
    let mut literals: Vec<&str> = keywords.iter().map(String::as_str).collect();
    literals.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let mut alternation = String::new();
    for (index, literal) in literals.into_iter().enumerate() {
        if index != 0 {
            alternation.push('|');
        }
        alternation.push_str(&regex::escape(literal));
    }
    if include_vendor_fallback {
        if !alternation.is_empty() {
            alternation.push('|');
        }
        alternation.push_str(GENERIC_RE_VENDOR_SUFFIX_ARM);
    }
    alternation
}

/// Compile the bridge from a pre-built group-1 alternation.
pub(crate) fn compile_generic_re_with_max(
    alternation: &str,
    max_len: usize,
) -> std::result::Result<regex::Regex, regex::Error> {
    let assignment_tail = format!(
        r#"(?:[._-]?(?:key|base|value|val|string|str|enc|raw|b64)){{0,2}}["'`]?\s*(?::\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]{{0,31}}\s*[=:]\s*)?|=\s*)["'`]?([{GENERIC_VALUE_CHARS}]{{8,{max_len}}})(?:["'`]|$|[^{GENERIC_VALUE_CHARS}])"#
    );
    regex::Regex::new(&format!("(?i)({alternation}){assignment_tail}"))
}

/// Compile the bridge from the live derived vocabulary.
pub(crate) fn build_generic_re() -> Result<regex::Regex, String> {
    let detectors = keyhog_core::load_embedded_detectors_or_fail().map_err(|error| {
        format!(
            "embedded detector corpus is corrupt: {error}; cannot compile the detector-owned generic assignment bridge"
        )
    })?;
    let mut max_len = None;
    for detector in detectors
        .iter()
        .filter(|detector| detector.kind == keyhog_core::DetectorKind::Phase2Generic)
    {
        let detector_max_len = detector.max_len.ok_or_else(|| {
            format!(
                "phase-2 detector {:?} omits max_len; fix its detector TOML",
                detector.id
            )
        })?;
        max_len = Some(max_len.map_or(detector_max_len, |current: usize| {
            current.max(detector_max_len)
        }));
    }
    let max_len = max_len
        .ok_or_else(|| "embedded detector corpus has no phase-2 generic detector".to_string())?;
    compile_generic_re_with_max(&generic_keyword_alternation(), max_len)
        .map_err(|error| format!("invalid generic assignment bridge: {error}"))
}
