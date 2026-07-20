//! Construction of the generic assignment bridge regex.

const GENERIC_VALUE_CHARS: &str = r"a-zA-Z0-9/+=_.:!@#$%^&*-";

const GENERIC_RE_VENDOR_PREFIX: &str = r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,2}[._-](?:";

pub(crate) fn generic_vendor_suffix_arm(suffixes: &[String]) -> String {
    let mut arm = String::from(GENERIC_RE_VENDOR_PREFIX);
    for (index, suffix) in suffixes.iter().enumerate() {
        if index != 0 {
            arm.push('|');
        }
        arm.push_str(&regex::escape(suffix));
    }
    arm.push(')');
    arm
}

/// Build group 1 from the single derived assignment-keyword vocabulary.
pub(crate) fn generic_keyword_alternation() -> String {
    generic_keyword_alternation_from(
        crate::assignment_keywords::assignment_keywords(),
        crate::assignment_keywords::generic_vendor_suffixes(),
    )
}

pub(crate) fn generic_keyword_alternation_from(
    keywords: &[String],
    vendor_suffixes: &[String],
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
    if !vendor_suffixes.is_empty() {
        if !alternation.is_empty() {
            alternation.push('|');
        }
        alternation.push_str(&generic_vendor_suffix_arm(vendor_suffixes));
    }
    alternation
}

/// Compile the bridge from a pre-built group-1 alternation.
pub(crate) fn compile_generic_re_with_policy(
    alternation: &str,
    max_len: usize,
    tail_suffixes: &[String],
) -> std::result::Result<regex::Regex, regex::Error> {
    let mut tail_alternation = String::new();
    for (index, suffix) in tail_suffixes.iter().enumerate() {
        if index != 0 {
            tail_alternation.push('|');
        }
        tail_alternation.push_str(&regex::escape(suffix));
    }
    let assignment_tail = if tail_alternation.is_empty() {
        format!(
            r#"["'`]?\s*(?::\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]{{0,31}}\s*[=:]\s*)?|=\s*)["'`]?([{GENERIC_VALUE_CHARS}]{{8,{max_len}}})(?:["'`]|$|[^{GENERIC_VALUE_CHARS}])"#
        )
    } else {
        format!(
            r#"(?:[._-]?(?:{tail_alternation})){{0,2}}["'`]?\s*(?::\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]{{0,31}}\s*[=:]\s*)?|=\s*)["'`]?([{GENERIC_VALUE_CHARS}]{{8,{max_len}}})(?:["'`]|$|[^{GENERIC_VALUE_CHARS}])"#
        )
    };
    regex::Regex::new(&format!("(?i)({alternation}){assignment_tail}"))
}

pub(crate) fn compile_generic_re_with_max(
    alternation: &str,
    max_len: usize,
) -> std::result::Result<regex::Regex, regex::Error> {
    compile_generic_re_with_policy(
        alternation,
        max_len,
        crate::assignment_keywords::generic_assignment_tail_suffixes(),
    )
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
    compile_generic_re_with_policy(
        &generic_keyword_alternation(),
        max_len,
        crate::assignment_keywords::generic_assignment_tail_suffixes(),
    )
    .map_err(|error| format!("invalid generic assignment bridge: {error}"))
}
