//! Construction of the generic assignment bridge regex.

/// Compatibility ceiling for custom phase-2 generic detectors that predate the
/// detector-owned `max_len` field.
pub(crate) const GENERIC_ASSIGNMENT_MAX_LEN_DEFAULT: usize = 128;

const GENERIC_VALUE_CHARS: &str = r"a-zA-Z0-9/+=_.:!@#$%^&*-";

/// Structural group-1 arm for bounded vendor-prefixed key names.
pub(crate) const GENERIC_RE_VENDOR_SUFFIX_ARM: &str =
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,2}[._-](?:key|secret|token)";

/// Build group 1 from the single derived assignment-keyword vocabulary.
pub(crate) fn generic_keyword_alternation() -> String {
    generic_keyword_alternation_from(crate::assignment_keywords::assignment_keywords())
}

pub(crate) fn generic_keyword_alternation_from(keywords: &[String]) -> String {
    let mut literals: Vec<&str> = keywords.iter().map(String::as_str).collect();
    literals.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let mut alternation = String::new();
    for literal in literals {
        alternation.push_str(&regex::escape(literal));
        alternation.push('|');
    }
    alternation.push_str(GENERIC_RE_VENDOR_SUFFIX_ARM);
    alternation
}

/// Compile the bridge from a pre-built group-1 alternation.
pub(crate) fn compile_generic_re(
    alternation: &str,
) -> std::result::Result<regex::Regex, regex::Error> {
    compile_generic_re_with_max(alternation, GENERIC_ASSIGNMENT_MAX_LEN_DEFAULT)
}

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
pub(crate) fn build_generic_re() -> std::result::Result<regex::Regex, regex::Error> {
    let detectors = match keyhog_core::load_embedded_detectors_or_fail() {
        Ok(detectors) => detectors,
        Err(error) => panic!(
            "embedded detector corpus is corrupt: {error}. Cannot compile the detector-owned generic assignment bridge"
        ),
    };
    let max_len = detectors
        .iter()
        .filter(|detector| detector.kind == keyhog_core::DetectorKind::Phase2Generic)
        .map(|detector| {
            detector
                .max_len
                .unwrap_or(GENERIC_ASSIGNMENT_MAX_LEN_DEFAULT) // LAW10: documented numeric default for an omitted max_len
        })
        .max()
        .unwrap_or(GENERIC_ASSIGNMENT_MAX_LEN_DEFAULT); // LAW10: documented numeric default when the optional generic-detector set is empty
    compile_generic_re_with_max(&generic_keyword_alternation(), max_len)
}
