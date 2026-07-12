//! Construction of the generic assignment bridge regex.

// The value/assignment tail of `GENERIC_RE`: assignment syntax, benign
// secret-suffix hops, and the group-2 value shape. The static 8..128 envelope
// belongs to this one global bridge; detector-specific admission floors remain
// in each detector TOML and are applied after capture.
const GENERIC_RE_ASSIGNMENT_TAIL: &str = r#"(?:[._-]?(?:key|base|value|val|string|str|enc|raw|b64)){0,2}["'`]?\s*(?::\s*(?:&?[a-zA-Z_][a-zA-Z0-9_<>]{0,31}\s*[=:]\s*)?|=\s*)["'`]?([a-zA-Z0-9/+=_.:!@#$%^&*-]{8,128})["'`]?"#;

/// Structural group-1 arm for bounded vendor-prefixed key names.
pub(crate) const GENERIC_RE_VENDOR_SUFFIX_ARM: &str =
    r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){0,2}[._-](?:key|secret|token)";

/// Build group 1 from the single derived assignment-keyword vocabulary.
pub(crate) fn generic_keyword_alternation() -> String {
    let mut literals: Vec<&str> = crate::assignment_keywords::assignment_keywords()
        .iter()
        .map(String::as_str)
        .collect();
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
    regex::Regex::new(&format!("(?i)({alternation}){GENERIC_RE_ASSIGNMENT_TAIL}"))
}

/// Compile the bridge from the live derived vocabulary.
pub(crate) fn build_generic_re() -> std::result::Result<regex::Regex, regex::Error> {
    compile_generic_re(&generic_keyword_alternation())
}
