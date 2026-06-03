//! Detector quality gate validation rules used while loading TOML specs.

use super::{DetectorSpec, VerifySpec};
use regex_syntax::ast;
use serde::Serialize;

const MAX_REGEX_PATTERN_LEN: usize = 4096;
// MAX_REGEX_AST_NODES / MAX_REGEX_ALTERNATION_BRANCHES /
// MAX_REGEX_REPEAT_BOUND were originally defined here too but are the
// canonical constants in `validate_regex.rs` (which is where they're
// actually consumed). Duplicates here had no consumers - clippy
// `dead_code` flagged them. Re-imports happen via the `use
// validate_regex::validate_regex_complexity;` below.

/// Quality issue found in a detector spec.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::QualityIssue;
///
/// let issue = QualityIssue::Warning("add keywords".into());
/// assert!(matches!(issue, QualityIssue::Warning(_)));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum QualityIssue {
    Error(String),
    Warning(String),
}

/// Validate a detector spec against the quality gate.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{DetectorSpec, PatternSpec, Severity, validate_detector};
///
/// let detector = DetectorSpec { tests: Vec::new(),
///     id: "demo".into(),
///     name: "Demo".into(),
///     service: "demo".into(),
///     severity: Severity::High,
///     patterns: vec![PatternSpec {
///         regex: "demo_[A-Z0-9]{8}".into(),
///         ..Default::default()
///     }],
///     companions: Vec::new(),
///     verify: None,
///     keywords: vec!["demo_".into()],
///     min_confidence: None,
/// };
///
/// assert!(validate_detector(&detector).is_empty());
/// ```
pub fn validate_detector(spec: &DetectorSpec) -> Vec<QualityIssue> {
    let mut issues = Vec::new();
    validate_patterns_present(spec, &mut issues);
    validate_regexes(spec, &mut issues);
    validate_keywords(spec, &mut issues);
    validate_pattern_specificity(spec, &mut issues);
    validate_companions(spec, &mut issues);
    validate_verify_spec(spec, &mut issues);
    issues
}

fn validate_patterns_present(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.patterns.is_empty() {
        issues.push(QualityIssue::Error("no patterns defined".into()));
    }
}

fn validate_regexes(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        validate_regex_definition("pattern", i, &pat.regex, issues);
    }
}

fn validate_keywords(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.keywords.is_empty() {
        issues.push(QualityIssue::Warning(
            "no keywords defined - pattern may produce false positives".into(),
        ));
    }
}

fn validate_pattern_specificity(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        let has_prefix = has_literal_prefix(&pat.regex, 3);
        let has_group = pat.group.is_some();
        let is_pure_charclass = is_pure_character_class(&pat.regex);

        if is_pure_charclass && !has_group {
            issues.push(QualityIssue::Error(format!(
                "pattern {} is a pure character class ({}) - too broad without context anchoring. \
                 Use a capture group or add a literal prefix.",
                i, pat.regex
            )));
        } else if !has_prefix && !has_group && spec.keywords.is_empty() {
            issues.push(QualityIssue::Warning(format!(
                "pattern {} has no literal prefix and no capture group - may false-positive",
                i
            )));
        }
    }
}

fn validate_companions(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (i, companion) in spec.companions.iter().enumerate() {
        if companion.name.trim().is_empty() {
            issues.push(QualityIssue::Error(format!(
                "companion {} name must not be empty",
                i
            )));
        }
        validate_regex_definition("companion", i, &companion.regex, issues);
        // A "pure character class" companion (e.g. `[A-Z0-9]{10}` for an
        // Algolia application_id) is acceptable when `within_lines` is small:
        // the positional constraint is itself the contextual anchor. Reject
        // only when the companion permits a wide search radius - at that
        // point the lack of textual context really does over-fire.
        if is_pure_character_class(&companion.regex) {
            if companion.within_lines <= TIGHT_COMPANION_RADIUS {
                issues.push(QualityIssue::Warning(format!(
                    "companion {} regex '{}' is a pure character class; \
                     allowed because within_lines={} ≤ {} (positional anchoring).",
                    i, companion.regex, companion.within_lines, TIGHT_COMPANION_RADIUS
                )));
            } else {
                issues.push(QualityIssue::Error(format!(
                    "companion {} regex '{}' is a pure character class with within_lines={} \
                     (> {}) - the wide search radius needs a literal context anchor",
                    i, companion.regex, companion.within_lines, TIGHT_COMPANION_RADIUS
                )));
            }
        } else if !has_substantial_literal(&companion.regex, 3) {
            issues.push(QualityIssue::Warning(format!(
                "companion {} regex '{}' is too broad - may produce false positives. \
                 Add a context anchor like 'KEY_NAME='.",
                i, companion.regex
            )));
        }
    }
}

/// Companion search radius (in lines) below which a pure character-class
/// regex is acceptable. The positional bound provides the context anchor.
const TIGHT_COMPANION_RADIUS: usize = 5;

fn validate_regex_definition(
    kind: &str,
    index: usize,
    regex: &str,
    issues: &mut Vec<QualityIssue>,
) {
    if regex.len() > MAX_REGEX_PATTERN_LEN {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is too large ({} bytes > {} byte limit)",
            regex.len(),
            MAX_REGEX_PATTERN_LEN
        )));
        return;
    }

    match ast::parse::Parser::new().parse(regex) {
        Ok(ast) => validate_regex_complexity(kind, index, &ast, issues),
        Err(error) => issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex does not compile: {error}"
        ))),
    }
}

fn has_substantial_literal(pattern: &str, min_len: usize) -> bool {
    let mut max_literal_len = 0;
    let mut current_literal_len = 0;
    let mut in_escape = false;
    let mut in_char_class = false;

    for ch in pattern.chars() {
        if in_escape {
            if is_escaped_literal(ch) {
                current_literal_len += 1;
            } else {
                max_literal_len = max_literal_len.max(current_literal_len);
                current_literal_len = 0;
            }
            in_escape = false;
            continue;
        }

        match ch {
            '\\' => in_escape = true,
            '[' => {
                max_literal_len = max_literal_len.max(current_literal_len);
                current_literal_len = 0;
                in_char_class = true;
            }
            ']' => {
                in_char_class = false;
            }
            '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '|' | '^' | '$' => {
                max_literal_len = max_literal_len.max(current_literal_len);
                current_literal_len = 0;
            }
            _ => {
                if !in_char_class {
                    current_literal_len += 1;
                }
            }
        }
    }
    max_literal_len = max_literal_len.max(current_literal_len);
    max_literal_len >= min_len
}

fn is_escaped_literal(ch: char) -> bool {
    matches!(
        ch,
        '[' | ']' | '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '\\' | '|' | '^' | '$'
    )
}

fn validate_verify_spec(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(ref verify) = spec.verify {
        // verify.service defaults to the detector's service - empty is fine
        if !verify.steps.is_empty() {
            for step in &verify.steps {
                validate_url(&step.url, issues);
                check_url_exfil_risk(&step.url, &verify.allowed_domains, issues);
            }
        } else if let Some(ref url) = verify.url {
            validate_url(url, issues);
            check_url_exfil_risk(url, &verify.allowed_domains, issues);
        } else {
            issues.push(QualityIssue::Error(
                "verify spec has no steps and no default URL".into(),
            ));
        }
        check_oob_consistency(verify, issues);
    }
    check_reserved_companion_names(spec, issues);
}

/// Reserved synthetic companion-map keys used by the OOB interpolator. A
/// detector that names a companion `__keyhog_oob_*` would either be
/// shadowed by the OOB injector or shadow it - either way, the verify
/// templates would resolve to surprising values. Reject the names so a
/// future detector author gets a clear error instead of a debugging
/// nightmare.
const RESERVED_COMPANION_NAMES: &[&str] =
    &["__keyhog_oob_url", "__keyhog_oob_host", "__keyhog_oob_id"];

fn check_reserved_companion_names(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (i, c) in spec.companions.iter().enumerate() {
        if RESERVED_COMPANION_NAMES.contains(&c.name.as_str()) {
            issues.push(QualityIssue::Error(format!(
                "companion {} name '{}' is reserved for the OOB interpolator. \
                 Pick a different name; this collision would corrupt verify templates.",
                i, c.name,
            )));
        }
    }
}

/// Check that `[detector.verify.oob]` and `{{interactsh}}` template tokens
/// are configured consistently:
///
/// - `oob` set but no `{{interactsh*}}` token anywhere in the verify
///   templates → the wait_for parks for nothing; the probe never embeds
///   the callback URL so the service can't reach our collector.
/// - `{{interactsh*}}` token present but `oob` unset → the token resolves
///   to an empty string at runtime, sending malformed requests (e.g.
///   `https:///x` or a JSON body with `"target":""`).
///
/// Both are misconfigurations that load successfully but produce
/// silently-wrong verify behavior. Fail-closed at the validator instead.
fn check_oob_consistency(verify: &VerifySpec, issues: &mut Vec<QualityIssue>) {
    let mut interactsh_referenced = false;
    let mut scan = |s: &str| {
        if s.contains("{{interactsh") {
            interactsh_referenced = true;
        }
    };
    if let Some(ref url) = verify.url {
        scan(url);
    }
    if let Some(ref body) = verify.body {
        scan(body);
    }
    for h in &verify.headers {
        scan(&h.value);
    }
    for step in &verify.steps {
        scan(&step.url);
        if let Some(ref body) = step.body {
            scan(body);
        }
        for h in &step.headers {
            scan(&h.value);
        }
    }
    let oob_configured = verify.oob.is_some();
    match (oob_configured, interactsh_referenced) {
        (true, false) => issues.push(QualityIssue::Error(
            "verify.oob is set but no `{{interactsh}}` / `{{interactsh.host}}` / \
             `{{interactsh.url}}` / `{{interactsh.id}}` token appears in any verify \
             template - the OOB callback URL has nowhere to land, so the wait_for \
             would always time out. Either embed an interactsh token in the body, \
             URL, or a header - or remove the [detector.verify.oob] block."
                .into(),
        )),
        (false, true) => issues.push(QualityIssue::Error(
            "an `{{interactsh*}}` token is referenced in a verify template but no \
             [detector.verify.oob] block is set - the token will resolve to an empty \
             string at runtime and ship a malformed request to the service. Either \
             add a [detector.verify.oob] block or remove the token."
                .into(),
        )),
        _ => {}
    }
}

/// Catch detectors whose `verify.url` is built from interpolation tokens
/// without a fixed authoritative host AND without an explicit
/// `allowed_domains` list. The verifier's runtime domain allowlist
/// catches these at request time, but flagging at load time gives the
/// detector author actionable feedback before the rule ships.
/// kimi-wave3 §1 + §1.HIGH (single-brace `{var}` and `{{shop}}` cases).
fn check_url_exfil_risk(url: &str, allowed_domains: &[String], issues: &mut Vec<QualityIssue>) {
    // Detect `{{match}}` or `{{companion.*}}` taking the place of the
    // authority component of the URL. Conservative match: anything that
    // starts with the templated host (e.g. `https://{{...}}`, plain
    // `{{match}}`, `https://{{...}}/path`).
    let trimmed = url.trim();
    let after_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host_starts_with_template =
        after_scheme.starts_with("{{") || after_scheme.starts_with("{") || trimmed == "{{match}}";
    if host_starts_with_template && allowed_domains.is_empty() {
        issues.push(QualityIssue::Error(
            "verify URL host is templated and no `allowed_domains` is set - \
             attacker-controlled interpolation could exfil credentials. \
             Either hardcode the authoritative host in the URL or set \
             `allowed_domains` explicitly. See kimi-wave3 §1."
                .into(),
        ));
    }
    // Single-brace `{name}` is a common author error - interpolate.rs
    // only handles `{{...}}`, so `{name}` lands in the URL literally.
    if url.contains('{') && !url.contains("{{") {
        issues.push(QualityIssue::Error(
            "verify URL uses single-brace `{var}` template syntax which the \
             interpolator does NOT honor (only `{{var}}` works); the URL will \
             be sent to a literal-string host. Use `{{companion.var}}`."
                .into(),
        ));
    }
}

fn validate_url(url: &str, issues: &mut Vec<QualityIssue>) {
    if url.is_empty() {
        issues.push(QualityIssue::Error("verify URL is empty".into()));
    }
    if url.starts_with("http://") && !url.contains("localhost") {
        issues.push(QualityIssue::Warning(
            "verify URL uses HTTP instead of HTTPS".into(),
        ));
    }
}

fn has_literal_prefix(pattern: &str, min_len: usize) -> bool {
    let mut count = 0;
    for ch in pattern.chars() {
        match ch {
            '[' | '(' | '.' | '*' | '+' | '?' | '{' | '\\' | '|' | '^' | '$' => break,
            _ => count += 1,
        }
    }
    count >= min_len
}

fn is_pure_character_class(pattern: &str) -> bool {
    let trimmed = pattern.trim();
    if !trimmed.starts_with('[') {
        return false;
    }

    let Some(close) = trimmed.find(']') else {
        return false;
    };
    let remainder = trimmed[close + 1..].trim();
    if remainder.is_empty() {
        return true;
    }
    if remainder == "+" || remainder == "*" || remainder == "?" {
        return true;
    }
    if remainder.starts_with('{') {
        if let Some(qclose) = remainder.find('}') {
            let after_quantifier = remainder[qclose + 1..].trim();
            return after_quantifier.is_empty();
        }
    }

    false
}

#[path = "validate_regex.rs"]
mod validate_regex;
use validate_regex::validate_regex_complexity;
