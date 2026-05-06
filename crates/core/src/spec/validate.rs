//! Detector quality gate validation rules used while loading TOML specs.

use super::{DetectorSpec, VerifySpec};
use regex_syntax::ast::{self, Ast};
use serde::Serialize;

const MAX_REGEX_PATTERN_LEN: usize = 4096;
const MAX_REGEX_AST_NODES: usize = 512;
const MAX_REGEX_ALTERNATION_BRANCHES: usize = 64;
const MAX_REGEX_REPEAT_BOUND: u32 = 1_000;

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
/// let detector = DetectorSpec {
///     id: "demo".into(),
///     name: "Demo".into(),
///     service: "demo".into(),
///     severity: Severity::High,
///     patterns: vec![PatternSpec {
///         regex: "demo_[A-Z0-9]{8}".into(),
///         description: None,
///         group: None,
///     }],
///     companions: Vec::new(),
///     verify: None,
///     keywords: vec!["demo_".into()],
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
            "no keywords defined — pattern may produce false positives".into(),
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
                "pattern {} is a pure character class ({}) — too broad without context anchoring. \
                 Use a capture group or add a literal prefix.",
                i, pat.regex
            )));
        } else if !has_prefix && !has_group && spec.keywords.is_empty() {
            issues.push(QualityIssue::Warning(format!(
                "pattern {} has no literal prefix and no capture group — may false-positive",
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
        // only when the companion permits a wide search radius — at that
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
                     (> {}) — the wide search radius needs a literal context anchor",
                    i, companion.regex, companion.within_lines, TIGHT_COMPANION_RADIUS
                )));
            }
        } else if !has_substantial_literal(&companion.regex, 3) {
            issues.push(QualityIssue::Warning(format!(
                "companion {} regex '{}' is too broad — may produce false positives. \
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
        // verify.service defaults to the detector's service — empty is fine
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
/// shadowed by the OOB injector or shadow it — either way, the verify
/// templates would resolve to surprising values. Reject the names so a
/// future detector author gets a clear error instead of a debugging
/// nightmare.
const RESERVED_COMPANION_NAMES: &[&str] = &[
    "__keyhog_oob_url",
    "__keyhog_oob_host",
    "__keyhog_oob_id",
];

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
             template — the OOB callback URL has nowhere to land, so the wait_for \
             would always time out. Either embed an interactsh token in the body, \
             URL, or a header — or remove the [detector.verify.oob] block."
                .into(),
        )),
        (false, true) => issues.push(QualityIssue::Error(
            "an `{{interactsh*}}` token is referenced in a verify template but no \
             [detector.verify.oob] block is set — the token will resolve to an empty \
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
            "verify URL host is templated and no `allowed_domains` is set — \
             attacker-controlled interpolation could exfil credentials. \
             Either hardcode the authoritative host in the URL or set \
             `allowed_domains` explicitly. See kimi-wave3 §1."
                .into(),
        ));
    }
    // Single-brace `{name}` is a common author error — interpolate.rs
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

fn validate_regex_complexity(kind: &str, index: usize, ast: &Ast, issues: &mut Vec<QualityIssue>) {
    let mut stats = RegexComplexityStats::default();
    collect_regex_complexity(ast, &mut stats);
    collect_redos_risks(ast, &mut stats, false);

    if stats.nodes > MAX_REGEX_AST_NODES {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is too complex ({} AST nodes > {} limit)",
            stats.nodes, MAX_REGEX_AST_NODES
        )));
    }

    if stats.max_alternation_branches > MAX_REGEX_ALTERNATION_BRANCHES {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex has too many alternation branches ({} > {} limit)",
            stats.max_alternation_branches, MAX_REGEX_ALTERNATION_BRANCHES
        )));
    }

    if stats.max_repeat_bound > MAX_REGEX_REPEAT_BOUND {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex has an excessive counted repetition bound ({} > {} limit)",
            stats.max_repeat_bound, MAX_REGEX_REPEAT_BOUND
        )));
    }

    if stats.has_nested_quantifier {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex contains nested quantifiers that can trigger pathological matching"
        )));
    }

    if stats.has_quantified_overlapping_alternation {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex repeats overlapping alternations; use unambiguous branches instead"
        )));
    }
}

#[derive(Default)]
struct RegexComplexityStats {
    nodes: usize,
    max_alternation_branches: usize,
    max_repeat_bound: u32,
    has_nested_quantifier: bool,
    has_quantified_overlapping_alternation: bool,
}

fn collect_regex_complexity(ast: &Ast, stats: &mut RegexComplexityStats) {
    stats.nodes += 1;
    match ast {
        Ast::Repetition(repetition) => {
            update_repeat_bound(&repetition.op.kind, stats);
            collect_regex_complexity(&repetition.ast, stats);
        }
        Ast::Group(group) => collect_regex_complexity(&group.ast, stats),
        Ast::Alternation(alternation) => {
            stats.max_alternation_branches =
                stats.max_alternation_branches.max(alternation.asts.len());
            for ast in &alternation.asts {
                collect_regex_complexity(ast, stats);
            }
        }
        Ast::Concat(concat) => {
            for ast in &concat.asts {
                collect_regex_complexity(ast, stats);
            }
        }
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => {}
    }
}

fn collect_redos_risks(ast: &Ast, stats: &mut RegexComplexityStats, inside_repetition: bool) {
    match ast {
        Ast::Repetition(repetition) => {
            // Flag nested quantifiers only when they can cause exponential backtracking.
            //
            // SAFE patterns (char class quantifier inside group quantifier):
            //   (?:api[_\s.-]*)? — [_\s.-]* is atomic, can't overlap
            //   (?:key|token)[=:\s"']+  — char class quantifier, deterministic
            //
            // DANGEROUS patterns (group/concat quantifier inside quantifier):
            //   (a+)+       — classic ReDoS
            //   (\w+\s*)+   — overlapping quantifiers on non-atomic elements
            //
            // Strategy: only flag when THIS repetition wraps a non-atomic element
            // AND we're inside another repetition, OR when our inner AST itself
            // contains a nested repetition wrapping a non-atomic element.
            let this_is_simple_atom = matches!(
                &*repetition.ast,
                Ast::Literal(_)
                    | Ast::Dot(_)
                    | Ast::ClassBracketed(_)
                    | Ast::ClassPerl(_)
                    | Ast::ClassUnicode(_)
            );
            let this_is_unbounded = matches!(
                repetition.op.kind,
                ast::RepetitionKind::ZeroOrMore
                    | ast::RepetitionKind::OneOrMore
                    | ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast { .. })
            );
            // Only flag when BOTH the outer and this repetition are unbounded
            // and this wraps a non-atomic element. (?:group)? is safe because
            // ? is {0,1} — it can't cause exponential backtracking.
            if inside_repetition && !this_is_simple_atom && this_is_unbounded {
                stats.has_nested_quantifier = true;
            }
            if !inside_repetition
                && this_is_unbounded
                && !this_is_simple_atom
                && ast_contains_repetition(&repetition.ast)
            {
                stats.has_nested_quantifier = true;
            }
            if alternation_has_overlapping_prefixes(&repetition.ast) {
                stats.has_quantified_overlapping_alternation = true;
            }
            // Only propagate inside_repetition when this is unbounded
            collect_redos_risks(
                &repetition.ast,
                stats,
                inside_repetition || this_is_unbounded,
            );
        }
        Ast::Group(group) => collect_redos_risks(&group.ast, stats, inside_repetition),
        Ast::Alternation(alternation) => {
            for ast in &alternation.asts {
                collect_redos_risks(ast, stats, inside_repetition);
            }
        }
        Ast::Concat(concat) => {
            for ast in &concat.asts {
                collect_redos_risks(ast, stats, inside_repetition);
            }
        }
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => {}
    }
}

fn ast_contains_repetition(ast: &Ast) -> bool {
    match ast {
        Ast::Repetition(_) => true,
        Ast::Group(group) => ast_contains_repetition(&group.ast),
        Ast::Alternation(alternation) => alternation.asts.iter().any(ast_contains_repetition),
        Ast::Concat(concat) => concat.asts.iter().any(ast_contains_repetition),
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => false,
    }
}

fn alternation_has_overlapping_prefixes(ast: &Ast) -> bool {
    let alternatives = match ast {
        Ast::Alternation(alternation) => &alternation.asts,
        Ast::Group(group) => return alternation_has_overlapping_prefixes(&group.ast),
        _ => return false,
    };

    let prefixes = alternatives
        .iter()
        .filter_map(literalish_prefix)
        .collect::<Vec<_>>();
    for (idx, prefix) in prefixes.iter().enumerate() {
        for other in prefixes.iter().skip(idx + 1) {
            if prefix.starts_with(other) || other.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

fn literalish_prefix(ast: &Ast) -> Option<String> {
    match ast {
        Ast::Literal(literal) => Some(literal.c.to_string()),
        Ast::Concat(concat) => {
            let mut prefix = String::new();
            for node in &concat.asts {
                match node {
                    Ast::Literal(literal) => prefix.push(literal.c),
                    Ast::Group(group) => prefix.push_str(&literalish_prefix(&group.ast)?),
                    _ => break,
                }
            }
            (!prefix.is_empty()).then_some(prefix)
        }
        Ast::Group(group) => literalish_prefix(&group.ast),
        _ => None,
    }
}

fn update_repeat_bound(kind: &ast::RepetitionKind, stats: &mut RegexComplexityStats) {
    let bound = match kind {
        ast::RepetitionKind::ZeroOrOne => 1,
        ast::RepetitionKind::ZeroOrMore | ast::RepetitionKind::OneOrMore => MAX_REGEX_REPEAT_BOUND,
        ast::RepetitionKind::Range(range) => match range {
            ast::RepetitionRange::Exactly(max)
            | ast::RepetitionRange::AtLeast(max)
            | ast::RepetitionRange::Bounded(_, max) => *max,
        },
    };
    stats.max_repeat_bound = stats.max_repeat_bound.max(bound);
}

#[cfg(test)]
mod oob_validation_tests {
    use super::*;
    use crate::spec::load_detectors_from_str;

    fn errors_for(toml_src: &str) -> Vec<String> {
        let detectors = load_detectors_from_str(toml_src).expect("toml parses");
        let mut errs = Vec::new();
        for d in &detectors {
            for issue in validate_detector(d) {
                if let QualityIssue::Error(msg) = issue {
                    errs.push(msg);
                }
            }
        }
        errs
    }

    #[test]
    fn oob_block_without_interactsh_token_is_error() {
        let toml_src = r#"
[detector]
id = "oob-no-token"
name = "OOB without token"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[detector.verify]
method = "POST"
url = "https://api.github.com/probe"
body = '{"static":"payload"}'

[detector.verify.oob]
protocol = "http"
"#;
        let errs = errors_for(toml_src);
        assert!(
            errs.iter().any(|e| e.contains("verify.oob is set but no")),
            "expected oob-without-token error; got {errs:?}"
        );
    }

    #[test]
    fn interactsh_token_without_oob_block_is_error() {
        let toml_src = r#"
[detector]
id = "token-no-oob"
name = "Token without OOB"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[detector.verify]
method = "POST"
url = "https://api.github.com/probe"
body = '{"target":"https://{{interactsh}}/x"}'
"#;
        let errs = errors_for(toml_src);
        assert!(
            errs.iter()
                .any(|e| e.contains("token is referenced") && e.contains("no [detector.verify.oob]")),
            "expected token-without-oob error; got {errs:?}"
        );
    }

    #[test]
    fn oob_with_interactsh_token_passes() {
        let toml_src = r#"
[detector]
id = "oob-good"
name = "OOB with token"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[detector.verify]
method = "POST"
url = "https://api.github.com/probe"
body = '{"target":"https://{{interactsh}}/x"}'

[detector.verify.oob]
protocol = "http"
"#;
        let errs = errors_for(toml_src);
        let oob_related: Vec<_> = errs
            .iter()
            .filter(|e| e.contains("oob") || e.contains("interactsh"))
            .collect();
        assert!(oob_related.is_empty(), "unexpected OOB errors: {oob_related:?}");
    }

    #[test]
    fn reserved_companion_name_is_error() {
        let toml_src = r#"
[detector]
id = "reserved-name"
name = "Reserved name collision"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[[detector.companions]]
name = "__keyhog_oob_url"
regex = "(?:URL=)([a-z]{4,})"
within_lines = 5
"#;
        let errs = errors_for(toml_src);
        assert!(
            errs.iter()
                .any(|e| e.contains("__keyhog_oob_url") && e.contains("reserved")),
            "expected reserved-name error; got {errs:?}"
        );
    }

    /// Companions that are referenced via `{{companion.X}}` in a verify
    /// template (URL / body / header / step) but whose regex contains a
    /// context anchor (`KEY=value` style) with NO parenthesized capture
    /// group will substitute the FULL anchor + value into the verify
    /// template — typically corrupting the resulting request.
    ///
    /// `CompiledCompanion` auto-detects the first capture group when the
    /// regex has any (`compiler.rs:369`); without a group, the whole
    /// match is the value. So `(?:KEY=)([a-z]+)` is fine (group resolves
    /// to `[a-z]+`), but `KEY=[a-z]+` substitutes the literal `KEY=` too.
    ///
    /// This audit walks the embedded corpus, identifies suspicious
    /// companions, and asserts none exist. Any new detector whose
    /// companion is anchored-but-not-grouped will trip this test.
    #[test]
    fn audit_companion_substitutions_have_capture_groups() {
        use crate::spec::load_detectors_from_str;
        let mut suspicious = Vec::new();
        for (filename, toml_src) in crate::embedded_detector_tomls() {
            let Ok(detectors) = load_detectors_from_str(toml_src) else { continue };
            for d in &detectors {
                let Some(verify) = d.verify.as_ref() else { continue };
                // Build the set of companion names referenced via
                // `{{companion.X}}` in any verify template.
                let mut substituted: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut scan = |s: &str| {
                    let mut rest = s;
                    while let Some(start) = rest.find("{{companion.") {
                        let after = &rest[start + "{{companion.".len()..];
                        if let Some(end) = after.find("}}") {
                            substituted.insert(after[..end].to_string());
                            rest = &after[end + 2..];
                        } else {
                            break;
                        }
                    }
                };
                if let Some(ref u) = verify.url { scan(u); }
                if let Some(ref b) = verify.body { scan(b); }
                for h in &verify.headers { scan(&h.value); }
                for step in &verify.steps {
                    scan(&step.url);
                    if let Some(ref b) = step.body { scan(b); }
                    for h in &step.headers { scan(&h.value); }
                    if let crate::AuthSpec::Header { template, .. } = &step.auth {
                        scan(template);
                    }
                }
                if let Some(ref auth) = verify.auth {
                    if let crate::AuthSpec::Header { template, .. } = auth {
                        scan(template);
                    }
                }

                for c in &d.companions {
                    if !substituted.contains(&c.name) {
                        continue;
                    }
                    // The companion's value will be substituted somewhere.
                    // If the regex has any unescaped `(`, regex auto-detects
                    // a capture group → fine. Otherwise check that the
                    // regex doesn't contain a context anchor that would
                    // bleed into the substitution.
                    let has_group = regex_has_capture_group(&c.regex);
                    if has_group {
                        continue;
                    }
                    // No group → entire match substitutes. Look for assignment
                    // markers `=` or `:` outside character classes — these
                    // indicate the regex anchors on `KEY=value` and the
                    // substitution would include the prefix.
                    if regex_likely_includes_anchor_prefix(&c.regex) {
                        suspicious.push(format!(
                            "{} (companion {} regex {:?})",
                            filename, c.name, c.regex
                        ));
                    }
                }
            }
        }
        assert!(
            suspicious.is_empty(),
            "companions referenced in verify substitutions but lacking a capture group \
             on a context-anchored regex (would substitute `KEY=value` instead of just \
             `value`):\n  {}",
            suspicious.join("\n  ")
        );
    }

    /// Cheap heuristic: returns true if the regex has any unescaped `(`
    /// outside a character class. Matches both capturing `(...)` and
    /// non-capturing `(?:...)` — but the auto-detect on the scanner side
    /// (`regex.captures_len() > 1`) only fires for capturing groups, so
    /// we want to be more precise. This walker tracks `(?:` / `(?i:` /
    /// `(?P<...>` etc. and only counts groups that produce a capture.
    fn regex_has_capture_group(pattern: &str) -> bool {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        let mut in_class = false;
        let mut escape = false;
        while i < bytes.len() {
            let b = bytes[i];
            if escape { escape = false; i += 1; continue; }
            match b {
                b'\\' => { escape = true; }
                b'[' if !in_class => { in_class = true; }
                b']' if in_class => { in_class = false; }
                b'(' if !in_class => {
                    // Distinguish (?: / (?i: / (?P<name>...) / (?<name>...) / (...)
                    if i + 1 < bytes.len() && bytes[i + 1] == b'?' {
                        // (?...) — non-capturing OR named group OR
                        // look-around assertion. Distinguish them:
                        //   (?P<name>...)  capturing (Rust + RE2 style)
                        //   (?<name>...)   capturing (PCRE + .NET style),
                        //                  but `(?<=` and `(?<!` are
                        //                  zero-width look-behinds — NOT
                        //                  capturing.
                        //   (?:...)        non-capturing
                        //   (?i:...) etc.  non-capturing flag groups
                        //   (?=...) (?!...) zero-width look-around
                        let after = &bytes[i + 2..];
                        if after.starts_with(b"P<") {
                            return true;
                        }
                        if after.starts_with(b"<") {
                            // Disambiguate look-behind from named group.
                            // `(?<=...)` and `(?<!...)` start with `<=`/`<!`;
                            // anything else after `<` is a name.
                            if after.starts_with(b"<=") || after.starts_with(b"<!") {
                                // look-behind, non-capturing
                            } else {
                                return true;
                            }
                        }
                        // Otherwise `(?:`, `(?i:)`, `(?=...)`, `(?!...)`,
                        // bare flags `(?i)`, etc. — all non-capturing.
                    } else {
                        return true; // Plain `(` = capturing group
                    }
                }
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// Returns true if the regex has an assignment marker `=` outside any
    /// character class. URL companions (the common no-capture-group case
    /// that's actually fine) typically don't contain `=` — only their
    /// query strings would, and matching query-string values via
    /// companion is rare. `=` outside character classes is a strong
    /// signal that the regex anchors on `KEY=value` and would bleed the
    /// `KEY=` prefix into the substitution.
    ///
    /// `:` is intentionally NOT flagged: it appears in URL schemes
    /// (`https://`) and would generate false positives on every URL-
    /// shaped companion regex.
    fn regex_likely_includes_anchor_prefix(pattern: &str) -> bool {
        let bytes = pattern.as_bytes();
        let mut i = 0;
        let mut in_class = false;
        let mut escape = false;
        while i < bytes.len() {
            let b = bytes[i];
            if escape { escape = false; i += 1; continue; }
            match b {
                b'\\' => { escape = true; }
                b'[' if !in_class => { in_class = true; }
                b']' if in_class => { in_class = false; }
                b'=' if !in_class => return true,
                _ => {}
            }
            i += 1;
        }
        false
    }

    /// Audit every detector's auth-field references (Bearer.field,
    /// Basic.username, Basic.password, Query.field, AwsV4.access_key/
    /// secret_key/session_token) and assert each one resolves to either:
    ///   - a literal value (anything that isn't `match`, `companion`, or
    ///     `{{...}}`),
    ///   - the special `match` token,
    ///   - or `companion.<name>` where `<name>` actually exists in the
    ///     detector's companions list.
    ///
    /// The `resolve_field` helper falls through to "literal string" for
    /// anything that doesn't match those exact shapes, so a typo like
    /// `companion` (no `.name`), `companion.<typo>`, or `{{match}}`
    /// (template syntax in a field-style slot) used to silently produce
    /// a request that authenticated as the literal string. This audit
    /// rejects those at validation time.
    #[test]
    fn audit_auth_field_references_resolve() {
        use crate::spec::load_detectors_from_str;
        use crate::AuthSpec;

        let mut errors: Vec<String> = Vec::new();
        for (filename, toml_src) in crate::embedded_detector_tomls() {
            let Ok(detectors) = load_detectors_from_str(toml_src) else { continue };
            for d in &detectors {
                let companion_names: std::collections::HashSet<&str> = d
                    .companions
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect();

                let check = |label: &str, field: &str| -> Option<String> {
                    if field.contains("{{") {
                        return Some(format!(
                            "{filename}: {label} field {field:?} contains `{{...}}` template — \
                             field-style slots use `match`/`companion.<name>`/literal, NOT `{{...}}`. \
                             It silently resolves to the literal string."
                        ));
                    }
                    if field == "companion" {
                        return Some(format!(
                            "{filename}: {label} field is bare `\"companion\"` with no \
                             `.<name>` — silently resolves to the literal string \"companion\"."
                        ));
                    }
                    if let Some(name) = field.strip_prefix("companion.") {
                        if !companion_names.contains(name) {
                            return Some(format!(
                                "{filename}: {label} field {field:?} references companion \
                                 {name:?} which is not declared on this detector."
                            ));
                        }
                    }
                    None
                };

                if let Some(verify) = d.verify.as_ref() {
                    let mut audit_auth = |auth: &AuthSpec, ctx: &str| {
                        match auth {
                            AuthSpec::Bearer { field } => {
                                if let Some(e) = check(&format!("{ctx} bearer.field"), field) {
                                    errors.push(e);
                                }
                            }
                            AuthSpec::Basic { username, password } => {
                                if let Some(e) = check(&format!("{ctx} basic.username"), username) {
                                    errors.push(e);
                                }
                                if let Some(e) = check(&format!("{ctx} basic.password"), password) {
                                    errors.push(e);
                                }
                            }
                            AuthSpec::Query { field, .. } => {
                                if let Some(e) = check(&format!("{ctx} query.field"), field) {
                                    errors.push(e);
                                }
                            }
                            AuthSpec::AwsV4 { access_key, secret_key, session_token, .. } => {
                                if let Some(e) = check(&format!("{ctx} awsv4.access_key"), access_key) {
                                    errors.push(e);
                                }
                                if let Some(e) = check(&format!("{ctx} awsv4.secret_key"), secret_key) {
                                    errors.push(e);
                                }
                                if let Some(tok) = session_token {
                                    if let Some(e) = check(&format!("{ctx} awsv4.session_token"), tok) {
                                        errors.push(e);
                                    }
                                }
                            }
                            // Header.template is a TEMPLATE (uses interpolate
                            // which honors `{{match}}` / `{{companion.X}}`),
                            // not a field — different validation path.
                            AuthSpec::Header { .. } | AuthSpec::None | AuthSpec::Script { .. } => {}
                        }
                    };
                    if let Some(ref auth) = verify.auth {
                        audit_auth(auth, "verify.auth");
                    }
                    for (i, step) in verify.steps.iter().enumerate() {
                        audit_auth(&step.auth, &format!("verify.steps[{i}].auth"));
                    }
                }
            }
        }
        assert!(
            errors.is_empty(),
            "auth field reference audit found broken detectors:\n  {}",
            errors.join("\n  ")
        );
    }

    #[test]
    fn interactsh_token_in_header_value_counts() {
        // The token can live in the body, URL, OR a header value — any one
        // satisfies the "interactsh referenced" check.
        let toml_src = r#"
[detector]
id = "header-oob"
name = "OOB via header"
service = "github"
severity = "high"
keywords = ["GHTOKEN"]

[[detector.patterns]]
regex = "GHTOKEN_[A-Z0-9]{16}"

[detector.verify]
method = "POST"
url = "https://api.github.com/probe"

[[detector.verify.headers]]
name = "X-Callback"
value = "https://{{interactsh}}/x"

[detector.verify.oob]
protocol = "http"
"#;
        let errs = errors_for(toml_src);
        let oob_related: Vec<_> = errs
            .iter()
            .filter(|e| e.contains("oob") || e.contains("interactsh"))
            .collect();
        assert!(oob_related.is_empty(), "header-token detection failed: {oob_related:?}");
    }
}

