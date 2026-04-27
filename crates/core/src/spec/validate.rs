//! Detector quality gate validation rules used while loading TOML specs.

use super::DetectorSpec;
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
