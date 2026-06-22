//! Detector quality gate validation rules used while loading TOML specs.

use super::{DetectorSpec, VerifySpec};
use regex_syntax::ast;
use serde::Serialize;

const MAX_REGEX_PATTERN_LEN: usize = 4096;
// MAX_REGEX_AST_NODES / MAX_REGEX_ALTERNATION_BRANCHES /
// MAX_REGEX_REPEAT_BOUND were originally defined here too but are the
// canonical constants in `validate/regex_complexity.rs` (which is where
// they're actually consumed). Duplicates here had no consumers - clippy
// `dead_code` flagged them. Re-imports happen via the `use
// regex_complexity::validate_regex_complexity;` below.

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
        validate_regex_definition(RegexKind::Pattern, i, &pat.regex, issues);
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
        validate_regex_definition(RegexKind::Companion, i, &companion.regex, issues);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegexKind {
    Pattern,
    Companion,
}

impl RegexKind {
    fn label(self) -> &'static str {
        match self {
            Self::Pattern => "pattern",
            Self::Companion => "companion",
        }
    }
}

fn validate_regex_definition(
    kind: RegexKind,
    index: usize,
    regex: &str,
    issues: &mut Vec<QualityIssue>,
) {
    let kind = kind.label();
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
    match ast::parse::Parser::new().parse(pattern) {
        Ok(ast) => ast_literal_runs(&ast).max >= min_len,
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

fn validate_verify_spec(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(ref verify) = spec.verify {
        // verify.service defaults to the detector's service - empty is fine
        validate_verify_urls(verify, issues);
        check_oob_consistency(verify, issues);
    }
    check_reserved_companion_names(spec, issues);
}

fn validate_verify_urls(verify: &VerifySpec, issues: &mut Vec<QualityIssue>) {
    let mut validated_url = false;
    visit_verify_template_fields(verify, |field| {
        if field.kind != VerifyTemplateFieldKind::Url {
            return;
        }
        let selected = if verify.steps.is_empty() {
            field.scope == VerifyTemplateScope::DefaultRequest
        } else {
            field.scope == VerifyTemplateScope::Step
        };
        if !selected {
            return;
        }
        validated_url = true;
        validate_url(field.value, issues);
        check_url_exfil_risk(field.value, &verify.allowed_domains, issues);
    });

    if !validated_url {
        issues.push(QualityIssue::Error(
            "verify spec has no steps and no default URL".into(),
        ));
    }
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
    visit_verify_template_fields(verify, |field| {
        if field.value.contains("{{interactsh") {
            interactsh_referenced = true;
        }
    });
    let oob_configured = verify.oob.is_some();
    if oob_configured && !verify.steps.is_empty() {
        issues.push(QualityIssue::Error(
            "verify.oob cannot be combined with multi-step verification: the \
             runtime must bind each interactsh callback to a concrete request \
             step, and this detector shape cannot be evaluated honestly. Use a \
             single request verifier for the OOB probe or split the detector."
                .into(),
        ));
    }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifyTemplateScope {
    DefaultRequest,
    Step,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifyTemplateFieldKind {
    Url,
    Body,
    Header,
}

#[derive(Clone, Copy)]
struct VerifyTemplateField<'a> {
    scope: VerifyTemplateScope,
    kind: VerifyTemplateFieldKind,
    value: &'a str,
}

fn visit_verify_template_fields<'a>(
    verify: &'a VerifySpec,
    mut visit: impl FnMut(VerifyTemplateField<'a>),
) {
    if let Some(ref url) = verify.url {
        visit(VerifyTemplateField {
            scope: VerifyTemplateScope::DefaultRequest,
            kind: VerifyTemplateFieldKind::Url,
            value: url,
        });
    }
    if let Some(ref body) = verify.body {
        visit(VerifyTemplateField {
            scope: VerifyTemplateScope::DefaultRequest,
            kind: VerifyTemplateFieldKind::Body,
            value: body,
        });
    }
    for header in &verify.headers {
        visit(VerifyTemplateField {
            scope: VerifyTemplateScope::DefaultRequest,
            kind: VerifyTemplateFieldKind::Header,
            value: &header.value,
        });
    }
    for step in &verify.steps {
        visit(VerifyTemplateField {
            scope: VerifyTemplateScope::Step,
            kind: VerifyTemplateFieldKind::Url,
            value: &step.url,
        });
        if let Some(ref body) = step.body {
            visit(VerifyTemplateField {
                scope: VerifyTemplateScope::Step,
                kind: VerifyTemplateFieldKind::Body,
                value: body,
            });
        }
        for header in &step.headers {
            visit(VerifyTemplateField {
                scope: VerifyTemplateScope::Step,
                kind: VerifyTemplateFieldKind::Header,
                value: &header.value,
            });
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
        .unwrap_or(trimmed); // LAW10: no scheme to strip -> analyze the whole URL; deterministic, not a failure
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
    match ast::parse::Parser::new().parse(pattern) {
        Ok(ast) => ast_literal_runs(&ast).prefix >= min_len,
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

#[derive(Clone, Copy)]
struct LiteralRunStats {
    prefix: usize,
    suffix: usize,
    max: usize,
    all_literal: bool,
}

impl LiteralRunStats {
    fn empty() -> Self {
        Self {
            prefix: 0,
            suffix: 0,
            max: 0,
            all_literal: true,
        }
    }

    fn literal(len: usize) -> Self {
        Self {
            prefix: len,
            suffix: len,
            max: len,
            all_literal: true,
        }
    }
}

fn ast_literal_runs(ast: &ast::Ast) -> LiteralRunStats {
    match ast {
        ast::Ast::Literal(_) => LiteralRunStats::literal(1),
        ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_) => {
            LiteralRunStats::empty()
        }
        ast::Ast::Group(group) => ast_literal_runs(&group.ast),
        ast::Ast::Concat(concat) => concat
            .asts
            .iter()
            .fold(LiteralRunStats::empty(), combine_literal_runs),
        ast::Ast::Alternation(alternation) => LiteralRunStats {
            max: match alternation
                .asts
                .iter()
                .map(|child| ast_literal_runs(child).max)
                .max()
            {
                Some(max) => max,
                None => 0,
            },
            prefix: 0,
            suffix: 0,
            all_literal: false,
        },
        ast::Ast::Repetition(repetition) => repeated_literal_runs(
            ast_literal_runs(&repetition.ast),
            repetition_min(&repetition.op.kind),
            repetition_is_exact(&repetition.op.kind),
        ),
        ast::Ast::Dot(_)
        | ast::Ast::ClassUnicode(_)
        | ast::Ast::ClassPerl(_)
        | ast::Ast::ClassBracketed(_) => LiteralRunStats {
            prefix: 0,
            suffix: 0,
            max: 0,
            all_literal: false,
        },
    }
}

fn combine_literal_runs(left: LiteralRunStats, right: &ast::Ast) -> LiteralRunStats {
    let right = ast_literal_runs(right);
    LiteralRunStats {
        prefix: if left.all_literal {
            left.prefix.saturating_add(right.prefix)
        } else {
            left.prefix
        },
        suffix: if right.all_literal {
            left.suffix.saturating_add(right.suffix)
        } else {
            right.suffix
        },
        max: left
            .max
            .max(right.max)
            .max(left.suffix.saturating_add(right.prefix)),
        all_literal: left.all_literal && right.all_literal,
    }
}

fn repeated_literal_runs(
    inner: LiteralRunStats,
    min_repetitions: usize,
    exact_repetition: bool,
) -> LiteralRunStats {
    if min_repetitions == 0 {
        return LiteralRunStats {
            prefix: 0,
            suffix: 0,
            max: inner.max,
            all_literal: false,
        };
    }

    if inner.all_literal {
        let repeated_len = inner.max.saturating_mul(min_repetitions);
        return LiteralRunStats {
            prefix: repeated_len,
            suffix: repeated_len,
            max: repeated_len,
            all_literal: exact_repetition,
        };
    }

    LiteralRunStats {
        prefix: inner.prefix,
        suffix: inner.suffix,
        max: inner.max,
        all_literal: false,
    }
}

fn repetition_min(kind: &ast::RepetitionKind) -> usize {
    match kind {
        ast::RepetitionKind::ZeroOrOne | ast::RepetitionKind::ZeroOrMore => 0,
        ast::RepetitionKind::OneOrMore => 1,
        ast::RepetitionKind::Range(ast::RepetitionRange::Exactly(min))
        | ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast(min))
        | ast::RepetitionKind::Range(ast::RepetitionRange::Bounded(min, _)) => *min as usize,
    }
}

fn repetition_is_exact(kind: &ast::RepetitionKind) -> bool {
    matches!(
        kind,
        ast::RepetitionKind::Range(ast::RepetitionRange::Exactly(_))
    )
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

mod regex_complexity;
use regex_complexity::validate_regex_complexity;
