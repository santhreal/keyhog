//! Detector quality gate validation rules used while loading TOML specs.

use super::{DetectorKind, DetectorSpec, VerifySpec};
use regex_syntax::ast;
use serde::Serialize;
use std::collections::{hash_map::Entry, HashMap};

const MAX_REGEX_PATTERN_LEN: usize = 4096;
const MAX_COMPANION_WITHIN_LINES: usize = 100;
const MIN_HTTP_STATUS: u16 = 100;
const MAX_HTTP_STATUS: u16 = 599;
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
/// let detector = DetectorSpec {
///     id: "demo".into(),
///     name: "Demo".into(),
///     service: "demo".into(),
///     severity: Severity::High,
///     patterns: vec![PatternSpec {
///         regex: "demo_[A-Z0-9]{8}".into(),
///         ..Default::default()
///     }],
///     keywords: vec!["demo_".into()],
///     ..Default::default()
/// };
///
/// assert!(validate_detector(&detector).is_empty());
/// ```
pub fn validate_detector(spec: &DetectorSpec) -> Vec<QualityIssue> {
    let mut issues = Vec::new();
    let mut regex_cache = RegexAstCache::default();
    validate_patterns_present(spec, &mut issues);
    validate_regexes(spec, &mut issues, &mut regex_cache);
    validate_pattern_groups(spec, &mut issues, &mut regex_cache);
    validate_keywords(spec, &mut issues);
    validate_simdsieve_prefixes(spec, &mut issues);
    validate_pattern_specificity(spec, &mut issues, &mut regex_cache);
    validate_companions(spec, &mut issues, &mut regex_cache);
    validate_verify_spec(spec, &mut issues);
    validate_thresholds(spec, &mut issues);
    validate_entropy_floor(spec, &mut issues);
    validate_credential_shape(spec, &mut issues);
    validate_detector_allowlists(spec, &mut issues);
    issues
}

fn validate_simdsieve_prefixes(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    let mut seen = std::collections::HashSet::new();
    for (index, prefix) in spec.simdsieve_prefixes.iter().enumerate() {
        if prefix.is_empty() {
            issues.push(QualityIssue::Error(format!(
                "simdsieve_prefixes[{index}] must not be empty"
            )));
        } else if !prefix.is_ascii() {
            issues.push(QualityIssue::Error(format!(
                "simdsieve_prefixes[{index}] must be ASCII because simdsieve performs byte-prefix matching"
            )));
        }
        if !seen.insert(prefix) {
            issues.push(QualityIssue::Error(format!(
                "simdsieve_prefixes contains duplicate literal {prefix:?}"
            )));
        }
    }
}

/// `min_confidence` is a probability in `[0.0, 1.0]`. It is a bare `Option<f64>`
/// with no serde bound, so a typo'd value parses cleanly and then silently
/// breaks the gate: `< 0.0` always clears the confidence floor (every candidate
/// surfaces), `> 1.0` can never clear it (the detector never fires), and `NaN`
/// makes every comparison false. Reject anything outside the closed unit range
/// (a `RangeInclusive::contains` check is false for `NaN`, so NaN is caught too).
fn validate_thresholds(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (name, value) in [
        ("min_len", spec.min_len),
        ("keyword_free_min_len", spec.keyword_free_min_len),
    ] {
        if value == Some(0) {
            issues.push(QualityIssue::Error(format!(
                "{name} must be greater than 0 when present; use omission to inherit the path default"
            )));
        }
    }
    if let Some(mc) = spec.min_confidence {
        if !(0.0..=1.0).contains(&mc) {
            issues.push(QualityIssue::Error(format!(
                "min_confidence {mc} is out of range; confidence is a probability in [0.0, 1.0] \
                 (outside it silently breaks the gate: < 0 always passes, > 1 never fires, NaN is undefined)"
            )));
        }
    }
    if let Some(bound) = spec.bpe_max_bytes_per_token {
        if !bound.is_finite() || bound <= 0.0 {
            issues.push(QualityIssue::Error(format!(
                "bpe_max_bytes_per_token {bound} must be finite and greater than 0; \
                 zero or a negative value suppresses every candidate and NaN/inf makes the gate undefined"
            )));
        }
    }
    if spec.bpe_enabled == Some(false) && spec.bpe_max_bytes_per_token.is_some() {
        issues.push(QualityIssue::Error(
            "bpe_enabled = false conflicts with bpe_max_bytes_per_token; remove the ceiling when token efficiency is disabled"
                .into(),
        ));
    }
    for (name, value) in [
        ("entropy_high", spec.entropy_high),
        ("entropy_low", spec.entropy_low),
        ("entropy_very_high", spec.entropy_very_high),
        ("mixed_alnum_floor", spec.mixed_alnum_floor),
    ] {
        let Some(score) = value else {
            continue;
        };
        if !score.is_finite() || !(0.0..=8.0).contains(&score) {
            issues.push(QualityIssue::Error(format!(
                "{name} must be a finite Shannon entropy score in [0.0, 8.0], found {score}"
            )));
        }
    }
}

fn validate_entropy_floor(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.entropy_floor.is_empty() {
        return;
    }
    let last = spec.entropy_floor.len() - 1;
    let mut previous_max = 0usize;
    for (index, bucket) in spec.entropy_floor.iter().enumerate() {
        if !bucket.floor.is_finite() || !(0.0..=8.0).contains(&bucket.floor) {
            issues.push(QualityIssue::Error(format!(
                "entropy_floor bucket {index} floor must be finite and in [0.0, 8.0], found {}",
                bucket.floor
            )));
        }
        if index < last && bucket.max_len.is_none() {
            issues.push(QualityIssue::Error(format!(
                "entropy_floor bucket {index} is an early catch-all; only the final bucket may omit max_len"
            )));
        }
        if index == last && bucket.max_len.is_some() {
            issues.push(QualityIssue::Error(
                "entropy_floor final bucket must omit max_len so longer candidates cannot bypass the floor"
                    .into(),
            ));
        }
        if let Some(max_len) = bucket.max_len {
            if max_len <= previous_max {
                issues.push(QualityIssue::Error(format!(
                    "entropy_floor max_len values must strictly increase from a positive length; found {max_len} after {previous_max}"
                )));
            }
            previous_max = max_len;
        }
    }
}

fn validate_credential_shape(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(shape) = &spec.credential_shape {
        if let Err(error) = shape.validate(&spec.id) {
            issues.push(QualityIssue::Error(error));
        }
    }
}

fn validate_detector_allowlists(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (field, patterns) in [
        ("allowlist_paths", &spec.allowlist_paths),
        ("allowlist_values", &spec.allowlist_values),
    ] {
        for (index, pattern) in patterns.iter().enumerate() {
            if let Err(error) = regex::Regex::new(pattern) {
                issues.push(QualityIssue::Error(format!(
                    "{field}[{index}] is not a valid regex ({pattern:?}): {error}"
                )));
            }
        }
    }
}

fn validate_patterns_present(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    match spec.kind {
        // A phase-1 regex detector is defined by its anchors — no patterns is an error.
        DetectorKind::Regex => {
            if spec.patterns.is_empty() {
                issues.push(QualityIssue::Error("no patterns defined".into()));
            }
        }
        // A phase-2 generic bridge is defined by keywords + entropy_floor and has
        // NO anchor to match: patterns are forbidden, keywords are required.
        DetectorKind::Phase2Generic => {
            if !spec.patterns.is_empty() {
                issues.push(QualityIssue::Error(
                    "phase2-generic detector must not define regex patterns (it fires on \
                     keywords + entropy_floor, not an anchor)"
                        .into(),
                ));
            }
            if spec.keywords.is_empty() {
                issues.push(QualityIssue::Error(
                    "phase2-generic detector must define keywords (its only pre-filter)".into(),
                ));
            }
        }
    }
}

fn validate_regexes<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        validate_regex_definition(RegexKind::Pattern, i, &pat.regex, issues, regex_cache);
    }
}

fn validate_keywords(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.keywords.is_empty() {
        issues.push(QualityIssue::Warning(
            "no keywords defined - pattern may produce false positives".into(),
        ));
    }
}

fn validate_pattern_groups<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        let Some(group) = pat.group else {
            continue;
        };
        let Ok(ast) = regex_cache.parse(&pat.regex) else {
            continue; // LAW10: invalid regex already emits a QualityIssue::Error; detector load fails closed, recall-safe
        };
        let captures = ast_captures_len(ast);
        if group >= captures {
            issues.push(QualityIssue::Error(format!(
                "pattern {i} capture group {group} is out of range; regex has {} capture groups \
                 (valid group indexes are 0..{})",
                captures.saturating_sub(1),
                captures.saturating_sub(1)
            )));
        }
    }
}

fn validate_pattern_specificity<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        let has_prefix = has_literal_prefix(regex_cache, &pat.regex, 3);
        let has_group = pat.group.is_some();
        let is_pure_charclass = is_pure_character_class(regex_cache, &pat.regex);

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

fn validate_companions<'a>(
    spec: &'a DetectorSpec,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    for (i, companion) in spec.companions.iter().enumerate() {
        if companion.name.trim().is_empty() {
            issues.push(QualityIssue::Error(format!(
                "companion {} name must not be empty",
                i
            )));
        }
        if companion.within_lines > MAX_COMPANION_WITHIN_LINES {
            issues.push(QualityIssue::Error(format!(
                "companion {} within_lines={} exceeds {} search-window limit",
                i, companion.within_lines, MAX_COMPANION_WITHIN_LINES
            )));
        }
        validate_regex_definition(
            RegexKind::Companion,
            i,
            &companion.regex,
            issues,
            regex_cache,
        );
        // A "pure character class" companion (e.g. `[A-Z0-9]{10}` for an
        // Algolia application_id) is acceptable when `within_lines` is small:
        // the positional constraint is itself the contextual anchor. Reject
        // only when the companion permits a wide search radius - at that
        // point the lack of textual context really does over-fire.
        if is_pure_character_class(regex_cache, &companion.regex) {
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
        } else if !has_substantial_literal(regex_cache, &companion.regex, 3) {
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

#[derive(Default)]
struct RegexAstCache<'a> {
    parsed: HashMap<&'a str, Result<ast::Ast, String>>,
}

impl<'a> RegexAstCache<'a> {
    fn parse(&mut self, regex: &'a str) -> Result<&ast::Ast, &str> {
        let parsed = match self.parsed.entry(regex) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                ast::parse::Parser::new()
                    .parse(regex)
                    .map_err(|error| error.to_string()),
            ),
        };
        parsed.as_ref().map_err(String::as_str)
    }
}

fn validate_regex_definition<'a>(
    kind: RegexKind,
    index: usize,
    regex: &'a str,
    issues: &mut Vec<QualityIssue>,
    regex_cache: &mut RegexAstCache<'a>,
) {
    let kind = kind.label();
    // An empty regex is VALID syntax — it parses cleanly and matches the empty
    // string at EVERY position, so a detector carrying one fires on every byte
    // of every file: a catastrophic false-positive flood that the parse check
    // below cannot catch (it compiles fine). Reject it up front, fail closed.
    if regex.is_empty() {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is empty; an empty pattern matches at every position \
             (a catastrophic false-positive flood) — define a real anchor or remove the pattern"
        )));
        return;
    }
    if regex.len() > MAX_REGEX_PATTERN_LEN {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is too large ({} bytes > {} byte limit)",
            regex.len(),
            MAX_REGEX_PATTERN_LEN
        )));
        return;
    }

    match regex_cache.parse(regex) {
        Ok(ast) => validate_regex_complexity(kind, index, ast, issues),
        Err(error) => issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex does not compile: {error}"
        ))),
    }
}

fn has_substantial_literal<'a>(
    regex_cache: &mut RegexAstCache<'a>,
    pattern: &'a str,
    min_len: usize,
) -> bool {
    match regex_cache.parse(pattern) {
        Ok(ast) => ast_literal_runs(ast).max >= min_len,
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

fn validate_verify_spec(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(ref verify) = spec.verify {
        // verify.service defaults to the detector's service - empty is fine
        validate_verify_urls(verify, issues);
        validate_verify_success_statuses(verify, issues);
        check_oob_consistency(verify, issues);
    }
    check_reserved_companion_names(spec, issues);
}

fn validate_verify_success_statuses(verify: &VerifySpec, issues: &mut Vec<QualityIssue>) {
    if let Some(success) = &verify.success {
        validate_success_status("verify.success", success, issues);
    }
    for (step_index, step) in verify.steps.iter().enumerate() {
        validate_success_status(
            &format!("verify.steps[{step_index}].success"),
            &step.success,
            issues,
        );
    }
}

fn validate_success_status(
    scope: &str,
    success: &super::SuccessSpec,
    issues: &mut Vec<QualityIssue>,
) {
    validate_http_status(scope, "status", success.status, issues);
    validate_http_status(scope, "status_not", success.status_not, issues);
}

fn validate_http_status(
    scope: &str,
    field: &str,
    status: Option<u16>,
    issues: &mut Vec<QualityIssue>,
) {
    let Some(status) = status else {
        return;
    };
    if !(MIN_HTTP_STATUS..=MAX_HTTP_STATUS).contains(&status) {
        issues.push(QualityIssue::Error(format!(
            "{scope}.{field}={status} is outside valid HTTP status range {MIN_HTTP_STATUS}..={MAX_HTTP_STATUS}"
        )));
    }
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
    if url.starts_with("http://") && !is_loopback_http_host(url) {
        issues.push(QualityIssue::Warning(
            "verify URL uses HTTP instead of HTTPS".into(),
        ));
    }
}

/// True when the `http://` URL's authority HOST is a loopback address
/// (`localhost` / `127.0.0.1` / `[::1]`), for which plaintext HTTP carries no
/// exfil risk. Matches the parsed host, not any occurrence of the literal, so
/// `http://evil.example.com/callback?host=localhost` is NOT exempt.
fn is_loopback_http_host(url: &str) -> bool {
    let Some(after_scheme) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 literal `[::1]:port` -> `::1`
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => return false,
        }
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn has_literal_prefix<'a>(
    regex_cache: &mut RegexAstCache<'a>,
    pattern: &'a str,
    min_len: usize,
) -> bool {
    match regex_cache.parse(pattern) {
        Ok(ast) => ast_literal_runs(ast).prefix >= min_len,
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

fn ast_captures_len(ast: &ast::Ast) -> usize {
    ast_max_capture_index(ast)
        .map(|index| index as usize + 1)
        .unwrap_or(1) // LAW10: no explicit capture groups still leaves regex capture group 0; this is the same captures_len contract, not a fallback.
}

fn ast_max_capture_index(ast: &ast::Ast) -> Option<u32> {
    let mut max_capture = None;
    let mut stack = vec![ast];
    while let Some(node) = stack.pop() {
        match node {
            ast::Ast::Group(group) => {
                max_capture = max_capture.max(group.capture_index());
                stack.push(&group.ast);
            }
            ast::Ast::Concat(concat) => stack.extend(concat.asts.iter()),
            ast::Ast::Alternation(alternation) => stack.extend(alternation.asts.iter()),
            ast::Ast::Repetition(repetition) => stack.push(&repetition.ast),
            ast::Ast::Empty(_)
            | ast::Ast::Flags(_)
            | ast::Ast::Literal(_)
            | ast::Ast::Dot(_)
            | ast::Ast::Assertion(_)
            | ast::Ast::ClassUnicode(_)
            | ast::Ast::ClassPerl(_)
            | ast::Ast::ClassBracketed(_) => {}
        }
    }
    max_capture
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
    enum LiteralFrame<'a> {
        Visit(&'a ast::Ast),
        FinishConcat(usize),
        FinishAlternation(usize),
        FinishRepetition(&'a ast::RepetitionKind),
    }

    let mut frames = vec![LiteralFrame::Visit(ast)];
    let mut results = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            LiteralFrame::Visit(node) => match node {
                ast::Ast::Literal(_) => results.push(LiteralRunStats::literal(1)),
                ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_) => {
                    results.push(LiteralRunStats::empty());
                }
                ast::Ast::Group(group) => frames.push(LiteralFrame::Visit(&group.ast)),
                ast::Ast::Concat(concat) => {
                    frames.push(LiteralFrame::FinishConcat(concat.asts.len()));
                    for child in concat.asts.iter().rev() {
                        frames.push(LiteralFrame::Visit(child));
                    }
                }
                ast::Ast::Alternation(alternation) => {
                    frames.push(LiteralFrame::FinishAlternation(alternation.asts.len()));
                    for child in alternation.asts.iter().rev() {
                        frames.push(LiteralFrame::Visit(child));
                    }
                }
                ast::Ast::Repetition(repetition) => {
                    frames.push(LiteralFrame::FinishRepetition(&repetition.op.kind));
                    frames.push(LiteralFrame::Visit(&repetition.ast));
                }
                ast::Ast::Dot(_)
                | ast::Ast::ClassUnicode(_)
                | ast::Ast::ClassPerl(_)
                | ast::Ast::ClassBracketed(_) => results.push(LiteralRunStats {
                    prefix: 0,
                    suffix: 0,
                    max: 0,
                    all_literal: false,
                }),
            },
            LiteralFrame::FinishConcat(child_count) => {
                let children = results.split_off(results.len() - child_count);
                let combined = children
                    .into_iter()
                    .fold(LiteralRunStats::empty(), combine_literal_runs);
                results.push(combined);
            }
            LiteralFrame::FinishAlternation(child_count) => {
                let children = results.split_off(results.len() - child_count);
                let max = match children.into_iter().map(|child| child.max).max() {
                    Some(max) => max,
                    None => 0,
                };
                results.push(LiteralRunStats {
                    max,
                    prefix: 0,
                    suffix: 0,
                    all_literal: false,
                });
            }
            LiteralFrame::FinishRepetition(kind) => {
                let inner = match results.pop() {
                    Some(inner) => inner,
                    None => LiteralRunStats::empty(),
                };
                results.push(repeated_literal_runs(
                    inner,
                    repetition_min(kind),
                    repetition_is_exact(kind),
                ));
            }
        }
    }
    match results.pop() {
        Some(stats) => stats,
        None => LiteralRunStats::empty(),
    }
}

fn combine_literal_runs(left: LiteralRunStats, right: LiteralRunStats) -> LiteralRunStats {
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

fn is_pure_character_class<'a>(regex_cache: &mut RegexAstCache<'a>, pattern: &'a str) -> bool {
    match regex_cache.parse(pattern) {
        Ok(ast) => pure_character_class_ast(ast).is_some(),
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

fn pure_character_class_ast(ast: &ast::Ast) -> Option<()> {
    enum PureFrame<'a> {
        Visit(&'a ast::Ast),
        FinishAllNonempty(usize),
    }

    let mut frames = vec![PureFrame::Visit(ast)];
    let mut results = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            PureFrame::Visit(node) => match node {
                ast::Ast::ClassBracketed(_) => results.push(Some(())),
                ast::Ast::Group(group) => frames.push(PureFrame::Visit(&group.ast)),
                ast::Ast::Repetition(repetition) => frames.push(PureFrame::Visit(&repetition.ast)),
                ast::Ast::Alternation(alternation) => {
                    frames.push(PureFrame::FinishAllNonempty(alternation.asts.len()));
                    for child in alternation.asts.iter().rev() {
                        frames.push(PureFrame::Visit(child));
                    }
                }
                ast::Ast::Concat(concat) => {
                    let children = concat
                        .asts
                        .iter()
                        .filter(|child| !is_regex_metadata_node(child))
                        .collect::<Vec<_>>();
                    frames.push(PureFrame::FinishAllNonempty(children.len()));
                    for child in children.into_iter().rev() {
                        frames.push(PureFrame::Visit(child));
                    }
                }
                ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_) => {
                    results.push(None);
                }
                ast::Ast::Literal(_)
                | ast::Ast::Dot(_)
                | ast::Ast::ClassUnicode(_)
                | ast::Ast::ClassPerl(_) => results.push(None),
            },
            PureFrame::FinishAllNonempty(child_count) => {
                if child_count == 0 {
                    results.push(None);
                    continue;
                }
                let children = results.split_off(results.len() - child_count);
                results.push(
                    children
                        .into_iter()
                        .all(|child| child.is_some())
                        .then_some(()),
                );
            }
        }
    }
    results.pop().flatten()
}

fn is_regex_metadata_node(ast: &ast::Ast) -> bool {
    matches!(
        ast,
        ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_)
    )
}

mod regex_complexity;
use regex_complexity::validate_regex_complexity;
