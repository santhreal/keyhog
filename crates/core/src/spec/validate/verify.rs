//! Verification-spec validation: HTTP method/status/success policy, URL
//! exfiltration risk, out-of-band callback consistency, and provider-evidence
//! selectors declared under `[detector.verify]`.

use super::{QualityIssue, MAX_HTTP_STATUS, MIN_HTTP_STATUS};
use crate::spec::{DetectorSpec, VerifySpec};

pub(super) fn validate_verify_spec(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(ref verify) = spec.verify {
        validate_verify_urls(spec, verify, issues);
        validate_verify_success_policies(verify, issues);
        validate_provider_evidence(verify, issues);
        issues.extend(
            crate::json_selector::validate_detector_response_selectors(spec)
                .into_iter()
                .map(QualityIssue::Error),
        );
        check_oob_consistency(verify, issues);
    }
    check_reserved_companion_names(spec, issues);
}

fn validate_provider_evidence(verify: &VerifySpec, issues: &mut Vec<QualityIssue>) {
    let mut roles = std::collections::HashSet::new();
    for (index, field) in verify.metadata.iter().enumerate() {
        let Some(role) = crate::spec::ProviderEvidenceRole::from_metadata_name(&field.name) else {
            issues.push(QualityIssue::Error(format!(
                "verify.metadata[{index}].name {:?} is not a supported provider evidence role; use a reviewed provider-neutral role such as account_id, email, scope, team_id, or user_id",
                field.name
            )));
            continue;
        };
        if !roles.insert(role) {
            issues.push(QualityIssue::Error(format!(
                "verify.metadata[{index}] repeats provider evidence role {:?}; each report role must have one detector-owned selector",
                role.as_str()
            )));
        }
    }
}

fn validate_verify_success_policies(verify: &VerifySpec, issues: &mut Vec<QualityIssue>) {
    if let Some(success) = &verify.success {
        validate_success_policy("verify.success", success, issues);
    }
    for (step_index, step) in verify.steps.iter().enumerate() {
        validate_success_policy(
            &format!("verify.steps[{step_index}].success"),
            &step.success,
            issues,
        );
    }
}

fn validate_success_policy(
    scope: &str,
    success: &crate::spec::SuccessSpec,
    issues: &mut Vec<QualityIssue>,
) {
    validate_http_status(scope, "status", success.status, issues);
    validate_http_status(scope, "status_not", success.status_not, issues);

    let has_body_positive = success
        .body_contains
        .as_deref()
        .is_some_and(|needle| !needle.is_empty())
        || success.json_path.is_some();
    let has_any_body_constraint = success.body_contains.is_some()
        || success.body_not_contains.is_some()
        || success.json_path.is_some()
        || success.equals.is_some();

    match success.policy {
        None => issues.push(QualityIssue::Error(format!(
            "{scope}.policy must classify success as body_positive, status_with_error_backstop, or status_authoritative"
        ))),
        Some(crate::spec::SuccessPolicy::BodyPositive) => {
            if !has_body_positive {
                issues.push(QualityIssue::Error(format!(
                    "{scope}.policy=body_positive requires stable positive evidence with non-empty body_contains or json_path"
                )));
            }
        }
        Some(
            policy
            @ (crate::spec::SuccessPolicy::StatusWithErrorBackstop
                | crate::spec::SuccessPolicy::StatusAuthoritative),
        ) => {
            if success.status.is_none() {
                issues.push(QualityIssue::Error(format!(
                    "{scope}.policy={policy:?} requires an accepted status; status_not alone would treat unrelated responses as success"
                )));
            }
            if has_any_body_constraint {
                issues.push(QualityIssue::Error(format!(
                    "{scope}.policy={policy:?} cannot be combined with body_contains, body_not_contains, json_path, or equals"
                )));
            }
        }
    }
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

fn validate_verify_urls(
    detector: &DetectorSpec,
    verify: &VerifySpec,
    issues: &mut Vec<QualityIssue>,
) {
    for (index, domain) in verify.allowed_domains.iter().enumerate() {
        if crate::verification_domain::normalize_allowlist_entry(domain).is_none() {
            issues.push(QualityIssue::Error(format!(
                "verify.allowed_domains[{index}] is not a bare domain or host-only URL: {domain:?}"
            )));
        }
    }

    if verify.steps.is_empty() {
        if let Some(url) = verify.url.as_deref() {
            validate_selected_verify_url("verify.url", url, &detector.service, verify, issues);
        } else {
            issues.push(QualityIssue::Error(
                "verify spec has no steps and no default URL".into(),
            ));
        }
    } else {
        for (index, step) in verify.steps.iter().enumerate() {
            validate_selected_verify_url(
                &format!("verify.steps[{index}].url"),
                &step.url,
                &detector.service,
                verify,
                issues,
            );
        }
    }
}

fn validate_selected_verify_url(
    field: &str,
    raw_url: &str,
    detector_service: &str,
    verify: &VerifySpec,
    issues: &mut Vec<QualityIssue>,
) {
    validate_url(raw_url, issues);
    check_url_exfil_risk(raw_url, &verify.allowed_domains, issues);
    if url_authority_is_templated(raw_url) {
        return;
    }
    let parsed = match url::Url::parse(raw_url) {
        Ok(parsed) => parsed,
        Err(error) => {
            issues.push(QualityIssue::Error(format!(
                "{field} is not a valid absolute URL: {error}"
            )));
            return;
        }
    };
    let Some(host) = parsed.host_str() else {
        issues.push(QualityIssue::Error(format!(
            "{field} has no host; use an absolute service URL"
        )));
        return;
    };
    let Some(allowlist) =
        crate::verification_domain::effective_allowlist(verify, Some(detector_service))
    else {
        issues.push(QualityIssue::Error(format!(
            "{field} host {host:?} has no domain policy; set verify.service to a known service or declare verify.allowed_domains"
        )));
        return;
    };
    if !crate::verification_domain::host_is_allowed(host, &allowlist) {
        let policy_service = if verify.service.trim().is_empty() {
            detector_service
        } else {
            verify.service.as_str()
        };
        issues.push(QualityIssue::Error(format!(
            "{field} host {host:?} is outside verify.allowed_domains for service {:?} (allowed: {})",
            policy_service,
            allowlist.join(", ")
        )));
    }
}

fn url_authority_is_templated(raw_url: &str) -> bool {
    let trimmed = raw_url.trim();
    let authority = trimmed
        .split_once("://")
        .map_or(trimmed, |(_, remainder)| remainder)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default(); // LAW10: infallible split iterator; the first authority segment always exists, including the documented empty value.
    authority.contains(['{', '}'])
}

/// Reserved synthetic companion-map keys used by the OOB interpolator. A
/// detector that names a companion `__keyhog_oob_*` would either be
/// shadowed by the OOB injector or shadow it - either way, the verify
/// templates would resolve to surprising values. Reject the names so a
/// future detector author gets a clear error instead of a debugging
/// nightmare.
const RESERVED_COMPANION_NAMES: &[&str] =
    &["__keyhog_oob_url", "__keyhog_oob_host", "__keyhog_oob_id"];

pub(super) fn check_reserved_companion_names(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
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
pub(super) fn check_oob_consistency(verify: &VerifySpec, issues: &mut Vec<QualityIssue>) {
    let mut interactsh_referenced = false;
    visit_verify_template_fields(verify, |value| {
        if value.contains("{{interactsh") {
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

fn visit_verify_template_fields(verify: &VerifySpec, mut visit: impl FnMut(&str)) {
    if let Some(ref url) = verify.url {
        visit(url);
    }
    if let Some(ref body) = verify.body {
        visit(body);
    }
    for header in &verify.headers {
        visit(&header.value);
    }
    for step in &verify.steps {
        visit(&step.url);
        if let Some(ref body) = step.body {
            visit(body);
        }
        for header in &step.headers {
            visit(&header.value);
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
        .map_or(after_scheme, |authority| authority);
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
        host_port.split(':').next().map_or(host_port, |host| host)
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}
