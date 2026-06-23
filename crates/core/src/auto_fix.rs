//! Auto-fix suggestions: turn each finding into "replace this credential
//! with `${ENV_VAR_NAME}`" advice.
//!
//! Tier-B moat innovation #15 + #17 from docs/EXECUTION_PLAN.md:
//! moves keyhog from "find" to "fix." We surface the suggestion in SARIF
//! `result.fixes[]` per the v2.2.0 spec; CLI consumers can apply the edit
//! interactively or in a pre-commit hook.
//!
//! This module provides only the SUGGESTION step (deterministic env-var
//! name from service + the `${VAR}` replacement string). Actually rewriting
//! files belongs in the CLI, where we can prompt the user before clobbering
//! their working tree.
//!
//! The curated `service -> env var` mappings are **Tier-B data**, compiled in
//! from `data/service-env-vars.toml`. They are NOT a hardcoded `match` arm and
//! are not extended by ambient process environment; changing the shipped map is
//! a data-file edit, reviewable in the same diff as the detector corpus.

use std::sync::LazyLock;

use crate::Severity;

/// One curated `service -> env var` mapping, deserialized from the Tier-B
/// `[[service]]` tables in `data/service-env-vars.toml`.
#[derive(serde::Deserialize)]
struct ServiceEnvEntry {
    /// ASCII-case-insensitive needle tested against the service string.
    #[serde(rename = "match")]
    needle: String,
    /// The environment-variable name emitted verbatim when the needle matches.
    env: String,
    /// When `true`, require the service to START with `needle` (used for the
    /// `gh-` / `ghp_` GitHub token prefixes); otherwise it is a substring test.
    #[serde(default)]
    prefix: bool,
}

#[derive(serde::Deserialize, Default)]
struct ServiceEnvFile {
    #[serde(default)]
    service: Vec<ServiceEnvEntry>,
}

/// The compiled-in service map. Ordering within the file is preserved; because
/// matching takes the first hit, the data file must list more-specific needles
/// before broader substrings they could otherwise shadow.
///
/// A corrupt baseline is a build-time-embedded constant, so a parse failure
/// there is a hard programming error and we surface it LOUDLY (unconditional
/// `eprintln!`) and fall back to the screaming-snake derivation rather than
/// silently producing wrong fix advice.
static SERVICE_ENV_MAP: LazyLock<Vec<ServiceEnvEntry>> = LazyLock::new(|| {
    parse_service_env_file(
        include_str!("../data/service-env-vars.toml"),
        "<embedded data/service-env-vars.toml>",
    )
});

/// Provider-specific remediation advice emitted by text, JSON, SARIF, and HTML
/// reporters. The values come from Tier-B data, never reporter-side match arms.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct Remediation {
    pub(crate) action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revoke_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) docs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) revoke_command: Option<String>,
}

impl Remediation {
    pub(crate) fn markdown(&self) -> String {
        let mut out = self.action.clone();
        if let Some(command) = &self.revoke_command {
            out.push_str("\n\nRevoke command:\n\n```sh\n");
            out.push_str(command);
            out.push_str("\n```");
        }
        if let Some(url) = self.revoke_url.as_ref().or(self.docs_url.as_ref()) {
            out.push_str("\n\nReference: ");
            out.push_str(url);
        }
        out
    }
}

#[derive(Clone, serde::Deserialize)]
struct RemediationFields {
    action: String,
    #[serde(default)]
    revoke_url: Option<String>,
    #[serde(default)]
    docs_url: Option<String>,
    #[serde(default)]
    revoke_command: Option<String>,
}

impl From<&RemediationFields> for Remediation {
    fn from(fields: &RemediationFields) -> Self {
        Self {
            action: fields.action.clone(),
            revoke_url: fields.revoke_url.clone(),
            docs_url: fields.docs_url.clone(),
            revoke_command: fields.revoke_command.clone(),
        }
    }
}

#[derive(serde::Deserialize)]
struct DetectorRemediationEntry {
    id: String,
    #[serde(flatten)]
    fields: RemediationFields,
}

#[derive(serde::Deserialize)]
struct ServiceRemediationEntry {
    #[serde(rename = "match")]
    needle: String,
    #[serde(default)]
    prefix: bool,
    #[serde(flatten)]
    fields: RemediationFields,
}

#[derive(serde::Deserialize)]
struct SeverityRemediationEntry {
    severity: String,
    #[serde(flatten)]
    fields: RemediationFields,
}

#[derive(Default, serde::Deserialize)]
struct RemediationFile {
    #[serde(default)]
    detector: Vec<DetectorRemediationEntry>,
    #[serde(default)]
    service: Vec<ServiceRemediationEntry>,
    #[serde(default)]
    severity: Vec<SeverityRemediationEntry>,
}

static REMEDIATION_MAP: LazyLock<RemediationFile> = LazyLock::new(|| {
    parse_remediation_file(
        include_str!("../data/remediation.toml"),
        "<embedded data/remediation.toml>",
    )
});

/// Parse one `service-env-vars.toml` document into its entries. On a parse
/// error we surface the failure LOUDLY (Law 10: no silent fallback) and return
/// an empty list so the caller degrades to the deterministic screaming-snake
/// derivation rather than silently dropping curated advice.
fn parse_service_env_file(raw: &str, origin: &str) -> Vec<ServiceEnvEntry> {
    match toml::from_str::<ServiceEnvFile>(raw) {
        Ok(parsed) => parsed.service,
        Err(e) => {
            eprintln!(
                "keyhog: service-env map '{origin}' failed to parse: {e}; \
                 falling back to <SERVICE>_KEY derivation for all services"
            );
            Vec::new()
        }
    }
}

fn parse_remediation_file(raw: &str, origin: &str) -> RemediationFile {
    match toml::from_str::<RemediationFile>(raw) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!(
                "keyhog: remediation map '{origin}' failed to parse: {e}; \
                 falling back to generic rotate/remove advice"
            );
            RemediationFile::default()
        }
    }
}

/// Map a detector's `service` string to a conventional environment-variable
/// name. Falls back to `<UPPER_SERVICE>_KEY` when the service isn't in the
/// curated [Tier-B map](../data/service-env-vars.toml).
///
/// The curated mappings follow community conventions (12-factor, common SDKs);
/// see `data/service-env-vars.toml` for the authoritative list.
pub(crate) fn env_var_name_for_service(service: &str) -> String {
    SERVICE_ENV_MAP
        .iter()
        .find(|entry| service_entry_matches(service, &entry.needle, entry.prefix))
        .map(|entry| entry.env.clone())
        // The default below is not an error fallback — it is the documented
        // `<SERVICE>_KEY` mapping for any service the curated Tier-B map does not
        // cover, always producing a deterministic, correct suggestion.
        .unwrap_or_else(|| service_to_screaming_snake(service)) // LAW10: documented default, not a failure path
}

fn service_to_screaming_snake(service: &str) -> String {
    let mut out = String::with_capacity(service.len() + 4);
    for ch in service.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string() + "_KEY"
}

/// Render the `${ENV_VAR_NAME}` shell-interpolation replacement string for
/// a detector. Reporters embed this in their `fixes[]` output.
/// Return the recommended replacement text for a leaked credential (e.g., "${STRIPE_KEY}").
pub(crate) fn fix_replacement_text(service: &str) -> String {
    format!("${{{}}}", env_var_name_for_service(service))
}

pub(crate) fn remediation_for(detector_id: &str, service: &str, severity: Severity) -> Remediation {
    let data = &*REMEDIATION_MAP;
    if let Some(entry) = data
        .detector
        .iter()
        .find(|entry| entry.id.as_str() == detector_id)
    {
        return Remediation::from(&entry.fields);
    }

    if let Some(entry) = data
        .service
        .iter()
        .find(|entry| service_entry_matches(service, &entry.needle, entry.prefix))
    {
        return Remediation::from(&entry.fields);
    }

    if let Some(entry) = data
        .severity
        .iter()
        .find(|entry| entry.severity == severity.as_str())
    {
        return Remediation::from(&entry.fields);
    }

    Remediation {
        action: "Remove the exposed credential from the codebase and rotate it at the provider."
            .to_string(),
        revoke_url: None,
        docs_url: None,
        revoke_command: None,
    }
}

fn service_entry_matches(service: &str, needle: &str, prefix: bool) -> bool {
    if prefix {
        starts_with_ignore_ascii_case(service, needle)
    } else {
        contains_ignore_ascii_case(service, needle)
    }
}

fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn contains_ignore_ascii_case(value: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
