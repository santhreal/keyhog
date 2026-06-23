//! `keyhog explain <detector-id>` - full spec dump for one detector.
//!
//! Prints id, name, service, severity, all patterns, keywords, companions,
//! verification spec presence, and a service-keyed rotation-guide URL when
//! one is known. Tier-B innovation #9 from docs/EXECUTION_PLAN.md.

use crate::args::ExplainArgs;
use anyhow::Result;
use keyhog_core::DetectorSpec;

pub(crate) fn run(args: ExplainArgs) -> Result<()> {
    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&args.detectors)?;

    let requested = args.detector_id.as_str();
    // `hot-*` ids are the SIMD fast-path's FINDING labels (see the scanner's
    // simdsieve_prefilter HOT_PATTERN_DETECTOR_IDS), NOT registry detector ids.
    // A user who copies an id straight out of `scan` output (`hot-github_pat`)
    // into `explain` would otherwise hit a bare "no such detector" - the two
    // commands would silently disagree. Resolve to the canonical registry spec
    // and tell them what happened.
    let (needle, hot_origin) = match canonical_for_hot_id(requested) {
        Some(canon) => (canon, Some(requested)),
        None => (requested, None),
    };

    let detector = detectors
        .iter()
        .find(|d| d.id.eq_ignore_ascii_case(needle))
        .ok_or_else(|| explain_not_found(&detectors, requested, requested))?;

    if let Some(hot) = hot_origin {
        println!(
            "\u{2139} '{hot}' is keyhog's SIMD fast-path label; showing the \
             canonical detector '{needle}'.\n"
        );
    }
    print_explanation(detector);
    Ok(())
}

/// Map a `hot-<name>` fast-path finding id to its canonical registry detector.
/// Index-aligned with the scanner's `HOT_PATTERN_DETECTOR_IDS`. Kept here (CLI
/// side, un-feature-gated) so `explain` resolves these ids in every build,
/// including `--no-default-features` portable binaries that compile the hot
/// labels out of the scanner but can still be fed a `hot-*` id by hand or from
/// a baseline produced on a SIMD build.
///
fn canonical_for_hot_id(id: &str) -> Option<&'static str> {
    const HOT_IDS: &[(&str, &str)] = &[
        ("hot-github_pat", "github-classic-pat"),
        ("hot-openai_key", "openai-api-key"),
        ("hot-aws_key", "aws-access-key"),
        ("hot-aws_session_key", "aws-session-token"),
        ("hot-sendgrid_key", "sendgrid-api-key"),
        ("hot-slack_bot_token", "slack-bot-token"),
        ("hot-slack_user_token", "slack-user-token"),
        ("hot-square_secret", "square-access-token"),
    ];
    HOT_IDS
        .iter()
        .find_map(|(hot, canonical)| id.eq_ignore_ascii_case(hot).then_some(*canonical))
}

/// Build the "not found" error, with a tailored branch for `hot-*` ids that
/// have no canonical registry detector so the user learns it's a real fast-path
/// pattern rather than chasing a typo.
fn explain_not_found(detectors: &[DetectorSpec], requested: &str, lowered: &str) -> anyhow::Error {
    if let Some(stripped) = strip_prefix_ignore_ascii_case(lowered, "hot-") {
        let svc = stripped.split('_').next().unwrap_or(stripped); // LAW10: split yields >=1 element; unwrap_or is the never-taken total default, recall-safe
        let related: Vec<&str> = detectors
            .iter()
            .filter(|d| {
                contains_ignore_ascii_case(&d.id, svc)
                    || contains_ignore_ascii_case(&d.service, svc)
            })
            .map(|d| d.id.as_str())
            .take(8)
            .collect();
        return if related.is_empty() {
            anyhow::anyhow!(
                "'{requested}' is a keyhog SIMD fast-path pattern with no standalone \
                 registry detector yet - it still surfaces in scans, there is just no \
                 separate spec to explain."
            )
        } else {
            anyhow::anyhow!(
                "'{requested}' is a keyhog SIMD fast-path label, not a registry detector id. \
                 Related detectors you can explain: {}",
                related.join(", ")
            )
        };
    }
    // Suggest near-matches by substring so a typo prints something useful
    // instead of "not found".
    let suggestions: Vec<&str> = detectors
        .iter()
        .filter(|d| contains_ignore_ascii_case(&d.id, lowered))
        .map(|d| d.id.as_str())
        .take(8)
        .collect();
    if suggestions.is_empty() {
        anyhow::anyhow!(
            "no detector with id '{requested}' (use `keyhog detectors` to list available ids)"
        )
    } else {
        anyhow::anyhow!(
            "no detector with id '{requested}'. Did you mean: {}?",
            suggestions.join(", ")
        )
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    use keyhog_core::DetectorSpec;

    pub(crate) fn canonical_for_hot_id(id: &str) -> Option<&'static str> {
        super::canonical_for_hot_id(id)
    }

    pub(crate) fn explain_not_found(
        detectors: &[DetectorSpec],
        requested: &str,
        lowered: &str,
    ) -> anyhow::Error {
        super::explain_not_found(detectors, requested, lowered)
    }
}

fn print_explanation(d: &DetectorSpec) {
    println!("\u{1F4D6} {}\n", d.id);
    println!("  Name:      {}", d.name);
    println!("  Service:   {}", d.service);
    println!("  Severity:  {:?}", d.severity);
    println!("  Patterns:  {}", d.patterns.len());
    for (i, p) in d.patterns.iter().enumerate() {
        println!("    [{i}] {}", p.regex);
        if let Some(group) = p.group {
            println!("        capture group: {group}");
        }
        if let Some(desc) = &p.description {
            println!("        description: {desc}");
        }
    }

    if !d.keywords.is_empty() {
        println!("  Keywords:");
        for kw in &d.keywords {
            println!("    - {kw}");
        }
    }

    if !d.companions.is_empty() {
        println!("  Companions:");
        for c in &d.companions {
            let req = if c.required { " (required)" } else { "" };
            println!(
                "    - {}{req}: {} (within {} lines)",
                c.name, c.regex, c.within_lines
            );
        }
    }

    if let Some(verify) = &d.verify {
        println!("  Verification:");
        if let Some(url) = verify.url.as_deref() {
            println!("    URL: {url}");
        }
        println!("    Steps: {}", verify.steps.len());
    } else {
        println!("  Verification:  (none; pattern match only)");
    }

    if let Some(rotation) = rotation_guide(&d.service) {
        println!();
        println!("\u{1F510} Rotation guide for {}:", d.service);
        println!("    {rotation}");
    }

    println!();
    println!("If this finding lands in your scan, the canonical remediation is:");
    println!("  1. Treat the credential as compromised; assume it has been read.");
    println!("  2. Rotate it at the issuer (see rotation-guide URL above).");
    println!("  3. Audit access logs for the old credential's identifier.");
    println!("  4. Replace the leaked value with an env-var reference and add to `.gitignore`.");
    println!();
}

/// Service-keyed rotation guide. The map is curated for the most-leaked
/// services per the GitGuardian + Snyk 2025 reports. Unknown services
/// return None and the explainer omits the rotation block.
fn rotation_guide(service: &str) -> Option<&'static str> {
    match service {
        s if contains_ignore_ascii_case(s, "aws") => Some(
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey",
        ),
        s if contains_ignore_ascii_case(s, "github") => Some(
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        ),
        s if contains_ignore_ascii_case(s, "gitlab") => Some(
            "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#revoke-a-personal-access-token",
        ),
        s if contains_ignore_ascii_case(s, "slack") => {
            Some("https://api.slack.com/legacy/oauth-scopes#auth.revoke")
        }
        s if contains_ignore_ascii_case(s, "openai") => Some("https://platform.openai.com/api-keys"),
        s if contains_ignore_ascii_case(s, "anthropic") => {
            Some("https://console.anthropic.com/settings/keys")
        }
        s if contains_ignore_ascii_case(s, "stripe") => Some("https://dashboard.stripe.com/apikeys"),
        s if contains_ignore_ascii_case(s, "twilio") => {
            Some("https://www.twilio.com/docs/iam/access-tokens#rotate-keys")
        }
        s if contains_ignore_ascii_case(s, "sendgrid") => {
            Some("https://docs.sendgrid.com/ui/account-and-settings/api-keys")
        }
        s if contains_ignore_ascii_case(s, "google") || contains_ignore_ascii_case(s, "gcp") => Some(
            "https://cloud.google.com/iam/docs/creating-managing-service-account-keys#rotating",
        ),
        s if contains_ignore_ascii_case(s, "azure") => Some(
            "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#authentication-two-options",
        ),
        s if contains_ignore_ascii_case(s, "npm") => Some("https://docs.npmjs.com/revoking-access-tokens"),
        s if contains_ignore_ascii_case(s, "pypi") => Some("https://pypi.org/help/#apitoken"),
        s if contains_ignore_ascii_case(s, "docker") => {
            Some("https://docs.docker.com/security/for-developers/access-tokens/")
        }
        s if contains_ignore_ascii_case(s, "datadog") => {
            Some("https://docs.datadoghq.com/account_management/api-app-keys/")
        }
        s if contains_ignore_ascii_case(s, "snowflake") => Some(
            "https://docs.snowflake.com/en/user-guide/key-pair-auth#configuring-key-pair-rotation",
        ),
        _ => None,
    }
}

fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .as_bytes()
        .get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
        .map(|_| &value[prefix.len()..])
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
