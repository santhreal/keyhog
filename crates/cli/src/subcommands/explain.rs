//! `keyhog explain <detector-id>` — full spec dump for one detector.
//!
//! Prints id, name, service, severity, all patterns, keywords, companions,
//! verification spec presence, and a service-keyed rotation-guide URL when
//! one is known. Tier-B innovation #9 from audits/legendary-2026-04-26.

use crate::args::ExplainArgs;
use anyhow::{Context, Result};
use keyhog_core::DetectorSpec;

pub fn run(args: ExplainArgs) -> Result<()> {
    let detectors = load_detectors(&args.detectors)?;

    let needle = args.detector_id.to_lowercase();
    let detector = detectors
        .iter()
        .find(|d| d.id.to_lowercase() == needle)
        .ok_or_else(|| {
            // Suggest near-matches by substring so a typo prints something
            // useful instead of "not found".
            let suggestions: Vec<&str> = detectors
                .iter()
                .filter(|d| d.id.to_lowercase().contains(&needle))
                .map(|d| d.id.as_str())
                .take(8)
                .collect();
            if suggestions.is_empty() {
                anyhow::anyhow!(
                    "no detector with id '{}' (use `keyhog detectors` to list available ids)",
                    args.detector_id
                )
            } else {
                anyhow::anyhow!(
                    "no detector with id '{}'. Did you mean: {}?",
                    args.detector_id,
                    suggestions.join(", ")
                )
            }
        })?;

    print_explanation(detector);
    Ok(())
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
        println!("  Verification:  (none — pattern match only)");
    }

    if let Some(rotation) = rotation_guide(&d.service) {
        println!();
        println!("\u{1F510} Rotation guide for {}:", d.service);
        println!("    {rotation}");
    }

    println!();
    println!("If this finding lands in your scan, the canonical remediation is:");
    println!("  1. Treat the credential as compromised — assume it has been read.");
    println!("  2. Rotate it at the issuer (see rotation-guide URL above).");
    println!("  3. Audit access logs for the old credential's identifier.");
    println!("  4. Replace the leaked value with an env-var reference and add to `.gitignore`.");
    println!();
}

/// Service-keyed rotation guide. The map is curated for the most-leaked
/// services per the GitGuardian + Snyk 2025 reports. Unknown services
/// return None and the explainer omits the rotation block.
fn rotation_guide(service: &str) -> Option<&'static str> {
    let lower = service.to_lowercase();
    match lower.as_str() {
        s if s.contains("aws") => Some("https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"),
        s if s.contains("github") => Some("https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"),
        s if s.contains("gitlab") => Some("https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#revoke-a-personal-access-token"),
        s if s.contains("slack") => Some("https://api.slack.com/legacy/oauth-scopes#auth.revoke"),
        s if s.contains("openai") => Some("https://platform.openai.com/api-keys"),
        s if s.contains("anthropic") => Some("https://console.anthropic.com/settings/keys"),
        s if s.contains("stripe") => Some("https://dashboard.stripe.com/apikeys"),
        s if s.contains("twilio") => Some("https://www.twilio.com/docs/iam/access-tokens#rotate-keys"),
        s if s.contains("sendgrid") => Some("https://docs.sendgrid.com/ui/account-and-settings/api-keys"),
        s if s.contains("google") || s.contains("gcp") => Some("https://cloud.google.com/iam/docs/creating-managing-service-account-keys#rotating"),
        s if s.contains("azure") => Some("https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#authentication-two-options"),
        s if s.contains("npm") => Some("https://docs.npmjs.com/revoking-access-tokens"),
        s if s.contains("pypi") => Some("https://pypi.org/help/#apitoken"),
        s if s.contains("docker") => Some("https://docs.docker.com/security/for-developers/access-tokens/"),
        s if s.contains("datadog") => Some("https://docs.datadoghq.com/account_management/api-app-keys/"),
        s if s.contains("snowflake") => Some("https://docs.snowflake.com/en/user-guide/key-pair-auth#configuring-key-pair-rotation"),
        _ => None,
    }
}

fn load_detectors(path: &std::path::Path) -> Result<Vec<DetectorSpec>> {
    if path.exists() && path.is_dir() {
        let loaded =
            keyhog_core::load_detectors(path).context("loading detectors from directory")?;
        crate::orchestrator_config::require_non_empty_detectors(&loaded, path)?;
        return Ok(loaded);
    }
    let embedded = keyhog_core::embedded_detector_tomls();
    if embedded.is_empty() {
        anyhow::bail!(
            "detector directory '{}' not found and no embedded detectors available",
            path.display()
        );
    }
    let mut out = Vec::with_capacity(embedded.len());
    for (name, body) in embedded {
        match toml::from_str::<keyhog_core::DetectorFile>(body) {
            Ok(file) => out.push(file.detector),
            Err(e) => eprintln!("warning: failed to parse embedded detector {name}: {e}"),
        }
    }
    crate::orchestrator_config::require_non_empty_detectors(&out, path)?;
    Ok(out)
}
