//! `keyhog explain <detector-id>` - full spec dump for one detector.
//!
//! Prints id, name, service, severity, all patterns, keywords, companions,
//! verification spec presence, and a service-keyed rotation-guide URL when
//! one is known. Tier-B innovation #9 from the internal design notes.

use crate::args::ExplainArgs;
use anyhow::Result;
use keyhog_core::{contains_ignore_ascii_case, DetectorSpec};

pub(crate) fn run(args: ExplainArgs) -> Result<()> {
    crate::orchestrator_config::validate_explicit_detector_path(
        &args.detectors,
        args.detectors_cli_explicit,
    )?;
    let detectors_path = crate::orchestrator_config::auto_discover_detectors(&args.detectors)?;
    let detectors = crate::orchestrator_config::load_detectors_or_embedded(&detectors_path)?;

    let requested = args.detector_id.as_str();
    let detector = detectors
        .iter()
        .find(|d| d.id.eq_ignore_ascii_case(requested))
        .ok_or_else(|| explain_not_found(&detectors, requested, requested))?;

    print_explanation(detector);
    Ok(())
}

/// Map a retired `hot-<name>` finding alias to its canonical registry detector.
/// The map provides an exact error migration but never aliases execution.
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

/// Build the "not found" error, including a tailored branch for an unknown
/// retired-alias shape.
fn explain_not_found(detectors: &[DetectorSpec], requested: &str, lowered: &str) -> anyhow::Error {
    if let Some(canonical) = canonical_for_hot_id(requested) {
        return anyhow::anyhow!(
            "'{requested}' is a retired detector id and is not accepted. Use \
             `keyhog explain {canonical}`."
        );
    }
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
                "'{requested}' is not a current detector id or a recognized retired \
                 fast-path alias (use `keyhog detectors` to list canonical ids)."
            )
        } else {
            anyhow::anyhow!(
                "'{requested}' resembles a retired fast-path alias, not a current detector id. \
                 Related canonical detectors you can explain: {}",
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
    let style = crate::style::for_stdout();
    let sev_color = match d.severity {
        keyhog_core::Severity::Critical | keyhog_core::Severity::High => style.red,
        _ => style.yellow,
    };

    println!(
        "\u{1F4D6} {}{}{}{}\n",
        style.bold, style.cyan, d.id, style.reset
    );
    println!("  {}Name:{}      {}", style.bold, style.reset, d.name);
    println!("  {}Service:{}   {}", style.bold, style.reset, d.service);
    println!(
        "  {}Severity:{}  {}{}{}",
        style.bold, style.reset, sev_color, d.severity, style.reset
    );
    println!(
        "  {}Patterns:{}  {}",
        style.bold,
        style.reset,
        d.patterns.len()
    );
    for (i, p) in d.patterns.iter().enumerate() {
        println!("    {}[{i}]{} {}", style.dim, style.reset, p.regex);
        if let Some(group) = p.group {
            println!("        {}capture group: {group}{}", style.dim, style.reset);
        }
        if let Some(desc) = &p.description {
            println!("        {}description: {desc}{}", style.dim, style.reset);
        }
        if !p.required_literals.is_empty() {
            println!(
                "        {}required_literals [detector TOML]: {}{}",
                style.dim,
                p.required_literals.join(", "),
                style.reset
            );
        }
    }

    if !d.keywords.is_empty() {
        println!("  {}Keywords:{}", style.bold, style.reset);
        for kw in &d.keywords {
            println!("    - {kw}");
        }
    }

    print_detection_policy(d, &style);

    if !d.companions.is_empty() {
        println!("  {}Companions:{}", style.bold, style.reset);
        for c in &d.companions {
            let req = if c.required {
                format!(" {}(required){}", style.dim, style.reset)
            } else {
                String::new()
            };
            println!(
                "    - {}{}: {} {}(within {} lines){}",
                c.name, req, c.regex, style.dim, c.within_lines, style.reset
            );
        }
    }

    if let Some(verify) = &d.verify {
        println!("  {}Verification:{}", style.bold, style.reset);
        if let Some(url) = verify.url.as_deref() {
            println!("    {}URL: {}{}", style.dim, url, style.reset);
        }
        println!(
            "    {}Steps: {}{}",
            style.dim,
            verify.steps.len(),
            style.reset
        );
    } else {
        println!(
            "  {}Verification:{}  {}(none; pattern match only){}",
            style.bold, style.reset, style.dim, style.reset
        );
    }

    if let Some(rotation) = rotation_guide(&d.service) {
        println!();
        println!(
            "{}\u{1F510} Rotation guide for {}:{}",
            style.bold, d.service, style.reset
        );
        println!("    {}{}{}", style.dim, rotation, style.reset);
    }

    println!();
    println!(
        "{}If this finding lands in your scan, the canonical remediation is:{}",
        style.bold, style.reset
    );
    println!(
        "  {}1. Treat the credential as compromised; assume it has been read.{}",
        style.dim, style.reset
    );
    println!(
        "  {}2. Rotate it at the issuer (see rotation-guide URL above).{}",
        style.dim, style.reset
    );
    println!(
        "  {}3. Audit access logs for the old credential's identifier.{}",
        style.dim, style.reset
    );
    println!(
        "  {}4. Replace the leaked value with an env-var reference and add to `.gitignore`.{}",
        style.dim, style.reset
    );
    println!();
}

/// Print the detector-local policy that changes candidate admission. This is
/// deliberately part of `explain`, not a second policy registry: every value
/// comes from the loaded detector TOML and absent values are identified as scan
/// fallbacks rather than rendered as invented detector defaults.
fn print_detection_policy(d: &DetectorSpec, style: &crate::style::Palette) {
    let kind = match d.kind {
        keyhog_core::DetectorKind::Regex => "regex",
        keyhog_core::DetectorKind::Phase2Generic => "phase2-generic",
    };
    println!("  {}Declared detector policy:{}", style.bold, style.reset);
    println!("    kind: {kind}");

    println!(
        "    ml: match_mode={} entropy_mode={} weight={} context_radius_lines={}",
        d.ml.match_mode.as_str(),
        d.ml.entropy_mode.as_str(),
        d.ml.weight,
        d.ml.context_radius_lines
    );
    if let Some(confidence) = d.match_confidence {
        println!(
            "    match_confidence: literal_prefix_weight={} context_anchor_weight={} entropy_weight={} high_entropy_partial_weight={} moderate_entropy_threshold={} moderate_entropy_weight={}",
            confidence.literal_prefix_weight,
            confidence.context_anchor_weight,
            confidence.entropy_weight,
            confidence.high_entropy_partial_weight,
            confidence.moderate_entropy_threshold,
            confidence.moderate_entropy_weight,
        );
        println!(
            "      low_entropy_penalty_floor={} low_entropy_min_match_length={} low_entropy_penalty_multiplier={} keyword_nearby_weight={} sensitive_file_weight={} companion_weight={} very_high_entropy_margin={}",
            confidence.low_entropy_penalty_floor,
            confidence.low_entropy_min_match_length,
            confidence.low_entropy_penalty_multiplier,
            confidence.keyword_nearby_weight,
            confidence.sensitive_file_weight,
            confidence.companion_weight,
            confidence.very_high_entropy_margin,
        );
        println!(
            "      named_anchor_floor={} low_promise_confidence={}",
            confidence
                .named_anchor_floor
                .map_or_else(|| "none".into(), |value| value.to_string()),
            confidence
                .low_promise_confidence
                .map_or_else(|| "none".into(), |value| value.to_string()),
        );
    }
    macro_rules! optional_policy {
        ($name:literal, $value:expr, $unit:literal) => {
            if let Some(value) = $value {
                println!("    {}: {}{}", $name, value, $unit);
            }
        };
    }
    optional_policy!("min_confidence", d.min_confidence, "");
    optional_policy!("entropy_high", d.entropy_high, " bits/byte");
    optional_policy!("entropy_low", d.entropy_low, " bits/byte");
    optional_policy!("entropy_very_high", d.entropy_very_high, " bits/byte");
    if let Some(metadata) = &d.entropy_fallback {
        println!(
            "    entropy_fallback: class={} id={} name={:?} service={}",
            metadata.class.as_str(),
            metadata.id,
            metadata.name,
            metadata.service
        );
    }
    if let Some(confidence) = d.entropy_fallback_confidence {
        println!(
            "    entropy_fallback_confidence: low_entropy_max={} high_entropy={} very_high_entropy={} keyword_lift={} max_confidence={}",
            confidence.low_entropy_max,
            confidence.high_entropy,
            confidence.very_high_entropy,
            confidence.keyword_lift,
            confidence.max_confidence,
        );
    }
    if let Some(confidence) = d.generic_assignment_confidence {
        println!(
            "    generic_assignment_confidence: ordinary_base={} test_base={} documentation_base={} comment_base={} scanned_comment_base={}",
            confidence.ordinary_base,
            confidence.test_base,
            confidence.documentation_base,
            confidence.comment_base,
            confidence.scanned_comment_base,
        );
        println!(
            "      entropy_reference={} entropy_gain_per_bit={} entropy_lift_max={} length_reference={} length_gain_per_byte={} length_lift_max={} max_confidence={}",
            confidence.entropy_reference,
            confidence.entropy_gain_per_bit,
            confidence.entropy_lift_max,
            confidence.length_reference,
            confidence.length_gain_per_byte,
            confidence.length_lift_max,
            confidence.max_confidence,
        );
    }
    if !d.entropy_roles.is_empty() {
        println!(
            "    entropy_roles: {}",
            d.entropy_roles
                .iter()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for shape in &d.entropy_shapes {
        let charset = match shape.charset {
            keyhog_core::ShapeCharset::LowerAlnum => "lower-alnum",
            keyhog_core::ShapeCharset::Hex => "hex",
            keyhog_core::ShapeCharset::Base64Standard => "base64-standard",
            keyhog_core::ShapeCharset::Base64Url => "base64-url",
        };
        let mut line = format!(
            "    entropy_shape: charset={charset} entropy_floor={} special_min_length={}",
            shape.entropy_floor, shape.special_min_length
        );
        if let Some(grouping) = shape.grouping {
            line.push_str(&format!(
                " grouping={}x{}sep{:?}",
                grouping.group_count, grouping.group_length, grouping.separator
            ));
        }
        for (flag, on) in [
            ("require_mixed_case", shape.require_mixed_case),
            ("require_digit", shape.require_digit),
            ("require_non_hex_alpha", shape.require_non_hex_alpha),
            ("require_group_alpha_digit", shape.require_group_alpha_digit),
        ] {
            if on {
                line.push(' ');
                line.push_str(flag);
            }
        }
        if shape.min_symbols > 0 {
            line.push_str(&format!(" min_symbols={}", shape.min_symbols));
        }
        println!("{line}");
    }
    optional_policy!(
        "sensitive_path_entropy_very_high",
        d.sensitive_path_entropy_very_high,
        " bits/byte"
    );
    if let Some(policy) = d.plausibility {
        println!("    {}plausibility:{}", style.bold, style.reset);
        println!(
            "    mixed_alnum_floor: {} bits/byte",
            policy.mixed_alnum_floor
        );
        println!(
            "    symbolic_entropy_floor: {} bits/byte",
            policy.symbolic_entropy_floor
        );
        println!(
            "    second_half_entropy_floor: {} bits/byte",
            policy.second_half_entropy_floor
        );
        if let Some(margin) = policy.keyword_free_operator_margin {
            println!(
                "    keyword_free_operator_margin: +{margin} bits/byte over the resolved Tier-A entropy threshold"
            );
        }
        println!(
            "    mixed_alnum_min_len: {} bytes",
            policy.mixed_alnum_min_len
        );
        println!(
            "    isolated_mixed_entropy_floor: {} bits/byte",
            policy.isolated_mixed_entropy_floor
        );
        println!(
            "    isolated_symbolic_min_len: {} bytes",
            policy.isolated_symbolic_min_len
        );
        println!(
            "    isolated_symbolic_min_symbols: {}",
            policy.isolated_symbolic_min_symbols
        );
        println!(
            "    isolated_symbolic_requires_non_underscore: {}",
            policy.isolated_symbolic_requires_non_underscore
        );
        println!(
            "    isolated_alpha_only_min_symbols: {}",
            policy.isolated_alpha_only_min_symbols
        );
        println!(
            "    isolated_alpha_only_min_alpha_ratio: {}",
            policy.isolated_alpha_only_min_alpha_ratio
        );
        println!("    min_alnum_ratio: {}", policy.min_alnum_ratio);
        println!(
            "    source_type_name_max_len: {} bytes",
            policy.source_type_name_max_len
        );
        println!(
            "    source_type_name_min_uppercase: {}",
            policy.source_type_name_min_uppercase
        );
        println!(
            "    url_path_high_entropy_min_len: {} bytes",
            policy.url_path_high_entropy_min_len
        );
        println!(
            "    isolated_colon_left_min_len: {} bytes",
            policy.isolated_colon_left_min_len
        );
        println!(
            "    isolated_colon_right_min_len: {} bytes",
            policy.isolated_colon_right_min_len
        );
        println!(
            "    leading_slash_base64_entropy_floor: {} bits/byte",
            policy.leading_slash_base64_entropy_floor
        );
        println!(
            "    reject_repeated_blocks: {}",
            policy.reject_repeated_blocks
        );
        println!(
            "    allow_alphabetic_credential: {}",
            policy.allow_alphabetic_credential
        );
        println!(
            "    reject_program_identifiers: {}",
            policy.reject_program_identifiers
        );
        println!(
            "    reject_source_symbol_identifiers: {}",
            policy.reject_source_symbol_identifiers
        );
        println!(
            "    reject_dash_segmented_alnum: {}",
            policy.reject_dash_segmented_alnum
        );
    }
    optional_policy!("entropy_policy_priority", d.entropy_policy_priority, "");
    optional_policy!(
        "bpe_max_bytes_per_token",
        d.bpe_max_bytes_per_token,
        " UTF-8 bytes/token"
    );
    optional_policy!("bpe_enabled", d.bpe_enabled, "");
    optional_policy!("keyword_free_min_len", d.keyword_free_min_len, " bytes");
    optional_policy!("min_len", d.min_len, " bytes");
    optional_policy!("max_len", d.max_len, " bytes");

    if !d.simdsieve_prefixes.is_empty() {
        println!(
            "    simdsieve_prefixes: {}",
            d.simdsieve_prefixes.join(", ")
        );
    }

    if !d.decoded_hex_key_material_lengths.is_empty() {
        let lengths = d
            .decoded_hex_key_material_lengths
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!("    decoded_hex_key_material_lengths: {lengths}");
    }
    for policy in &d.canonical_hex_key_material {
        let lengths = policy
            .lengths
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let suffixes = if policy.suffixes.is_empty() {
            String::new()
        } else {
            format!(" suffixes=[{}]", policy.suffixes.join(", "))
        };
        let excluded = if policy.excluded_keywords.is_empty() {
            String::new()
        } else {
            format!(
                " excluded_keywords=[{}]",
                policy.excluded_keywords.join(", ")
            )
        };
        if policy.keywords.is_empty() && policy.suffixes.is_empty() {
            println!("    canonical_hex_key_material: lengths=[{lengths}] anchor=matched-pattern");
        } else {
            println!(
                "    canonical_hex_key_material: lengths=[{lengths}] keywords=[{}]{suffixes}{excluded}",
                policy.keywords.join(", ")
            );
        }
    }

    for bucket in &d.entropy_floor {
        match bucket.max_len {
            Some(max_len) => println!(
                "    entropy_floor: {} bits/byte through {} bytes",
                bucket.floor, max_len
            ),
            None => println!("    entropy_floor: {} bits/byte (remainder)", bucket.floor),
        }
    }
    if !d.stopwords.is_empty() {
        println!("    stopwords: {}", d.stopwords.join(", "));
    }
    if !d.public_identifier_assignment_markers.is_empty() {
        println!(
            "    public_identifier_assignment_markers: {}",
            d.public_identifier_assignment_markers.join(", ")
        );
    }
    for path in &d.allowlist_paths {
        println!("    allowlist_path: {path}");
    }
    for value in &d.allowlist_values {
        println!("    allowlist_value: {value}");
    }
    for (name, enabled) in [
        ("structural_password_slot", d.structural_password_slot),
        ("weak_anchor", d.weak_anchor),
        ("private_key_block", d.private_key_block),
    ] {
        if enabled {
            println!("    {name}: true");
        }
    }
    for (index, pattern) in d.patterns.iter().enumerate() {
        if pattern.weak_anchor {
            println!("    pattern[{index}].weak_anchor: true");
        }
    }
    if let Some(shape) = &d.credential_shape {
        if let Some(length) = shape.exact_length {
            println!("    credential_shape.exact_length: {length} bytes");
        }
        if let Some(prefix) = &shape.prefix {
            println!("    credential_shape.prefix: {prefix}");
        }
        if let Some(length) = shape.body_min_length {
            println!("    credential_shape.body_min_length: {length} bytes");
        }
        if let Some(length) = shape.body_max_length {
            println!("    credential_shape.body_max_length: {length} bytes");
        }
    }
    println!(
        "    {}declared policy owner: [detector] in the loaded detector TOML{}",
        style.dim, style.reset
    );
    println!(
        "    {}unset optional fields: field defaults or scan policy resolve at scan time; use `config --effective` for scan-fallback/scan-override{}",
        style.dim, style.reset
    );
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
        s if contains_ignore_ascii_case(s, "openai") => {
            Some("https://platform.openai.com/api-keys")
        }
        s if contains_ignore_ascii_case(s, "anthropic") => {
            Some("https://console.anthropic.com/settings/keys")
        }
        s if contains_ignore_ascii_case(s, "stripe") => {
            Some("https://dashboard.stripe.com/apikeys")
        }
        s if contains_ignore_ascii_case(s, "twilio") => {
            Some("https://www.twilio.com/docs/iam/access-tokens#rotate-keys")
        }
        s if contains_ignore_ascii_case(s, "sendgrid") => {
            Some("https://docs.sendgrid.com/ui/account-and-settings/api-keys")
        }
        s if contains_ignore_ascii_case(s, "google") || contains_ignore_ascii_case(s, "gcp") => {
            Some(
                "https://cloud.google.com/iam/docs/creating-managing-service-account-keys#rotating",
            )
        }
        s if contains_ignore_ascii_case(s, "azure") => Some(
            "https://learn.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal#authentication-two-options",
        ),
        s if contains_ignore_ascii_case(s, "npm") => {
            Some("https://docs.npmjs.com/revoking-access-tokens")
        }
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
