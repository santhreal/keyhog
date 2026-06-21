use super::{shannon_entropy, HIGH_ENTROPY_THRESHOLD, MIXED_ALNUM_TOKEN_THRESHOLD};
use crate::engine::phase2_generic::shape_helpers::is_structured_dotted_token;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PlausibilityContext {
    pub(crate) is_credential_context: bool,
    pub(crate) allow_canonical_shapes: bool,
}

impl PlausibilityContext {
    pub(crate) const fn new(is_credential_context: bool, allow_canonical_shapes: bool) -> Self {
        Self {
            is_credential_context,
            allow_canonical_shapes,
        }
    }
}

enum PlausibilityMode {
    Lenient,
    Strict,
}

fn is_known_non_secret(value: &str, context: PlausibilityContext) -> bool {
    // UUID / k8s-resource-uid (8-4-4-12 hex). Dropped at extraction so a bare
    // `TOKEN_LIST=<uuid>` env identifier does not generate. CredData recall lane:
    // when the lift is engaged (model authoritative + strong credential anchor),
    // a whole-value UUID is the CredData `UUID` miss class (LaunchDarkly SDK key,
    // Heroku UUID key, PowerBI client secret) and MUST be extracted as a
    // candidate for the MoE to arbitrate, so the gate releases here. Off the lift
    // it is byte-identical.
    if !context.allow_canonical_shapes && value.len() == 36 {
        let bytes = value.as_bytes();
        if bytes[8] == b'-'
            && bytes[13] == b'-'
            && bytes[18] == b'-'
            && bytes[23] == b'-'
            && value
                .chars()
                .filter(|&ch| ch != '-')
                .all(|ch| ch.is_ascii_hexdigit())
        {
            return true;
        }
    }

    // Pure-hex canonical lengths are usually file/commit/image digests. A
    // credential keyword only earns the narrow key-material carve-out; it does
    // not make sha1/git-sha (40) or sha512 (128) secrets. Hex64 can be extracted
    // only when the model-authoritative lift is active; the scanner-side owner
    // then narrows it again to explicit crypto-key anchors.
    let hex_len = value.len();
    if [32, 40, 64, 128].contains(&hex_len) && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        if !context.is_credential_context {
            return true;
        }
        if hex_len == 40 || hex_len == 128 {
            return true;
        }
        if hex_len == 64 && !context.allow_canonical_shapes {
            return true;
        }
    }

    value.starts_with("data:image/")
}

fn passes_plausibility_checks(
    value: &str,
    mode: PlausibilityMode,
    placeholder_keywords: &[String],
    context: PlausibilityContext,
) -> bool {
    if matches_universal_rejection(value)
        || is_known_non_secret(value, context)
        || is_placeholder_ci(value.as_bytes(), placeholder_keywords)
        || has_low_alnum_ratio(value)
    {
        return false;
    }

    if matches!(mode, PlausibilityMode::Strict) && !passes_secret_strength_checks(value, context) {
        return false;
    }
    true
}

fn matches_universal_rejection(value: &str) -> bool {
    value.contains("://")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("${{")
        || value.starts_with("{{")
        || value.starts_with("${")
        || value.starts_with("(?")
        || value.starts_with('^')
        || value.starts_with("ssh-")
        || value.starts_with("ecdsa-")
        || (value.starts_with("eyJ") && value.matches('.').count() == 2)
        || value.starts_with("$ANSIBLE_VAULT")
        || value.starts_with("ENC[")
        || value.starts_with("-----BEGIN")
        || (value.starts_with("Ag") && value.len() > 40)
        || value.starts_with("age1")
        || value.starts_with("vault:")
        || value.starts_with("AQI")
        || value.starts_with("CiQ")
        || (value.len() > 2
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic()
            && (value.as_bytes()[2] == b'\\' || value.as_bytes()[2] == b'/'))
        || value.starts_with("```")
        || value.starts_with("---")
        || value.starts_with("===")
}

fn has_low_alnum_ratio(value: &str) -> bool {
    let alnum =
        value.chars().filter(|ch| ch.is_alphanumeric()).count() as f64 / value.len().max(1) as f64;
    alnum < 0.5
}

pub(crate) fn passes_secret_strength_checks(value: &str, context: PlausibilityContext) -> bool {
    if !passes_secret_shape_checks(value, context) {
        return false;
    }

    // Symbolic-charset / credential-anchored entropy relaxation.
    // The blanket `HIGH_ENTROPY_THRESHOLD` (4.5) floor over-rejects
    // real symbolic-password shapes whose Shannon entropy lands in
    // the 3.5-4.5 band - e.g. `1E1B3b4Ho$U4kYBi` (entropy ~3.95),
    // `Y6NPMwS*rWGUv!JQnSG6a#D14` (entropy ~4.1). When the value
    // arrives WITH a strong credential-keyword anchor AND carries
    // at least one symbolic (non-alphanumeric) character, the
    // anchor + symbol-set together are positive evidence that the
    // value is a credential, not a code identifier or English word.
    // Use a lower 3.5 floor in that case. Pure-alphanumeric values
    // keep the original 4.5 floor (those are harder to distinguish
    // from CamelCase/snake_case identifiers).
    let entropy = shannon_entropy(value.as_bytes());
    if entropy >= HIGH_ENTROPY_THRESHOLD {
        return true;
    }
    if context.is_credential_context {
        let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
        let has_digit = value.bytes().any(|b| b.is_ascii_digit());
        let has_symbol = value.bytes().any(|b| !b.is_ascii_alphanumeric());
        if has_symbol && entropy >= 3.5 {
            return true;
        }
        if !has_symbol
            && has_alpha
            && has_digit
            && value.len() >= 20
            && entropy >= MIXED_ALNUM_TOKEN_THRESHOLD
        {
            return true;
        }
    }
    false
}

pub(crate) fn is_isolated_bare_secret_plausible(
    value: &str,
    placeholder_keywords: &[String],
) -> bool {
    if is_isolated_leading_slash_base64_secret(value, placeholder_keywords) {
        return true;
    }
    if value.contains('.') {
        if value.len() >= 40
            && !is_placeholder_ci(value.as_bytes(), placeholder_keywords)
            && is_structured_dotted_token(value)
        {
            return true;
        }
        if value.starts_with("eyJ") {
            return false;
        }
        if crate::suppression::shape::looks_like_dotted_source_identifier(value) {
            return false;
        }
    }
    passes_plausibility_checks(
        value,
        PlausibilityMode::Lenient,
        placeholder_keywords,
        PlausibilityContext::default(),
    ) && passes_secret_shape_checks(value, PlausibilityContext::default())
}

fn is_isolated_leading_slash_base64_secret(value: &str, placeholder_keywords: &[String]) -> bool {
    let Some(body) = value.strip_prefix('/') else {
        return false;
    };
    if value.len() < 40
        || is_placeholder_ci(value.as_bytes(), placeholder_keywords)
        || has_low_alnum_ratio(value)
    {
        return false;
    }
    let padding = body.bytes().rev().take_while(|&b| b == b'=').count();
    if padding > 2 || body[..body.len() - padding].contains('=') {
        return false;
    }
    if body.contains('/') && !body.contains('+') && padding == 0 {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for b in body.bytes() {
        if b == b'=' {
            continue;
        }
        if !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/') {
            return false;
        }
        has_upper |= b.is_ascii_uppercase();
        has_lower |= b.is_ascii_lowercase();
        has_digit |= b.is_ascii_digit();
    }
    has_upper
        && has_lower
        && has_digit
        && shannon_entropy(value.as_bytes()) >= 4.8
        && passes_secret_shape_checks(value, PlausibilityContext::default())
}

fn passes_secret_shape_checks(value: &str, context: PlausibilityContext) -> bool {
    // Outside a credential-keyword anchor, any >10-char pure-hex value is a
    // checksum/digest, not a credential. Inside one (`apiKey: <hex>`), the
    // keyword is positive evidence the hex IS the credential - the entropy
    // path's strict mode would otherwise drop every md5/sha1/sha256-shaped
    // planted secret. Mirror v30 had 112 generic-high-entropy-string FNs
    // driven by exactly this gate firing in credential context.
    if !context.is_credential_context
        && value.chars().all(|ch| ch.is_ascii_hexdigit())
        && value.len() > 10
    {
        return false;
    }
    if value.len() > 4 {
        if let Some(first) = value.chars().next() {
            if value.chars().all(|ch| ch == first) {
                return false;
            }
        }
    }
    if value.len() > 16 && unique_char_count(value) < 8 {
        return false;
    }
    if value.len() > 16 && second_half_entropy(value) < 2.5 {
        return false;
    }
    // Defect #81: entropy-api-key was firing on Java/Go camelCase and
    // PascalCase identifiers like `BulkUpdateApiKeyResponse`,
    // `convertSearchHitToVersionedApiKeyDoc`, `targetVersionedDocs`
    // (149 FPs in one ApiKeyService.java alone). These pass every
    // other check - high entropy, mixed case, decent length, no
    // placeholder words - but they're clearly source-code symbols,
    // not credentials. Reject strings that look like programming-
    // language identifiers: only letters/underscore, no digits, and
    // a camelCase / PascalCase shape (at least one internal
    // uppercase boundary). Real secrets virtually always include
    // digits or special characters.
    if crate::suppression::shape::looks_like_program_identifier(value) {
        return false;
    }

    // Dash-segmented-alnum decoy shapes. License/product serials
    // (`A1B2C-D3E4F-G5H6I-J7K8L-M9N0P`), template placeholders
    // (`XXXXX-XXXXX-...`) and segmented identifiers
    // (`my-service-prod-key-name-here`) are dash-joined runs that can
    // reach the entropy floor without being credentials. Keep this
    // gate narrow: real service tokens often contain one or more
    // dashes inside otherwise random alnum bodies.
    if crate::suppression::shape::is_dash_segmented_alnum_decoy(value) {
        return false;
    }
    true
}

fn unique_char_count(value: &str) -> usize {
    let mut seen = std::collections::HashSet::new();
    for ch in value.chars() {
        seen.insert(ch);
    }
    seen.len()
}

fn second_half_entropy(value: &str) -> f64 {
    let mid = value.len() / 2;
    let half_start = crate::floor_char_boundary(value, mid);
    shannon_entropy(&value.as_bytes()[half_start..])
}

pub(crate) fn is_candidate_plausible(
    value: &str,
    placeholder_keywords: &[String],
    context: PlausibilityContext,
) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Lenient,
        placeholder_keywords,
        context,
    )
}

pub(crate) fn is_secret_plausible(
    value: &str,
    placeholder_keywords: &[String],
    context: PlausibilityContext,
) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Strict,
        placeholder_keywords,
        context,
    )
}

fn is_placeholder_ci(bytes: &[u8], placeholder_keywords: &[String]) -> bool {
    if placeholder_keywords.iter().any(|placeholder| {
        let placeholder_bytes = placeholder.as_bytes();
        bytes
            .windows(placeholder_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(placeholder_bytes))
    }) {
        return true;
    }

    let upper = String::from_utf8_lossy(bytes).to_uppercase();
    upper.contains("EXAMPLE")
        || upper.contains("YOUR_")
        || upper.contains("REPLACE_ME")
        || upper.contains("CHANGE_ME")
        || upper.contains("INSERT_HERE")
        || upper.contains("FAKE_")
        || upper.contains("DUMMY_")
        || upper.contains("MOCK_")
        || (upper.contains("SECRET_KEY") && upper.len() < 20)
        || (upper.starts_with("AKIA")
            && (upper.ends_with("EXAMPLE") || upper.contains("1234567890")))
        || bytes.contains(&b'<')
        || bytes.contains(&b'>')
        || matches!(
            bytes,
            b"null" | b"none" | b"undefined" | b"empty" | b"default" | b"secret" | b"password"
        )
}
