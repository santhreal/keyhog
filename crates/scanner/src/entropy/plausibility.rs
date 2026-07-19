use std::sync::LazyLock;

use super::shannon_entropy;

/// Tier-B structural non-secret rules compiled once from the single data owner.
static UNIVERSAL_REJECTIONS: LazyLock<UniversalRejectionRules> = LazyLock::new(|| {
    UniversalRejectionRules::parse(include_str!(
        "../../../../rules/entropy-universal-rejections.toml"
    ))
    .unwrap_or_else(|error| {
        panic!(
            "rules/entropy-universal-rejections.toml is invalid: {error}. Fix the bundled \
             Tier-B universal-rejection policy."
        )
    })
});

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct UniversalRejectionRules {
    prefixes: Box<[String]>,
    prefix_min_lengths: Box<[PrefixMinLengthRule]>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixMinLengthRule {
    prefix: String,
    min_length_exclusive: usize,
}

impl UniversalRejectionRules {
    fn parse(raw: &str) -> Result<Self, String> {
        let parsed: Self = toml::from_str(raw).map_err(|error| error.to_string())?;
        if parsed.prefixes.is_empty() {
            return Err("prefixes must not be empty".into());
        }
        let mut seen = std::collections::HashSet::new();
        for prefix in &parsed.prefixes {
            if prefix.is_empty() {
                return Err("prefixes must not contain an empty value".into());
            }
            if !seen.insert(prefix.as_str()) {
                return Err(format!("duplicate prefix {prefix:?}"));
            }
        }
        for rule in &parsed.prefix_min_lengths {
            if rule.prefix.is_empty() {
                return Err("prefix_min_lengths must not contain an empty prefix".into());
            }
            if rule.min_length_exclusive <= rule.prefix.len() {
                return Err(format!(
                    "prefix_min_lengths entry {:?} must set min_length_exclusive above its prefix length",
                    rule.prefix
                ));
            }
            if seen.contains(rule.prefix.as_str()) {
                return Err(format!(
                    "prefix_min_lengths entry {:?} is unreachable because prefixes already rejects it",
                    rule.prefix
                ));
            }
            if !seen.insert(rule.prefix.as_str()) {
                return Err(format!(
                    "duplicate universal-rejection prefix {:?}",
                    rule.prefix
                ));
            }
        }
        Ok(parsed)
    }

    fn rejects(&self, value: &str) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| value.starts_with(prefix.as_str()))
            || self.prefix_min_lengths.iter().any(|rule| {
                value.len() > rule.min_length_exclusive && value.starts_with(&rule.prefix)
            })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PlausibilityContext {
    pub(crate) is_credential_context: bool,
    pub(crate) allow_canonical_hex_key: bool,
    entropy_high: f64,
    mixed_alnum_floor: f64,
    symbolic_entropy_floor: f64,
    second_half_entropy_floor: f64,
    second_half_min_len: usize,
    unique_chars_min_len: usize,
    min_unique_chars: usize,
    unanchored_hex_max_len: usize,
    identical_char_max_len: usize,
    structured_dotted_min_len: usize,
    reject_repeated_blocks: bool,
    allow_alphabetic_credential: bool,
    reject_program_identifiers: bool,
    reject_source_symbol_identifiers: bool,
    reject_dash_segmented_alnum: bool,
    mixed_alnum_min_len: usize,
    min_alnum_ratio: f64,
    leading_slash_base64_entropy_floor: f64,
    leading_slash_base64_min_len: usize,
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
}

impl PlausibilityContext {
    pub(crate) fn from_compiled(
        is_credential_context: bool,
        allow_canonical_hex_key: bool,
        policy: &crate::entropy::policy::CompiledEntropyPolicy,
    ) -> Self {
        Self {
            is_credential_context,
            allow_canonical_hex_key,
            entropy_high: policy.entropy_high,
            mixed_alnum_floor: policy.mixed_alnum_floor,
            symbolic_entropy_floor: policy.symbolic_entropy_floor,
            second_half_entropy_floor: policy.second_half_entropy_floor,
            second_half_min_len: policy.second_half_min_len,
            unique_chars_min_len: policy.unique_chars_min_len,
            min_unique_chars: policy.min_unique_chars,
            unanchored_hex_max_len: policy.unanchored_hex_max_len,
            identical_char_max_len: policy.identical_char_max_len,
            structured_dotted_min_len: policy.structured_dotted_min_len,
            reject_repeated_blocks: policy.reject_repeated_blocks,
            allow_alphabetic_credential: policy.allow_alphabetic_credential,
            reject_program_identifiers: policy.reject_program_identifiers,
            reject_source_symbol_identifiers: policy.reject_source_symbol_identifiers,
            reject_dash_segmented_alnum: policy.reject_dash_segmented_alnum,
            mixed_alnum_min_len: policy.mixed_alnum_min_len,
            min_alnum_ratio: policy.min_alnum_ratio,
            leading_slash_base64_entropy_floor: policy.leading_slash_base64_entropy_floor,
            leading_slash_base64_min_len: policy.leading_slash_base64_min_len,
            entropy_shape: policy.entropy_shape,
        }
    }
}

enum PlausibilityMode {
    Lenient,
    Strict,
}

fn is_known_non_secret(value: &str, context: PlausibilityContext) -> bool {
    // UUID / k8s-resource-uid (8-4-4-12 hex). A generic assignment keyword does
    // not turn an identifier into a credential. Providers that issue
    // UUID-bodied secrets own that syntax in their detector TOML.
    if crate::suppression::shape::looks_like_entropy_uuid_shape(value) {
        return true;
    }

    // Pure-hex canonical lengths are usually file/commit/image digests. Only
    // the owning detector's exact keyword-and-length policy can classify one as
    // key material; generic credential context is not sufficient evidence.
    if crate::suppression::shape::looks_like_entropy_canonical_hex_digest(value) {
        return !context.allow_canonical_hex_key;
    }

    false
}

fn passes_plausibility_checks(
    value: &str,
    mode: PlausibilityMode,
    placeholder_keywords: &[String],
    context: PlausibilityContext,
) -> bool {
    if matches_universal_rejection(value)
        || is_known_non_secret(value, context)
        || is_placeholder_ci(value, placeholder_keywords)
        || has_low_alnum_ratio(value, context.min_alnum_ratio)
    {
        return false;
    }

    if matches!(mode, PlausibilityMode::Strict) && !passes_secret_strength_checks(value, context) {
        return false;
    }
    true
}

pub(crate) fn matches_universal_rejection(value: &str) -> bool {
    // Prefix rejections live in the Tier-B list (order-independent: any match
    // rejects, exactly as the former `||` chain). Compound rejections that need
    // more than a prefix stay in code below.
    if UNIVERSAL_REJECTIONS.rejects(value) {
        return true;
    }
    value.contains("://")
        || (crate::jwt::has_jwt_header_prefix(value) && crate::jwt::looks_like_jwt(value))
        || crate::credential_shapes::is_pem_block(value)
        || (value.len() > 2
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic()
            && (value.as_bytes()[2] == b'\\' || value.as_bytes()[2] == b'/'))
}

pub(crate) fn has_low_alnum_ratio(value: &str, min_alnum_ratio: f64) -> bool {
    // Count both sides in characters so multibyte letters do not reduce the
    // detector-owned alphanumeric ratio.
    let mut total = 0usize;
    let mut alnum = 0usize;
    for ch in value.chars() {
        total += 1;
        if ch.is_alphanumeric() {
            alnum += 1;
        }
    }
    if total == 0 {
        return true;
    }
    (alnum as f64) < (total as f64) * min_alnum_ratio
}

pub(crate) fn passes_secret_strength_checks(value: &str, context: PlausibilityContext) -> bool {
    if !passes_secret_shape_checks(value, context) {
        return false;
    }
    if context.allow_canonical_hex_key {
        return true;
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
    // Per-detector entropy-gate resolution: the active generic detector's values
    // are copied into `PlausibilityContext` at extraction, so custom corpora and
    // operator-composed specs override the blanket high-entropy / mixed-alnum
    // floors without any embedded-registry read here.
    let entropy_high = context.entropy_high;
    if entropy >= entropy_high {
        return true;
    }
    if context.is_credential_context {
        // Single pass over the bytes (was three independent `.any()` scans), the
        // three character-class flags are folded from one iteration.
        let mut has_alpha = false;
        let mut has_digit = false;
        let mut has_symbol = false;
        for b in value.bytes() {
            has_alpha |= b.is_ascii_alphabetic();
            has_digit |= b.is_ascii_digit();
            has_symbol |= !b.is_ascii_alphanumeric();
        }
        let symbolic_entropy_floor = context.symbolic_entropy_floor;
        if has_symbol && entropy >= symbolic_entropy_floor {
            return true;
        }
        // An assignment anchor is the positive evidence for a human-chosen
        // alphabetic password/passphrase. It still passed the detector-owned
        // length, tail-randomness, placeholder, identifier, and BPE gates; do
        // not force it through the mixed-alphanumeric carve-out.
        if context.allow_alphabetic_credential && has_alpha && !has_digit && !has_symbol {
            return true;
        }
        let mixed_alnum_floor = context.mixed_alnum_floor;
        let mixed_alnum_min_len = context.mixed_alnum_min_len;
        if !has_symbol
            && has_alpha
            && has_digit
            && value.len() >= mixed_alnum_min_len
            && entropy >= mixed_alnum_floor
        {
            return true;
        }
    }
    false
}

pub(crate) fn is_isolated_bare_secret_plausible(
    value: &str,
    placeholder_keywords: &[String],
    plausibility_policy: &crate::entropy::policy::CompiledEntropyPolicy,
) -> bool {
    let context = PlausibilityContext::from_compiled(false, false, plausibility_policy);
    if value.starts_with('/') {
        return is_isolated_leading_slash_base64_secret(value, placeholder_keywords, context);
    }
    if value.contains('.') {
        if crate::suppression::shape::is_structured_dotted_token(value) {
            return value.len() >= context.structured_dotted_min_len
                && !is_placeholder_ci(value, placeholder_keywords);
        }
        if crate::jwt::has_jwt_header_prefix(value) {
            return false;
        }
        if crate::suppression::shape::looks_like_dotted_source_identifier(value) {
            return false;
        }
    }
    if super::isolated::isolated_special_shape_floor_met_with_policy(
        value,
        shannon_entropy(value.as_bytes()),
        context.entropy_shape.as_ref(),
        plausibility_policy,
    ) {
        return passes_plausibility_checks(
            value,
            PlausibilityMode::Lenient,
            placeholder_keywords,
            context,
        ) && passes_secret_shape_checks(value, context);
    }
    passes_plausibility_checks(
        value,
        PlausibilityMode::Lenient,
        placeholder_keywords,
        context,
    ) && passes_secret_shape_checks(value, context)
}

fn is_isolated_leading_slash_base64_secret(
    value: &str,
    placeholder_keywords: &[String],
    context: PlausibilityContext,
) -> bool {
    let Some(body) = value.strip_prefix('/') else {
        return false;
    };
    if value.len() < context.leading_slash_base64_min_len
        || is_placeholder_ci(value, placeholder_keywords)
        || has_low_alnum_ratio(value, context.min_alnum_ratio)
    {
        return false;
    }
    if crate::decode::contains_non_padding_equals(body) {
        return false;
    }
    // Every `=` is now confirmed valid trailing padding; its length (0 ⇒
    // unpadded) distinguishes url-safe-shaped bodies below. Recounting the
    // padding run rescans only the ≤2 trailing `=`, a rounding error.
    let padding = body.bytes().rev().take_while(|&b| b == b'=').count();
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
        && shannon_entropy(value.as_bytes()) >= context.leading_slash_base64_entropy_floor
        && passes_secret_shape_checks(value, context)
}

fn passes_secret_shape_checks(value: &str, context: PlausibilityContext) -> bool {
    if context.reject_repeated_blocks && crate::suppression::shape::has_repeated_block_mask(value) {
        return false;
    }
    // Outside a credential-keyword anchor, any >10-char pure-hex value is a
    // checksum/digest, not a credential. Inside one (`apiKey: <hex>`), the
    // keyword is positive evidence the hex IS the credential - the entropy
    // path's strict mode would otherwise drop every md5/sha1/sha256-shaped
    // planted secret. Mirror v30 had 112 generic-high-entropy-string FNs
    // driven by exactly this gate firing in credential context.
    if !context.is_credential_context
        && value.chars().all(|ch| ch.is_ascii_hexdigit())
        && value.len() > context.unanchored_hex_max_len
    {
        return false;
    }
    if value.len() > context.identical_char_max_len {
        if let Some(first) = value.chars().next() {
            if value.chars().all(|ch| ch == first) {
                return false;
            }
        }
    }
    if value.len() >= context.unique_chars_min_len
        && unique_char_count(value) < context.min_unique_chars
    {
        return false;
    }
    let second_half_entropy_floor = context.second_half_entropy_floor;
    if value.len() >= context.second_half_min_len
        && second_half_entropy(value) < second_half_entropy_floor
    {
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
    // An exact detector-owned canonical-hex rule is stronger evidence than
    // lexical source-symbol shape; otherwise the generic identifier guard
    // silently cancels the detector TOML declaration it was given.
    if context.reject_program_identifiers && !context.allow_canonical_hex_key {
        if crate::suppression::shape::looks_like_program_identifier(value) {
            return false;
        }
        // Digits deliberately exclude a value from the narrow lexical helper
        // above, but detector-owned identifier rejection must still recognize
        // pronounceable CamelCase symbols such as `ClientSecretConfigValue2`.
        // Keep underscore-bearing mixed tokens on their existing policy path;
        // their shape is also common for real generated credentials.
        if context.reject_source_symbol_identifiers
            && !value.contains('_')
            && value.bytes().any(|byte| byte.is_ascii_digit())
            && crate::suppression::shape::looks_like_source_symbol_identifier_with_randomness(
                value,
                &crate::suppression::token_randomness::TokenRandomness::for_candidate(value),
            )
        {
            return false;
        }
    }

    // Dash-segmented-alnum decoy shapes. License/product serials
    // (`A1B2C-D3E4F-G5H6I-J7K8L-M9N0P`), template placeholders
    // (`XXXXX-XXXXX-...`) and segmented identifiers
    // (`my-service-prod-key-name-here`) are dash-joined runs that can
    // reach the entropy floor without being credentials. Keep this
    // gate narrow: real service tokens often contain one or more
    // dashes inside otherwise random alnum bodies.
    if context.reject_dash_segmented_alnum
        && crate::suppression::shape::is_dash_segmented_alnum_decoy(value)
        && !super::isolated::lower_dash_app_password_floor_met_with_policy(
            value,
            shannon_entropy(value.as_bytes()),
            context.entropy_shape.as_ref(),
        )
    {
        return false;
    }
    true
}

pub(crate) fn unique_char_count(value: &str) -> usize {
    // ASCII fast path: distinct bytes == distinct chars (every ASCII byte is a
    // single-byte char), so reuse the one canonical distinct-byte primitive
    // (`entropy::unique_byte_count`) instead of re-inlining its 256-slot
    // presence-table loop a fourth time. mod.rs documents that primitive as the
    // single owner of this loop; this branch was an undocumented copy.
    if value.is_ascii() {
        return super::unique_byte_count(value.as_bytes());
    }

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

fn is_placeholder_ci(value: &str, placeholder_keywords: &[String]) -> bool {
    let bytes = value.as_bytes();
    if placeholder_keywords
        .iter()
        .any(|placeholder| crate::ascii_ci::ci_find_nonempty(bytes, placeholder.as_bytes()))
    {
        return true;
    }

    crate::placeholder_words::contains_placeholder_word_with_entropy_hint(
        value,
        Some(shannon_entropy(bytes)),
    ) || crate::placeholder_words::bytes_contain_entropy_placeholder_marker(bytes)
}

// Tests for this module live in `crates/scanner/tests/unit/entropy.rs`
// (`generic_detectors_declare_valid_per_detector_entropy_floors`). The
// `entropy_plausibility_no_inline_tests` folder contract forbids inline
// `#[cfg(test)]` here; external tests exercise the active-spec policy through the
// scanner testing facade without widening this module's production API.
