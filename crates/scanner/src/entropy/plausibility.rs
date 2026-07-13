use std::sync::LazyLock;

use super::{shannon_entropy, HIGH_ENTROPY_THRESHOLD, MIXED_ALNUM_TOKEN_THRESHOLD};

/// Tier-B "universal rejection" value prefixes, the single owner
/// (`rules/universal-rejection-prefixes.toml`; were inline `starts_with` terms in
/// [`matches_universal_rejection`]). A value beginning with any of these is a
/// structural non-secret or an encrypted/wrapped blob, never a plaintext secret.
/// Fails closed on an invalid/empty list.
static UNIVERSAL_REJECTION_PREFIXES: LazyLock<Vec<String>> = LazyLock::new(|| {
    #[derive(serde::Deserialize)]
    struct Prefixes {
        prefixes: Vec<String>,
    }
    let raw = include_str!("../../../../rules/universal-rejection-prefixes.toml");
    match toml::from_str::<Prefixes>(raw) {
        Ok(parsed) if !parsed.prefixes.is_empty() => parsed.prefixes,
        Ok(_) => panic!(
            "rules/universal-rejection-prefixes.toml is empty; it must list the \
             universal-rejection value prefixes."
        ),
        Err(error) => panic!(
            "rules/universal-rejection-prefixes.toml is invalid: {error}. \
             Fix the bundled Tier-B universal-rejection prefix list."
        ),
    }
});

/// Relaxed Shannon floor for a symbolic (non-alphanumeric-bearing) value that
/// ALSO carries a strong credential-keyword anchor. The blanket
/// [`HIGH_ENTROPY_THRESHOLD`] (4.5) over-rejects real symbolic-password shapes
/// whose entropy lands in the 3.5–4.5 band (e.g. `1E1B3b4Ho$U4kYBi` ≈ 3.95);
/// the anchor + symbol set together are the positive evidence that licenses this
/// lower floor. Single named owner for the value used in
/// [`passes_secret_strength_checks`]. Kept below [`HIGH_ENTROPY_THRESHOLD`].
pub(crate) const SYMBOLIC_CREDENTIAL_ENTROPY_FLOOR: f64 = 3.5;

/// Shannon floor for an isolated leading-`/` base64 value
/// (`is_isolated_leading_slash_base64_secret`). Deliberately the strictest floor
/// in this module: a bare `/`-prefixed base64 blob has no keyword anchor, so it
/// must clear a high entropy bar before it is treated as a secret. Sits above
/// [`HIGH_ENTROPY_THRESHOLD`].
pub(crate) const LEADING_SLASH_BASE64_ENTROPY_FLOOR: f64 = 4.8;

/// Minimum Shannon entropy the SECOND HALF of a >16-char value must carry for the
/// value to survive the shape gate. Catches values whose randomness is
/// front-loaded (a real prefix followed by a low-entropy tail). Single owner for
/// the floor in [`passes_secret_shape_checks`].
pub(crate) const SECOND_HALF_ENTROPY_FLOOR: f64 = 2.5;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PlausibilityContext {
    pub(crate) is_credential_context: bool,
    pub(crate) allow_canonical_shapes: bool,
    entropy_high: Option<f64>,
    mixed_alnum_floor: Option<f64>,
}

impl PlausibilityContext {
    pub(crate) const fn new(is_credential_context: bool, allow_canonical_shapes: bool) -> Self {
        Self {
            is_credential_context,
            allow_canonical_shapes,
            entropy_high: None,
            mixed_alnum_floor: None,
        }
    }

    pub(crate) fn with_detector(mut self, detector: Option<&keyhog_core::DetectorSpec>) -> Self {
        self.entropy_high = detector.and_then(|spec| spec.entropy_high);
        self.mixed_alnum_floor = detector.and_then(|spec| spec.mixed_alnum_floor);
        self
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
    if !context.allow_canonical_shapes
        && crate::suppression::shape::looks_like_entropy_uuid_shape(value)
    {
        return true;
    }

    // Pure-hex canonical lengths are usually file/commit/image digests. A
    // credential keyword only earns the narrow key-material carve-out; it does
    // not make sha1/git-sha (40) or sha512 (128) secrets. Hex64 can be extracted
    // only when the model-authoritative lift is active; the scanner-side owner
    // then narrows it again to explicit crypto-key anchors.
    let hex_len = value.len();
    if crate::suppression::shape::looks_like_entropy_canonical_hex_digest(value) {
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
        || is_placeholder_ci(value, placeholder_keywords)
        || has_low_alnum_ratio(value)
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
    if UNIVERSAL_REJECTION_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix.as_str()))
    {
        return true;
    }
    value.contains("://")
        || (crate::jwt::has_jwt_header_prefix(value) && crate::jwt::looks_like_jwt(value))
        || crate::credential_shapes::is_pem_block(value)
        || (value.starts_with("Ag") && value.len() > 40)
        || (value.len() > 2
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic()
            && (value.as_bytes()[2] == b'\\' || value.as_bytes()[2] == b'/'))
}

pub(crate) fn has_low_alnum_ratio(value: &str) -> bool {
    // Fewer than half the CHARACTERS are alphanumeric. Both numerator and
    // denominator are counted in characters: a multibyte alphanumeric char (an
    // accented letter, a CJK ideograph) is one alphanumeric unit, so dividing
    // the char count by the BYTE length, as this once did, understates the
    // ratio and would wrongly reject a real secret that contains non-ASCII
    // letters. ASCII values are unaffected (char count == byte count there).
    // The integer comparison `alnum * 2 < total` avoids a float division on this
    // hot plausibility gate; an empty value has no alphanumerics and stays low.
    // Single pass over the chars (was two: one for the total, one filtered for
    // the alnum count) (the two counters are derived from the same iteration).
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
    alnum * 2 < total
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
    // Per-detector entropy-gate resolution: the active generic detector's values
    // are copied into `PlausibilityContext` at extraction, so custom corpora and
    // operator-composed specs override the blanket high-entropy / mixed-alnum
    // floors without any embedded-registry read here.
    let entropy_high = context
        .entropy_high
        .map_or(HIGH_ENTROPY_THRESHOLD, |threshold| threshold);
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
        if has_symbol && entropy >= SYMBOLIC_CREDENTIAL_ENTROPY_FLOOR {
            return true;
        }
        let mixed_alnum_floor = context
            .mixed_alnum_floor
            .map_or(MIXED_ALNUM_TOKEN_THRESHOLD, |threshold| threshold);
        if !has_symbol
            && has_alpha
            && has_digit
            && value.len() >= 20
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
) -> bool {
    if is_isolated_leading_slash_base64_secret(value, placeholder_keywords) {
        return true;
    }
    if value.contains('.') {
        if value.len() >= 40
            && !is_placeholder_ci(value, placeholder_keywords)
            && crate::suppression::shape::is_structured_dotted_token(value)
        {
            return true;
        }
        if crate::jwt::has_jwt_header_prefix(value) {
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
        || is_placeholder_ci(value, placeholder_keywords)
        || has_low_alnum_ratio(value)
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
        && shannon_entropy(value.as_bytes()) >= LEADING_SLASH_BASE64_ENTROPY_FLOOR
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
    if value.len() > 16 && second_half_entropy(value) < SECOND_HALF_ENTROPY_FLOOR {
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
    if crate::suppression::shape::is_dash_segmented_alnum_decoy(value)
        && !super::isolated::lower_dash_app_password_floor_met(
            value,
            shannon_entropy(value.as_bytes()),
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
