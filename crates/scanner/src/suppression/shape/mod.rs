//! Value-shape predicates (`looks_like_*`, `contains_uuid_v4_substring`).
//! These look only at the credential string itself; no path or context
//! is involved. Sibling modules (`api`, `decision`) chain them together
//! into actual suppression decisions.

mod canonical;
mod path;
// `prose` is consumed by `engine::phase2_entropy::gates`, which is compiled
// unconditionally (engine/mod.rs declares `mod phase2_entropy` with no cfg), so
// the predicate must be available in every feature combo. Gating it on
// `feature = "entropy"` broke `--no-default-features` builds with E0425
// (Feature matrix CI). It is a tiny pure string predicate, so always compiling
// it costs nothing.
mod prose;
pub(crate) mod public;
pub(crate) mod source;

pub(crate) use canonical::{
    generic_base64_candidate_is_ambiguous, has_n_or_more_consecutive_identical,
    has_repeated_block_mask, has_three_or_more_consecutive_identical, is_canonical_service_hex_key,
    is_dash_segmented_alnum_decoy, is_structured_dotted_token, is_uuid_v4_shape,
    looks_like_aws_iam_arn, looks_like_bare_hex_digest, looks_like_base64_integrity_body,
    looks_like_bracketed_template_placeholder, looks_like_dashed_serial_key,
    looks_like_entropy_canonical_hex_digest, looks_like_entropy_canonical_non_secret_shape,
    looks_like_entropy_random_base64_blob_decoy, looks_like_entropy_uuid_shape,
    looks_like_generic_random_base64_blob_decoy, looks_like_prefixed_hash_digest,
    looks_like_prefixed_masked_sequence, looks_like_random_byte_base64_blob,
    looks_like_standard_base64_blob, looks_like_trimmed_aws_iam_arn,
    looks_like_truncated_uuid_v4_suffix, HASH_ALGO_COLON_LABELS, HASH_ALGO_INTEGRITY_LABELS,
    HIGH_ENTROPY_BASE64_CUTOFF, RFC7519_EXAMPLE_JWT_PREFIX,
};
pub(crate) use path::{
    looks_like_filename_reference, looks_like_scheme_prefixed_uri, looks_like_url_or_path_segment,
};
pub(crate) use prose::looks_like_english_prose;
pub(crate) use public::{
    looks_like_html_event_handler_fragment, looks_like_percent_encoded_markup,
    looks_like_public_evidence_identifier, looks_like_public_reference_selector,
    looks_like_public_version_identifier_with_randomness,
};
#[cfg(feature = "entropy")]
pub(crate) use source::looks_like_source_type_identifier_with_randomness;
pub(crate) use source::{
    looks_like_dotted_source_identifier, looks_like_kebab_config_identifier,
    looks_like_program_identifier, looks_like_source_code_expression_with_randomness,
    looks_like_source_symbol_identifier_with_randomness,
};

/// True if `credential` is an identifier / natural-language shape rather
/// than a real credential. Covers three FP families seen in dogfood:
///   * snake_case-no-digit (≥ 2 underscores) - C/Rust function names like
///     `sk_SRP_user_pwd_new_null` (openssl) captured by `_pwd = ` regexes.
///   * CamelCase-no-digit alphabetic - Java/JS method references like
///     `getParameter` captured by `password = getParameter(...)` shapes
///     (webgoat WebgoatContext.java, line 93).
///   * Pure-alphabetic words ≥ 8 chars - natural-language strings like
///     German "Benutzername" or English "yourpasswordisbasic" captured
///     by `(?i)password[=:]<word>` shapes in i18n .properties files.
///
/// Real credentials almost always have a digit, hyphen, slash, or other
/// non-letter byte - this filter never trips on those.
pub(crate) fn looks_like_pure_identifier(credential: &str) -> bool {
    let bytes = credential.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut underscore_count = 0usize;
    let mut hyphen_count = 0usize;
    let mut has_digit = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut alpha_count = 0usize;
    for &b in bytes {
        if b == b'_' {
            underscore_count += 1;
        } else if b == b'-' {
            hyphen_count += 1;
        } else if b.is_ascii_digit() {
            has_digit = true;
        } else if b.is_ascii_uppercase() {
            has_upper = true;
            alpha_count += 1;
        } else if b.is_ascii_lowercase() {
            has_lower = true;
            alpha_count += 1;
        } else {
            // Any byte outside `[A-Za-z0-9_-]` means this is NOT a
            // pure identifier: real credentials reach here through `!`,
            // `=`, `/`, `+`, `:`, etc. in the value alphabet.
            return false;
        }
    }
    if has_digit {
        return false;
    }
    // snake_case_no_digit: ≥ 2 underscores. Covers `sk_SRP_user_pwd_new_null`
    // (openssl), `auth_decoders`, `gss_token`-style C/Rust identifiers.
    if underscore_count >= 2 {
        return true;
    }
    // CamelCase / pure-alphabetic / single-separator identifier: bytes
    // are all `[A-Za-z_-]` (no digit), length 8..=40, ≤ 1 underscore,
    // ≤ 1 hyphen, ≥ 8 alphabetic characters. Covers:
    //   * `getParameter`, `Benutzername` - pure alphabetic CamelCase
    //     or natural-language word
    //   * `curlx_strdup`, `auth_decoders` - single-underscore C names
    //   * `user-password`, `aria-secret`, `Get-Function` - kebab-case
    //     / PowerShell verb-noun identifiers
    // Bounded above 40 so a real long random alpha-only credential
    // (rare) isn't suppressed. Real credentials have at least one
    // digit / symbol - none of the FP shapes do.
    if (underscore_count + hyphen_count) <= 1
        && (8..=40).contains(&alpha_count)
        && (has_upper || has_lower)
    {
        return true;
    }
    false
}

/// True for the narrow process-path false-positive shape: no ASCII digit and at
/// least two lower-to-upper camel transitions, e.g. `getUserName`.
pub(crate) fn looks_like_camel_case_no_digit(credential: &str) -> bool {
    if credential.bytes().any(|b| b.is_ascii_digit()) {
        return false;
    }
    credential
        .as_bytes()
        .windows(2)
        .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
        .take(2)
        .count()
        >= 2
}

/// Word-separated identifier with embedded digits. Catches the FP class
/// that `looks_like_pure_identifier` misses because digits short-circuit
/// its `!has_digit` guard:
///   * `s3_secret_access_key` (alist const.go) - snake_case constant
///   * `d2i_PKCS7_bio`, `sqlite3_int`, `sqlite3_malloc64` (openssl, sqlite)
///   * `curlx_memdup0` (curl ntlm_sspi.c)
///   * `X-Shopify-Access-Token`, `Shopify-Storefront-Private-Token` (shopify-api-js headers)
///
/// Distinguishes from real credentials like `sk_live_4eC39HqLyjWDarjtT1zdp7dc`
/// (Stripe) by requiring every separator-delimited word to be ≤ 10 chars.
/// Real credentials have ≥1 long-random segment (24+ chars of base58/base64)
/// AFTER the prefix; programmer identifiers are sequences of short
/// dictionary-word fragments.
pub(crate) fn looks_like_word_separated_identifier(value: &str) -> bool {
    if value.len() < 8 || value.len() > 50 {
        return false;
    }
    // Pure ASCII alphanumeric + `_` + `-`
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return false;
    }
    // Must have at least one separator
    let sep_count = value.bytes().filter(|&b| b == b'_' || b == b'-').count();
    if sep_count == 0 {
        return false;
    }
    // Single pass over `_`/`-` separated words:
    //   * reject empty words (`--foo`, `foo--bar`, `_foo`, `foo_`)
    //   * every word must contain ≥1 ASCII letter (pure-digit `12345` is not a word)
    //   * max word length ≤ 10 (real credentials concentrate randomness in one
    //     long suffix; programmer identifiers are short dictionary fragments)
    for w in value.split(['_', '-']) {
        if w.is_empty() || w.len() > 10 || !w.bytes().any(|b| b.is_ascii_alphabetic()) {
            return false;
        }
    }
    true
}

#[derive(serde::Deserialize)]
struct ProseConnectors {
    connectors: Vec<String>,
}

fn parse_prose_connectors(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<ProseConnectors>(raw)
        .map(|parsed| parsed.connectors)
        .map_err(|error| error.to_string())
}

static PROSE_CONNECTORS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_prose_connectors(include_str!("../../../../../rules/prose-connectors.toml")) {
        Ok(connectors) => connectors,
        Err(error) => panic!(
            "rules/prose-connectors.toml is invalid: {error}. \
             Fix the bundled Tier-B prose connectors list."
        ),
    }
});

#[derive(serde::Deserialize)]
struct RegexSigilSuffixes {
    suffixes: Vec<String>,
}

fn parse_regex_sigil_suffixes(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<RegexSigilSuffixes>(raw)
        .map(|parsed| parsed.suffixes)
        .map_err(|error| error.to_string())
}

static REGEX_SIGIL_SUFFIXES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_regex_sigil_suffixes(include_str!(
        "../../../../../rules/regex-sigil-suffixes.toml"
    )) {
        Ok(suffixes) => suffixes,
        Err(error) => panic!(
            "rules/regex-sigil-suffixes.toml is invalid: {error}. \
             Fix the bundled regex sigil suffixes list."
        ),
    }
});

/// True when a hyphen-separated value is policy/config prose rather than an
/// opaque token. This targets long train-case status strings such as
/// `ExecStart-points-to-public-vyre-binary-or-verified-install-path` that carry
/// credential keywords in the surrounding key but are made of natural-language
/// words.
pub(crate) fn looks_like_train_case_prose_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 24 || bytes.len() > 160 || !bytes.contains(&b'-') {
        return false;
    }
    if !bytes.iter().all(|&b| b.is_ascii_alphabetic() || b == b'-') {
        return false;
    }
    let mut part_count = 0usize;
    let mut lower_parts = 0usize;
    let mut has_connector = false;
    for part in value.split('-') {
        if part.is_empty() || part.len() > 18 {
            return false;
        }
        part_count += 1;
        if part.bytes().any(|b| b.is_ascii_lowercase()) {
            lower_parts += 1;
        }
        if PROSE_CONNECTORS
            .iter()
            .any(|connector| part.eq_ignore_ascii_case(connector.as_str()))
        {
            has_connector = true;
        }
    }
    if part_count < 4 || lower_parts < 3 || !has_connector {
        return false;
    }
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicShapeScope {
    Full,
    WeakAnchor,
}

/// One owner for public/non-credential value shapes. The scope is explicit
/// because weak-anchor named detectors still carry service evidence: they need
/// public template/version/markup/prose suppression, but broad artifact/domain
/// suppressors would erase real service URLs and tenant hostnames.
#[cfg(test)]
pub(crate) fn public_noncredential_shape(
    value: &str,
    scope: PublicShapeScope,
) -> Option<&'static str> {
    let randomness = crate::suppression::token_randomness::TokenRandomness::for_candidate(value);
    public_noncredential_shape_with_randomness(value, scope, &randomness)
}

pub(crate) fn public_noncredential_shape_with_randomness(
    value: &str,
    scope: PublicShapeScope,
    randomness: &crate::suppression::token_randomness::TokenRandomness<'_>,
) -> Option<&'static str> {
    if looks_like_train_case_prose_identifier(value) {
        return Some("train_case_prose_identifier");
    }
    if public::looks_like_public_version_identifier_with_randomness(value, randomness) {
        return Some("public_version_identifier");
    }
    if scope == PublicShapeScope::WeakAnchor {
        if public::looks_like_shell_template_value_with_randomness(value, randomness) {
            return Some("shell_template_value");
        }
        if looks_like_percent_encoded_markup(value) {
            return Some("percent_encoded_markup");
        }
        if looks_like_html_event_handler_fragment(value) {
            return Some("html_event_handler_fragment");
        }
        return None;
    }
    if looks_like_public_reference_selector(value) {
        return Some("public_reference_selector");
    }
    if public::looks_like_public_metadata_identifier_with_randomness(value, randomness) {
        return Some("public_metadata_identifier");
    }
    if looks_like_public_evidence_identifier(value) {
        return Some("public_evidence_identifier");
    }
    if public::looks_like_public_artifact_reference_with_randomness(value, randomness) {
        return Some("public_artifact_reference");
    }
    if public::looks_like_shell_template_value_with_randomness(value, randomness) {
        return Some("shell_template_value");
    }
    if looks_like_percent_encoded_markup(value) {
        return Some("percent_encoded_markup");
    }
    if looks_like_html_event_handler_fragment(value) {
        return Some("html_event_handler_fragment");
    }
    None
}

/// True for opaque high-entropy punctuation payloads where punctuation is part
/// of the credential body, not syntax around an identifier. This is shared by
/// the generic and entropy emit paths so the base64 and symbolic-secret
/// carve-outs do not drift.
pub(crate) fn looks_like_high_entropy_punctuation_payload(value: &str, entropy: f64) -> bool {
    if entropy < HIGH_ENTROPY_BASE64_CUTOFF || value.len() < 40 {
        return false;
    }
    if value.contains('+') || value.contains('/') {
        return true;
    }
    looks_like_bang_led_opaque_secret(value)
}

fn looks_like_bang_led_opaque_secret(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !bytes.starts_with(b"!") || bytes.starts_with(b"!!") {
        return false;
    }

    let mut has_alpha = false;
    let mut has_digit = false;
    let mut alnum = 0usize;
    let mut punctuation = 0usize;
    for &byte in bytes {
        if !byte.is_ascii_graphic() {
            return false;
        }
        if byte.is_ascii_alphabetic() {
            has_alpha = true;
            alnum += 1;
        } else if byte.is_ascii_digit() {
            has_digit = true;
            alnum += 1;
        } else {
            punctuation += 1;
        }
    }

    has_alpha && has_digit && punctuation >= 4 && alnum * 2 >= bytes.len()
}

/// True if `value` ends in a regex-literal sigil (`)/g`, `]+`, `})\\b`,
/// `)?$`, etc.). These are JavaScript / Python / Go / Rust regex pattern
/// definitions captured by a credential detector running on a *secret
/// scanner's own source code* (e.g. claude-code's
/// `teamMemorySync/secretScanner.ts` had `hot-aws_session_key` /
/// `hot-slack_bot_token` findings on its own regex definitions).
///
/// Real credentials don't end in regex sigils.
pub(crate) fn looks_like_regex_literal_tail(value: &str) -> bool {
    REGEX_SIGIL_SUFFIXES
        .iter()
        .any(|sig| value.ends_with(sig.as_str()))
}

/// True if `value` looks like an email address. Captures FP shapes where
/// the entropy detector or generic regex grabs an email from a `USER=`
/// or `FROM=` config line (gogs TestInit.golden.ini:89
/// `USER=noreply@gogs.localhost`, then PASSWORD=…@host pattern fires).
/// Real credentials are never email-shaped.
pub(crate) fn looks_like_email_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 5 || bytes.len() > 64 {
        return false;
    }
    let at = match bytes.iter().position(|&b| b == b'@') {
        Some(idx) => idx,
        None => return false,
    };
    // Exactly one `@`
    if bytes.iter().skip(at + 1).any(|&b| b == b'@') {
        return false;
    }
    let local = &bytes[..at];
    let domain = &bytes[at + 1..];
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // Local part: alphanumeric + `_`, `-`, `.`, `+`
    if !local
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'+')
    {
        return false;
    }
    // Domain part: must contain at least one `.`
    if !domain.contains(&b'.') {
        return false;
    }
    // Domain alphabet: alphanumeric + `_`, `-`, `.`
    domain
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// True if `value` contains a UUID v4 / RFC-4122 substring anywhere
/// inside it. Catches `TOKEN_LIST=636765a9-1f92-4b40-ab0b-85ebd1e2c23d`
/// (bat-go docker-compose.reputation.yml:42) - the entropy detector
/// captures the whole env-var assignment but the actual high-entropy
/// content is the UUID identifier, which is not a credential. Real
/// credentials with UUIDs embedded as part of their structure
/// (extremely rare) would also benefit from suppression here - UUIDs
/// are public identifiers, not secrets.
pub(crate) fn contains_uuid_v4_substring(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 36 {
        return false;
    }
    // A UUID's first dash sits at relative offset 8. Anchor each '-' as that
    // dash (memchr-skip to dash positions) rather than testing every offset:
    // O(dashes·36) instead of O(n·36) on long captured values.
    for dash in memchr::memchr_iter(b'-', bytes) {
        if dash < 8 || dash + 28 > bytes.len() {
            continue;
        }
        let slice = &bytes[dash - 8..dash + 28];
        if slice[13] == b'-'
            && slice[18] == b'-'
            && slice[23] == b'-'
            && slice.iter().enumerate().all(|(j, &c)| match j {
                8 | 13 | 18 | 23 => c == b'-',
                _ => c.is_ascii_hexdigit(),
            })
        {
            return true;
        }
    }
    false
}

/// True if `value` is a pure *syntactic* punctuation marker that is NEVER
/// the body of a real credential, regardless of which detector matched:
///   * leading `--` (CLI flag) - `--api-secret`, `--api-key`
///   * leading `&` (C/Go pointer reference) - `&gss_recv_token`, `&password`
///   * leading `@` (SQL/Ruby variable) - `@v_password`, `@api_key`
///   * leading `$` (GraphQL/shell var, `${SECRET}` template placeholder)
///   * trailing `:` after pure-alpha - `Password:`, `Username:`
///
/// These are grammar tokens, not secret bytes, so the filter is safe to
/// apply universally (Tier A). Shapes that CAN legitimately appear as a
/// credential body (`/`-led base64, `!`-led / `!`-trailed secrets) live in
/// [`looks_like_credential_colliding_punctuation`] and must be Tier-B gated.
pub(crate) fn looks_like_syntactic_punctuation_marker(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    //   `--` - CLI flag (`--api-secret`). A SINGLE leading `-` is allowed
    //          for tokens like `xoxb-…`, and `-----` (5+ dashes) is a PEM
    //          block marker which is a legitimate private-key TP - only
    //          reject `--X` where `X` is NOT another dash.
    let starts_with_double_dash = bytes.starts_with(b"--") && bytes.len() >= 3 && bytes[2] != b'-';
    if starts_with_double_dash {
        return true;
    }
    // Leading `&`/`@`/`$`/`*` is a grammar marker ONLY when what follows is a bare
    // identifier: `&password` (C pointer), `@api_key` (attribute), `$API_KEY`
    // (shell/GraphQL var), `*input_key` (Rust/C dereference). When the remainder carries credential symbols
    // (`%`, `!`, `+`, `-`, `=`, …) it is a real secret body that merely starts
    // with the sigil - e.g. tower's `@gAdtFo%B!tcnSl+A-Rt5x…`. Requiring a
    // pure-identifier tail keeps the FP suppression while letting anchored
    // secrets through.
    if matches!(bytes[0], b'&' | b'@' | b'$' | b'*') {
        let rest = &bytes[1..];
        let pure_ident_tail =
            !rest.is_empty() && rest.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_');
        if pure_ident_tail {
            return true;
        }
    }
    let last = bytes[bytes.len() - 1];
    // Trailing `:` after an alphabetic/underscore label.
    if last == b':' {
        // Allow only if everything before the trailing `:` is an identifier
        // label (`Password:`, `Username:`, `ptx_source_key:`). A real
        // credential containing `:` mid-string lands elsewhere (scheme reject
        // above).
        let prefix = &bytes[..bytes.len() - 1];
        if !prefix.is_empty()
            && prefix.iter().any(|b| b.is_ascii_alphabetic())
            && prefix.iter().all(|&b| b.is_ascii_alphabetic() || b == b'_')
        {
            return true;
        }
    }
    false
}

/// True if `value` carries punctuation that *looks* like decoration but can
/// equally be a legitimate credential body:
/// * leading `/` - Unix path (`/etc/passwd:…`) OR base64 body (`/ZM9…`, `/7j3…`,
///   LINE channel tokens + paloalto keys start `/`).
/// * leading `!` - JS truthy coercion (`!!token`) OR a session secret that
///   legitimately starts `!` (keystonejs `!t1c!_…`).
///
/// A trailing `!` is decoration only for source-identifier bodies such as
/// `privateAccessToken!` (TypeScript non-null assertion). Password bodies like
/// `SnowFlakePass123!` are common and must not be suppressed.
///
/// For an *unanchored* generic/entropy match these are FP signals, so this is
/// applied Tier-B only. A named, service-anchored detector (e.g. the regex
/// already matched `snowflake.password=<value>`) has proven the bytes are the
/// credential, so this filter must NOT fire there - doing so silently killed
/// snowflake / sourcetree / paloalto / line / keystonejs / tower positives.
pub(crate) fn looks_like_credential_colliding_punctuation(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    bytes[0] == b'!' || bytes[0] == b'/' || looks_like_ts_non_null_identifier(bytes)
}

/// Canonical credential-keyword needles (lowercased, for `ci_find`). ONE owner
/// for the shape gates that scan a candidate for an embedded credential word;
/// `looks_like_ts_non_null_identifier` here and `looks_like_dotted_source_identifier`
/// in `source.rs` previously each pasted their own near-identical copy (DEDUP).
pub(super) const CREDENTIAL_KEYWORD_NEEDLES: &[&[u8]] = &[
    b"token",
    b"secret",
    b"key",
    b"password",
    b"passwd",
    b"auth",
    b"credential",
];

fn looks_like_ts_non_null_identifier(bytes: &[u8]) -> bool {
    if !bytes.ends_with(b"!") || bytes.len() < 9 {
        return false;
    }
    let body = &bytes[..bytes.len() - 1];
    if !body.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_') {
        return false;
    }
    if body.iter().any(|b| b.is_ascii_digit()) {
        return false;
    }
    let has_camel_transition = body
        .windows(2)
        .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());
    if !has_camel_transition {
        return false;
    }
    CREDENTIAL_KEYWORD_NEEDLES
        .iter()
        .any(|needle| crate::ascii_ci::ci_find(body, needle))
}

/// Combined Tier-A + body-collision punctuation filter. Retained for the
/// generic/entropy fallback callers ([`phase2_generic`], [`phase2_entropy`]),
/// which are unanchored by construction and so want the full (stricter) set.
/// Named-detector suppression must use the split functions so the body-
/// collision half stays Tier-B gated.
pub(crate) fn looks_like_punctuation_decorated_identifier(value: &str) -> bool {
    looks_like_syntactic_punctuation_marker(value)
        || looks_like_credential_colliding_punctuation(value)
}

#[cfg(test)]
#[path = "../../../tests/unit/suppression_shape_mod.rs"]
mod tests;
