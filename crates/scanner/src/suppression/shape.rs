//! Value-shape predicates (`looks_like_*`, `contains_uuid_v4_substring`).
//! These look only at the credential string itself; no path or context
//! is involved. Sibling modules (`api`, `decision`) chain them together
//! into actual suppression decisions.

mod path;
mod public;
mod source;

pub(crate) use path::{looks_like_scheme_prefixed_uri, looks_like_url_or_path_segment};
pub(crate) use public::{
    looks_like_html_event_handler_fragment, looks_like_percent_encoded_markup,
    looks_like_public_artifact_reference, looks_like_public_evidence_identifier,
    looks_like_public_metadata_identifier, looks_like_public_reference_selector,
    looks_like_public_version_identifier, looks_like_shell_template_value,
};
#[cfg(feature = "entropy")]
pub(crate) use source::looks_like_source_type_identifier;
pub(crate) use source::{looks_like_source_code_expression, looks_like_source_symbol_identifier};

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
    // Split on either separator. Real credentials use one consistent separator
    // (or none); programmer identifiers can mix `_` and `-`.
    let words: Vec<&str> = value.split(['_', '-']).collect();
    // No empty words (rejects `--foo`, `foo--bar`, `_foo`, `foo_`)
    if words.iter().any(|w| w.is_empty()) {
        return false;
    }
    // Every word must contain at least one ASCII letter - pure-digit
    // segments like `12345` are not identifier words.
    if !words
        .iter()
        .all(|w| w.bytes().any(|b| b.is_ascii_alphabetic()))
    {
        return false;
    }
    // Max word length ≤ 10. Real credentials concentrate randomness in one
    // long suffix (e.g. `sk_live_<24-char-base58>`); programmer identifiers
    // are short dictionary fragments throughout.
    let max_word_len = words.iter().map(|w| w.len()).max().unwrap_or(0); // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
    if max_word_len > 10 {
        return false;
    }
    true
}

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
    const PROSE_CONNECTORS: &[&str] = &[
        "and", "or", "to", "for", "from", "with", "without", "non", "only", "into",
    ];
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
            .any(|connector| part.eq_ignore_ascii_case(connector))
        {
            has_connector = true;
        }
    }
    if part_count < 4 || lower_parts < 3 || !has_connector {
        return false;
    }
    !super::token_randomness::is_random_token(value)
}

/// True for opaque high-entropy punctuation payloads where punctuation is part
/// of the credential body, not syntax around an identifier. This is shared by
/// the generic and entropy emit paths so the base64 and symbolic-secret
/// carve-outs do not drift.
pub(crate) fn looks_like_high_entropy_punctuation_payload(value: &str, entropy: f64) -> bool {
    if entropy < 4.8 || value.len() < 40 {
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
    const REGEX_SIGIL_SUFFIXES: &[&str] = &[
        ")/g", ")/g,", // JS object literal: `key: /pattern/g, ...`
        ")/gi", ")/gi,", ")/i", ")/i,", ")/m", ")/m,", ")\\b", "})\\b", "})\\\\b", "]+", "]*",
        "]?", "]+/", "]+\\b", "*/g", "+/g", "+/i", ")*", ")+", ")?", ")?$", ")$",
    ];
    REGEX_SIGIL_SUFFIXES.iter().any(|sig| value.ends_with(sig))
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
    let mut i = 0;
    while i + 36 <= bytes.len() {
        let slice = &bytes[i..i + 36];
        if slice[8] == b'-' && slice[13] == b'-' && slice[18] == b'-' && slice[23] == b'-' {
            let all_hex_or_dash = slice.iter().enumerate().all(|(j, &c)| match j {
                8 | 13 | 18 | 23 => c == b'-',
                _ => c.is_ascii_hexdigit(),
            });
            if all_hex_or_dash {
                return true;
            }
        }
        i += 1;
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
    // Trailing `:` after a value of pure-alpha + colon shape.
    if last == b':' {
        // Allow only if everything before the trailing `:` is an identifier
        // label (`Password:`, `Username:`, `ptx_source_key:`). A real
        // credential containing `:` mid-string lands elsewhere (scheme reject
        // above).
        let prefix = &bytes[..bytes.len() - 1];
        if !prefix.is_empty()
            && prefix.iter().any(|b| b.is_ascii_alphabetic())
            && prefix
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
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
    [
        b"token".as_slice(),
        b"secret".as_slice(),
        b"key".as_slice(),
        b"password".as_slice(),
        b"passwd".as_slice(),
        b"auth".as_slice(),
        b"credential".as_slice(),
    ]
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
