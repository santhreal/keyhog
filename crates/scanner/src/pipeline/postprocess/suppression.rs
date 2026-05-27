use super::shape_gates::RFC7519_EXAMPLE_JWT_PREFIX;
use super::shape_gates::*;
use crate::context;

fn upper_contains_token(upper: &str, token: &str) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        // `idx` is a BYTE index from `match_indices`; use byte-index slicing
        // for both sides. The previous `upper.chars().nth(idx - 1)` mixed
        // byte- and char-indexing — for any credential with non-ASCII bytes
        // before `idx`, `nth(byte_idx - 1)` returned the wrong character
        // (sometimes a character INSIDE the match), miscomputing the
        // word-boundary check and silently letting placeholder tokens slip
        // past the suppression. ASCII inputs happened to work because
        // byte_idx == char_idx for pure ASCII.
        let before = upper[..idx].chars().next_back();
        let after = upper[idx + token.len()..].chars().next();
        before.is_none_or(|c| !c.is_alphanumeric()) && after.is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Check if a credential should be suppressed (e.g., if it is a known example token).
pub fn should_suppress_known_example_credential(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
) -> bool {
    should_suppress_known_example_credential_with_source(credential, path, context, None)
}

/// Variant of [`should_suppress_known_example_credential`] that also takes the
/// chunk's `source_type`. When the credential arrived through an
/// **adversarial-evasion decoder** (reverse, Caesar/ROT-N), the EXAMPLE-token
/// suppression is skipped — legitimate test fixtures don't typically reverse
/// or rotate their EXAMPLE markers; only attackers building evasions do, so
/// the marker becomes evidence FOR a real leak rather than against it.
///
/// Other decoders (base64, hex, URL) decode legitimate transport encodings
/// where EXAMPLE-suppression remains appropriate, so we don't blanket-bypass
/// the rule on every decoder origin.
pub fn should_suppress_known_example_credential_with_source(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
) -> bool {
    should_suppress_inner(credential, path, context, source_type, false, false)
}

/// Variant for named-detector findings that have already matched a
/// service-specific anchor (e.g. `ALGOLIA_ADMIN_KEY=<32hex>`). When set,
/// the shape-based gates (pure-hash-digest, UUID, b64-blob, dashed-serial,
/// hex-uniformity) are bypassed because the regex anchor IS the positive
/// evidence — a 32-hex value after `ALGOLIA_ADMIN_KEY=` is an Algolia key,
/// NOT an MD5. Use ONLY from detector paths whose regex requires a
/// service-keyword anchor in the alternation list.
pub fn should_suppress_named_detector_finding(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    detector_id: &str,
) -> bool {
    // Shape filters split into two tiers based on whether the shape
    // can legitimately appear as the body of a real service-anchored
    // credential.
    //
    // **Tier A — applies to ALL detectors.** Only `punctuation_decorated`
    // stays universal — `--api-secret`, `&password`, `Password:` are
    // grammar / syntax markers, never the body of a real credential
    // regardless of which detector matched.
    //
    // **Tier B — generic-* / entropy-* only.** These shapes CAN appear
    // as legitimate credential bodies when paired with a service-
    // specific regex anchor. The anchor is positive evidence that the
    // value is a credential, so the shape filter would be wrong to drop
    // it. (Examples the contract corpus enforces:
    //   * `powerbi-credentials` — body IS a UUID
    //   * `mongodb-atlas-credentials` — body IS `mongodb://...` URI
    //   * `cockroachdb-api-key` — body has underscore-separated words
    //   * `avalanche-api-credentials` — body IS an RPC URL
    //   * `aws-secret-access-key` — body has `/+=` URL-segment chars
    // These all DROPPED when the Tier-B filters fired on named
    // detectors. The generic-* / entropy-* fallbacks have no anchor —
    // there the shape filter IS the only positive-evidence gate, so
    // it must stay.)
    //
    // The previous flow applied Tier B universally and dropped 400+
    // contract evasions. See task #41 + the 2026-05-27 audit.
    let apply_tier_b = is_generic_or_entropy_detector(detector_id);

    if apply_tier_b && looks_like_pure_identifier(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "pure_identifier_no_digit",
        );
        return true;
    }
    if apply_tier_b && looks_like_word_separated_identifier(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "word_separated_identifier",
        );
        return true;
    }
    if apply_tier_b && looks_like_scheme_prefixed_uri(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "scheme_prefixed_uri",
        );
        return true;
    }
    if looks_like_punctuation_decorated_identifier(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "punctuation_decorated_identifier",
        );
        return true;
    }
    if apply_tier_b && looks_like_url_or_path_segment(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "url_or_path_segment",
        );
        return true;
    }
    // Captured value contains a UUID v4 / RFC-4122 substring anywhere.
    // Tier B because many real credentials are UUIDs (powerbi
    // client_id, opsgenie heartbeat, docusign integration key,
    // launchdarkly sdk-key, etc.) — only suppress in generic/entropy
    // paths where there's no service anchor.
    if apply_tier_b && contains_uuid_v4_substring(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "contains_uuid_v4",
        );
        return true;
    }
    // Email-address shape: `noreply@gogs.localhost` (gogs golden test
    // ini), `bob.norman@mail.example.com` (shopify test response).
    // Email addresses are public identifiers, not credentials.
    if looks_like_email_address(credential) {
        crate::telemetry::record_example_suppression("pipeline", path, credential, "email_address");
        return true;
    }
    // Vendored 3rd-party minified bundle path: applies to ALL detectors,
    // not just generic-*. A "secret-like" sequence in a minified
    // codemirror/pdfjs/jquery/etc. bundle is never a real leak.
    if looks_like_vendored_minified_path(path) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "vendored_minified_path",
        );
        return true;
    }
    // Native-binary string extraction (`filesystem:binary-strings`,
    // `filesystem/archive-binary`): the file is an ELF / Mach-O / PE /
    // wasm / archived binary whose printable strings were extracted as
    // a fallback. Short-prefix detectors (openai `sk-`, stabilityai
    // `sk-`, helicone `sk-`/`pk-`/`eu-`, clickup `pk_`, AKIA / ASIA,
    // K00M, AIza, dn_, …) generate noise on random compiled-code byte
    // sequences that happen to start with the prefix. A real credential
    // embedded in a native binary is best caught via the optional
    // `binary` feature (Ghidra-based extraction with context), not via
    // brute-force strings. Skip every named-detector finding here so
    // we don't ship FPs from compiled apps' rodata.
    if source_type.is_some_and(|s| s.contains("binary-strings") || s.contains("archive-binary")) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "native_binary_strings",
        );
        return true;
    }
    // The file at `path` is itself a secret scanner — every detector
    // routinely matches its own regex definitions inside the source.
    if looks_like_secret_scanner_source(path) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "secret_scanner_source",
        );
        return true;
    }
    // Files explicitly marked as base64 (`.b64`, `.base64`, or basename
    // starting with `base64_` / containing `base64_string`) hold base64-
    // encoded blobs — usually images or binaries that the operator
    // wants the base64 decoder to handle. Raw text-mode hits inside the
    // base64 stream (AIza, sk-, ASIA, etc.) are alphabet coincidences,
    // not credentials. The base64-decoder pass produces a separate
    // `filesystem/base64` chunk with the decoded content; that chunk
    // hits `has_binary_magic` if it's image/binary, otherwise it's
    // scanned normally.
    if path.is_some_and(|p| {
        let lower = p.to_ascii_lowercase();
        if lower.ends_with(".b64") || lower.ends_with(".base64") {
            return true;
        }
        // Both `/` and `\` so Windows paths (`C:\foo\base64_x.txt`)
        // collapse to the same basename. Same rationale as the
        // fallback_entropy path-gate sibling.
        let basename = lower.rsplit(['/', '\\']).next().unwrap_or(&lower);
        basename.starts_with("base64_")
            || basename.contains("base64_string")
            || basename == "base64.txt"
    }) && source_type.is_some_and(|s| s == "filesystem")
    {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "raw_base64_file",
        );
        return true;
    }
    // Regex-literal tail: applies to ALL detectors. A capture ending
    // in `)/g`, `)/g,`, `]+`, `})\\b`, etc. is a JS/Go/Python regex
    // pattern definition (often in another secret-scanner's own
    // source code), not a credential. claude-code's Feedback.tsx
    // has 1 `hot-aws_key` finding on its own AWS regex definition
    // `/AKIA[A-Z0-9]{16,17}/g,`.
    if looks_like_regex_literal_tail(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "regex_literal_tail",
        );
        return true;
    }
    // Generic detectors (generic-secret, generic-private-key, entropy-*)
    // never use this bypass — their anchor is keyword-class, not
    // service-specific, and shape gates are load-bearing for them.
    let bypass_shape_gates = !detector_id.starts_with("generic-")
        && !detector_id.starts_with("entropy-")
        && detector_id != "private-key";
    should_suppress_inner(
        credential,
        path,
        context,
        source_type,
        false,
        bypass_shape_gates,
    )
}

/// True if `credential` is an identifier / natural-language shape rather
/// than a real credential. Covers three FP families seen in dogfood:
///   * snake_case-no-digit (≥ 2 underscores) — C/Rust function names like
///     `sk_SRP_user_pwd_new_null` (openssl) captured by `_pwd = ` regexes.
///   * CamelCase-no-digit alphabetic — Java/JS method references like
///     `getParameter` captured by `password = getParameter(...)` shapes
///     (webgoat WebgoatContext.java, line 93).
///   * Pure-alphabetic words ≥ 8 chars — natural-language strings like
///     German "Benutzername" or English "yourpasswordisbasic" captured
///     by `(?i)password[=:]<word>` shapes in i18n .properties files.
///
/// Real credentials almost always have a digit, hyphen, slash, or other
/// non-letter byte — this filter never trips on those.
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
    //   * `getParameter`, `Benutzername` — pure alphabetic CamelCase
    //     or natural-language word
    //   * `curlx_strdup`, `auth_decoders` — single-underscore C names
    //   * `user-password`, `aria-secret`, `Get-Function` — kebab-case
    //     / PowerShell verb-noun identifiers
    // Bounded above 40 so a real long random alpha-only credential
    // (rare) isn't suppressed. Real credentials have at least one
    // digit / symbol — none of the FP shapes do.
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
///   * `s3_secret_access_key` (alist const.go) — snake_case constant
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
    // Every word must contain at least one ASCII letter — pure-digit
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
    let max_word_len = words.iter().map(|w| w.len()).max().unwrap_or(0);
    if max_word_len > 10 {
        return false;
    }
    true
}

/// True if `value` looks like a URI / URN / scheme-prefixed string.
/// Captures these FP shapes seen in dogfood:
///   * `urn:shopify:params:oauth:token-type:online-access-token`
///     (shopify-api-js token-exchange.ts)
///   * `secret-token:wjOtYCQypY5ky1AM_co1lTXNJdOe3Q_waNnnfdyl5u3eOKHCKL-galY9Wklf`
///     (bat-go merchant README log-line example)
///   * `something://...`
///
/// Pattern: starts with a lowercase-alpha scheme of length 3-15,
/// followed by `:` and ≥2 more `:` chars (URN) OR `//` (URL).
/// Real credentials never have this leading-scheme shape.
pub(crate) fn looks_like_scheme_prefixed_uri(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 6 {
        return false;
    }
    // Find first `:`
    let Some(colon_idx) = bytes.iter().position(|&b| b == b':') else {
        return false;
    };
    if !(3..=15).contains(&colon_idx) {
        return false;
    }
    // Scheme part [0..colon_idx) must be alpha (allow `-` for `secret-token`)
    let scheme = &bytes[..colon_idx];
    if !scheme.iter().all(|&b| b.is_ascii_alphabetic() || b == b'-') {
        return false;
    }
    // Must have at least one letter in the scheme
    if !scheme.iter().any(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    let after = &bytes[colon_idx + 1..];
    // URL form: starts with `//`
    if after.starts_with(b"//") {
        return true;
    }
    // URN form: at least one more `:` in the rest of the value
    if after.contains(&b':') {
        return true;
    }
    // Compound-scheme single-colon form: scheme contains `-`
    // (`secret-token`, `auth-token`, `bearer-token`). Real credentials don't
    // have a colon `<8` chars in from the start; URI-like prefixes do.
    if scheme.contains(&b'-') {
        return true;
    }
    // Common content-addressable hash schemes — `sha256:<hex>`, `sha1:<hex>`,
    // `md5:<hex>`. These are integrity digests, not credentials; the generic
    // regex captures them when an `image: sha256:<hex>` config line appears.
    let scheme_str = std::str::from_utf8(scheme).unwrap_or("");
    if matches!(
        scheme_str,
        "sha256" | "sha512" | "sha1" | "md5" | "blake3" | "blake2"
    ) {
        return true;
    }
    // Type-annotation / documentation `<short-alpha>:<short-alpha>` shape:
    // both sides are pure-alpha ≤ 10 chars, total length ≤ 20. Catches
    // `bool:false`, `int:42`, `string:USD`, `kind:Secret` documentation
    // examples (llama-cpp arg.cpp:2468 has
    // `--override-kv tokenizer.ggml.add_bos_token=bool:false,...` whose
    // `token=bool:false` substring captures as `bool:false`). Real
    // credentials never have this shape.
    if bytes.len() <= 20
        && after.iter().all(|&b| b.is_ascii_alphabetic())
        && !after.is_empty()
        && after.len() <= 10
    {
        return true;
    }
    false
}

/// True if `value` looks like a `/`-separated path or URL fragment.
/// Catches Go template paths `user/settings/password` (gogs setting.go),
/// `user/auth/forgot_passwd` (gogs auth.go), URL fragments like
/// `/api/v1/access_token` (alist 123_open/api.go). Real credentials don't
/// have multiple `/` segments — they're random opaque tokens.
///
/// Pattern: value contains `/` AND every `/`-delimited non-empty segment
/// looks like a path component (alphanumeric + `_-.`, contains a letter).
/// Requires ≥ 2 segments to avoid suppressing single-`/` opaque tokens.
pub(crate) fn looks_like_url_or_path_segment(value: &str) -> bool {
    if !value.contains('/') {
        return false;
    }
    let segments: Vec<&str> = value.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().all(|s| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            && s.bytes().any(|b| b.is_ascii_alphabetic())
    })
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
/// (bat-go docker-compose.reputation.yml:42) — the entropy detector
/// captures the whole env-var assignment but the actual high-entropy
/// content is the UUID identifier, which is not a credential. Real
/// credentials with UUIDs embedded as part of their structure
/// (extremely rare) would also benefit from suppression here — UUIDs
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

/// True if the file at `path` is itself a secret-scanner source file.
/// Such files contain detector regex patterns (`/AKIA[A-Z0-9]{16}/g`,
/// `'(?:ASIA|AKIA)[A-Z2-7]{16}'`, `dn_[a-zA-Z0-9_-]{20,}`) that the engine
/// will match against itself — every named detector + hot pattern routinely
/// emits a finding on its own regex DEFINITION. Most of these are caught
/// by `looks_like_regex_literal_tail`, but the unicode-escape / caesar
/// decoders mangle the trailing sigil out of recognition. Skipping the
/// whole file (any source whose path or basename contains a secret-scanner
/// keyword) is safer than playing whack-a-mole with decoder variants.
pub(crate) fn looks_like_secret_scanner_source(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    let lower = p.to_ascii_lowercase();
    lower.contains("secretscanner")
        || lower.contains("secret-scanner")
        || lower.contains("secret_scanner")
        || lower.contains("credentialscanner")
        || lower.contains("credential-scanner")
        || lower.contains("credential_scanner")
        || lower.contains("trufflehog")
        || lower.contains("gitleaks")
        || lower.contains("detect-secrets")
        || lower.contains("detect_secrets")
}

/// True if the detector that fired has no service-specific anchor —
/// only the generic `generic-password`, `generic-secret`,
/// `entropy-*` fallbacks. Used by `should_suppress_named_detector_finding`
/// to decide whether the Tier-B shape filters apply: anchored
/// detectors (everything else) have positive evidence in their regex
/// that the shape filter would otherwise destroy.
fn is_generic_or_entropy_detector(detector_id: &str) -> bool {
    detector_id.starts_with("generic-") || detector_id.starts_with("entropy-")
}

/// Path-segment substring test that tolerates either `/seg/` (POSIX)
/// or `\seg\` (Windows). Used by the vendored-path gate below so that
/// Windows checkouts (`C:\src\app\node_modules\…`) get the same
/// suppression treatment as POSIX checkouts. No allocations — walks
/// `path` once with `find()`.
fn contains_path_segment(path: &str, segment: &str) -> bool {
    let mut needle_unix = String::with_capacity(segment.len() + 2);
    needle_unix.push('/');
    needle_unix.push_str(segment);
    needle_unix.push('/');
    let mut needle_win = String::with_capacity(segment.len() + 2);
    needle_win.push('\\');
    needle_win.push_str(segment);
    needle_win.push('\\');
    path.contains(needle_unix.as_str()) || path.contains(needle_win.as_str())
}

/// Two-segment variant: matches `/a/b/` (POSIX) or `\a\b\` (Windows).
/// Used for the `public/plugins`, `wp-content/plugins`, etc. matches
/// where both segments must be present in sequence.
fn contains_path_segment_two(path: &str, a: &str, b: &str) -> bool {
    let mut needle_unix = String::with_capacity(a.len() + b.len() + 3);
    needle_unix.push('/');
    needle_unix.push_str(a);
    needle_unix.push('/');
    needle_unix.push_str(b);
    needle_unix.push('/');
    let mut needle_win = String::with_capacity(a.len() + b.len() + 3);
    needle_win.push('\\');
    needle_win.push_str(a);
    needle_win.push('\\');
    needle_win.push_str(b);
    needle_win.push('\\');
    path.contains(needle_unix.as_str()) || path.contains(needle_win.as_str())
}

/// True if `path` looks like a vendored 3rd-party JS/CSS/wasm bundle.
/// These are minified copies of libraries the project does NOT author —
/// any "secret-like" match inside them is a coincidence in the minified
/// byte stream, not a leaked credential.
///
/// Catches:
///   * `gogs/public/plugins/codemirror-5.17.0/mode/dockerfile/dockerfile.js`
///     (`variable-2`/`variable-3` token classes captured as generic-secret)
///   * `gogs/public/plugins/pdfjs-5.2.133/web/wasm/openjpeg_nowasm_fallback.js`
///     (minified WASM glue with `ASIA` random byte sequence triggering
///     `hot-aws_session_key`)
///   * `node_modules/`, `vendor/`, `wp-includes/`, `wp-content/plugins/`
///     (npm / Composer / WordPress vendored trees)
pub(crate) fn looks_like_vendored_minified_path(path: Option<&str>) -> bool {
    let Some(p) = path else {
        return false;
    };
    // Substring-match both POSIX-style (`/dir/`) and Windows-style
    // (`\dir\`) vendored-tree fragments. Without this, every match
    // inside `C:\src\app\node_modules\…` on a Windows checkout would
    // skip the vendored-suppression and surface as a finding —
    // emitting thousands of FPs the moment a Windows user scans a
    // typical Node project. `contains_segment` is path-shape-only;
    // no allocation per call (just byte scans).
    if contains_path_segment(p, "node_modules")
        || contains_path_segment_two(p, "public", "plugins")
        || contains_path_segment_two(p, "public", "static")
        || contains_path_segment_two(p, "public", "vendor")
        || contains_path_segment_two(p, "static", "vendor")
        || contains_path_segment(p, "wp-includes")
        || contains_path_segment_two(p, "wp-content", "plugins")
        || contains_path_segment_two(p, "wp-content", "themes")
        || contains_path_segment(p, "bower_components")
        || contains_path_segment(p, "jspm_packages")
        || contains_path_segment(p, "site-packages")
        || p.contains("/dist/vendor")
        || p.contains("\\dist\\vendor")
        || contains_path_segment_two(p, "dist", "assets")
        || contains_path_segment_two(p, "vendor", "assets")
        || p.ends_with(".min.js")
        || p.ends_with(".bundle.js")
        || p.ends_with(".min.css")
    {
        return true;
    }
    // Rails legacy asset path: `app/assets/javascripts/<name>.js`. First-
    // party Rails JS today lives in `app/javascript/` (Webpacker era) or
    // `app/assets/builds/` (esbuild/Vite era). The `app/assets/javascripts/`
    // directory predominantly holds vendored libraries (bootstrap-*,
    // jquery-*, alertify, datatables, fullcalendar, jsapi). Match the
    // most common vendored filename prefixes.
    if p.contains("/app/assets/javascripts/")
        || p.contains("\\app\\assets\\javascripts\\")
        || p.contains("/vendor/javascripts/")
        || p.contains("\\vendor\\javascripts\\")
    {
        // `rsplit(['/', '\\'])` so Windows-style paths still collapse
        // to the bare filename — the prefix list below would otherwise
        // never match on Windows checkouts.
        let basename = p
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(p)
            .to_ascii_lowercase();
        const VENDORED_JS_PREFIXES: &[&str] = &[
            "bootstrap",
            "jquery",
            "react.",
            "react-",
            "vue.",
            "vue-",
            "angular",
            "ember",
            "backbone",
            "lodash",
            "underscore",
            "moment",
            "alertify",
            "fullcalendar",
            "datatables",
            "highcharts",
            "chart.",
            "chart-",
            "select2",
            "tinymce",
            "ckeditor",
            "codemirror",
            "html5",
            "modernizr",
            "respond",
        ];
        if VENDORED_JS_PREFIXES
            .iter()
            .any(|prefix| basename.starts_with(prefix))
        {
            return true;
        }
    }
    false
}

/// True if `value` is a non-credential punctuation/prefix shape:
///   * leading `--` (CLI flag) — `--api-secret`, `--api-key`
///   * leading `&` (C/Go pointer reference) — `&gss_recv_token`, `&password`
///   * leading `@` (SQL/Ruby variable) — `@v_password`, `@api_key`
///   * leading `!` (JS/TS truthy coercion) — `!!apiKeyOrOAuthToken`
///   * trailing `:` after pure-alpha — `Password:`, `Username:`
///   * trailing `!` after pure-alpha (TS non-null assertion) — `privateAccessToken!`
///
/// Real credentials don't start or end with these tokens.
pub(crate) fn looks_like_punctuation_decorated_identifier(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    // Leading sigils that real credentials never start with.
    //   `--` — CLI flag (`--api-secret`). A SINGLE leading `-` is allowed
    //          for tokens like `xoxb-…`, and `-----` (5+ dashes) is a PEM
    //          block marker which is a legitimate private-key TP — only
    //          reject `--X` where `X` is NOT another dash.
    //   `&` — C/Go pointer reference (`&password`, `&gss_recv_token`)
    //   `@` — SQL/Ruby/Rust attribute (`@v_password`, `@api_key`, `@deprecated`)
    //   `!` — JS truthy coercion (`!!apiKeyOrOAuthToken`)
    //   `/` — Unix absolute path (`/etc/passwd:/etc/passwd:ro` docker mount).
    //   `$` — GraphQL variable reference (`apiKey: $api_key`), shell var
    //          expansion (`$API_KEY`), template placeholder (`${SECRET}`).
    let starts_with_double_dash = bytes.starts_with(b"--") && bytes.len() >= 3 && bytes[2] != b'-';
    if starts_with_double_dash
        || bytes[0] == b'&'
        || bytes[0] == b'@'
        || bytes[0] == b'!'
        || bytes[0] == b'/'
        || bytes[0] == b'$'
    {
        return true;
    }
    let last = bytes[bytes.len() - 1];
    // Trailing `:` after a value of pure-alpha + colon shape.
    if last == b':' {
        // Allow only if everything before the trailing `:` is alpha (UI label
        // shape `Password:`, `Username:`). A real credential containing `:`
        // mid-string lands elsewhere (scheme reject above).
        let prefix = &bytes[..bytes.len() - 1];
        if !prefix.is_empty() && prefix.iter().all(|&b| b.is_ascii_alphabetic()) {
            return true;
        }
    }
    // Trailing `!` (TypeScript non-null assertion on a variable name).
    if last == b'!' && bytes.len() >= 4 {
        let prefix = &bytes[..bytes.len() - 1];
        // Variable-name shape: all `[A-Za-z0-9_]`, has letter
        let pure_ident = prefix
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_');
        let has_letter = prefix.iter().any(|b| b.is_ascii_alphabetic());
        if pure_ident && has_letter {
            return true;
        }
    }
    false
}

fn should_suppress_inner(
    credential: &str,
    path: Option<&str>,
    context: context::CodeContext,
    source_type: Option<&str>,
    skip_b64_decode_recheck: bool,
    bypass_shape_gates: bool,
) -> bool {
    let from_evasion_decoder =
        source_type.is_some_and(|s| s.contains("/reverse") || s.contains("/caesar"));
    let upper = credential.to_uppercase();

    // ── 1. Universal placeholder keywords (case-insensitive) ──
    const PLACEHOLDER_WORDS: &[&str] = &["DUMMY", "PLACEHOLDER", "FAKE", "MOCK", "SAMPLE"];
    for word in PLACEHOLDER_WORDS {
        if upper_contains_token(&upper, word) {
            return true;
        }
    }
    // EXAMPLE is special: only suppress if it is in the credential value itself,
    // not in a URL domain (example.com is a reserved domain per RFC 2606).
    // Skip entirely when the credential arrived through an evasion decoder
    // (see fn-doc): an attacker reversing/ROTating an EXAMPLE-suffixed AWS
    // test key is exactly the kind of leak the engine should report.
    if !from_evasion_decoder
        && (upper_contains_token(&upper, "EXAMPLE") || upper.ends_with("EXAMPLE"))
        && !credential.contains("example.com")
        && !credential.contains("example.org")
    {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "contains_EXAMPLE_token",
        );
        return true;
    }

    // ── 2. Common instructional fragments ──
    const INSTRUCTIONAL_FRAGMENTS: &[&str] = &["YOUR_", "YOUR-", "INSERT", "CHANGE", "REPLACE"];
    for frag in INSTRUCTIONAL_FRAGMENTS {
        if upper.contains(frag) {
            // Require a word boundary before the fragment to avoid substring
            // false-positions in real secrets (e.g. "CHANGE" inside base64).
            let mut positions = upper.match_indices(frag);
            if positions.any(|(idx, _)| {
                idx == 0
                    || upper
                        .chars()
                        .nth(idx - 1)
                        .is_none_or(|c| !c.is_alphanumeric())
            }) {
                return true;
            }
        }
    }

    // Developer markers override provider-prefix trust.
    if upper_contains_token(&upper, "TODO") || upper_contains_token(&upper, "FIXME") {
        return true;
    }

    // The RFC 7519 specimen JWT must be checked BEFORE the
    // known-prefix bypass below — the specimen starts with `eyJ`
    // which IS a known-prefix (JWT header marker), so the
    // bypass would otherwise return `false` and let the
    // textbook-example token through as a real finding.
    // SecretBench-medium 15k seed-0: 142 leaked FPs on this
    // exact specimen pre-fix.
    // Prefix-or-substring match on the 61-char RFC7519 specimen JWT
    // (literal base64url encoding of
    // `{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890`). Any token
    // containing those exact bytes IS the documentation specimen —
    // no production JWT in the wild uses the literal
    // `"sub":"1234567890` claim except cargo-culted from the spec.
    // `contains` (not just `starts_with`) is required because some
    // extractor paths capture surrounding context such as
    // `auth_token=eyJhbGci...` — `starts_with` misses every one of
    // those; `contains` catches them. SecretBench-medium 15k seed-0:
    // 349 leaked FPs in `jwt-rfc-example` category were the
    // `auth_token=…` log-line + `api.key=…` properties shape.
    if credential.contains(RFC7519_EXAMPLE_JWT_PREFIX) {
        return true;
    }

    // Documentation/placeholder markers embedded *inside* a
    // known-prefix token (e.g. `ghp_EXAMPLE_TOKEN_FROM_DOCS`,
    // `AKIAEXAMPLEEXAMPLE12`, `sk_live_PLACEHOLDER_NOT_A_REAL_KEY`,
    // `xoxb-…-EXAMPLE-TOKEN`). The general EXAMPLE check at the
    // top requires a *word-boundary* token match, which misses
    // these because the marker is surrounded by alphanumerics
    // (camelCase or snake_case). Then the known-prefix bypass
    // below would early-return `false`, letting them through.
    // SecretBench-medium 15k seed-0: 234 leaked FPs from
    // docs-example-marker pre-fix. Substring match is safe here
    // because real secrets do not contain these literal strings.
    //
    // Service-prefix credentials are vetted before doc-marker substring
    // checks. `TESTKEY_*` adversarial fixtures carry the marker as
    // their prefix, so they fall through to repetitive-mask gates
    // instead of taking the service-prefix fast path.
    let known_prefix_body = known_prefix_body(credential);
    if let Some(body) = known_prefix_body {
        if looks_like_prefixed_masked_sequence(body) {
            return true;
        }
        if !credential.starts_with("TESTKEY_") {
            return false;
        }
    }

    const DOC_MARKER_SUBSTRINGS: &[&str] = &[
        "EXAMPLE",
        "PLACEHOLDER",
        "NOT_A_REAL",
        "NOTAREAL",
        "INSERT_TOKEN_HERE",
        "INSERT-TOKEN-HERE",
        "CHANGE-ME",
        "CHANGEME",
        "REPLACE_ME",
        "REPLACEME",
        "REDACTED",
        "FAKE_KEY",
        "FAKEKEY",
        "TEST_KEY",
        "TESTKEY",
        "SAMPLE_KEY",
        "SAMPLEKEY",
    ];
    if !from_evasion_decoder
        && !credential.contains("example.com")
        && !credential.contains("example.org")
    {
        for marker in DOC_MARKER_SUBSTRINGS {
            if upper.contains(marker) {
                if credential.starts_with("TESTKEY_")
                    && (*marker == "TESTKEY" || *marker == "TEST_KEY")
                {
                    continue;
                }
                return true;
            }
        }
    }

    // PEM-framed credentials (private keys, certificates) get a hard
    // bypass on the body-entropy heuristics below: the BEGIN/END
    // frame IS the high-confidence signal, and base64-encoded
    // structured data (notably the `openssh-key-v1\0\0\0\0…` prefix
    // every OPENSSH PRIVATE KEY starts with) legitimately contains
    // long runs of identical characters like `AAAAAAAA` from
    // zero-padding. Without this carve-out, real OPENSSH keys get
    // suppressed by `has_n_or_more_consecutive_identical` and the
    // PEM `private-key` detector silently misses them — see
    // `tests/contracts/private-key.toml` OPENSSH positive.
    if credential.starts_with("-----BEGIN") {
        return false;
    }

    // ── 3. Repetitive masking patterns ──
    // These all gate on !bypass_shape_gates: a named detector whose
    // regex specifically requested e.g. `[A-Z0-9]{5,10}` for a
    // Paylocity company ID has already vetted that the credential
    // shape is real; suppressing `AAA12345` on a "three identical
    // leading chars" heuristic silently drops the company ID for
    // any tenant whose ID starts with a triple. Kimi-suppress
    // findings #2-5. Generic / entropy detectors (bypass_shape_gates
    // = false) keep the gates because their anchor is keyword-class,
    // not vendor-fingerprint, and the masks DO catch real noise on
    // those paths.
    // 5+ consecutive 'x' or 'X' (e.g., xxxxx, XXXXXXX) — masks and placeholders.
    // 3x can appear in real base64/hex, so only suppress longer runs.
    if !bypass_shape_gates && upper.contains("XXXXX") {
        return true;
    }
    // 5+ consecutive identical characters in any credential, or 3+ in short credentials.
    // Real secrets can have short runs (e.g., "000" in base64) but rarely 5+.
    if !bypass_shape_gates
        && credential.len() < 20
        && has_three_or_more_consecutive_identical(credential)
    {
        return true;
    }
    if !bypass_shape_gates && has_n_or_more_consecutive_identical(credential, 5) {
        return true;
    }
    if !bypass_shape_gates && has_repeated_block_mask(credential) {
        return true;
    }
    // Entirely filler symbols
    if !bypass_shape_gates
        && credential
            .chars()
            .all(|c| c == 'x' || c == 'X' || c == '*' || c == '-' || c == '.')
    {
        return true;
    }
    // Purely symbolic strings that look like filler/placeholder
    // (e.g., "********", "--------") — NOT real passwords like "!@#$%^&*()"
    // Check for ≤2 unique chars without heap allocation.
    if !bypass_shape_gates
        && credential.len() >= 8
        && credential.chars().all(|c| !c.is_alphanumeric())
    {
        let bytes = credential.as_bytes();
        let first = bytes[0];
        let mut second = first;
        let mut distinct = 1u32;
        for &b in &bytes[1..] {
            if b != first && b != second {
                distinct += 1;
                if distinct > 2 {
                    break;
                }
                second = b;
            }
        }
        if distinct <= 2 {
            return true;
        }
    }

    // ── 4. Known fake sequences ──
    // Only suppress if the fake sequence is a DOMINANT part of the credential
    // (>50% of the non-prefix content). Substring matches in long credentials
    // produce false suppressions on real secrets.
    const FAKE_SEQUENCES: &[&str] = &["1234567890", "0123456789", "ABCDEFGH", "ABCDEFGHIJ"];
    for seq in FAKE_SEQUENCES {
        if upper.contains(seq) {
            // Only suppress short credentials dominated by the fake sequence,
            // not long ones where it's a small substring.
            let seq_ratio = seq.len() as f64 / credential.len().max(1) as f64;
            if seq_ratio > 0.4 {
                return true;
            }
        }
    }

    // ── 5b. Bare hash digest / UUID shape suppression ──
    // Values whose entire body is an MD5 (32-hex), SHA1 (40-hex),
    // SHA256 (64-hex), SHA512 (128-hex) or RFC-4122 UUID-v4
    // (8-4-4-4-12 with version-4 nibble) are almost never secrets in
    // practice — they're git commit IDs, npm-lock integrity hashes,
    // requirements.txt --hash entries, docker image digests, and
    // k8s resource UIDs. Surfaced by the secretbench mirror corpus
    // as the dominant FP class.
    // Known-prefix credentials bypass this (a 64-char hex AWS key
    // shouldn't be filtered) — we already returned `false` above
    // when known_prefix_body matched.
    // Split the old "hash digest OR UUID" gate by *which side* is
    // load-bearing. Both are gated by `bypass_shape_gates` — the
    // comment used to say the hash-digest side was always-on, which
    // contradicted the code (kimi-suppress audit caught the mismatch).
    // The code is correct: gate both, because ~30 named detectors
    // (Algolia 32-hex, New Relic 40-hex, Redis Labs 64-hex, AlienVault
    // OTX, Splunk HEC, Rollbar, etc.) explicitly request pure-hex
    // credentials in their regexes. Suppressing those would tank recall
    // for every hex-shaped service-specific secret.
    //
    //   - Hash digest (32/40/48/56/64/72/128-char uniform hex, plus
    //     `sha256:` / `sha512:` prefixed forms): bench v18 showed
    //     unbounded suppression of bare hex added 3304 FPs
    //     (sha256-hex 1460 + sha1-hex 1027 + git-commit-sha 817) on
    //     generic / entropy detectors. Gate keeps generic FPs out
    //     while letting named hex-anchored detectors fire.
    //
    //   - UUID v4 (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`): Heroku
    //     API key, Cypress record key, the body of many license-server
    //     tokens use UUID v4. A named detector with a service-specific
    //     anchor is positive evidence the UUID is a credential, NOT a
    //     docker image digest or k8s resource ID. Generic / entropy
    //     detectors stay gated because for them a bare UUID is noise.
    //
    // Bench v19 confirmed both gates close the FP regression without
    // losing recall; the contracts_runner test caught the earlier
    // UUID over-suppression that prompted the split.
    if !bypass_shape_gates && looks_like_hash_digest(credential) {
        return true;
    }
    if !bypass_shape_gates && is_uuid_v4_shape(credential) {
        return true;
    }

    // ── 5c. License-key / serial shape: 5 blocks of 5 alnum chars,
    //         dash-separated (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX). Used
    //         by Microsoft Office / Adobe / Atlassian license keys
    //         and a thousand similar product-key surfaces. Real
    //         credentials almost never carry this shape. From
    //         secretbench-medium-15k: 464 FPs (3rd-largest cluster).
    if !bypass_shape_gates && looks_like_dashed_serial_key(credential) {
        return true;
    }

    // ── 5d. The well-known RFC 7519 example JWT (specimen token
    //         from the spec, copy-pasted into thousands of docs).
    //         Conservative literal-prefix match so we don't
    //         accidentally suppress real JWTs that begin with the
    //         same header.
    // Prefix-only match: the 61-char RFC7519_EXAMPLE_JWT_PREFIX is
    // the literal base64url encoding of
    // `{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890`. Any token
    // beginning with those exact bytes IS the documentation
    // specimen — no production JWT in the wild uses the literal
    // `"sub":"1234567890` claim except cargo-culted from the spec.
    // (The previous belt-and-suspenders `contains(signature)`
    // check failed when an upstream regex value-extractor
    // truncated the captured credential before the signature
    // segment — the prefix-only check is sufficient and survives
    // truncation.)
    if credential.starts_with(RFC7519_EXAMPLE_JWT_PREFIX) {
        return true;
    }

    // ── 5e0. Credentials never contain interior whitespace runs.
    //          The dotenv/properties/log-line extractors sometimes
    //          capture the entire RHS as the credential when the
    //          source line is `TOKEN=Session opened with handle
    //          XYZ. See documentation.` — multi-word English
    //          prose with a high-entropy substring is never a
    //          real credential. SecretBench-medium 15k seed-0:
    //          68 FPs from lorem-with-high-entropy.
    if credential.len() > 30 && credential.chars().filter(|c| c.is_whitespace()).count() >= 2 {
        // Cheap English-word sanity check: at least one lowercase
        // alphabetic run of length 3+ between whitespace tokens —
        // characteristic of prose, not credentials.
        let has_word_run = credential
            .split_whitespace()
            .any(|tok| tok.len() >= 3 && tok.chars().all(|c| c.is_ascii_lowercase()));
        if has_word_run {
            return true;
        }
    }

    // ── 5e1. AWS IAM resource ARNs (`arn:aws:iam::ACCT:role/...`,
    //          `:user/`, `:group/`, `:policy/`, `:instance-profile/`)
    //          are identifiers, not credentials — they only name a
    //          resource, they don't authenticate against it.
    //          Other ARN namespaces (e.g. `secretsmanager:*:secret:*`,
    //          `rds:*:cluster:*`) ARE credential REFERENCES that
    //          downstream detectors should keep firing on, so the
    //          gate is intentionally narrow to the IAM namespace.
    //          SecretBench-medium 15k seed-0: 27 FPs from aws-arn
    //          (all IAM role ARNs).
    if (credential.starts_with("arn:aws:iam::")
        || credential.starts_with("arn:aws-cn:iam::")
        || credential.starts_with("arn:aws-us-gov:iam::"))
        && (credential.contains(":role/")
            || credential.contains(":user/")
            || credential.contains(":group/")
            || credential.contains(":policy/")
            || credential.contains(":instance-profile/"))
    {
        return true;
    }

    // ── 5e2. HTML colour codes (`#RRGGBB`, `#RGB`). 6-or-3 hex
    //          digits prefixed by `#`. Real credentials are never
    //          prefixed with `#`. SecretBench-medium 15k seed-0:
    //          22 FPs from html-color.
    if let Some(body) = credential.strip_prefix('#') {
        if (body.len() == 3 || body.len() == 6 || body.len() == 8)
            && body.chars().all(|c| c.is_ascii_hexdigit())
        {
            return true;
        }
    }

    // ── 5e3. Template placeholders wrapped in `{...}`, `<...>`,
    //          `${...}`, `{{...}}`. Real credentials are never
    //          delivered wrapped in brace/angle markers. The
    //          dotenv/yaml extractor sometimes preserves these
    //          wrappers when the placeholder is the entire RHS.
    //          SecretBench-medium 15k seed-0: 41 FPs from
    //          template-placeholder.
    {
        let trimmed = credential.trim();
        let bracketed = (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('<') && trimmed.ends_with('>'))
            || (trimmed.starts_with("${") && trimmed.ends_with('}'));
        if bracketed && trimmed.len() <= 80 {
            return true;
        }
    }

    // ── 5f. base64-of-arbitrary-bytes (e.g. protobuf wire dumps,
    //         random binary blobs encoded for transport). Real
    //         credential tokens almost never use standard base64
    //         with `+/` punctuation AND `=` padding AND lack a
    //         known prefix; they're either base64URL (`-_` instead
    //         of `+/`) or pure alphanumeric. SecretBench-medium
    //         15k seed-0: 705 leaked FPs from base64-protobuf
    //         (largest single FP class).
    //
    //         Gate: standard-base64 alphabet only, contains at
    //         least one of `+/`, ends in `=` padding, length ≥ 40,
    //         and is NOT preceded by a known hash-algo label
    //         (already handled above by the prefixed-hash gate).
    //
    //         BYPASS LIST: detectors whose regex anchors on a
    //         service-specific keyword (AWS_SECRET_ACCESS_KEY,
    //         AccountKey=, etc.) carry positive evidence strong
    //         enough that the b64 shape is irrelevant. Those
    //         findings come through `engine/scan.rs` and don't
    //         pass this gate when `bypass_b64_blob_suppression`
    //         is set in the source_type. The default is to apply
    //         the gate (keeps base64-protobuf FP suppression).
    // Named detectors with service-specific anchors bypass the b64-blob
    // gate too (e.g. AWS_SECRET_ACCESS_KEY=<40b64> would otherwise be
    // dropped as a protobuf-shaped blob).
    if !bypass_shape_gates && looks_like_standard_base64_blob(credential) {
        return true;
    }

    // ── 6. Algorithmic placeholder detection ──
    // Credentials dominated by filler after stripping known prefixes.
    if crate::context::is_known_example_credential(credential) {
        crate::telemetry::record_example_suppression(
            "pipeline",
            path,
            credential,
            "algorithmic_placeholder",
        );
        return true;
    }

    // ── 7. Context-based suppression for docs/comments ──
    // Only suppress in docs/comments if the credential IS a placeholder word
    // (not if it merely contains one as a substring of a longer value).
    if matches!(
        context,
        context::CodeContext::Documentation | context::CodeContext::Comment
    ) {
        let trimmed = credential.trim_matches(|c: char| !c.is_alphanumeric());
        let trimmed_upper = trimmed.to_uppercase();
        if trimmed_upper == "TOKEN"
            || trimmed_upper == "KEY"
            || trimmed_upper == "SECRET"
            || trimmed_upper == "PASSWORD"
            || trimmed_upper == "API_KEY"
            || trimmed_upper == "API_TOKEN"
            || trimmed_upper == "YOUR_TOKEN"
            || trimmed_upper == "YOUR_API_KEY"
        {
            return true;
        }
    }

    // ── 8. Path-based heuristic ──
    if let Some(path) = path {
        // ASCII case-insensitive segment compare — no per-call lowercase
        // alloc of the full path. Hot path during placeholder rejection.
        let is_example_path = path.split(['/', '\\']).any(|component| {
            component.eq_ignore_ascii_case("example")
                || component.eq_ignore_ascii_case("examples")
                || component.eq_ignore_ascii_case("test")
                || component.eq_ignore_ascii_case("tests")
                || component.eq_ignore_ascii_case("fixture")
                || component.eq_ignore_ascii_case("fixtures")
        });
        if is_example_path && upper_contains_token(&upper, "EXAMPLE") {
            return true;
        }
    }

    // ── 9. Base64-decode-and-recheck ──
    //          Bench fixtures (notably kubernetes-secret-shape yaml in
    //          the SecretBench mirror) wrap placeholder/hash/UUID/ARN
    //          payloads in base64 inside `data:` fields. A k8s-secret
    //          detector match on the outer base64 wrapper bypasses the
    //          inner gates above because the OUTER token is just
    //          opaque base64 — none of the EXAMPLE / PLACEHOLDER /
    //          hash / UUID / IAM-ARN substrings appear in it.
    //          Decoding the wrapper once and re-running the core
    //          suppression on the decoded UTF-8 catches all of them:
    //            • `Z2hwX0VYQU1QTEVfVE9LRU5fRlJPTV9ET0NT`
    //                → `ghp_EXAMPLE_TOKEN_FROM_DOCS` (EXAMPLE marker)
    //            • `YXJuOmF3czppYW06Ojc4MzY2NDQ5MjgxNjpyb2xlL1JlYWRlc...`
    //                → `arn:aws:iam::...:role/ReaderRole` (IAM gate)
    //            • `Y2U3ZWUxZDAtZThiNi00ZDNmLTk2YjAtYmU3YjBiZDdiOGFj`
    //                → uuid v4 shape (UUID gate)
    //            • `MzRiNTIyOWY5NDdlZGZjOTIxMzVlZDNiMWU0MjE1Y2NlNm...`
    //                → 64-char sha256 hex (hash gate)
    //          The `skip_b64_decode_recheck` flag prevents recursion
    //          when called from a previously-decoded payload.
    //          SecretBench-medium 15k seed-0: estimated 3000-5000 of
    //          the 14k FPs come from this exact path.
    if !skip_b64_decode_recheck {
        if let Some(decoded) = try_decode_b64_to_utf8(credential) {
            // Sanity bound: the decoded text must look like a sensible
            // payload (printable, not too long, not empty). Random
            // bytes that happen to base64-decode to UTF-8 of pure
            // garbage shouldn't trigger gates that rely on shape.
            if !decoded.is_empty()
                && decoded.len() <= credential.len()
                && decoded
                    .chars()
                    .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
                && should_suppress_inner(
                    &decoded,
                    path,
                    context,
                    source_type,
                    true,
                    bypass_shape_gates,
                )
            {
                return true;
            }
        }
    }
    false
}

/// Try to decode `credential` as standard or url-safe base64 and
/// return the result as UTF-8 if successful. Returns `None` on any
/// decode failure or non-UTF-8 payload.
///
/// Used by the suppression gate to peek inside base64-wrapped
/// fixtures whose outer shape looks generic but whose decoded
/// content is a known placeholder / hash / ARN / UUID.
fn try_decode_b64_to_utf8(credential: &str) -> Option<String> {
    // Cheap shape gate before paying for the decode allocation.
    // Standard base64 alphabet (`[A-Za-z0-9+/=]`) and url-safe
    // (`[A-Za-z0-9_\-=]`). Length must be ≥ 8 so we don't waste
    // cycles on every 4-char identifier we see.
    if credential.len() < 8 || credential.len() > 4096 {
        return None;
    }
    let valid = credential.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    });
    if !valid {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;
    // Try standard, url-safe, and their no-pad variants in order.
    // A no-trait-object array sidesteps the `base64::Engine` non-
    // dyn-compatible trait bound.
    if let Ok(bytes) = STANDARD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = URL_SAFE.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(credential) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            return Some(s.to_string());
        }
    }
    None
}
