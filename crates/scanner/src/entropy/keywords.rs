use super::{shannon_entropy, HIGH_ENTROPY_THRESHOLD};
use crate::engine::fallback_generic::keywords::normalize_assignment_keyword;

pub(crate) struct KeywordContext {
    pub(crate) keyword: String,
    pub(crate) threshold: f64,
    pub(crate) min_len: usize,
    pub(crate) is_credential_context: bool,
    /// CredData candidate-generation lift (recall lane). When `true`, a STRONG
    /// credential-anchored line is allowed to GENERATE a candidate whose value
    /// is a canonical hash/UUID/serial shape (`is_canonical_non_secret_shape`),
    /// so the downstream MoE — the precision authority when
    /// `entropy_ml_authoritative` is on — can arbitrate it instead of the shape
    /// being hard-dropped at the generation source before the model ever sees
    /// it. This is the root candidate-GENERATION gap for the CredData `UUID`
    /// and `hex64` (AES-256 key) miss classes: ~83% of CredData misses never
    /// generate a candidate, and these two shapes are dropped HERE.
    ///
    /// Set ONLY when the MoE is the runtime precision authority
    /// (`ml_enabled && entropy_ml_authoritative`) AND the line is in credential
    /// context (a strong keyword anchor is positive evidence). Left `false`
    /// everywhere else, so the non-ML path's behaviour — and the SecretBench
    /// mirror precision (where `TOKEN=<32-hex>` is planted in BOTH the positive
    /// and the sha256/git-sha/k8s-uid negative classes) — is byte-identical:
    /// no model, no lift. The keyword-FREE path keeps the strict gate
    /// unconditionally (no anchor ⇒ no evidence ⇒ no lift).
    pub(crate) allow_canonical_shapes: bool,
}

pub(super) fn find_keyword_assignment_lines<'a>(
    lines: &'a [&str],
    secret_keywords: &[String],
) -> Vec<(usize, &'a str)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            is_keyword_assignment_line(line, secret_keywords).then_some((index, *line))
        })
        .collect()
}

fn is_keyword_assignment_line(line: &str, secret_keywords: &[String]) -> bool {
    let trimmed = line.trim();
    if is_import_like(trimmed) {
        return false;
    }
    if line_has_credential_assignment_surface(line) {
        return true;
    }

    let line_bytes = line.as_bytes();
    let has_keyword = secret_keywords.iter().any(|keyword| {
        let keyword_bytes = keyword.as_bytes();
        line_bytes
            .windows(keyword_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(keyword_bytes))
    });
    has_keyword && (line.contains('=') || line.contains(':'))
}

pub(super) fn is_likely_innocuous_line(line: &str) -> bool {
    let trimmed = line.trim();
    let starts_with_uri = trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("ftp://")
        || trimmed.starts_with("file://")
        || trimmed.starts_with("ssh://")
        || trimmed.starts_with("git://");
    if starts_with_uri && line_has_credential_assignment_surface(trimmed) {
        return false;
    }
    if trimmed.starts_with("import ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("package ")
        || trimmed.starts_with("include ")
        || trimmed.starts_with("#include ")
        || starts_with_uri
    {
        return true;
    }

    let without_quotes = trimmed.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
    if without_quotes.starts_with("sha256:")
        || without_quotes.starts_with("sha512:")
        || without_quotes.starts_with("sha1:")
        || without_quotes.starts_with("md5:")
        || without_quotes.starts_with("git-sha:")
    {
        return true;
    }
    without_quotes.len() == 40 && without_quotes.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn extract_candidates(
    line: &str,
    min_length: usize,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    // CredData recall lane: when set (the MoE is authoritative and a strong
    // credential keyword anchors the line), the extraction-time canonical-shape
    // gate (`is_known_non_secret`'s UUID + hex32/40/64/128 arms) is released so a
    // UUID-bodied or 64-hex (AES-256) value is EXTRACTED as a candidate for the
    // model to arbitrate, instead of being dropped before any candidate exists.
    // This is the third (and earliest) of the three generation gates the lift
    // must release for the `UUID`/`hex64` miss classes.
    allow_canonical_shapes: bool,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if is_likely_concatenation_fragment(line) {
        return candidates;
    }

    let mut push_candidate = |raw: &str, strict: bool| {
        let cleaned = clean_candidate_value(raw);
        if cleaned.len() < min_length {
            return;
        }
        let plausible = if strict {
            is_secret_plausible_with_lift(
                cleaned,
                placeholder_keywords,
                is_credential_context,
                allow_canonical_shapes,
            )
        } else {
            is_candidate_plausible_with_lift(
                cleaned,
                placeholder_keywords,
                is_credential_context,
                allow_canonical_shapes,
            )
        };
        if plausible && !candidates.iter().any(|c| c == cleaned) {
            candidates.push(cleaned.to_string());
        }
    };

    if let Some(value) = authorization_header_value(line) {
        push_candidate(value, false);
    }
    if let Some(value) = xml_assignment_value(line) {
        push_candidate(value, false);
    }

    if let Some(sep_pos) = line.find('=').or_else(|| line.find(':')) {
        push_candidate(&line[sep_pos + 1..], false);
    }

    for quote in ['"', '\''] {
        let mut start = None;
        for (index, ch) in line.char_indices() {
            if ch == quote {
                match start {
                    None => start = Some(index + 1),
                    Some(begin) => {
                        let content = &line[begin..index];
                        push_candidate(content, true);
                        start = None;
                    }
                }
            }
        }
    }

    candidates
}

fn is_import_like(trimmed: &str) -> bool {
    trimmed.starts_with("import")
        || trimmed.starts_with("package")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(")
}

pub(crate) fn line_has_credential_assignment_surface(line: &str) -> bool {
    authorization_header_value(line).is_some()
        || assignment_keyword_for_line(line)
            .as_deref()
            .is_some_and(normalized_assignment_keyword_is_credential)
}

pub(crate) fn assignment_keyword_for_line(line: &str) -> Option<String> {
    if let Some(tag) = xml_assignment_tag(line) {
        return normalize_assignment_keyword(tag);
    }
    let sep_pos = line.find('=').or_else(|| line.find(':'))?;
    let lhs = &line[..sep_pos];
    let key = lhs
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
        .find(|part| !part.is_empty())?;
    normalize_assignment_keyword(key)
}

pub(crate) fn normalized_assignment_keyword_is_credential(normalized: &str) -> bool {
    let compact: String = normalized
        .bytes()
        .filter(|b| *b != b'_')
        .map(|b| b.to_ascii_lowercase() as char)
        .collect();
    let separated_secret_suffix = normalized.contains('_')
        && matches!(
            normalized.rsplit('_').next(),
            Some("key" | "secret" | "token" | "password" | "passwd" | "pwd")
        );
    if separated_secret_suffix {
        return true;
    }
    matches!(
        compact.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "passphrase"
            | "token"
            | "secret"
            | "credential"
            | "bearer"
            | "authorization"
            | "apikey"
            | "accesskey"
            | "authkey"
            | "privatekey"
            | "signingkey"
            | "encryptionkey"
            | "masterkey"
            | "secretkey"
            | "sessionkey"
            | "clientsecret"
            | "appsecret"
            | "salt"
            | "nonce"
            | "seed"
            | "hmacsalt"
            | "hmacseed"
            | "passwordsalt"
    ) || compact.ends_with("salt")
        || compact.ends_with("nonce")
        || compact.ends_with("seed")
}

fn clean_candidate_value(raw: &str) -> &str {
    let trimmed = raw
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == ',');
    let end = match trimmed.find(|c: char| c.is_whitespace() || c == '&' || c == '<') {
        Some(index) => index,
        None => trimmed.len(),
    };
    trimmed[..end].trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == ',')
}

fn authorization_header_value(line: &str) -> Option<&str> {
    let (name, rhs) = line.trim().split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("authorization") {
        return None;
    }
    let rhs = rhs.trim();
    let lower = rhs.to_ascii_lowercase();
    let token = if lower.starts_with("bearer ") {
        &rhs[7..]
    } else if lower.starts_with("basic ") {
        &rhs[6..]
    } else {
        return None;
    };
    token.split_whitespace().next()
}

fn xml_assignment_tag(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let start = trimmed.find('<')?;
    let after_open = &trimmed[start + 1..];
    if after_open.starts_with('/') || after_open.starts_with('!') || after_open.starts_with('?') {
        return None;
    }
    let tag_end = after_open.find('>')?;
    let tag = after_open[..tag_end].split_whitespace().next()?;
    if tag.is_empty() || tag.starts_with('/') {
        return None;
    }
    let close = format!("</{tag}>");
    trimmed[start + 1 + tag_end + 1..]
        .contains(&close)
        .then_some(tag)
}

fn xml_assignment_value(line: &str) -> Option<&str> {
    let tag = xml_assignment_tag(line)?;
    let trimmed = line.trim();
    let open_start = trimmed.find('<')?;
    let open_end = trimmed[open_start..].find('>')? + open_start;
    let close = format!("</{tag}>");
    let close_start = trimmed[open_end + 1..].find(&close)? + open_end + 1;
    let normalized = normalize_assignment_keyword(tag)?;
    normalized_assignment_keyword_is_credential(&normalized)
        .then_some(trimmed[open_end + 1..close_start].trim())
}

fn is_likely_concatenation_fragment(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('"') || trimmed.starts_with('\'') {
        let double_quotes = trimmed.matches('"').count();
        let single_quotes = trimmed.matches('\'').count();
        if (double_quotes == 2 && single_quotes == 0) || (single_quotes == 2 && double_quotes == 0)
        {
            let after_quote = if double_quotes == 2 {
                trimmed
                    .rfind('"')
                    .map(|index| &trimmed[index + 1..])
                    .unwrap_or("") // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                    .trim()
            } else {
                trimmed
                    .rfind('\'')
                    .map(|index| &trimmed[index + 1..])
                    .unwrap_or("") // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                    .trim()
            };
            let is_fragment_suffix = after_quote.is_empty()
                || after_quote == "+"
                || after_quote == "\\"
                || after_quote == ","
                || after_quote == ")"
                || after_quote.starts_with('+')
                || after_quote.starts_with(')');
            if is_fragment_suffix {
                return true;
            }
        }
    }
    trimmed.ends_with("\\\"") || trimmed.ends_with("-\\")
}

enum PlausibilityMode {
    Lenient,
    Strict,
}

fn is_known_non_secret(
    value: &str,
    is_credential_context: bool,
    allow_canonical_shapes: bool,
) -> bool {
    // UUID / k8s-resource-uid (8-4-4-4-12 hex). Dropped at extraction so a bare
    // `TOKEN_LIST=<uuid>` env identifier does not generate. CredData recall lane:
    // when the lift is engaged (model authoritative + strong credential anchor),
    // a whole-value UUID is the CredData `UUID` miss class (LaunchDarkly SDK key,
    // Heroku UUID key, PowerBI client secret) and MUST be extracted as a
    // candidate for the MoE to arbitrate, so the gate releases here. Off the lift
    // it is byte-identical.
    if !allow_canonical_shapes && value.len() == 36 {
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
        if !is_credential_context {
            return true;
        }
        if hex_len == 40 || hex_len == 128 {
            return true;
        }
        if hex_len == 64 && !allow_canonical_shapes {
            return true;
        }
    }

    value.starts_with("data:image/")
}

fn passes_plausibility_checks(
    value: &str,
    mode: PlausibilityMode,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    allow_canonical_shapes: bool,
) -> bool {
    if matches_universal_rejection(value)
        || is_known_non_secret(value, is_credential_context, allow_canonical_shapes)
        || is_placeholder_ci(value.as_bytes(), placeholder_keywords)
        || has_low_alnum_ratio(value)
    {
        return false;
    }

    if matches!(mode, PlausibilityMode::Strict)
        && !passes_strict_secret_checks(value, is_credential_context)
    {
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

/// Heuristic for "this value looks like an English-prose run", not a
/// credential. Tightens FP filtering when the keyword-anchor is weak
/// (e.g. the word `secret` appears in a comment or commit message that
/// happens to also contain a high-entropy looking token-substring). Real
/// credentials never contain consecutive lowercase ASCII letters longer
/// than ~12 chars (longest common English word still in heavy use), and
/// they don't contain multiple whitespace-delimited words.
///
/// Returns true if `value` should be treated as English prose.
pub(crate) fn looks_like_english_prose(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 16 {
        return false;
    }

    // Branch 1: pure lowercase ASCII letters with no digit/symbol. A 16+
    // char string of nothing but lowercase letters is overwhelmingly a
    // dictionary-word concatenation, joined sentence fragment, or
    // identifier sentence (e.g. `description = "thequickbrownfoxjumps..."`
    // emitted from a free-text field). Real high-entropy credentials at
    // this length virtually always include at least one digit or a
    // mixed-case transition - the entropy of pure-lowercase-letters tops
    // out at log2(26) = 4.7 bits/byte, but English compressed via the
    // narrow vowel/consonant alternation lands well under that.
    if bytes.iter().all(|b| b.is_ascii_lowercase()) && bytes.len() >= 16 {
        return true;
    }

    // Branch 2: multi-word whitespace-bearing prose. The dotenv / log-line
    // / properties extractors occasionally capture the entire RHS as a
    // single value when the source is `KEY=this is the description of
    // something interesting and long`. The whitespace-bearing gate at the
    // emit site already drops these unconditionally for the entropy
    // fallback, but Strict-mode plausibility (called from quoted-value
    // extraction) sees the raw string and needs an explicit prose branch:
    // 2+ whitespace-separated tokens where every token is 2+ chars of
    // pure ASCII letters (any case) and there is at least one lowercase
    // run of 3+ chars. Real credentials never split into multiple
    // alphabetic tokens.
    let tokens: Vec<&str> = value.split_whitespace().collect();
    if tokens.len() >= 2 {
        let all_alpha = tokens
            .iter()
            .all(|t| t.len() >= 2 && t.bytes().all(|b| b.is_ascii_alphabetic()));
        if all_alpha {
            let has_lowercase_word = tokens
                .iter()
                .any(|t| t.len() >= 3 && t.bytes().all(|b| b.is_ascii_lowercase()));
            if has_lowercase_word {
                return true;
            }
        }
    }

    false
}

/// Public predicate for callers in the entropy emit-path. Returns true
/// when the value would be classified as English prose; the emit-path
/// uses this to tighten plausibility when no strong credential keyword
/// anchor is adjacent.
pub(crate) fn entropy_value_looks_like_prose(value: &str) -> bool {
    looks_like_english_prose(value)
}

pub(crate) fn passes_strict_secret_checks(value: &str, is_credential_context: bool) -> bool {
    // Outside a credential-keyword anchor, any >10-char pure-hex value is a
    // checksum/digest, not a credential. Inside one (`apiKey: <hex>`), the
    // keyword is positive evidence the hex IS the credential - the entropy
    // path's strict mode would otherwise drop every md5/sha1/sha256-shaped
    // planted secret. Mirror v30 had 112 generic-high-entropy-string FNs
    // driven by exactly this gate firing in credential context.
    if !is_credential_context && value.chars().all(|ch| ch.is_ascii_hexdigit()) && value.len() > 10
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
    if looks_like_program_identifier(value) {
        return false;
    }

    // Dash-segmented-alnum decoy shape. License/product serials
    // (`A1B2C-D3E4F-G5H6I-J7K8L-M9N0P`), template placeholders
    // (`XXXXX-XXXXX-...`) and segmented identifiers
    // (`my-service-prod-key-name-here`) are dash-joined runs of
    // alphanumerics with no other symbol class. The dash inflates
    // their byte alphabet enough that the serial shape lands AT or
    // ABOVE the 4.5 blanket floor (a 5x5 mixed serial measures
    // ~4.58), so the entropy admit below would let them through.
    // They are not credentials - the 0f05b3de mirror admitted 42 of
    // them as false positives. Reject the shape outright; symbolic
    // passwords keep a richer symbol set (`$`, `*`, `!`, `#`, ...)
    // and never reduce to pure dash-segmented alnum.
    if is_dash_segmented_alnum_decoy(value) {
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
    if is_credential_context {
        let has_symbol = value.bytes().any(|b| !b.is_ascii_alphanumeric());
        if has_symbol && entropy >= 3.5 {
            return true;
        }
    }
    false
}

/// Heuristic: is this value a dash-segmented run of alphanumerics with
/// no other symbol class? Matches license/product serials
/// (`A1B2C-D3E4F-G5H6I-J7K8L-M9N0P`), template placeholders
/// (`XXXXX-XXXXX-...`) and segmented identifiers
/// (`my-service-prod-key-name-here`). The only non-alphanumeric byte is
/// `-`, and it joins at least two non-empty alphanumeric groups. Real
/// symbolic passwords carry richer symbol sets (`$`, `*`, `!`, `#`)
/// and never reduce to this shape, so gating on it is precision-positive
/// at near-zero recall cost.
pub(crate) fn is_dash_segmented_alnum_decoy(value: &str) -> bool {
    if !value.contains('-') {
        return false;
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return false;
    }
    let mut groups = 0usize;
    for group in value.split('-') {
        if group.is_empty() {
            // A leading/trailing/double dash breaks the uniform serial
            // shape - leave those to the entropy floors.
            return false;
        }
        groups += 1;
    }
    groups >= 2
}

/// Heuristic: is this string a likely source-code identifier rather
/// than a credential? Identifiers in mainstream languages are all
/// `[A-Za-z_]` (no digits) with camelCase / PascalCase / snake_case
/// shape. Real API keys almost always include at least one digit (the
/// few that don't are short - `<8` chars - and rejected upstream by
/// length gates).
pub(crate) fn looks_like_program_identifier(value: &str) -> bool {
    // Letters + underscore only. Any digit, hyphen, slash, or special
    // char means it's not a typical identifier.
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return false;
    }
    // snake_case (lowercase + underscore segments) - `my_long_helper_name`.
    if value.contains('_') && value.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_') {
        return true;
    }
    // camelCase / PascalCase - at least one internal lower→Upper
    // boundary. `BulkUpdateApiKeyResponse` has many; `Foo` has none.
    let bytes = value.as_bytes();
    let mut transitions = 0usize;
    for pair in bytes.windows(2) {
        if pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase() {
            transitions += 1;
        }
    }
    transitions >= 1
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

pub(crate) fn is_candidate_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Lenient,
        placeholder_keywords,
        false,
        false,
    )
}

pub(crate) fn is_secret_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Strict,
        placeholder_keywords,
        false,
        false,
    )
}

/// Credential-context-aware plausibility check (Lenient mode).
///
/// Pass `is_credential_context = true` when the candidate came from a line
/// containing a credential keyword (`token`, `api_key`, `password`, ...).
/// In that case the hex-digest blacklist is skipped so md5/sha1/sha256-shaped
/// values can surface as candidates - the credential keyword anchor provides
/// the positive evidence that they're secrets, not digests.
pub(crate) fn is_candidate_plausible_with_context(
    value: &str,
    placeholder_keywords: &[String],
    is_credential_context: bool,
) -> bool {
    is_candidate_plausible_with_lift(value, placeholder_keywords, is_credential_context, false)
}

/// Lift-aware sibling of [`is_candidate_plausible_with_context`] (Lenient mode):
/// `allow_canonical_shapes` additionally releases the extraction-time canonical-
/// shape gate (UUID / hex32-128) so a UUID-bodied or 64-hex value is EXTRACTED
/// as a candidate for the MoE. Off the lift it is byte-identical to
/// [`is_candidate_plausible_with_context`]. See the CredData recall lane in
/// `entropy::scanner`.
pub(super) fn is_candidate_plausible_with_lift(
    value: &str,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    allow_canonical_shapes: bool,
) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Lenient,
        placeholder_keywords,
        is_credential_context,
        allow_canonical_shapes,
    )
}

/// Credential-context-aware plausibility check (Strict mode, for quoted values).
pub(crate) fn is_secret_plausible_with_context(
    value: &str,
    placeholder_keywords: &[String],
    is_credential_context: bool,
) -> bool {
    is_secret_plausible_with_lift(value, placeholder_keywords, is_credential_context, false)
}

/// Lift-aware sibling of [`is_secret_plausible_with_context`] (Strict mode).
/// `allow_canonical_shapes` releases the extraction-time canonical-shape gate.
/// Off the lift it is byte-identical.
pub(super) fn is_secret_plausible_with_lift(
    value: &str,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    allow_canonical_shapes: bool,
) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Strict,
        placeholder_keywords,
        is_credential_context,
        allow_canonical_shapes,
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
