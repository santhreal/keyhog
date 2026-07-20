//! Entropy keyword-context parsing, candidate cleaning, and value extraction.
//!
//! Per-detector entropy gates: extraction receives the owning detector's
//! compiled policies, so candidate work never re-reads `DetectorSpec` or
//! substitutes scanner-owned tuning.

use std::sync::LazyLock;

use super::plausibility::{is_candidate_plausible, is_secret_plausible, PlausibilityContext};
use crate::adjudicate::{EntropyShapeStage, StageId};
use crate::assignment_keyword_matcher::AssignmentKeywordMatcher;
use crate::engine::phase2_generic::keywords::normalize_assignment_keyword;

const ASSIGNMENT_KEY_STACK_BYTES: usize = 128;

pub(crate) struct KeywordContext {
    pub(crate) keyword: String,
    pub(crate) threshold: f64,
    pub(crate) min_len: usize,
    pub(crate) is_credential_context: bool,
    pub(crate) plausibility_policy: super::policy::CompiledEntropyPolicy,
}

pub(crate) fn find_keyword_assignment_lines<'a>(
    lines: &'a [&str],
    secret_keywords: &[String],
) -> Vec<(usize, &'a str)> {
    find_keyword_assignment_lines_with_policy(lines, secret_keywords, &[])
}

pub(crate) fn find_keyword_assignment_lines_with_policy<'a>(
    lines: &'a [&str],
    secret_keywords: &[String],
    detector_policy_keywords: &[String],
) -> Vec<(usize, &'a str)> {
    let matcher = AssignmentKeywordMatcher::compile(secret_keywords, detector_policy_keywords);
    find_keyword_assignment_lines_with_matcher(lines, &matcher)
}

pub(crate) fn find_keyword_assignment_lines_with_matcher<'a>(
    lines: &'a [&str],
    matcher: &AssignmentKeywordMatcher,
) -> Vec<(usize, &'a str)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            is_declared_keyword_assignment_line(line, matcher).then_some((index, *line))
        })
        .collect()
}

fn is_declared_keyword_assignment_line(line: &str, matcher: &AssignmentKeywordMatcher) -> bool {
    let trimmed = line.trim();
    if is_import_like_prefix(trimmed) {
        return false;
    }
    let line_bytes = line.as_bytes();
    memchr::memchr3(b'=', b':', b'<', line_bytes).is_some() && matcher.matches(line_bytes)
}

pub(crate) fn is_keyword_assignment_line(line: &str, secret_keywords: &[String]) -> bool {
    is_keyword_assignment_line_with_policy(line, secret_keywords, &[])
}

fn is_keyword_assignment_line_with_policy(
    line: &str,
    secret_keywords: &[String],
    detector_policy_keywords: &[String],
) -> bool {
    let trimmed = line.trim();
    if is_import_like_prefix(trimmed) {
        return false;
    }
    // Fast path: every credential-assignment surface and every keyword-
    // anchored assignment requires '=' or ':'. A single SIMD memchr2 scan
    // skips the expensive credential-surface check and 19-keyword CI search
    // for the ~50% of source lines that have neither separator.
    let line_bytes = line.as_bytes();
    if memchr::memchr3(b'=', b':', b'<', line_bytes).is_none() {
        return false;
    }
    if line_has_credential_assignment_surface(line) {
        return true;
    }

    let has_keyword = secret_keywords
        .iter()
        .chain(detector_policy_keywords)
        .any(|keyword| crate::ascii_ci::ci_find_nonempty(line_bytes, keyword.as_bytes()));
    has_keyword
}

/// True when a line is structurally innocuous and should be dropped before
/// entropy candidate extraction: a bare URI, an `import`/`use`/`package`-style
/// declaration, a hash-digest line (algo-labelled or a bare 40-hex git SHA), and
/// similar non-secret shapes.
///
/// `pub(crate)` so the `is_likely_innocuous_line_for_test` facade can lock the
/// contract from `tests/unit/`.
pub(crate) fn is_likely_innocuous_line(line: &str) -> bool {
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
    if is_import_like_prefix(trimmed) || starts_with_uri {
        return true;
    }

    let without_quotes = trimmed.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
    // Case-insensitive: ssh-keygen fingerprints (`SHA256:<base64>`) and Windows
    // certutil emit upper-case algo labels. The bare-40-hex arm below already
    // accepts either case via is_ascii_hexdigit, so matching these labels
    // case-sensitively was the lone inconsistency that let upper-case digest
    // lines leak into entropy extraction as false positives.
    let wq = without_quotes.as_bytes();
    // Shared colon-form hash-algo labels from the single owner
    // (`suppression::shape::HASH_ALGO_COLON_LABELS`), plus `git-sha:` (git commit
    // refs), an entropy-LOCAL extra the suppression digest-strip intentionally
    // does not carry. A prefix match means this value is an algo-labelled digest,
    // not a secret. (Byte-identical to the former 5-way `||` chain.)
    if crate::suppression::shape::HASH_ALGO_COLON_LABELS
        .iter()
        .copied()
        .chain(std::iter::once(b"git-sha:".as_slice()))
        .any(|label| crate::ascii_ci::starts_with_ignore_ascii_case(wq, label))
    {
        return true;
    }
    without_quotes.len() == 40 && without_quotes.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn extract_candidates(
    line: &str,
    keyword: &str,
    min_length: usize,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    compiled_policy: &crate::entropy::policy::CompiledEntropyPolicy,
    key_material_policy: Option<
        &crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy,
    >,
) -> Vec<String> {
    extract_candidates_internal(
        line,
        keyword,
        min_length,
        placeholder_keywords,
        is_credential_context,
        false,
        compiled_policy,
        key_material_policy,
    )
    .candidates
}

pub(super) struct ExtractionRejection {
    pub(super) value: String,
    pub(super) stage_id: StageId,
}

pub(super) struct ExtractedCandidates {
    pub(super) candidates: Vec<String>,
    pub(super) rejections: Vec<ExtractionRejection>,
}

pub(super) fn extract_candidates_with_rejections(
    line: &str,
    keyword: &str,
    min_length: usize,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    compiled_policy: &crate::entropy::policy::CompiledEntropyPolicy,
    key_material_policy: Option<
        &crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy,
    >,
) -> ExtractedCandidates {
    extract_candidates_internal(
        line,
        keyword,
        min_length,
        placeholder_keywords,
        is_credential_context,
        true,
        compiled_policy,
        key_material_policy,
    )
}

fn extract_candidates_internal(
    line: &str,
    keyword: &str,
    min_length: usize,
    placeholder_keywords: &[String],
    is_credential_context: bool,
    trace_rejections: bool,
    compiled_policy: &crate::entropy::policy::CompiledEntropyPolicy,
    key_material_policy: Option<
        &crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy,
    >,
) -> ExtractedCandidates {
    let mut candidates = Vec::new();
    let mut rejections = Vec::new();
    if is_likely_concatenation_fragment(line) {
        let trimmed = line.trim();
        if trace_rejections && !trimmed.is_empty() {
            push_extraction_rejection(
                &mut rejections,
                trimmed,
                StageId::EntropyValueShape(EntropyShapeStage::ConcatenationFragmentLine),
            );
        }
        return ExtractedCandidates {
            candidates,
            rejections,
        };
    }

    let mut push_candidate = |raw: &str, strict: bool, allow_structured_dotted: bool| {
        let cleaned = clean_candidate_value(raw);
        if cleaned.len() > compiled_policy.length.max_len {
            if trace_rejections {
                push_extraction_rejection(
                    &mut rejections,
                    cleaned,
                    StageId::EntropyValueShape(EntropyShapeStage::ValueTooLong),
                );
            }
            return;
        }
        if cleaned.len() < min_length {
            if trace_rejections && !cleaned.is_empty() {
                let stage_id = if is_credential_context {
                    StageId::EntropyValueShape(EntropyShapeStage::CredentialContextTooShort)
                } else {
                    StageId::EntropyValueShape(EntropyShapeStage::KeywordFreeTooShort)
                };
                push_extraction_rejection(&mut rejections, cleaned, stage_id);
            }
            return;
        }
        let structured_dotted = allow_structured_dotted
            && crate::suppression::shape::is_structured_dotted_token(cleaned);
        let detector_owned_canonical_hex_key =
            key_material_policy.is_some_and(|policy| policy.allows_canonical_hex(keyword, cleaned));
        let plausibility_context = PlausibilityContext::from_compiled(
            is_credential_context,
            detector_owned_canonical_hex_key,
            compiled_policy,
        );
        let plausible = structured_dotted
            || if strict {
                is_secret_plausible(cleaned, placeholder_keywords, plausibility_context)
            } else {
                is_candidate_plausible(cleaned, placeholder_keywords, plausibility_context)
            };
        if !plausible && trace_rejections {
            let stage = if strict {
                EntropyShapeStage::SecretPlausibilityRejected
            } else {
                EntropyShapeStage::CandidatePlausibilityRejected
            };
            push_extraction_rejection(&mut rejections, cleaned, StageId::EntropyValueShape(stage));
        }
        if plausible && !candidates.iter().any(|c| c == cleaned) {
            candidates.push(cleaned.to_string());
        }
    };

    if let Some(value) = authorization_header_value(line) {
        push_candidate(value, false, false);
    }
    if let Some(value) = xml_assignment_value(line) {
        push_candidate(value, false, true);
    }

    if let Some(sep_pos) = line.find('=').or_else(|| line.find(':')) {
        // SAFETY: `line.find('=')` / `line.find(':')` returns a byte offset at which
        // a single-byte ASCII character (`=` or `:`) sits. Adding 1 steps to the byte
        // immediately after that ASCII character, which is always a valid UTF-8 char
        // boundary (any byte following a single-byte ASCII is boundary-aligned).
        // `sep_pos + 1 <= line.len()` because `find` guarantees the match is within the
        // string, so the character plus one byte never exceeds the string length.
        push_candidate(&line[sep_pos + 1..], false, true);
    }

    for quote in ['"', '\''] {
        let mut start = None;
        for (index, ch) in line.char_indices() {
            if ch == quote {
                match start {
                    None => start = Some(index + 1),
                    Some(begin) => {
                        let content = &line[begin..index];
                        push_candidate(content, true, false);
                        start = None;
                    }
                }
            }
        }
    }

    if trace_rejections {
        rejections.retain(|rejection| !candidates.iter().any(|value| value == &rejection.value));
    }

    ExtractedCandidates {
        candidates,
        rejections,
    }
}

fn push_extraction_rejection(
    rejections: &mut Vec<ExtractionRejection>,
    cleaned: &str,
    stage_id: StageId,
) {
    if !rejections
        .iter()
        .any(|rejection| rejection.value == cleaned && rejection.stage_id == stage_id)
    {
        rejections.push(ExtractionRejection {
            value: cleaned.to_string(),
            stage_id,
        });
    }
}

/// Import/module-declaration line prefixes, the single Tier-B owner
/// (`rules/import-line-prefixes.toml`; was an inline `&[&str]` const). A line
/// opening with one of these is a language `import`/`use`/`include`/`package`
/// statement, never a credential assignment. Every prefix is space- or
/// paren-terminated so an identifier that merely *begins* with the keyword
/// (`important_key`, `package_secret`) is NOT matched, that divergence used to
/// reject real credential lines here while [`is_likely_innocuous_line`] accepted
/// them (the termination contract is documented in the data file). Fails closed
/// on an invalid/empty list.
static IMPORT_LINE_PREFIXES: LazyLock<Vec<String>> = LazyLock::new(|| {
    #[derive(serde::Deserialize)]
    struct Prefixes {
        prefixes: Vec<String>,
    }
    let raw = include_str!("../../../../rules/import-line-prefixes.toml");
    match toml::from_str::<Prefixes>(raw) {
        Ok(parsed) if !parsed.prefixes.is_empty() => parsed.prefixes,
        Ok(_) => panic!(
            "rules/import-line-prefixes.toml is empty; it must list the \
             import/module-declaration line prefixes."
        ),
        Err(error) => panic!(
            "rules/import-line-prefixes.toml is invalid: {error}. \
             Fix the bundled Tier-B import-line-prefix list."
        ),
    }
});

pub(crate) fn is_import_like_prefix(trimmed: &str) -> bool {
    IMPORT_LINE_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix.as_str()))
}

pub(crate) fn line_has_credential_assignment_surface(line: &str) -> bool {
    if authorization_header_value(line).is_some() {
        return true;
    }
    if xml_assignment_tag(line).is_some_and(assignment_keyword_is_credential) {
        return true;
    }
    line.char_indices()
        .rev()
        .filter(|(_, ch)| matches!(ch, '=' | ':'))
        .filter_map(|(sep_pos, _)| {
            line[..sep_pos]
                .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
                .find(|part| !part.is_empty())
        })
        .any(assignment_keyword_is_credential)
}

/// Credential classification for a raw assignment key without allocating its
/// normalized spelling. Entropy admission calls this for every separator-bearing
/// source line, so materializing a `String` for ordinary names such as `x` was a
/// measurable whole-file tail. The slow path preserves the exact normalizer for
/// unusually long keys.
fn assignment_keyword_is_credential(keyword: &str) -> bool {
    let mut normalized = [0u8; ASSIGNMENT_KEY_STACK_BYTES];
    let mut len = 0usize;
    let mut last_was_separator = false;
    for byte in keyword.bytes() {
        let normalized_byte = if byte.is_ascii_alphanumeric() {
            last_was_separator = false;
            byte.to_ascii_lowercase()
        } else if matches!(byte, b'_' | b'-' | b'.') && len > 0 && !last_was_separator {
            last_was_separator = true;
            b'_'
        } else {
            continue;
        };
        if len == normalized.len() {
            return normalize_assignment_keyword(keyword)
                .as_deref()
                .is_some_and(normalized_assignment_keyword_is_credential);
        }
        normalized[len] = normalized_byte;
        len += 1;
    }
    if last_was_separator {
        len = len.saturating_sub(1);
    }
    std::str::from_utf8(&normalized[..len])
        // LAW10: normalization writes only ASCII bytes; invalid UTF-8 is structurally impossible and conservative `false` cannot admit a candidate.
        .ok()
        .is_some_and(normalized_assignment_keyword_is_credential)
}

pub(crate) fn assignment_keyword_for_line(line: &str) -> Option<String> {
    if let Some(tag) = xml_assignment_tag(line) {
        return normalize_assignment_keyword(tag);
    }
    let mut fallback = None;
    for (sep_pos, _) in line
        .char_indices()
        .rev()
        .filter(|(_, ch)| matches!(ch, '=' | ':'))
    {
        let lhs = &line[..sep_pos];
        let Some(key) = lhs
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
            .find(|part| !part.is_empty())
        else {
            continue;
        };
        let Some(normalized) = normalize_assignment_keyword(key) else {
            continue;
        };
        if normalized_assignment_keyword_is_credential(&normalized) {
            return Some(normalized);
        }
        if fallback.is_none() {
            fallback = Some(normalized);
        }
    }
    fallback
}

pub(crate) fn normalized_assignment_keyword_is_credential(normalized: &str) -> bool {
    let separated_secret_suffix = normalized.contains('_')
        && matches!(
            normalized.rsplit('_').next(),
            // `pass` is the `*_PASS=` credential-env stem (the dominant CredData
            // shape, e.g. `SES_PASS=`, `DB_PASS=`). The `_`-separated-SUFFIX
            // requirement is the left boundary: `bypass`/`compass` (no `_`) and
            // `CI_BYPASS` (suffix `bypass`) never match, so only a genuine
            // `<name>_PASS=` assignment is promoted. Mirrors the `pass` prefilter
            // stem in `assignment_keywords::PASS_STEM` (ONE intent, both paths).
            Some("key" | "secret" | "token" | "password" | "passwd" | "pwd" | "pass")
        );
    if separated_secret_suffix {
        return true;
    }

    let mut compact = [0u8; 128];
    let mut len = 0usize;
    for byte in normalized.bytes().filter(|byte| *byte != b'_') {
        if len == compact.len() {
            return compact_normalized_assignment_keyword_is_credential_slow(normalized);
        }
        compact[len] = byte.to_ascii_lowercase();
        len += 1;
    }
    compact_assignment_keyword_bytes_are_credential(&compact[..len])
}

/// True when an assignment key names a PASSWORD-FAMILY credential slot: it
/// contains `password`/`pwd`, OR its last separator-delimited segment is exactly
/// `pass` (the dominant `*_PASS=` CredData credential-env stem, e.g. `SES_PASS`,
/// `DB_PASS`, `app.pass`). The last-segment requirement is the boundary that
/// keeps `bypass`/`compass`/`encompass` (no separator before `pass`) and
/// `*_PASSING` (segment `passing`, not `pass`) out. ONE PLACE for the
/// password-family keyword test shared by entropy policy resolution and the
/// keyword-context detector classifier, so those paths cannot drift on which
/// keys are passwords.
pub(crate) fn keyword_is_password_family(keyword: &str) -> bool {
    use crate::ascii_ci::ci_find;
    let bytes = keyword.as_bytes();
    if ci_find(bytes, b"password") || ci_find(bytes, b"pwd") {
        return true;
    }
    keyword
        .rsplit(|c: char| matches!(c, '_' | '-' | '.'))
        .next()
        .is_some_and(|segment| segment.eq_ignore_ascii_case("pass"))
}

/// Parse the requested field of the Tier-B credential-keyword vocabulary
/// `rules/credential-keywords.toml`, leaking each keyword to `&'static [u8]` (a
/// one-time init, conceptually static data) so the loaded list keeps the exact
/// `&[u8]` element type the byte-exact membership checks below and the shared
/// `entropy::scanner::KEY_MATERIAL_ANCHORS` lift gate consume, no caller type
/// change vs the former inline `&[&[u8]]` consts. Fails closed on invalid/empty.
fn parse_credential_keyword_field(key_material: bool) -> Vec<&'static [u8]> {
    #[derive(serde::Deserialize)]
    struct Vocab {
        compact: Vec<String>,
        key_material: Vec<String>,
    }
    let raw = include_str!("../../../../rules/credential-keywords.toml");
    let vocab: Vocab = match toml::from_str(raw) {
        Ok(vocab) => vocab,
        Err(error) => panic!(
            "rules/credential-keywords.toml is invalid: {error}. \
             Fix the bundled Tier-B credential-keyword vocabulary."
        ),
    };
    let list = if key_material {
        vocab.key_material
    } else {
        vocab.compact
    };
    assert!(
        !list.is_empty(),
        "rules/credential-keywords.toml must list the {} credential keywords",
        if key_material {
            "key-material"
        } else {
            "compact"
        }
    );
    list.into_iter()
        .map(|word| &*word.into_bytes().leak())
        .collect()
}

/// Broad credential-keyword vocabulary, the single Tier-B owner
/// (`rules/credential-keywords.toml` `compact` list; was an inline `&[&[u8]]`).
static CREDENTIAL_COMPACT_KEYWORDS: LazyLock<Vec<&'static [u8]>> =
    LazyLock::new(|| parse_credential_keyword_field(false));

/// Explicit cryptographic key-material vocabulary. Canonical owner shared by the
/// broad compact credential membership check above AND the entropy
/// canonical-shape lift anchors (`entropy::scanner::KEY_MATERIAL_ANCHORS`), so a
/// new key-material word reaches BOTH gates instead of being pasted twice and
/// drifting. Both membership predicates chain this list, so it participates in
/// the compact credential check exactly as if it were still inlined. Now the
/// Tier-B `rules/credential-keywords.toml` `key_material` list (was inline).
pub(crate) static KEY_MATERIAL_COMPACT_KEYWORDS: LazyLock<Vec<&'static [u8]>> =
    LazyLock::new(|| parse_credential_keyword_field(true));

fn compact_assignment_keyword_bytes_are_credential(compact: &[u8]) -> bool {
    CREDENTIAL_COMPACT_KEYWORDS
        .iter()
        .chain(KEY_MATERIAL_COMPACT_KEYWORDS.iter())
        .any(|keyword| *keyword == compact)
        || compact.ends_with(b"salt")
        || compact.ends_with(b"nonce")
        || compact.ends_with(b"seed")
}

fn compact_normalized_assignment_keyword_is_credential_slow(normalized: &str) -> bool {
    CREDENTIAL_COMPACT_KEYWORDS
        .iter()
        .chain(KEY_MATERIAL_COMPACT_KEYWORDS.iter())
        .any(|keyword| compact_normalized_keyword_eq(normalized, keyword))
        || compact_normalized_keyword_ends_with(normalized, b"salt")
        || compact_normalized_keyword_ends_with(normalized, b"nonce")
        || compact_normalized_keyword_ends_with(normalized, b"seed")
}

fn compact_normalized_keyword_eq(normalized: &str, needle: &[u8]) -> bool {
    let mut bytes = normalized
        .bytes()
        .filter(|byte| *byte != b'_')
        .map(|byte| byte.to_ascii_lowercase());
    for &expected in needle {
        if bytes.next() != Some(expected) {
            return false;
        }
    }
    bytes.next().is_none()
}

fn compact_normalized_keyword_ends_with(normalized: &str, suffix: &[u8]) -> bool {
    let mut suffix_index = suffix.len();
    for byte in normalized
        .bytes()
        .rev()
        .filter(|byte| *byte != b'_')
        .map(|byte| byte.to_ascii_lowercase())
    {
        if suffix_index == 0 {
            return true;
        }
        suffix_index -= 1;
        if byte != suffix[suffix_index] {
            return false;
        }
    }
    suffix_index == 0
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

pub(crate) fn authorization_header_value(line: &str) -> Option<&str> {
    let (name, rhs) = line.trim().split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("authorization") {
        return None;
    }
    let rhs = rhs.trim();
    // Match the scheme case-insensitively against the raw bytes instead of
    // allocating a full lowercase copy of the header value per line (Law 7:
    // authorization_header_value runs in the per-line entropy keyword scan).
    // Byte-identical: the schemes are ASCII, and the returned token is sliced
    // from `rhs` (not the lowercased copy), so `lower.starts_with("bearer ")`
    // holds iff the raw bytes start with `bearer ` ignoring ASCII case. The 7/6
    // byte offsets are char boundaries because the matched prefix is all ASCII.
    let bytes = rhs.as_bytes();
    let token = if crate::ascii_ci::starts_with_ignore_ascii_case(bytes, b"bearer ") {
        &rhs[7..]
    } else if crate::ascii_ci::starts_with_ignore_ascii_case(bytes, b"basic ") {
        &rhs[6..]
    } else {
        return None;
    };
    token.split_whitespace().next()
}

/// Parse an `<tag>value</tag>` assignment line ONCE, returning the tag name and
/// the trimmed inner value. Single owner of the open-tag + close-tag scan that
/// `xml_assignment_tag` and `xml_assignment_value` previously each ran. `value`
/// re-found the `<`, the `>`, and re-ran the close-tag search the tag parse had
/// already computed. The close-tag search is zero-alloc (matches `</` + tag-name
/// + `>` instead of building a `format!("</{tag}>")` needle) and runs exactly once.
fn parse_xml_assignment(line: &str) -> Option<(&str, &str)> {
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
    // Value starts just past the open tag's `>`. `find_xml_close_tag` returns the
    // offset relative to that slice, so the value is `[value_start, value_start+rel)`.
    let value_start = start + 1 + tag_end + 1;
    let close_rel = find_xml_close_tag(&trimmed[value_start..], tag)?;
    Some((tag, trimmed[value_start..value_start + close_rel].trim()))
}

pub(crate) fn xml_assignment_tag(line: &str) -> Option<&str> {
    parse_xml_assignment(line).map(|(tag, _)| tag)
}

pub(crate) fn xml_assignment_value(line: &str) -> Option<&str> {
    let (tag, value) = parse_xml_assignment(line)?;
    let normalized = normalize_assignment_keyword(tag)?;
    normalized_assignment_keyword_is_credential(&normalized).then_some(value)
}

/// Byte offset of the `</tag>` closing tag within `haystack`, or `None`.
/// Replaces `haystack.find(&format!("</{tag}>"))` with no per-call allocation:
/// `tag` is a tag NAME (it stopped at `>` and was split on whitespace, so it
/// contains no `<`/`>`/space), so matching `</` + the exact name bytes + `>`
/// from each `<` is byte-for-byte equivalent to substring-finding the formatted
/// `</tag>` needle.
fn find_xml_close_tag(haystack: &str, tag: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let tag_bytes = tag.as_bytes();
    let mut cursor = 0;
    while let Some(rel) = memchr::memchr(b'<', &bytes[cursor..]) {
        // SAFETY: `cursor` starts at 0 and is only advanced to `open + 1` where
        // `open = cursor + rel` and `rel < bytes.len() - cursor` (guaranteed by memchr);
        // therefore `cursor <= bytes.len()` always holds and the slice is valid.
        let open = cursor + rel;
        let name_start = open + 2;
        let name_end = name_start + tag_bytes.len();
        if bytes.get(open + 1) == Some(&b'/')
            && bytes.get(name_start..name_end) == Some(tag_bytes)
            && bytes.get(name_end) == Some(&b'>')
        {
            return Some(open);
        }
        cursor = open + 1;
    }
    None
}

pub(crate) fn is_likely_concatenation_fragment(line: &str) -> bool {
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
