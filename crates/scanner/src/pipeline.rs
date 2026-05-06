use crate::context;
use crate::types::*;
use keyhog_core::{Chunk, MatchLocation, RawMatch};
use std::borrow::Cow;
use std::collections::HashMap;

pub fn build_raw_match(
    detector: &keyhog_core::DetectorSpec,
    chunk: &Chunk,
    credential: &str,
    companions: HashMap<String, String>,
    offset: usize,
    line: usize,
    ent: f64,
    confidence: f64,
    scan_state: &mut ScanState,
) -> RawMatch {
    // Diff-aware severity: a credential whose only sighting is in non-HEAD
    // git history (the developer already removed it from `main`) is still
    // a leak — but it's strictly less urgent than a credential live in HEAD
    // that an attacker can grep right now. Drop one tier when the source
    // backend tagged this chunk as `git/history`. Everything else (live
    // filesystem, `git/head`, S3/Docker/Web/etc) keeps the detector's
    // declared severity.
    let severity = if chunk.metadata.source_type == "git/history" {
        detector.severity.downgrade_one()
    } else {
        detector.severity
    };
    RawMatch {
        detector_id: scan_state.intern_metadata(&detector.id),
        detector_name: scan_state.intern_metadata(&detector.name),
        service: scan_state.intern_metadata(&detector.service),
        severity,
        credential_hash: crate::sha256_hash(credential),
        credential: scan_state.intern_credential(credential),
        companions,
        location: MatchLocation {
            source: scan_state.intern_metadata(&chunk.metadata.source_type),
            file_path: chunk
                .metadata
                .path
                .as_ref()
                .map(|p| scan_state.intern_metadata(p)),
            line: Some(line),
            offset: offset + chunk.metadata.base_offset,
            commit: chunk
                .metadata
                .commit
                .as_ref()
                .map(|c| scan_state.intern_metadata(c)),
            author: chunk
                .metadata
                .author
                .as_ref()
                .map(|a| scan_state.intern_metadata(a)),
            date: chunk
                .metadata
                .date
                .as_ref()
                .map(|d| scan_state.intern_metadata(d)),
        },
        entropy: Some(ent),
        confidence: Some(confidence),
    }
}

pub fn local_context_window(text: &str, line: usize, radius: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let start = line.saturating_sub(radius).saturating_sub(1);
    let end = (line + radius).min(lines.len());
    lines[start..end].join("\n")
}

/// Compute the byte offsets for every line in a string.
pub fn compute_line_offsets(text: &str) -> Vec<usize> {
    let mut offsets = vec![0];
    for (idx, _) in text.match_indices('\n') {
        offsets.push(idx + 1);
    }
    offsets
}

pub fn match_line_number(
    preprocessed: &ScannerPreprocessedText,
    line_offsets: &[usize],
    offset: usize,
) -> usize {
    preprocessed.line_for_offset(offset).unwrap_or_else(|| {
        line_offsets
            .iter()
            .position(|&lo| lo > offset)
            .unwrap_or(line_offsets.len())
    })
}

pub fn normalize_scannable_chunk<'a>(chunk: &'a Chunk, owned: &'a mut Option<Chunk>) -> &'a Chunk {
    let normalized = crate::normalize_chunk_data(&chunk.data);
    if let Cow::Owned(data) = normalized {
        *owned = Some(Chunk {
            data: data.into(),
            metadata: chunk.metadata.clone(),
        });
        owned.as_ref().unwrap_or(chunk)
    } else {
        chunk
    }
}

fn upper_contains_token(upper: &str, token: &str) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        let before = idx.checked_sub(1).and_then(|i| upper.chars().nth(i));
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

    let known_prefix_body = known_prefix_body(credential);
    if let Some(body) = known_prefix_body {
        if looks_like_prefixed_masked_sequence(body) {
            return true;
        }
        return false;
    }

    // ── 3. Repetitive masking patterns ──
    // 5+ consecutive 'x' or 'X' (e.g., xxxxx, XXXXXXX) — masks and placeholders.
    // 3x can appear in real base64/hex, so only suppress longer runs.
    if upper.contains("XXXXX") {
        return true;
    }
    // 5+ consecutive identical characters in any credential, or 3+ in short credentials.
    // Real secrets can have short runs (e.g., "000" in base64) but rarely 5+.
    if credential.len() < 20 && has_three_or_more_consecutive_identical(credential) {
        return true;
    }
    if has_n_or_more_consecutive_identical(credential, 5) {
        return true;
    }
    if has_repeated_block_mask(credential) {
        return true;
    }
    // Entirely filler symbols
    if credential
        .chars()
        .all(|c| c == 'x' || c == 'X' || c == '*' || c == '-' || c == '.')
    {
        return true;
    }
    // Purely symbolic strings that look like filler/placeholder
    // (e.g., "********", "--------") — NOT real passwords like "!@#$%^&*()"
    if credential.len() >= 8
        && credential.chars().all(|c| !c.is_alphanumeric())
        && credential
            .chars()
            .collect::<std::collections::HashSet<_>>()
            .len()
            <= 2
    {
        return true;
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

    // ── 6. Algorithmic placeholder detection ──
    // Credentials dominated by filler after stripping known prefixes.
    if crate::context::is_known_example_credential(credential) {
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
        let lower_path = path.to_lowercase();
        let is_example_path = lower_path.split(['/', '\\']).any(|component| {
            matches!(
                component,
                "example" | "examples" | "test" | "tests" | "fixture" | "fixtures"
            )
        });
        if is_example_path && upper_contains_token(&upper, "EXAMPLE") {
            return true;
        }
    }
    false
}

/// Return true if the credential contains three or more consecutive identical characters.
fn has_three_or_more_consecutive_identical(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        let mut run = 1;
        while chars.peek() == Some(&ch) {
            run += 1;
            chars.next();
        }
        if run >= 3 {
            return true;
        }
    }
    false
}

fn known_prefix_body(credential: &str) -> Option<&str> {
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "sk_live_",
        "sk_test_",
        "pk_live_",
        "pk_test_",
        "rk_live_",
        "AKIA",
        "ASIA",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxr-",
        "sk-proj-",
        "sk-ant-",
        "SG.",
        "hf_",
        "npm_",
        "pypi-",
        "glpat-",
        "dop_v1_",
        "PRIVATE KEY",
        "eyJ",
    ];
    PREFIXES
        .iter()
        .find_map(|prefix| credential.strip_prefix(prefix))
}

fn looks_like_prefixed_masked_sequence(body: &str) -> bool {
    let upper = body.to_ascii_uppercase();
    let starts_with_mask = upper.starts_with("XXX") || upper.starts_with("***");
    let contains_fake_sequence = ["1234567890", "0123456789", "ABCDEFGH", "ABCDEFGHIJ"]
        .iter()
        .any(|seq| upper.contains(seq));
    starts_with_mask && contains_fake_sequence
}

fn has_repeated_block_mask(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    let mut long_runs = 0usize;
    while let Some(ch) = chars.next() {
        let mut run = 1usize;
        while chars.peek() == Some(&ch) {
            run += 1;
            chars.next();
        }
        if run >= 4 && ch.is_ascii_alphanumeric() {
            long_runs += 1;
            if long_runs >= 3 {
                return true;
            }
        }
    }
    false
}

fn has_n_or_more_consecutive_identical(s: &str, n: usize) -> bool {
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        let mut run = 1;
        while chars.peek() == Some(&ch) {
            run += 1;
            chars.next();
        }
        // Dashes are legitimate delimiters in structured formats (PEM headers,
        // UUIDs, JWT separators). Don't count them as repetitive masking.
        if run >= n && ch != '-' {
            return true;
        }
    }
    false
}

pub fn find_companion(
    preprocessed: &ScannerPreprocessedText,
    primary_line: usize,
    companion: &CompiledCompanion,
) -> Option<String> {
    let start = primary_line.saturating_sub(companion.within_lines);
    let end = primary_line.saturating_add(companion.within_lines);
    let (window_start, window_end) =
        line_window_offsets(preprocessed, start + FIRST_LINE_NUMBER, end)?;
    // Defensive: `line_window_offsets` returns offsets relative to the
    // line index, but the underlying text may have been truncated
    // mid-scan (windowed mode, decoded chunk shorter than original)
    // so the offsets can exceed `text.len()`. Use `get` to bail out
    // cleanly instead of panicking on a `&str[..]` slice — a single
    // bogus companion lookup must never crash a worker.
    let haystack = preprocessed.text.get(window_start..window_end)?;
    let group = companion
        .capture_group
        .unwrap_or(FIRST_CAPTURE_GROUP_INDEX);
    let line_range = (start + FIRST_LINE_NUMBER)..=end;

    // Capture-group fast path: when the regex has no groups, `find_iter` is
    // strictly cheaper than `captures_iter` — `find` allocates no
    // `Captures` object per iteration. The previous unconditional
    // `captures_iter` paid for that allocation on every match across every
    // companion lookup in every scan.
    if companion.capture_group.is_none() {
        for m in companion.regex.find_iter(haystack) {
            if m.len() > 4096 {
                continue;
            }
            if let Some(line) = preprocessed.line_for_offset(window_start + m.start()) {
                if line_range.contains(&line) {
                    return Some(m.as_str().to_string());
                }
            }
        }
        return None;
    }

    // Capture-group path: reuse one `CaptureLocations` buffer across every
    // iter tick. `captures_iter` allocates a fresh `Captures` per match;
    // `captures_read_at` writes into the borrowed buffer instead.
    let mut locs = companion.regex.capture_locations();
    let mut cursor = 0usize;
    let bytes_total = haystack.len();
    while cursor <= bytes_total {
        let Some(whole) = companion
            .regex
            .captures_read_at(&mut locs, haystack, cursor)
        else {
            break;
        };
        // Advance the cursor before any branch that might `continue`, to
        // keep the loop monotonic. Zero-width matches bump by one byte
        // and we then align onto a UTF-8 boundary — `captures_read_at`'s
        // behavior is unspecified at non-boundary positions, so we must
        // never feed it one.
        let mut next = if whole.end() == cursor {
            cursor + 1
        } else {
            whole.end()
        };
        while next < bytes_total && !haystack.is_char_boundary(next) {
            next += 1;
        }
        let prev_cursor = cursor;
        cursor = next;

        if let Some((s, e)) = locs.get(group) {
            if e.saturating_sub(s) <= 4096 {
                if let Some(line) = preprocessed.line_for_offset(window_start + s) {
                    if line_range.contains(&line) {
                        return Some(haystack[s..e].to_string());
                    }
                }
            }
        }
        let _ = prev_cursor; // borrowck scope marker; cursor is already updated
    }
    None
}

pub fn line_window_offsets(
    preprocessed: &ScannerPreprocessedText,
    start_line: usize,
    end_line: usize,
) -> Option<(usize, usize)> {
    let mut start_offset = None;
    let mut end_offset = None;

    for mapping in &preprocessed.mappings {
        if start_offset.is_none() && mapping.line_number >= start_line {
            start_offset = Some(mapping.start_offset);
        }
        if mapping.line_number <= end_line {
            end_offset = Some(mapping.end_offset);
        }
    }

    Some((start_offset?, end_offset?))
}

pub fn is_within_hex_context(data: &str, match_start: usize, match_end: usize) -> bool {
    if !valid_match_bounds(data, match_start, match_end) {
        return false;
    }
    let matched = &data[match_start..match_end];
    let matched_hex_digits = matched.chars().filter(|c| c.is_ascii_hexdigit()).count();
    if matched.len() < MIN_HEX_MATCH_LEN || matched_hex_digits < MIN_HEX_DIGITS_IN_MATCH {
        return false;
    }
    let (before, after) = surrounding_hex_context(data, match_start, match_end);
    let hex_before = formatted_hex_run(before.chars().rev());
    let hex_after = formatted_hex_run(after.chars());
    hex_before >= MIN_HEX_CONTEXT_DIGITS && hex_after >= MIN_HEX_CONTEXT_DIGITS
}

fn valid_match_bounds(data: &str, match_start: usize, match_end: usize) -> bool {
    match_end > match_start
        && data.is_char_boundary(match_start)
        && data.is_char_boundary(match_end)
}

fn surrounding_hex_context(data: &str, match_start: usize, match_end: usize) -> (&str, &str) {
    let context_start = crate::engine::floor_char_boundary(
        data,
        match_start.saturating_sub(HEX_CONTEXT_RADIUS_CHARS),
    );
    let context_end = {
        let mut end = (match_end + HEX_CONTEXT_RADIUS_CHARS).min(data.len());
        while end < data.len() && !data.is_char_boundary(end) {
            end += 1;
        }
        end.min(data.len())
    };
    (
        &data[context_start..match_start],
        &data[match_end..context_end],
    )
}

fn formatted_hex_run(iter: impl Iterator<Item = char>) -> usize {
    let mut hex_digits = 0usize;
    let mut separators = 0usize;
    let mut seen_hex = false;

    for ch in iter {
        if ch.is_ascii_hexdigit() {
            hex_digits += 1;
            seen_hex = true;
            continue;
        }
        if matches!(ch, ' ' | '\t' | ':' | '-')
            && (!seen_hex || separators < MAX_HEX_CONTEXT_SEPARATORS)
        {
            separators += 1;
            continue;
        }
        break;
    }

    hex_digits
}

pub fn match_entropy(data: &[u8]) -> f64 {
    #[cfg(feature = "entropy")]
    {
        crate::entropy::shannon_entropy(data)
    }

    #[cfg(not(feature = "entropy"))]
    {
        fallback_entropy(data)
    }
}

#[cfg(not(feature = "entropy"))]
fn fallback_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}
