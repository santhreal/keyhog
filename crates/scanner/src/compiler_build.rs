//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::Result;
use crate::types::*;
use keyhog_core::DetectorSpec;

use super::compiler_prefix::{extract_inner_literals, extract_literal_prefixes};

use super::compiler_compile::{compile_detector_companions, compile_pattern};

pub struct CompileState {
    pub ac_literals: Vec<String>,
    pub ac_map: Vec<CompiledPattern>,
    pub fallback: Vec<(CompiledPattern, Vec<String>)>,
    pub companions: Vec<Vec<CompiledCompanion>>,
    pub quality_warnings: Vec<String>,
}

pub fn build_compile_state(detectors: &[DetectorSpec]) -> Result<CompileState> {
    use rayon::prelude::*;
    use std::collections::HashMap;

    // De-duplicate identical regex strings BEFORE compilation. The 888-
    // detector corpus has ~6-15% duplicate patterns (e.g. multiple
    // google-* detectors share the `AIza` regex shape). Compiling each
    // once cuts startup-compile time and RAM proportionally - see
    // audits/legendary-2026-04-26.
    let unique_patterns: HashMap<String, ()> = detectors
        .iter()
        .flat_map(|d| d.patterns.iter().map(|p| (p.regex.clone(), ())))
        .collect();
    tracing::debug!(
        unique = unique_patterns.len(),
        "compiler dedup: unique pattern regexes"
    );

    // Phase 1: Pre-compile all regexes in parallel (the expensive part).
    let compiled_results: Vec<Result<(Vec<CompiledPattern>, Vec<CompiledCompanion>)>> = detectors
        .par_iter()
        .enumerate()
        .map(|(detector_index, detector)| {
            let companions = compile_detector_companions(detector)?;
            let mut patterns = Vec::new();
            for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
                patterns.push(compile_pattern(
                    detector_index,
                    pattern_index,
                    pattern,
                    &detector.id,
                )?);
            }
            Ok((patterns, companions))
        })
        .collect();

    // Phase 2: Assemble results sequentially (fast, no regex compilation).
    let mut ac_literals = Vec::new();
    let mut ac_map = Vec::new();
    let mut fallback = Vec::new();
    let mut companions = Vec::with_capacity(detectors.len());
    let mut quality_warnings = Vec::new();

    for (detector_index, (result, detector)) in compiled_results
        .into_iter()
        .zip(detectors.iter())
        .enumerate()
    {
        let (compiled_patterns, detector_companions) = result?;
        companions.push(detector_companions);

        for (pattern_index, (compiled, pattern)) in compiled_patterns
            .into_iter()
            .zip(detector.patterns.iter())
            .enumerate()
        {
            let prefixes = extract_literal_prefixes(&pattern.regex);

            // Homoglyph expansion for high-confidence patterns: catches
            // tokens where the literal prefix has been visually spoofed
            // with Cyrillic/Greek/full-width lookalikes. Earlier code
            // dropped just the expanded PREFIX into fallback as
            // `Regex::new("^[hh][ff]_")` - anchored to start, but with
            // NO body constraint, so any string beginning with the
            // prefix would match. Combined with the task #69 fallback
            // wire fix that finally runs these patterns, that turned
            // every prefix-anchored detector into "fires on `<prefix>*`."
            // Fix: substitute the expanded prefix into the FULL regex so
            // the homoglyph variant still requires the rest of the
            // pattern to match.
            for prefix in &prefixes {
                if prefix.len() < 3 {
                    continue;
                }
                let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
                if expanded_prefix == *prefix {
                    continue;
                }
                let full_homoglyph_regex =
                    if let Some(suffix) = pattern.regex.strip_prefix(prefix.as_str()) {
                        // Simple case: prefix is the literal head of the regex.
                        format!("{expanded_prefix}{suffix}")
                    } else if let Some(rewritten) =
                        rewrite_alternation_prefix(&pattern.regex, &expanded_prefix)
                    {
                        // Alternation case: regex is `(?:p1|p2|...)body`. Replace
                        // the leading `(?:...)` with the expanded prefix so the
                        // homoglyph variant still requires the rest of the pattern
                        // to match. Without this, every alternation-prefix detector
                        // silently skipped its homoglyph fallback - leaving
                        // Cyrillic/full-width spoofed credentials of the form
                        // `[ɡ̅р][hн]p_<body>` invisible to the scanner.
                        rewritten
                    } else {
                        // Prefix appears in the parse tree but isn't a leading
                        // literal slice and isn't a trivially-rewritable alternation
                        // (e.g. it sits inside a nested group). Skip - there's no
                        // safe text rewrite we can do here.
                        continue;
                    };
                // Deferred like every other pattern: build the homoglyph
                // variant's Regex on first use, not here. The old eager
                // `Regex::new` doubled as a validity gate (skip-if-Err); the
                // lazy path's never-match fallback covers a non-compiling
                // variant instead, so a bad expansion simply never fires
                // rather than being silently dropped at build.
                fallback.push((
                    CompiledPattern {
                        detector_index,
                        regex: LazyRegex::plain(full_homoglyph_regex),
                        group: pattern.group,
                        client_safe: pattern.client_safe,
                    },
                    detector.keywords.clone(),
                ));
            }

            if !prefixes.is_empty() {
                for prefix in prefixes {
                    ac_literals.push(prefix);
                    ac_map.push(compiled.clone());
                }
            } else {
                // Prefix extraction failed - try the AST-walking inner-literal
                // extractor before falling back. Patterns like
                // `[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}` have no leading literal
                // but contain `_AKIA` mid-pattern; pulling that into the AC
                // moves the detector out of the O(m × n) fallback loop and
                // into the O(n) prefilter path.
                let inner = extract_inner_literals(&pattern.regex);
                if !inner.is_empty() {
                    for lit in inner {
                        ac_literals.push(lit);
                        ac_map.push(compiled.clone());
                    }
                } else {
                    if detector.keywords.is_empty() {
                        quality_warnings.push(format!(
                            "Detector {} pattern {pattern_index} has no literal prefix and no keywords.",
                            detector.id
                        ));
                    }
                    fallback.push((compiled, detector.keywords.clone()));
                }
            }
        }
    }

    Ok(CompileState {
        ac_literals,
        ac_map,
        fallback,
        companions,
        quality_warnings,
    })
}

/// If `regex` is `(?:p1|p2|...)body` (with optional inline flags / `?:`
/// variants), replace the leading alternation group with `expanded_prefix`.
/// Returns the rewritten regex source; returns `None` if the regex doesn't
/// start with a non-capturing alternation group we know how to rewrite.
///
/// This is the homoglyph counterpart of `extract_literal_prefixes`'s
/// alternation handling - when the prefix extractor returned a literal
/// from inside `(?:ghp_|github_pat_)`, the homoglyph compiler needs the
/// matching surgical rewrite to splice the expanded prefix into the
/// regex without losing the trailing body constraint.
pub fn rewrite_alternation_prefix(regex: &str, expanded_prefix: &str) -> Option<String> {
    // Strip a leading inline flag group like `(?i)`.
    let (flag_prefix, body) = split_leading_inline_flag(regex);
    // Only consider non-capturing groups - `(?:p1|p2|...)`. A bare
    // `(...)` is a capturing group around the whole credential, NOT an
    // alternation of prefixes; rewriting it as "{expanded_prefix}{suffix}"
    // would drop the credential body and leave a regex that matches just
    // the prefix. That was the flutterwave false-positive on negative:
    // `(FLWSECK_(?:TEST|LIVE)-[a-f0-9]{32,64}-X)` got rewritten to
    // `FLW[SСＳ][EЕΕＥ]C[KКΚＫ]_` which then matched bare `FLWSECK_`
    // anywhere in the text.
    let group_open_end = if let Some(rest) = body.strip_prefix("(?:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?i:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?m:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?s:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?im:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?is:") {
        body.len() - rest.len()
    } else if let Some(rest) = body.strip_prefix("(?ms:") {
        body.len() - rest.len()
    } else {
        // Bare `(` or no leading group - refuse to rewrite. The simple
        // strip_prefix path in the caller handles literal-head regexes;
        // this function is strictly for `(?:...)` alternation prefixes.
        return None;
    };
    // Find the matching closing `)` for the leading group.
    let bytes = body.as_bytes();
    let mut depth: i32 = 0;
    let mut close_at: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close_at = Some(i);
                    break;
                }
            }
            // Don't track escapes - we only need to find the *top-level*
            // closing paren, and within a regex source a literal `(` or
            // `)` inside a character class is rare in real detectors.
            _ => {}
        }
    }
    let close = close_at?;
    // The leading group must actually contain a `|` - without one this
    // is just `(?:singleton)pattern`, not an alternation, and rewriting
    // would silently drop the singleton body.
    let inside = &body[group_open_end..close];
    if !inside.contains('|') {
        return None;
    }
    // Trailing body after the alternation group.
    let suffix = &body[close + 1..];
    Some(format!("{flag_prefix}{expanded_prefix}{suffix}"))
}

pub fn split_leading_inline_flag(s: &str) -> (&str, &str) {
    if !s.starts_with("(?") {
        return ("", s);
    }
    let bytes = s.as_bytes();
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        (&s[..=i], &s[i + 1..])
    } else {
        ("", s)
    }
}
