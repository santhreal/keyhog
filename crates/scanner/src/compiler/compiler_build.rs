//! Logic for compiling detector specifications into an efficient scanning engine.

use crate::error::{Result, ScanError};
use crate::types::*;
use keyhog_core::DetectorSpec;

use super::compiler_prefix::{
    extract_literal_prefixes, is_escaped_literal, split_leading_boundary_guard,
};

use super::compiler_compile::{compile_detector_companions, compile_pattern};

pub(crate) struct CompileState {
    pub(crate) ac_literals: Vec<String>,
    pub(crate) ac_map: Vec<CompiledPattern>,
    pub(crate) phase2_patterns: Vec<(CompiledPattern, Vec<String>)>,
    pub(crate) companions: Vec<Vec<CompiledCompanion>>,
    pub(crate) quality_warnings: Vec<String>,
}

pub(crate) fn validate_compiled_pattern_detector_indices(
    ac_map: &[CompiledPattern],
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
    detectors_len: usize,
) -> Result<()> {
    for (pattern_index, pattern) in ac_map.iter().enumerate() {
        validate_compiled_pattern_detector_index("ac_map", pattern_index, pattern, detectors_len)?;
    }
    for (pattern_index, (pattern, _keywords)) in phase2_patterns.iter().enumerate() {
        validate_compiled_pattern_detector_index(
            "phase2_patterns",
            pattern_index,
            pattern,
            detectors_len,
        )?;
    }
    Ok(())
}

fn validate_compiled_pattern_detector_index(
    table: &'static str,
    pattern_index: usize,
    pattern: &CompiledPattern,
    detectors_len: usize,
) -> Result<()> {
    if pattern.detector_index >= detectors_len {
        return Err(ScanError::CompiledPatternDetectorIndex {
            table,
            pattern_index,
            detector_index: pattern.detector_index,
            detectors_len,
        });
    }
    Ok(())
}

pub(crate) fn phase2_always_active_indices(
    phase2_patterns: &[(CompiledPattern, Vec<String>)],
) -> Vec<usize> {
    phase2_patterns
        .iter()
        .enumerate()
        // Mirrors `build_phase2_keyword_ac`'s 4-char floor. The experimental
        // 3-char floor regressed F1, so both checks stay at 4.
        .filter_map(|(index, (_, keywords))| {
            (!keywords.iter().any(|keyword| keyword.len() >= 4)).then_some(index)
        })
        .collect()
}

/// The one routing decision produced for a compiled detector pattern.
/// Detector-declared literals are authoritative; otherwise only a leading
/// literal encoded directly in the regex can enter phase one.
enum PatternRoute {
    DetectorRequired(Vec<String>),
    LiteralPrefix(Vec<String>),
    Phase2 {
        keywords: Vec<String>,
        warn_missing_anchor: bool,
    },
}

impl PatternRoute {
    fn ac_literals(&self) -> Option<&[String]> {
        match self {
            Self::DetectorRequired(literals) | Self::LiteralPrefix(literals) => Some(literals),
            Self::Phase2 { .. } => None,
        }
    }
}

/// Everything the serial assembly phase needs for one compiled pattern, all
/// derived inside the parallel compile map. The typed route prevents detector
/// declarations, regex prefixes, and phase two from becoming competing owners.
struct PatternArtifacts {
    compiled: CompiledPattern,
    route: PatternRoute,
    homoglyph_variants: Vec<CompiledPattern>,
}

fn append_ac_pattern(
    ac_literals: &mut Vec<String>,
    ac_map: &mut Vec<CompiledPattern>,
    literals: &[String],
    pattern: &CompiledPattern,
) {
    for literal in literals {
        ac_literals.push(literal.clone());
        ac_map.push(pattern.clone());
    }
}

/// Minimum byte length of a literal prefix before it is worth generating a
/// homoglyph phase-2 variant. A 1-2 byte prefix carries too little signal: its
/// homoglyph expansion would broaden the AC set for almost no spoof-coverage
/// gain. A homoglyph variant still splices back into the full regex, so its
/// three-byte prefix remains selective enough for phase two.
pub(crate) const MIN_HOMOGLYPH_PREFIX_LEN: usize = 3;

pub(crate) fn build_compile_state(detectors: &[DetectorSpec]) -> Result<CompileState> {
    use rayon::prelude::*;

    // De-duplicate identical regex strings BEFORE compilation. The 888-
    // detector corpus has ~6-15% duplicate patterns (e.g. multiple
    // google-* detectors share the `AIza` regex shape). Compiling each
    // once cuts startup-compile time and RAM proportionally - see
    // the internal design notes.
    //
    // The count is informational only (one debug log line), so gate the
    // whole computation behind the DEBUG level check and borrow the regex
    // sources instead of cloning them. Under any non-debug level this is
    // zero allocation - it used to heap-clone ~1000+ regex source strings
    // into an owned HashMap on every scanner construction (every CLI
    // invocation, every daemon/watch recompile) solely to print the count.
    if tracing::enabled!(tracing::Level::DEBUG) {
        let unique = detectors
            .iter()
            .flat_map(|d| d.patterns.iter().map(|p| p.regex.as_str()))
            .collect::<std::collections::HashSet<&str>>()
            .len();
        tracing::debug!(unique, "compiler dedup: unique pattern regexes");
    }

    // Phase 1: compile every regex AND derive all of its per-pattern artifacts
    // (literal prefixes and homoglyph phase-2 variants) in
    // parallel. The derivation used to live in the serial assembly loop below,
    // where its per-pattern AST parsing and homoglyph DFA compilation dominated
    // cold compile (~430ms over the full corpus on a 22-core box, scaling ~2x
    // with detector count while every core but one idled). It is independent
    // per pattern, so it belongs in the `par_iter`; Phase 2 is now pure
    // assembly (cheap vec pushes, no regex work).
    let compiled_results: Vec<Result<(Vec<PatternArtifacts>, Vec<CompiledCompanion>)>> = detectors
        .par_iter()
        .enumerate()
        .map(|(detector_index, detector)| {
            let companions = compile_detector_companions(detector)?;
            let mut artifacts = Vec::with_capacity(detector.patterns.len());
            for (pattern_index, pattern) in detector.patterns.iter().enumerate() {
                let compiled = compile_pattern(
                    detector_index,
                    pattern_index,
                    pattern,
                    &detector.id,
                    &detector.keywords,
                )?;

                let prefixes = extract_literal_prefixes(&pattern.regex);

                // Homoglyph expansion for patterns with a literal prefix:
                // catches tokens whose prefix is visually spoofed with
                // Cyrillic/Greek/full-width lookalikes. The expanded prefix is
                // substituted back into the FULL regex so the variant still
                // requires the rest of the pattern to match (a bare prefix
                // anchor would turn every detector into "fires on `<prefix>*`").
                let mut homoglyph_variants = Vec::new();
                for prefix in &prefixes {
                    if prefix.len() < MIN_HOMOGLYPH_PREFIX_LEN {
                        continue;
                    }
                    let expanded_prefix = crate::homoglyph::expand_homoglyphs(prefix);
                    if expanded_prefix == *prefix {
                        continue;
                    }
                    // Prefix appears in the parse tree but isn't a leading
                    // literal slice / trivially-rewritable alternation (e.g. it
                    // sits inside a nested group): no safe text rewrite, skip.
                    let Some(full_homoglyph_regex) =
                        rewrite_homoglyph_literal_prefix(&pattern.regex, prefix, &expanded_prefix)
                    else {
                        continue;
                    };
                    let compiled_homoglyph_regex = regex::Regex::new(&full_homoglyph_regex)
                        .map(std::sync::Arc::new)
                        .map_err(|source| ScanError::RegexCompile {
                            detector_id: detector.id.clone(),
                            index: pattern_index,
                            source,
                        })?;
                    homoglyph_variants.push(CompiledPattern {
                        detector_index,
                        regex: LazyRegex::plain_compiled(
                            full_homoglyph_regex,
                            compiled_homoglyph_regex,
                        ),
                        group: pattern.group,
                        client_safe: pattern.client_safe,
                        weak_anchor: pattern.weak_anchor,
                        match_proves_keyword_nearby: false,
                        homoglyph_variant: true,
                    });
                }

                let route = if !pattern.required_literals.is_empty() {
                    PatternRoute::DetectorRequired(pattern.required_literals.clone())
                } else if !prefixes.is_empty() {
                    PatternRoute::LiteralPrefix(prefixes)
                } else {
                    PatternRoute::Phase2 {
                        keywords: detector.keywords.clone(),
                        warn_missing_anchor: detector.keywords.is_empty(),
                    }
                };

                artifacts.push(PatternArtifacts {
                    compiled,
                    route,
                    homoglyph_variants,
                });
            }
            Ok((artifacts, companions))
        })
        .collect();

    // Phase 2: Assemble results sequentially (fast, no regex compilation).
    let mut ac_literals = Vec::new();
    let mut ac_map = Vec::new();
    let mut phase2_patterns = Vec::new();
    let mut companions = Vec::with_capacity(detectors.len());
    let mut quality_warnings = Vec::new();

    // Phase 2 is now a pure drain of the parallel-derived artifacts. Every
    // push preserves deterministic detector-then-pattern order and keeps every
    // variant on the pattern's single selected route.
    for (result, detector) in compiled_results.into_iter().zip(detectors.iter()) {
        let (artifacts, detector_companions) = result?;
        companions.push(detector_companions);

        for (pattern_index, artifact) in artifacts.into_iter().enumerate() {
            let PatternArtifacts {
                compiled,
                route,
                homoglyph_variants,
            } = artifact;

            for homoglyph in homoglyph_variants {
                if let PatternRoute::DetectorRequired(literals) = &route {
                    append_ac_pattern(&mut ac_literals, &mut ac_map, literals, &homoglyph);
                } else {
                    phase2_patterns.push((homoglyph, Vec::new()));
                }
            }

            if let Some(literals) = route.ac_literals() {
                append_ac_pattern(&mut ac_literals, &mut ac_map, literals, &compiled);
            } else if let PatternRoute::Phase2 {
                keywords,
                warn_missing_anchor,
            } = route
            {
                if warn_missing_anchor {
                    quality_warnings.push(format!(
                        "Detector {} pattern {pattern_index} has no literal prefix and no keywords.",
                        detector.id
                    ));
                }
                phase2_patterns.push((compiled, keywords));
            }
        }
    }

    Ok(CompileState {
        ac_literals,
        ac_map,
        phase2_patterns,
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
pub(crate) fn rewrite_alternation_prefix(
    regex: &str,
    prefix: &str,
    expanded_prefix: &str,
) -> Option<String> {
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
    // Find the matching closing `)` for the leading group, using the SAME
    // escape- and char-class-aware discipline as `split_top_level_alternatives`
    // (the two paren scanners in this file must agree). An escaped `\)` or a
    // `)` / `(` inside a `[...]` class is a LITERAL, not a group delimiter:
    // counting it would prematurely balance `depth` and mis-locate the close,
    // then splice a wrong slice, e.g. `(?:a|b\)c)x` with prefix `a` stopped at
    // the escaped `\)` and produced the malformed `{expanded}c)x` (unbalanced
    // paren). Tracking escapes and classes finds the real top-level close, so
    // the rewrite is either correct or cleanly declined (`None`), never wrong.
    let mut depth: i32 = 0;
    let mut close_at: Option<usize> = None;
    let mut in_class = false;
    let mut escaped = false;
    for (idx, ch) in body.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                depth -= 1;
                if depth == 0 {
                    close_at = Some(idx);
                    break;
                }
            }
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
    for alt in split_top_level_alternatives(inside) {
        if let Some(branch_suffix) = alt.strip_prefix(prefix) {
            return Some(format!(
                "{flag_prefix}{expanded_prefix}{branch_suffix}{suffix}"
            ));
        }
    }
    None
}

pub(crate) fn rewrite_homoglyph_literal_prefix(
    regex: &str,
    prefix: &str,
    expanded_prefix: &str,
) -> Option<String> {
    let (flag_prefix, body) = split_leading_inline_flag(regex);
    if let Some(rewritten) = rewrite_homoglyph_body_prefix(body, prefix, expanded_prefix) {
        return Some(format!("{flag_prefix}{rewritten}"));
    }
    if let Some((guard, rest)) = split_leading_boundary_guard(body) {
        if let Some(rewritten) = rewrite_homoglyph_body_prefix(rest, prefix, expanded_prefix) {
            return Some(format!("{flag_prefix}{guard}{rewritten}"));
        }
    }
    rewrite_alternation_prefix(regex, prefix, expanded_prefix)
}

fn rewrite_homoglyph_body_prefix(
    body: &str,
    prefix: &str,
    expanded_prefix: &str,
) -> Option<String> {
    if let Some(suffix) = strip_literal_prefix_source(body, prefix) {
        return Some(format!("{expanded_prefix}{suffix}"));
    }
    let inner = body.strip_prefix('(')?;
    if inner.starts_with('?') {
        return None;
    }
    let suffix = strip_literal_prefix_source(inner, prefix)?;
    Some(format!("({expanded_prefix}{suffix}"))
}

fn strip_literal_prefix_source<'a>(source: &'a str, prefix: &str) -> Option<&'a str> {
    let mut offset = 0usize;
    for wanted in prefix.chars() {
        let rest = source.get(offset..)?;
        let mut chars = rest.char_indices();
        let (_, first) = chars.next()?;
        if first == '\\' {
            let (next_offset, escaped) = chars.next()?;
            if escaped != wanted || !is_escaped_literal(escaped) {
                return None;
            }
            offset += next_offset + escaped.len_utf8();
        } else {
            if first != wanted {
                return None;
            }
            offset += first.len_utf8();
        }
    }
    source.get(offset..)
}

fn split_top_level_alternatives(group: &str) -> Vec<&str> {
    let mut alts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut in_class = false;
    let mut escaped = false;
    for (idx, ch) in group.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth -= 1,
            '|' if depth == 0 && !in_class => {
                alts.push(&group[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    alts.push(&group[start..]);
    alts
}

pub(crate) fn split_leading_inline_flag(s: &str) -> (&str, &str) {
    if !s.starts_with("(?") {
        return ("", s);
    }
    let bytes = s.as_bytes();
    let mut i = 2;
    while i < bytes.len() && matches!(bytes[i], b'i' | b'm' | b's' | b'x' | b'u' | b'U' | b'-') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b')' {
        (&s[..=i], &s[i + 1..])
    } else {
        ("", s)
    }
}
