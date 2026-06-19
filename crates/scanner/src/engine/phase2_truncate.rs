//! Prefilter input-truncation + UTF-8 boundary helpers, extracted from
//! `phase2.rs`. Pure `&str` functions — regex prefix-anchorability and
//! focus-window truncation — with no engine-state coupling.
//! `truncate_for_prefilter` is re-exported at the crate root (see lib.rs);
//! `regex_prefix_anchorable` and `truncate_src` are pub(crate) for phase-2
//! prefilter and profiling paths. Pure move, no behaviour change.

/// True iff `src` has a finite, enumerable required-prefix literal set every
/// member of which is >= 3 bytes — the soundness precondition for driving the
/// pattern from prefix-anchor positions instead of a whole-chunk walk.
pub(crate) fn regex_prefix_anchorable(src: &str) -> bool {
    use regex_syntax::hir::literal::{ExtractKind, Extractor};
    let Ok(hir) = regex_syntax::ParserBuilder::new().build().parse(src) else {
        return false;
    };
    let mut ex = Extractor::new();
    ex.kind(ExtractKind::Prefix);
    let seq = ex.extract(&hir);
    matches!(
        (seq.is_finite(), seq.len(), seq.min_literal_len()),
        (true, Some(n), Some(min)) if n > 0 && min >= 3
    )
}

/// For the PREFILTER (presence/marking) ONLY: truncate a pattern at its FIRST
/// top-level unbounded repetition and bound that repetition to its minimum, so
/// the always-active prefilter RegexSet stays on the fast lazy-DFA instead of
/// falling to PikeVM on `{N,}`/`+`/`*` bodies (the measured ~793 ms dominant
/// cost on BOTH parent and decode sub-chunk scans).
///
/// SOUNDNESS: any match of the FULL pattern `A B{n,} <rest>` contains the prefix
/// `A B{n}` at its start, so if the truncated form does NOT match, the full
/// pattern cannot match anywhere — i.e. the truncated set is a SOUND SUPERSET
/// presence gate. It may over-mark (a pattern whose `A B{n}` is present but whose
/// `<rest>` is absent), but extraction runs the FULL pattern and filters those,
/// so the finding set is unchanged. For the common credential shape `prefix
/// charclass{n,}` (no trailing `<rest>`) the truncation is EXACT, not merely a
/// superset.
///
/// Returns `None` when there is no top-level unbounded repetition (already
/// bounded → use the source verbatim) or the structure is not a simple top-level
/// concat/repetition (kept full — sound, just stays on the slow path). The
/// returned string is validated to compile.
pub(crate) fn truncate_for_prefilter(src: &str) -> Option<String> {
    use regex_syntax::ast::{Ast, RepetitionKind, RepetitionRange};
    let ast = match regex_syntax::ast::parse::Parser::new().parse(src) {
        Ok(ast) => ast,
        Err(error) => {
            tracing::warn!(
                pattern = %src,
                %error,
                "prefilter regex truncation parse failed; using full pattern (perf-only impact)"
            );
            return None;
        }
    };
    let single;
    let nodes: &[Ast] = match &ast {
        Ast::Concat(c) => &c.asts,
        // A bare top-level repetition (e.g. `[a-z]{20,}`): a one-node concat.
        Ast::Repetition(_) => {
            single = [ast.clone()];
            &single
        }
        _ => return None,
    };
    for node in nodes {
        let Ast::Repetition(rep) = node else { continue };
        let b_start = rep.span.start.offset; // start of the repeated sub-expr B
        let op_start = rep.op.span.start.offset; // start of the `{n,}`/`+`/`*` op
        let truncated = match &rep.op.kind {
            // B* → drop B entirely; the gate is the prefix before it.
            RepetitionKind::ZeroOrMore => src.get(..b_start)?.to_string(),
            // B+ → B{1} == one B; keep through the repeated expr, drop the `+`.
            RepetitionKind::OneOrMore => src.get(..op_start)?.to_string(),
            // B{n,} → B{n}; keep through the repeated expr, bound to the minimum.
            RepetitionKind::Range(RepetitionRange::AtLeast(n)) => {
                format!("{}{{{}}}", src.get(..op_start)?, n)
            }
            // ZeroOrOne / Exactly / Bounded are already finite — not a blow-up
            // source; keep scanning for a later unbounded repetition.
            _ => continue,
        };
        // Defensive: never ship a prefilter pattern that fails to compile.
        match regex::Regex::new(&truncated) {
            Ok(_) => return Some(truncated),
            Err(error) => {
                tracing::warn!(
                    pattern = %src,
                    truncated = %truncated,
                    %error,
                    "prefilter regex truncation compile failed; using full pattern (perf-only impact)"
                );
                return None;
            }
        }
    }
    None
}

/// Round `idx` down to the nearest UTF-8 char boundary (stable-Rust stand-in
/// for the unstable `str::floor_char_boundary`). Used to snap the decode-focus
/// window so a slice never splits a multi-byte codepoint.
pub(crate) fn focus_floor_boundary(s: &str, idx: usize) -> usize {
    super::floor_char_boundary(s, idx)
}

pub(crate) fn focus_ceil_boundary(s: &str, idx: usize) -> usize {
    super::ceil_char_boundary(s, idx)
}

pub(crate) fn truncate_src(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let i = super::floor_char_boundary(s, n.min(s.len()));
    format!("{}…", &s[..i])
}

// Tests live in `tests/fallback_truncate_contract.rs` (scanner src forbids
// inline test modules, KH-GAP-004); `truncate_for_prefilter` is re-exported at
// the crate root (lib.rs) so the contract is proven through the public path.
