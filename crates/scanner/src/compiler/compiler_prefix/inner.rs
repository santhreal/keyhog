pub(crate) fn is_escaped_literal(ch: char) -> bool {
    matches!(
        ch,
        '[' | ']' | '(' | ')' | '.' | '*' | '+' | '?' | '{' | '}' | '\\' | '|' | '^' | '$'
    )
}

/// Minimum length for an inner literal to be eligible for the AC prefilter.
///
/// Inner literals are pulled from anywhere in the regex (after a leading
/// character class, between groups, etc.) rather than just the prefix, so
/// they're typically less specific than a prefix-anchored literal. We
/// require ≥ 4 chars to keep the AC working set tight and avoid spurious
/// chunks getting promoted to regex confirmation. The 3-char prefix
/// threshold remains for `extract_literal_prefix` because a 3-char prefix
/// is positionally anchored and far more discriminative.
pub(crate) const MIN_INNER_LITERAL_CHARS: usize = 4;

/// Suggest literal substrings from anywhere in a regex for detector-route
/// auditing. The production compiler never applies these implicitly: a
/// detector must declare the selected set as `required_literals` in its TOML.
///
/// Walks the parsed regex AST and collects every contiguous run of
/// `Literal` nodes inside a `Concat`. Alternation branches are walked
/// recursively only when every branch has at least one eligible trigger;
/// partial alternation coverage would make the unanchored branch unreachable.
/// Repetitions and assertions break the run conservatively: even though
/// `\babc\b` always contains "abc", we also allow that the surrounding
/// regex might never match, in which case we'd be promoting chunks for
/// nothing - the regex confirmation still has to succeed, but the AC's
/// job is to skip work, not generate it.
///
/// Examples:
///   `[a-zA-Z0-9]{20}_AKIA[A-Z0-9]{16}` → `["_AKIA"]`
///   `(?:secret|api_key)\s*=\s*[a-z0-9]{32}` → `["secret", "api_key"]`
///   `[a-f0-9]{32}` → `[]`
///   `wx[a-f0-9]{16}` → `[]` (the `wx` prefix is below the 4-char floor)
#[cfg(test)]
pub(crate) fn extract_inner_literals(pattern: &str) -> Vec<String> {
    use regex_syntax::ast::{parse::Parser, Ast};
    let Ok(ast) = Parser::new().parse(pattern) else {
        return Vec::new();
    };

    // AC routing is sound only when every possible regex match contains at
    // least one extracted literal. Collecting a long literal from just one
    // alternation arm would silently kill a shorter arm with no eligible
    // literal (for example `DD.API.KEY|DATADOG.API.KEY`).
    fn has_complete_trigger_coverage(ast: &Ast) -> bool {
        match ast {
            Ast::Concat(concat) => {
                let mut run_bytes = 0usize;
                for node in &concat.asts {
                    if let Ast::Literal(literal) = node {
                        run_bytes += literal.c.len_utf8();
                        if run_bytes >= MIN_INNER_LITERAL_CHARS {
                            return true;
                        }
                    } else {
                        run_bytes = 0;
                        if has_complete_trigger_coverage(node) {
                            return true;
                        }
                    }
                }
                false
            }
            Ast::Group(group) => has_complete_trigger_coverage(&group.ast),
            Ast::Alternation(alternation) => {
                !alternation.asts.is_empty()
                    && alternation.asts.iter().all(has_complete_trigger_coverage)
            }
            _ => false,
        }
    }
    if !has_complete_trigger_coverage(&ast) {
        return Vec::new();
    }
    let mut out = Vec::new();
    walk_ast(&ast, &mut out);
    out.retain(|s| s.len() >= MIN_INNER_LITERAL_CHARS);
    // Dedup while preserving order - alternation branches commonly produce
    // duplicates when patterns share prefixes (e.g. `(KEY|key)` lowered to
    // canonical literals).
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}

#[cfg(test)]
fn walk_ast(ast: &regex_syntax::ast::Ast, out: &mut Vec<String>) {
    use regex_syntax::ast::Ast;
    match ast {
        Ast::Concat(concat) => {
            // Collect runs of consecutive `Literal` nodes; flush a run when
            // a non-literal node breaks it. The `Literal::c` field is the
            // character - for `\.` it's `.`, for `\\` it's `\`, etc.
            let mut run = String::new();
            for inner in concat.asts.iter() {
                match inner {
                    Ast::Literal(lit) => run.push(lit.c),
                    _ => {
                        if run.len() >= MIN_INNER_LITERAL_CHARS {
                            out.push(std::mem::take(&mut run));
                        } else {
                            run.clear();
                        }
                        walk_ast(inner, out);
                    }
                }
            }
            if run.len() >= MIN_INNER_LITERAL_CHARS {
                out.push(run);
            }
        }
        Ast::Group(group) => walk_ast(&group.ast, out),
        Ast::Alternation(alt) => {
            for branch in alt.asts.iter() {
                walk_ast(branch, out);
            }
        }
        // Single literal at the top level - wrap into a one-char run; the
        // caller's filter rejects it for length but the case is rare anyway.
        Ast::Literal(lit) => {
            let s = lit.c.to_string();
            if s.len() >= MIN_INNER_LITERAL_CHARS {
                out.push(s);
            }
        }
        // Repetition operands could in principle contribute a literal when
        // `min >= 1`, but the operand's literals would also need to be
        // resolved through the operand's own AST shape. Keeping this
        // conservative dodges a class of "we extracted `a` from `a+`,
        // promoted every chunk with an `a` to regex confirmation" gotchas.
        Ast::Repetition(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_)
        | Ast::Dot(_)
        | Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Assertion(_) => {}
    }
}

/// Minimum length of a REQUIRED literal run for it to count as a distinctive
/// inner-literal anchor. A required run this long inside a token is a service
/// signature (the terraform `.atlasv1.` infix, 9 chars) rather than incidental
/// punctuation, so a named-detector match that contains it has earned the same
/// anchor credit as a leading literal prefix.
pub(crate) const MIN_DISTINCTIVE_INFIX_CHARS: usize = 8;

/// True iff EVERY match of `pattern` necessarily contains a literal run of at
/// least `min_len` characters, a required distinctive literal such as the
/// terraform `…\.atlasv1\.…` infix, whose detector regex opens with a character
/// class (no extractable prefix) and captures the whole match (no keyword
/// group), so it earns neither existing anchor signal despite being unmistakably
/// service-specific.
///
/// Sound by construction, only literals guaranteed in every match are counted:
///   * a top-level `Concat` contributes its longest run of CONSECUTIVE literal
///     nodes;
///   * a plain/non-capturing/capturing `Group` is always entered, so it is
///     descended into; and
///   * an `Alternation` (only one branch matches), a `Repetition` (the operand
///     may repeat zero times, and even `+`/`{n,}` the run is not contiguous with
///     its neighbours here), a class, dot, or assertion contribute nothing.
/// A literal inside an optional/alternative therefore never produces a false
/// "required" claim. The walk does not multiply repeated operands, so it can
/// only UNDER-count, never over-claim.
pub(crate) fn regex_has_required_literal_run(pattern: &str, min_len: usize) -> bool {
    use regex_syntax::ast::{parse::Parser, Ast};

    fn max_required_run(ast: &Ast) -> usize {
        match ast {
            Ast::Literal(_) => 1,
            Ast::Concat(concat) => {
                let mut best = 0usize;
                let mut run = 0usize;
                for node in concat.asts.iter() {
                    if matches!(node, Ast::Literal(_)) {
                        run += 1;
                        best = best.max(run);
                    } else {
                        // A required group may carry its own internal run, but it
                        // breaks the contiguous run of its literal neighbours.
                        best = best.max(max_required_run(node));
                        run = 0;
                    }
                }
                best
            }
            Ast::Group(group) => max_required_run(&group.ast),
            // Alternation, Repetition (optional operand), classes, dot,
            // assertions, flags, empty: not a guaranteed contiguous literal run.
            _ => 0,
        }
    }

    let Ok(ast) = Parser::new().parse(pattern) else {
        return false;
    };
    max_required_run(&ast) >= min_len
}
