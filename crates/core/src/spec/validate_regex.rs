//! Regex complexity and ReDoS validation helpers.

use super::QualityIssue;
use regex_syntax::ast::{self, Ast};

const MAX_REGEX_AST_NODES: usize = 512;
const MAX_REGEX_ALTERNATION_BRANCHES: usize = 64;
const MAX_REGEX_REPEAT_BOUND: u32 = 1_000;

pub(crate) fn validate_regex_complexity(
    kind: &str,
    index: usize,
    ast: &Ast,
    issues: &mut Vec<QualityIssue>,
) {
    let mut stats = RegexComplexityStats::default();
    collect_regex_complexity(ast, &mut stats);
    collect_redos_risks(ast, &mut stats, false);

    if stats.nodes > MAX_REGEX_AST_NODES {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex is too complex ({} AST nodes > {} limit)",
            stats.nodes, MAX_REGEX_AST_NODES
        )));
    }

    if stats.max_alternation_branches > MAX_REGEX_ALTERNATION_BRANCHES {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex has too many alternation branches ({} > {} limit)",
            stats.max_alternation_branches, MAX_REGEX_ALTERNATION_BRANCHES
        )));
    }

    if stats.max_repeat_bound > MAX_REGEX_REPEAT_BOUND {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex has an excessive counted repetition bound ({} > {} limit)",
            stats.max_repeat_bound, MAX_REGEX_REPEAT_BOUND
        )));
    }

    if stats.has_nested_quantifier {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex contains nested quantifiers that can trigger pathological matching"
        )));
    }

    if stats.has_quantified_overlapping_alternation {
        issues.push(QualityIssue::Error(format!(
            "{kind} {index} regex repeats overlapping alternations; use unambiguous branches instead"
        )));
    }
}

#[derive(Default)]
struct RegexComplexityStats {
    nodes: usize,
    max_alternation_branches: usize,
    max_repeat_bound: u32,
    has_nested_quantifier: bool,
    has_quantified_overlapping_alternation: bool,
}

fn collect_regex_complexity(ast: &Ast, stats: &mut RegexComplexityStats) {
    stats.nodes += 1;
    match ast {
        Ast::Repetition(repetition) => {
            update_repeat_bound(&repetition.op.kind, stats);
            collect_regex_complexity(&repetition.ast, stats);
        }
        Ast::Group(group) => collect_regex_complexity(&group.ast, stats),
        Ast::Alternation(alternation) => {
            stats.max_alternation_branches =
                stats.max_alternation_branches.max(alternation.asts.len());
            for ast in &alternation.asts {
                collect_regex_complexity(ast, stats);
            }
        }
        Ast::Concat(concat) => {
            for ast in &concat.asts {
                collect_regex_complexity(ast, stats);
            }
        }
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => {}
    }
}

fn collect_redos_risks(ast: &Ast, stats: &mut RegexComplexityStats, inside_repetition: bool) {
    match ast {
        Ast::Repetition(repetition) => {
            // Flag nested quantifiers only when they can cause exponential backtracking.
            //
            // SAFE patterns (char class quantifier inside group quantifier):
            //   (?:api[_\s.-]*)? — [_\s.-]* is atomic, can't overlap
            //   (?:key|token)[=:\s"']+  — char class quantifier, deterministic
            //
            // DANGEROUS patterns (group/concat quantifier inside quantifier):
            //   (a+)+       — classic ReDoS
            //   (\w+\s*)+   — overlapping quantifiers on non-atomic elements
            //
            // Strategy: only flag when THIS repetition wraps a non-atomic element
            // AND we're inside another repetition, OR when our inner AST itself
            // contains a nested repetition wrapping a non-atomic element.
            let this_is_simple_atom = matches!(
                &*repetition.ast,
                Ast::Literal(_)
                    | Ast::Dot(_)
                    | Ast::ClassBracketed(_)
                    | Ast::ClassPerl(_)
                    | Ast::ClassUnicode(_)
            );
            let this_is_unbounded = matches!(
                repetition.op.kind,
                ast::RepetitionKind::ZeroOrMore
                    | ast::RepetitionKind::OneOrMore
                    | ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast { .. })
            );
            // Only flag when BOTH the outer and this repetition are unbounded
            // and this wraps a non-atomic element. (?:group)? is safe because
            // ? is {0,1} — it can't cause exponential backtracking.
            if inside_repetition && !this_is_simple_atom && this_is_unbounded {
                stats.has_nested_quantifier = true;
            }
            if !inside_repetition
                && this_is_unbounded
                && !this_is_simple_atom
                && ast_contains_repetition(&repetition.ast)
            {
                stats.has_nested_quantifier = true;
            }
            if alternation_has_overlapping_prefixes(&repetition.ast) {
                stats.has_quantified_overlapping_alternation = true;
            }
            // Only propagate inside_repetition when this is unbounded
            collect_redos_risks(
                &repetition.ast,
                stats,
                inside_repetition || this_is_unbounded,
            );
        }
        Ast::Group(group) => collect_redos_risks(&group.ast, stats, inside_repetition),
        Ast::Alternation(alternation) => {
            for ast in &alternation.asts {
                collect_redos_risks(ast, stats, inside_repetition);
            }
        }
        Ast::Concat(concat) => {
            for ast in &concat.asts {
                collect_redos_risks(ast, stats, inside_repetition);
            }
        }
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => {}
    }
}

fn ast_contains_repetition(ast: &Ast) -> bool {
    match ast {
        Ast::Repetition(_) => true,
        Ast::Group(group) => ast_contains_repetition(&group.ast),
        Ast::Alternation(alternation) => alternation.asts.iter().any(ast_contains_repetition),
        Ast::Concat(concat) => concat.asts.iter().any(ast_contains_repetition),
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => false,
    }
}

fn alternation_has_overlapping_prefixes(ast: &Ast) -> bool {
    let alternatives = match ast {
        Ast::Alternation(alternation) => &alternation.asts,
        Ast::Group(group) => return alternation_has_overlapping_prefixes(&group.ast),
        _ => return false,
    };

    let prefixes = alternatives
        .iter()
        .filter_map(literalish_prefix)
        .collect::<Vec<_>>();
    for (idx, prefix) in prefixes.iter().enumerate() {
        for other in prefixes.iter().skip(idx + 1) {
            if prefix.starts_with(other) || other.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

fn literalish_prefix(ast: &Ast) -> Option<String> {
    match ast {
        Ast::Literal(literal) => Some(literal.c.to_string()),
        Ast::Concat(concat) => {
            let mut prefix = String::new();
            for node in &concat.asts {
                match node {
                    Ast::Literal(literal) => prefix.push(literal.c),
                    Ast::Group(group) => prefix.push_str(&literalish_prefix(&group.ast)?),
                    _ => break,
                }
            }
            (!prefix.is_empty()).then_some(prefix)
        }
        Ast::Group(group) => literalish_prefix(&group.ast),
        _ => None,
    }
}

fn update_repeat_bound(kind: &ast::RepetitionKind, stats: &mut RegexComplexityStats) {
    let bound = match kind {
        ast::RepetitionKind::ZeroOrOne => 1,
        ast::RepetitionKind::ZeroOrMore | ast::RepetitionKind::OneOrMore => MAX_REGEX_REPEAT_BOUND,
        ast::RepetitionKind::Range(range) => match range {
            ast::RepetitionRange::Exactly(max)
            | ast::RepetitionRange::AtLeast(max)
            | ast::RepetitionRange::Bounded(_, max) => *max,
        },
    };
    stats.max_repeat_bound = stats.max_repeat_bound.max(bound);
}
