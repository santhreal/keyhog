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
    collect_regex_stats(ast, &mut stats);

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

    if stats.max_repeat_bound > u128::from(MAX_REGEX_REPEAT_BOUND) {
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
    max_repeat_bound: u128,
    has_nested_quantifier: bool,
    has_quantified_overlapping_alternation: bool,
}

#[derive(Clone, Copy)]
struct RegexWalkFrame<'a> {
    ast: &'a Ast,
    inside_unbounded_repetition: bool,
    repeat_product: u128,
}

fn collect_regex_stats(ast: &Ast, stats: &mut RegexComplexityStats) {
    let mut stack = vec![RegexWalkFrame {
        ast,
        inside_unbounded_repetition: false,
        repeat_product: 1,
    }];

    while let Some(frame) = stack.pop() {
        stats.nodes += 1;
        match frame.ast {
            Ast::Repetition(repetition) => {
                let this_is_simple_atom = is_simple_atom(&repetition.ast);
                let this_is_unbounded = is_unbounded_repeat(&repetition.op.kind);
                let repeat_bound = repeat_bound(&repetition.op.kind);
                let cumulative_bound = frame.repeat_product.saturating_mul(repeat_bound);
                stats.max_repeat_bound = stats.max_repeat_bound.max(cumulative_bound);

                if frame.inside_unbounded_repetition && !this_is_simple_atom && this_is_unbounded {
                    stats.has_nested_quantifier = true;
                }
                if !frame.inside_unbounded_repetition
                    && this_is_unbounded
                    && !this_is_simple_atom
                    && ast_contains_repetition(&repetition.ast)
                {
                    stats.has_nested_quantifier = true;
                }
                if alternation_has_overlapping_prefixes(&repetition.ast) {
                    stats.has_quantified_overlapping_alternation = true;
                }

                stack.push(RegexWalkFrame {
                    ast: &repetition.ast,
                    inside_unbounded_repetition: frame.inside_unbounded_repetition
                        || this_is_unbounded,
                    repeat_product: cumulative_bound,
                });
            }
            Ast::Group(group) => stack.push(RegexWalkFrame {
                ast: &group.ast,
                ..frame
            }),
            Ast::Alternation(alternation) => {
                stats.max_alternation_branches =
                    stats.max_alternation_branches.max(alternation.asts.len());
                for ast in &alternation.asts {
                    stack.push(RegexWalkFrame { ast, ..frame });
                }
            }
            Ast::Concat(concat) => {
                for ast in &concat.asts {
                    stack.push(RegexWalkFrame { ast, ..frame });
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
}

fn ast_contains_repetition(ast: &Ast) -> bool {
    let mut stack = vec![ast];
    while let Some(node) = stack.pop() {
        match node {
            Ast::Repetition(_) => return true,
            Ast::Group(group) => stack.push(&group.ast),
            Ast::Alternation(alternation) => stack.extend(alternation.asts.iter()),
            Ast::Concat(concat) => stack.extend(concat.asts.iter()),
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
    false
}

fn alternation_has_overlapping_prefixes(ast: &Ast) -> bool {
    let mut node = ast;
    let alternatives = loop {
        match node {
            Ast::Alternation(alternation) => break &alternation.asts,
            Ast::Group(group) => node = &group.ast,
            _ => return false,
        }
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
    let mut prefix = String::new();
    let mut stack = vec![ast];

    while let Some(node) = stack.pop() {
        match node {
            Ast::Literal(literal) => prefix.push(literal.c),
            Ast::Group(group) => stack.push(&group.ast),
            Ast::Concat(concat) => {
                for child in concat.asts.iter().rev() {
                    stack.push(child);
                }
            }
            Ast::Empty(_)
            | Ast::Flags(_)
            | Ast::Dot(_)
            | Ast::Assertion(_)
            | Ast::ClassUnicode(_)
            | Ast::ClassPerl(_)
            | Ast::ClassBracketed(_)
            | Ast::Alternation(_)
            | Ast::Repetition(_) => break,
        }
    }

    (!prefix.is_empty()).then_some(prefix)
}

fn is_simple_atom(ast: &Ast) -> bool {
    matches!(
        ast,
        Ast::Literal(_)
            | Ast::Dot(_)
            | Ast::ClassBracketed(_)
            | Ast::ClassPerl(_)
            | Ast::ClassUnicode(_)
    )
}

fn is_unbounded_repeat(kind: &ast::RepetitionKind) -> bool {
    matches!(
        kind,
        ast::RepetitionKind::ZeroOrMore
            | ast::RepetitionKind::OneOrMore
            | ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast { .. })
    )
}

fn repeat_bound(kind: &ast::RepetitionKind) -> u128 {
    match kind {
        ast::RepetitionKind::ZeroOrOne => 1,
        ast::RepetitionKind::ZeroOrMore | ast::RepetitionKind::OneOrMore => {
            u128::from(MAX_REGEX_REPEAT_BOUND)
        }
        ast::RepetitionKind::Range(range) => match range {
            ast::RepetitionRange::Exactly(max)
            | ast::RepetitionRange::AtLeast(max)
            | ast::RepetitionRange::Bounded(_, max) => u128::from(*max),
        },
    }
}
