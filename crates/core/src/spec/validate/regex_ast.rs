//! Regex AST analysis primitives shared by the detector quality gate.
//!
//! Parsing, literal-run measurement, capture counting, and character-class
//! classification over `regex_syntax` ASTs. These are pure structural
//! predicates: they know nothing about detectors, so the gate rules in the
//! parent module stay about detector policy rather than regex internals.

use regex_syntax::ast;
use std::collections::{hash_map::Entry, HashMap};

#[derive(Default)]
pub(super) struct RegexAstCache<'a> {
    parsed: HashMap<&'a str, Result<ast::Ast, String>>,
}

impl<'a> RegexAstCache<'a> {
    pub(super) fn parse(&mut self, regex: &'a str) -> Result<&ast::Ast, &str> {
        let parsed = match self.parsed.entry(regex) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                ast::parse::Parser::new()
                    .parse(regex)
                    .map_err(|error| error.to_string()),
            ),
        };
        parsed.as_ref().map_err(String::as_str)
    }
}

pub(super) fn has_substantial_literal<'a>(
    regex_cache: &mut RegexAstCache<'a>,
    pattern: &'a str,
    min_len: usize,
) -> bool {
    match regex_cache.parse(pattern) {
        Ok(ast) => ast_literal_runs(ast).max >= min_len,
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

pub(super) fn has_literal_prefix<'a>(
    regex_cache: &mut RegexAstCache<'a>,
    pattern: &'a str,
    min_len: usize,
) -> bool {
    match regex_cache.parse(pattern) {
        Ok(ast) => ast_literal_runs(ast).prefix >= min_len,
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

pub(super) fn ast_captures_len(ast: &ast::Ast) -> usize {
    ast_max_capture_index(ast)
        .map(|index| index as usize + 1)
        .unwrap_or(1) // LAW10: no explicit capture groups still leaves regex capture group 0; this is the same captures_len contract, not a fallback.
}

pub(super) fn ast_max_capture_index(ast: &ast::Ast) -> Option<u32> {
    let mut max_capture = None;
    let mut stack = vec![ast];
    while let Some(node) = stack.pop() {
        match node {
            ast::Ast::Group(group) => {
                max_capture = max_capture.max(group.capture_index());
                stack.push(&group.ast);
            }
            ast::Ast::Concat(concat) => stack.extend(concat.asts.iter()),
            ast::Ast::Alternation(alternation) => stack.extend(alternation.asts.iter()),
            ast::Ast::Repetition(repetition) => stack.push(&repetition.ast),
            ast::Ast::Empty(_)
            | ast::Ast::Flags(_)
            | ast::Ast::Literal(_)
            | ast::Ast::Dot(_)
            | ast::Ast::Assertion(_)
            | ast::Ast::ClassUnicode(_)
            | ast::Ast::ClassPerl(_)
            | ast::Ast::ClassBracketed(_) => {}
        }
    }
    max_capture
}

#[derive(Clone, Copy)]
struct LiteralRunStats {
    prefix: usize,
    suffix: usize,
    max: usize,
    all_literal: bool,
}

impl LiteralRunStats {
    fn empty() -> Self {
        Self {
            prefix: 0,
            suffix: 0,
            max: 0,
            all_literal: true,
        }
    }

    fn literal(len: usize) -> Self {
        Self {
            prefix: len,
            suffix: len,
            max: len,
            all_literal: true,
        }
    }
}

fn ast_literal_runs(ast: &ast::Ast) -> LiteralRunStats {
    enum LiteralFrame<'a> {
        Visit(&'a ast::Ast),
        FinishConcat(usize),
        FinishAlternation(usize),
        FinishRepetition(&'a ast::RepetitionKind),
    }

    let mut frames = vec![LiteralFrame::Visit(ast)];
    let mut results = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            LiteralFrame::Visit(node) => match node {
                ast::Ast::Literal(_) => results.push(LiteralRunStats::literal(1)),
                ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_) => {
                    results.push(LiteralRunStats::empty());
                }
                ast::Ast::Group(group) => frames.push(LiteralFrame::Visit(&group.ast)),
                ast::Ast::Concat(concat) => {
                    frames.push(LiteralFrame::FinishConcat(concat.asts.len()));
                    for child in concat.asts.iter().rev() {
                        frames.push(LiteralFrame::Visit(child));
                    }
                }
                ast::Ast::Alternation(alternation) => {
                    frames.push(LiteralFrame::FinishAlternation(alternation.asts.len()));
                    for child in alternation.asts.iter().rev() {
                        frames.push(LiteralFrame::Visit(child));
                    }
                }
                ast::Ast::Repetition(repetition) => {
                    frames.push(LiteralFrame::FinishRepetition(&repetition.op.kind));
                    frames.push(LiteralFrame::Visit(&repetition.ast));
                }
                ast::Ast::Dot(_)
                | ast::Ast::ClassUnicode(_)
                | ast::Ast::ClassPerl(_)
                | ast::Ast::ClassBracketed(_) => results.push(LiteralRunStats {
                    prefix: 0,
                    suffix: 0,
                    max: 0,
                    all_literal: false,
                }),
            },
            LiteralFrame::FinishConcat(child_count) => {
                let children = results.split_off(results.len() - child_count);
                let combined = children
                    .into_iter()
                    .fold(LiteralRunStats::empty(), combine_literal_runs);
                results.push(combined);
            }
            LiteralFrame::FinishAlternation(child_count) => {
                let children = results.split_off(results.len() - child_count);
                let max = children
                    .into_iter()
                    .map(|child| child.max)
                    .max()
                    .unwrap_or_default();
                results.push(LiteralRunStats {
                    max,
                    prefix: 0,
                    suffix: 0,
                    all_literal: false,
                });
            }
            LiteralFrame::FinishRepetition(kind) => {
                let inner = match results.pop() {
                    Some(inner) => inner,
                    None => LiteralRunStats::empty(),
                };
                results.push(repeated_literal_runs(
                    inner,
                    repetition_min(kind),
                    repetition_is_exact(kind),
                ));
            }
        }
    }
    match results.pop() {
        Some(stats) => stats,
        None => LiteralRunStats::empty(),
    }
}

fn combine_literal_runs(left: LiteralRunStats, right: LiteralRunStats) -> LiteralRunStats {
    LiteralRunStats {
        prefix: if left.all_literal {
            left.prefix.saturating_add(right.prefix)
        } else {
            left.prefix
        },
        suffix: if right.all_literal {
            left.suffix.saturating_add(right.suffix)
        } else {
            right.suffix
        },
        max: left
            .max
            .max(right.max)
            .max(left.suffix.saturating_add(right.prefix)),
        all_literal: left.all_literal && right.all_literal,
    }
}

fn repeated_literal_runs(
    inner: LiteralRunStats,
    min_repetitions: usize,
    exact_repetition: bool,
) -> LiteralRunStats {
    if min_repetitions == 0 {
        return LiteralRunStats {
            prefix: 0,
            suffix: 0,
            max: inner.max,
            all_literal: false,
        };
    }

    if inner.all_literal {
        let repeated_len = inner.max.saturating_mul(min_repetitions);
        return LiteralRunStats {
            prefix: repeated_len,
            suffix: repeated_len,
            max: repeated_len,
            all_literal: exact_repetition,
        };
    }

    LiteralRunStats {
        prefix: inner.prefix,
        suffix: inner.suffix,
        max: inner.max,
        all_literal: false,
    }
}

fn repetition_min(kind: &ast::RepetitionKind) -> usize {
    match kind {
        ast::RepetitionKind::ZeroOrOne | ast::RepetitionKind::ZeroOrMore => 0,
        ast::RepetitionKind::OneOrMore => 1,
        ast::RepetitionKind::Range(ast::RepetitionRange::Exactly(min))
        | ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast(min))
        | ast::RepetitionKind::Range(ast::RepetitionRange::Bounded(min, _)) => *min as usize,
    }
}

fn repetition_is_exact(kind: &ast::RepetitionKind) -> bool {
    matches!(
        kind,
        ast::RepetitionKind::Range(ast::RepetitionRange::Exactly(_))
    )
}

pub(super) fn is_pure_character_class<'a>(
    regex_cache: &mut RegexAstCache<'a>,
    pattern: &'a str,
) -> bool {
    match regex_cache.parse(pattern) {
        Ok(ast) => pure_character_class_ast(ast).is_some(),
        Err(_) => false, // LAW10: invalid regex already emits a QualityIssue::Error; no recall impact
    }
}

fn pure_character_class_ast(ast: &ast::Ast) -> Option<()> {
    enum PureFrame<'a> {
        Visit(&'a ast::Ast),
        FinishAllNonempty(usize),
    }

    let mut frames = vec![PureFrame::Visit(ast)];
    let mut results = Vec::new();
    while let Some(frame) = frames.pop() {
        match frame {
            PureFrame::Visit(node) => match node {
                ast::Ast::ClassBracketed(_) => results.push(Some(())),
                ast::Ast::Group(group) => frames.push(PureFrame::Visit(&group.ast)),
                ast::Ast::Repetition(repetition) => frames.push(PureFrame::Visit(&repetition.ast)),
                ast::Ast::Alternation(alternation) => {
                    frames.push(PureFrame::FinishAllNonempty(alternation.asts.len()));
                    for child in alternation.asts.iter().rev() {
                        frames.push(PureFrame::Visit(child));
                    }
                }
                ast::Ast::Concat(concat) => {
                    let children = concat
                        .asts
                        .iter()
                        .filter(|child| !is_regex_metadata_node(child))
                        .collect::<Vec<_>>();
                    frames.push(PureFrame::FinishAllNonempty(children.len()));
                    for child in children.into_iter().rev() {
                        frames.push(PureFrame::Visit(child));
                    }
                }
                ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_) => {
                    results.push(None);
                }
                ast::Ast::Literal(_)
                | ast::Ast::Dot(_)
                | ast::Ast::ClassUnicode(_)
                | ast::Ast::ClassPerl(_) => results.push(None),
            },
            PureFrame::FinishAllNonempty(child_count) => {
                if child_count == 0 {
                    results.push(None);
                    continue;
                }
                let children = results.split_off(results.len() - child_count);
                results.push(
                    children
                        .into_iter()
                        .all(|child| child.is_some())
                        .then_some(()),
                );
            }
        }
    }
    results.pop().flatten()
}

fn is_regex_metadata_node(ast: &ast::Ast) -> bool {
    matches!(
        ast,
        ast::Ast::Empty(_) | ast::Ast::Flags(_) | ast::Ast::Assertion(_)
    )
}
