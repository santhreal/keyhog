//! Tests for `scheduler.rs`. Split out per audit item #85 to keep the
//! parent file focused on production code.

use super::*;
use crate::ir::{BufferDecl, DataType, Expr, Node, Program};
use crate::optimizer::passes::const_fold::ConstFold;
use crate::optimizer::passes::fusion::Fusion;
use crate::optimizer::passes::normalize_atomics::NormalizeAtomicsPass;
use crate::optimizer::passes::strength_reduce::StrengthReduce;
use crate::optimizer::{PassAnalysis, PassMetadata, PassResult, ProgramPass, RefusalReason};
use std::sync::Arc;

fn trivial_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
    )
}

#[derive(Debug)]
struct TestPass {
    metadata: PassMetadata,
    changes: bool,
}

impl crate::optimizer::private::Sealed for TestPass {}

impl ProgramPass for TestPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        if self.changes {
            let mut entry = Clone::clone(&program).into_entry_vec();
            entry.push(Node::barrier());
            PassResult {
                program: program.with_rewritten_entry(entry),
                changed: true,
            }
        } else {
            PassResult::unchanged(program)
        }
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct ExprOnlyPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for ExprOnlyPass {}

impl ProgramPass for ExprOnlyPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        let mut entry = Clone::clone(&program).into_entry_vec();
        if rewrite_first_store_value(&mut entry) {
            return PassResult {
                program: program.with_rewritten_entry(entry),
                changed: true,
            };
        }
        PassResult::unchanged(program)
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct SkipPass;

impl crate::optimizer::private::Sealed for SkipPass {}

impl ProgramPass for SkipPass {
    fn metadata(&self) -> PassMetadata {
        PassMetadata::new("skip_pass", &[], &[])
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::SKIP
    }

    fn transform(&self, program: Program) -> PassResult {
        PassResult::unchanged(program)
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct RefusingPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for RefusingPass {}

impl ProgramPass for RefusingPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, _program: Program) -> PassResult {
        panic!("cost-monotone scheduler must call try_transform before transform")
    }

    fn try_transform(&self, _program: Program) -> Result<PassResult, RefusalReason> {
        Err(RefusalReason::CostIncrease {
            delta: 1,
            detail: "test pass refuses cost-up rewrite",
        })
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

fn rewrite_first_store_value(nodes: &mut [Node]) -> bool {
    for node in nodes {
        match node {
            Node::Store { value, .. } => {
                *value = Expr::u32(43);
                return true;
            }
            Node::If {
                then, otherwise, ..
            } => {
                if rewrite_first_store_value(then) || rewrite_first_store_value(otherwise) {
                    return true;
                }
            }
            Node::Loop { body, .. } | Node::Block(body) => {
                if rewrite_first_store_value(body) {
                    return true;
                }
            }
            Node::Region { body, .. } => {
                let body_vec: &mut Vec<Node> = Arc::make_mut(body);
                if rewrite_first_store_value(body_vec.as_mut_slice()) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

mod basic_execution;
mod cost_monotone;
mod invalidation_metrics;
mod lookup_identity;
