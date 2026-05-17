//! Subgroup operation lowering.

use naga::{Expression, Span, Statement};
use vyre_lower::KernelOp;

use super::BodyBuilder;
use crate::EmitError;

impl BodyBuilder<'_> {
    pub(super) fn emit_subgroup_ballot(&mut self, op: &KernelOp) -> Result<(), EmitError> {
        let cond_id = *op
            .operands
            .first()
            .ok_or_else(|| EmitError::InvalidDescriptor("SubgroupBallot missing cond".into()))?;
        let predicate = self.values.get(&cond_id).copied().ok_or_else(|| {
            EmitError::InvalidDescriptor(format!(
                "SubgroupBallot cond id {cond_id} not yet emitted"
            ))
        })?;
        let result = self
            .function
            .expressions
            .append(Expression::SubgroupBallotResult, Span::UNDEFINED);
        self.function.body.push(
            Statement::SubgroupBallot {
                result,
                predicate: Some(predicate),
            },
            Span::UNDEFINED,
        );
        let first_word = self.append_expr(Expression::AccessIndex {
            base: result,
            index: 0,
        });
        self.bind_result_typed(op, first_word, self.types.u32_ty)
    }

    pub(super) fn emit_subgroup_add(&mut self, op: &KernelOp) -> Result<(), EmitError> {
        let value_id = *op
            .operands
            .first()
            .ok_or_else(|| EmitError::InvalidDescriptor("SubgroupAdd missing value".into()))?;
        let argument = self.values.get(&value_id).copied().ok_or_else(|| {
            EmitError::InvalidDescriptor(format!("SubgroupAdd value id {value_id} not yet emitted"))
        })?;
        let result = self.function.expressions.append(
            Expression::SubgroupOperationResult {
                ty: self.types.u32_ty,
            },
            Span::UNDEFINED,
        );
        self.function.body.push(
            Statement::SubgroupCollectiveOperation {
                op: naga::SubgroupOperation::Add,
                collective_op: naga::CollectiveOperation::Reduce,
                argument,
                result,
            },
            Span::UNDEFINED,
        );
        let ty = self.value_type_operand(op, 0)?;
        self.bind_result_typed(op, result, ty)
    }

    pub(super) fn emit_subgroup_shuffle(&mut self, op: &KernelOp) -> Result<(), EmitError> {
        let value_id = *op
            .operands
            .first()
            .ok_or_else(|| EmitError::InvalidDescriptor("SubgroupShuffle missing value".into()))?;
        let lane_id = *op
            .operands
            .get(1)
            .ok_or_else(|| EmitError::InvalidDescriptor("SubgroupShuffle missing lane".into()))?;
        let argument = self.values.get(&value_id).copied().ok_or_else(|| {
            EmitError::InvalidDescriptor(format!(
                "SubgroupShuffle value id {value_id} not yet emitted"
            ))
        })?;
        let lane = self.values.get(&lane_id).copied().ok_or_else(|| {
            EmitError::InvalidDescriptor(format!(
                "SubgroupShuffle lane id {lane_id} not yet emitted"
            ))
        })?;
        let result = self.function.expressions.append(
            Expression::SubgroupOperationResult {
                ty: self.types.u32_ty,
            },
            Span::UNDEFINED,
        );
        self.function.body.push(
            Statement::SubgroupGather {
                mode: naga::GatherMode::Shuffle(lane),
                argument,
                result,
            },
            Span::UNDEFINED,
        );
        let ty = self.value_type_operand(op, 0)?;
        self.bind_result_typed(op, result, ty)
    }
}
