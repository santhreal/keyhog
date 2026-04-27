use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::ShiftLeft;

impl common::ReferenceEvaluator for ShiftLeft {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "shift_left")?;
        let shift = common::read_u32(right, "shift_left")? & 31;
        Ok(common::scalar(
            common::read_u32(left, "shift_left")? << shift,
        ))
    }
}
