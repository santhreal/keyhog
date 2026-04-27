use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::ShiftRight;

impl common::ReferenceEvaluator for ShiftRight {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "shift_right")?;
        let shift = common::read_u32(right, "shift_right")? & 31;
        Ok(common::scalar(
            common::read_u32(left, "shift_right")? >> shift,
        ))
    }
}
