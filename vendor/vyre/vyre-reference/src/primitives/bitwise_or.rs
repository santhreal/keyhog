use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::BitwiseOr;

impl common::ReferenceEvaluator for BitwiseOr {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "bitwise_or")?;
        Ok(common::scalar(
            common::read_u32(left, "bitwise_or")? | common::read_u32(right, "bitwise_or")?,
        ))
    }
}
