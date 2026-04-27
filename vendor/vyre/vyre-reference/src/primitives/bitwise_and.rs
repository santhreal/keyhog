use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::BitwiseAnd;

impl common::ReferenceEvaluator for BitwiseAnd {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "bitwise_and")?;
        Ok(common::scalar(
            common::read_u32(left, "bitwise_and")? & common::read_u32(right, "bitwise_and")?,
        ))
    }
}
