use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::BitwiseXor;

impl common::ReferenceEvaluator for BitwiseXor {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "bitwise_xor")?;
        Ok(common::scalar(
            common::read_u32(left, "bitwise_xor")? ^ common::read_u32(right, "bitwise_xor")?,
        ))
    }
}
