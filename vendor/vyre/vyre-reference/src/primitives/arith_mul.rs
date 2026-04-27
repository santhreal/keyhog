use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::ArithMul;

impl common::ReferenceEvaluator for ArithMul {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "arith_mul")?;
        Ok(common::scalar(
            common::read_u32(left, "arith_mul")?
                .wrapping_mul(common::read_u32(right, "arith_mul")?),
        ))
    }
}
