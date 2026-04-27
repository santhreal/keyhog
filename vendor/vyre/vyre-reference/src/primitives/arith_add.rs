use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::ArithAdd;

impl common::ReferenceEvaluator for ArithAdd {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "arith_add")?;
        Ok(common::scalar(
            common::read_u32(left, "arith_add")?
                .wrapping_add(common::read_u32(right, "arith_add")?),
        ))
    }
}
