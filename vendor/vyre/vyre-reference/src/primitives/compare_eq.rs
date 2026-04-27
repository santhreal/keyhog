use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::CompareEq;

impl common::ReferenceEvaluator for CompareEq {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "compare_eq")?;
        let matched =
            common::read_u32(left, "compare_eq")? == common::read_u32(right, "compare_eq")?;
        Ok(common::scalar(u32::from(matched)))
    }
}
