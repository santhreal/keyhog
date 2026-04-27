use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::CompareLt;

impl common::ReferenceEvaluator for CompareLt {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (left, right) = common::two_inputs(inputs, "compare_lt")?;
        let matched =
            common::read_u32(left, "compare_lt")? < common::read_u32(right, "compare_lt")?;
        Ok(common::scalar(u32::from(matched)))
    }
}
