use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::Clz;

impl common::ReferenceEvaluator for Clz {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let input = common::one_input(inputs, "clz")?;
        Ok(common::scalar(
            common::read_u32(input, "clz")?.leading_zeros(),
        ))
    }
}
