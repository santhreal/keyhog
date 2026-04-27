use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::Popcount;

impl common::ReferenceEvaluator for Popcount {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let input = common::one_input(inputs, "popcount")?;
        Ok(common::scalar(
            common::read_u32(input, "popcount")?.count_ones(),
        ))
    }
}
