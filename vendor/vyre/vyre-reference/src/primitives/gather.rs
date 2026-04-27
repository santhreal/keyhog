use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::Gather;

impl common::ReferenceEvaluator for Gather {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (values, indices) = common::two_inputs(inputs, "gather")?;
        let values = common::u32_words(values, "gather")?;
        let indices = common::u32_words(indices, "gather")?;
        let mut output = Vec::with_capacity(indices.len());
        for index in indices {
            output.push(values[common::checked_index(index, values.len(), "gather")?]);
        }
        Ok(common::write_u32s(output))
    }
}
