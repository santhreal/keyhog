use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::Shuffle;

impl common::ReferenceEvaluator for Shuffle {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let (values, indices) = common::two_inputs(inputs, "shuffle")?;
        let values = common::u32_words(values, "shuffle")?;
        let indices = common::u32_words(indices, "shuffle")?;
        let mut output = Vec::with_capacity(indices.len());
        for index in indices {
            output.push(values[common::checked_index(index, values.len(), "shuffle")?]);
        }
        Ok(common::write_u32s(output))
    }
}
