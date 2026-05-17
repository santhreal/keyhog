use crate::{dual_impls::common, workgroup::Memory};
use vyre_primitives::Reduce;

impl common::ReferenceEvaluator for Reduce {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let words = common::u32_words(common::one_input(inputs, "reduce")?, "reduce")?;
        let Some((&first, tail)) = words.split_first() else {
            return Ok(common::scalar(0));
        };
        let mut value = first;
        for next in tail.iter().copied() {
            value = common::combine(self.combine, value, next)?;
        }
        Ok(common::scalar(value))
    }
}
