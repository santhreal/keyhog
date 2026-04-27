use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::HashFnv1a;

const FNV_OFFSET: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

impl common::ReferenceEvaluator for HashFnv1a {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let mut hash = FNV_OFFSET;
        let input = common::one_input(inputs, "hash_fnv1a")?;
        for byte in &input {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        Ok(Memory::from_bytes(hash.to_le_bytes().to_vec()))
    }
}
