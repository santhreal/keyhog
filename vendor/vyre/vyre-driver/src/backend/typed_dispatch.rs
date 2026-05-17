//! Typed dispatch helpers layered over the frozen backend contract.

use std::mem;

use bytemuck::Pod;
use smallvec::SmallVec;
use vyre_foundation::ir::Program;

use crate::backend::{BackendError, DispatchConfig, VyreBackend};

/// Extension methods for callers that work with typed POD buffers instead of
/// manually packing and unpacking byte vectors.
pub trait TypedDispatchExt: VyreBackend {
    /// Dispatch borrowed byte slices.
    ///
    /// This is a naming convenience over [`VyreBackend::dispatch_borrowed`]
    /// for call sites that are migrating away from owned `Vec<u8>` inputs.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the backend rejects the program, inputs,
    /// or dispatch.
    fn dispatch_bytes(
        &self,
        program: &Program,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        self.dispatch_borrowed(program, inputs, config)
    }

    /// Dispatch borrowed typed POD inputs and decode each output as `T`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when an output byte length is not a whole
    /// number of `T` values or when the backend dispatch fails.
    fn dispatch_pod<T: Pod>(
        &self,
        program: &Program,
        inputs: &[&[T]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<T>>, BackendError> {
        let byte_inputs: SmallVec<[&[u8]; 8]> = inputs
            .iter()
            .map(|input| bytemuck::cast_slice::<T, u8>(input))
            .collect();
        let outputs = self.dispatch_borrowed(program, &byte_inputs, config)?;
        decode_pod_outputs(outputs)
    }

    /// Dispatch borrowed `u32` inputs and decode each output as `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] on backend failure or malformed output length.
    fn dispatch_u32(
        &self,
        program: &Program,
        inputs: &[&[u32]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u32>>, BackendError> {
        self.dispatch_pod(program, inputs, config)
    }

    /// Dispatch borrowed `f32` inputs and decode each output as `f32`.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] on backend failure or malformed output length.
    fn dispatch_f32(
        &self,
        program: &Program,
        inputs: &[&[f32]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<f32>>, BackendError> {
        self.dispatch_pod(program, inputs, config)
    }
}

impl<T: VyreBackend + ?Sized> TypedDispatchExt for T {}

fn decode_pod_outputs<T: Pod>(outputs: Vec<Vec<u8>>) -> Result<Vec<Vec<T>>, BackendError> {
    let width = mem::size_of::<T>();
    if width == 0 {
        return Err(BackendError::InvalidProgram {
            fix: "Fix: typed dispatch does not support zero-sized POD outputs.".to_string(),
        });
    }
    outputs
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| decode_pod_output(index, bytes, width))
        .collect()
}

fn decode_pod_output<T: Pod>(
    index: usize,
    bytes: Vec<u8>,
    width: usize,
) -> Result<Vec<T>, BackendError> {
    let remainder = bytes.len() % width;
    if remainder != 0 {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: output buffer {index} has {} bytes, which is not a whole number of {}-byte typed values.",
                bytes.len(),
                width
            ),
        });
    }
    Ok(bytes
        .chunks_exact(width)
        .map(bytemuck::pod_read_unaligned::<T>)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use vyre_foundation::ir::{OpId, Program};

    use super::*;
    use crate::backend::private;

    struct EchoBackend;

    impl private::Sealed for EchoBackend {}

    impl VyreBackend for EchoBackend {
        fn id(&self) -> &'static str {
            "typed-dispatch-test"
        }

        fn supported_ops(&self) -> &HashSet<OpId> {
            static OPS: std::sync::OnceLock<HashSet<OpId>> = std::sync::OnceLock::new();
            OPS.get_or_init(HashSet::new)
        }

        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            Ok(inputs.to_vec())
        }
    }

    #[test]
    fn dispatch_u32_packs_inputs_and_decodes_outputs() {
        let backend = EchoBackend;
        let input = [1u32, 2, 0x0102_0304];
        let outputs = backend
            .dispatch_u32(&Program::empty(), &[&input], &DispatchConfig::default())
            .unwrap_or_else(|error| panic!("typed u32 dispatch must succeed: {error}"));

        assert_eq!(outputs, vec![input.to_vec()]);
    }

    #[test]
    fn typed_decode_rejects_partial_words() {
        let error = decode_pod_outputs::<u32>(vec![vec![1, 2, 3]])
            .expect_err("partial u32 output must fail");

        assert!(
            error.to_string().contains("whole number of 4-byte"),
            "malformed typed output must produce actionable width error: {error}"
        );
    }
}
