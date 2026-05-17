use vyre_driver::BackendError;
use vyre_foundation::ir::BufferDecl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CudaOutputReadback {
    pub(crate) device_offset: usize,
    pub(crate) byte_len: usize,
}

pub(crate) fn cuda_output_readback(
    buffer: &BufferDecl,
    full_size: usize,
) -> Result<CudaOutputReadback, BackendError> {
    let range = buffer.output_byte_range().unwrap_or(0..full_size);
    if range.start > range.end || range.end > full_size {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA output `{}` declares byte range {:?} outside its {full_size}-byte buffer.",
                buffer.name(),
                range
            ),
        });
    }
    Ok(CudaOutputReadback {
        device_offset: range.start,
        byte_len: range.end - range.start,
    })
}
