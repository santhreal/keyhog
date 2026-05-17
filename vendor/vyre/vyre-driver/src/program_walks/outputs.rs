//! Output-buffer readback layout and budget checks.

use std::sync::Arc;

use vyre_foundation::ir::{BufferDecl, DataType, Program};

use crate::backend::{BackendError, DispatchConfig};

/// Enforces [`DispatchConfig::max_output_bytes`] against materialized readback buffers.
///
/// # Errors
///
/// Returns when the summed output length exceeds the configured cap.
pub fn enforce_actual_output_budget(
    config: &DispatchConfig,
    outputs: &[Vec<u8>],
) -> Result<(), BackendError> {
    let Some(limit) = config.max_output_bytes else {
        return Ok(());
    };
    let actual = outputs.iter().try_fold(0usize, |sum, output| {
        sum.checked_add(output.len()).ok_or_else(|| {
            BackendError::new(
                "actual readback size overflows usize. Fix: split the Program output before dispatch.",
            )
        })
    })?;
    if actual > limit {
        return Err(BackendError::new(format!(
            "actual readback size {actual} exceeds DispatchConfig.max_output_bytes {limit}. Fix: narrow BufferDecl::output_byte_range or raise max_output_bytes."
        )));
    }
    Ok(())
}

/// Output readback layout derived from a program's declared output range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputLayout {
    /// Full output buffer byte size allocated on the GPU.
    pub full_size: usize,
    /// Consumer-visible byte count returned from dispatch.
    pub read_size: usize,
    /// Aligned source offset copied from the GPU output buffer.
    pub copy_offset: usize,
    /// Aligned staging-buffer byte size.
    pub copy_size: usize,
    /// Offset within the staging buffer where the requested range starts.
    pub trim_start: usize,
}

/// Readback and allocation metadata for one writable buffer.
#[derive(Clone, Debug)]
pub struct OutputBindingLayout {
    /// Buffer binding slot.
    pub binding: u32,
    /// Buffer name for diagnostics.
    pub name: Arc<str>,
    /// Full readback/copy layout for this binding.
    pub layout: OutputLayout,
    /// Rounded-up 32-bit word count used for allocation and clears.
    pub word_count: usize,
}

/// Derive output readback layout for a program.
///
/// # Errors
///
/// Returns a backend error when the program has no output buffer or declares
/// an out-of-bounds output byte range.
pub fn output_layout_from_program(program: &Program) -> Result<OutputLayout, BackendError> {
    let Some(&index) = program.output_buffer_indices().first() else {
        return Err(BackendError::new(
            "program has no output buffer. Fix: declare exactly one output buffer in the vyre Program.",
        ));
    };
    let output = program.buffers().get(index as usize).ok_or_else(|| {
        BackendError::new(format!(
            "output buffer index {index} is out of bounds. Fix: rebuild the Program so writable buffer metadata stays consistent."
        ))
    })?;
    output_binding_layout(output).map(|output| output.layout)
}

/// All output-buffer binding layouts for `program`, in declaration order.
///
/// # Errors
///
/// Returns when there is no output buffer, an index is invalid, or layout
/// math fails.
pub fn output_binding_layouts(program: &Program) -> Result<Vec<OutputBindingLayout>, BackendError> {
    let mut outputs = Vec::with_capacity(program.output_buffer_indices().len());
    output_binding_layouts_into(program, &mut outputs)?;
    Ok(outputs)
}

/// Write output-buffer binding layouts into caller-owned storage.
///
/// # Errors
///
/// Returns when there is no output buffer, an index is invalid, or layout
/// math fails.
pub fn output_binding_layouts_into(
    program: &Program,
    outputs: &mut Vec<OutputBindingLayout>,
) -> Result<(), BackendError> {
    outputs.clear();
    outputs.reserve(program.output_buffer_indices().len());
    for &index in program.output_buffer_indices() {
        let output = program.buffers().get(index as usize).ok_or_else(|| {
            BackendError::new(
                format!(
                    "output buffer index {index} is out of bounds. Fix: rebuild the Program so writable buffer metadata stays consistent."
                ),
            )
        })?;
        outputs.push(output_binding_layout(output)?);
    }
    if outputs.is_empty() {
        return Err(BackendError::new(
            "program has no output buffer. Fix: declare at least one writable buffer in the vyre Program.",
        ));
    }
    Ok(())
}

/// Per-output binding layout for a single declared output buffer.
///
/// # Errors
///
/// Returns when counts, element size, or declared byte range are inconsistent.
pub fn output_binding_layout(output: &BufferDecl) -> Result<OutputBindingLayout, BackendError> {
    let count = usize::try_from(output.count()).map_err(|_| {
        BackendError::new(
            "program output element count exceeds usize. Fix: split the dispatch into smaller output buffers.",
        )
    })?;
    let element_size = element_size_bytes(&output.element)?;
    let full_size = count.checked_mul(element_size).ok_or_else(|| {
        BackendError::new(
            "program output byte size overflows usize. Fix: split the dispatch into smaller output buffers.",
        )
    })?;
    let layout = output_layout(output, full_size)?;
    let word_count = full_size
        .checked_add(3)
        .and_then(|n| n.checked_div(4))
        .unwrap_or(full_size)
        .max(1);
    Ok(OutputBindingLayout {
        binding: output.binding(),
        name: Arc::clone(&output.name),
        layout,
        word_count,
    })
}

fn output_layout(output: &BufferDecl, full_size: usize) -> Result<OutputLayout, BackendError> {
    let range = output.output_byte_range().unwrap_or(0..full_size);
    if range.start > range.end || range.end > full_size {
        return Err(BackendError::new(format!(
            "output byte range {:?} is outside output buffer size {full_size}. Fix: declare a range within the output buffer.",
            range
        )));
    }
    let copy_offset = range.start & !3;
    let copy_end = range.end.next_multiple_of(4).min(full_size.max(4));
    let copy_size = (copy_end.saturating_sub(copy_offset)).max(4);
    Ok(OutputLayout {
        full_size,
        read_size: range.end - range.start,
        copy_offset,
        copy_size,
        trim_start: range.start - copy_offset,
    })
}

/// Fixed scalar element size in bytes for [`DataType`].
///
/// # Errors
///
/// Returns when the type has no fixed size (e.g. unsized or dynamic).
pub fn element_size_bytes(data_type: &DataType) -> Result<usize, BackendError> {
    data_type.size_bytes().ok_or_else(|| {
        BackendError::new(
            "output buffer element type has no fixed scalar element size. Fix: validate the Program and flatten variable-size outputs before backend pipeline compilation.",
        )
    })
}
