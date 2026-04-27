//! Flat byte adapter that turns every CPU reference into a uniform byte-in,
//! byte-out contract.
//!
//! The parity engine compares raw bytes, not structured values. This module
//! exists so primitive ops can be tested with the same binary-diff harness
//! regardless of their internal Value representation.

use vyre::ir::{BufferAccess, DataType, Program};

use crate::reference_eval;
use crate::value::Value;
/// Execute a program from a concatenated single-case byte payload.
///
/// Fixed-width input buffers consume one element each from `input`. Read-write
/// output buffers are initialized to one zero element and appended to `output`
/// after interpretation.
///
/// # Errors
///
/// Returns [`vyre::error::Error`] if the program is invalid or execution fails.
///
/// # Examples
///
/// ```rust,ignore
/// let mut out = Vec::new();
/// vyre::reference::flat_cpu::run_flat(&program, &input_bytes, &mut out)?;
/// ```
pub fn run_flat(program: &Program, input: &[u8], output: &mut Vec<u8>) -> Result<(), vyre::Error> {
    let mut offset = 0usize;
    let mut values = Vec::new();
    for buffer in program.buffers() {
        match buffer.access() {
            BufferAccess::ReadOnly | BufferAccess::Uniform => {
                let width = buffer.element().min_bytes();
                let mut bytes = vec![0; width];
                let available = input.len().saturating_sub(offset).min(width);
                bytes[..available].copy_from_slice(&input[offset..offset + available]);
                offset = offset.saturating_add(width).min(input.len());
                values.push(Value::from(bytes));
            }
            BufferAccess::ReadWrite => {
                values.push(Value::from(vec![0; output_width(buffer.element())]));
            }
            BufferAccess::Workgroup => {}
            _ => {}
        }
    }
    let values = reference_eval(program, &values)?;
    output.clear();
    for value in values {
        output.extend_from_slice(&value.to_bytes());
    }
    Ok(())
}

fn output_width(data_type: DataType) -> usize {
    data_type.min_bytes().max(4)
}
