#![forbid(unsafe_code)]

//! Registry adapter that exposes `vyre-reference` as a `VyreBackend`.

use std::sync::Arc;

use vyre_driver::backend::private;
use vyre_driver::backend::{
    core_supported_ops, BackendCapability, BackendError, BackendPrecedence, BackendRegistration,
};
use vyre_driver::{DispatchConfig, VyreBackend};
use vyre_foundation::ir::{BufferAccess, BufferDecl, Program};
use vyre_reference::value::Value;

/// Stable backend id for the pure-Rust reference interpreter.
pub const CPU_REF_BACKEND_ID: &str = "cpu-ref";

/// Dispatch backend backed by `vyre_reference::reference_eval`.
#[derive(Debug, Default, Clone, Copy)]
pub struct CpuRefBackend;

impl private::Sealed for CpuRefBackend {}

impl VyreBackend for CpuRefBackend {
    fn id(&self) -> &'static str {
        CPU_REF_BACKEND_ID
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        _config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let values = reference_values(program, inputs)?;
        vyre_reference::reference_eval(program, &values)
            .map(|outputs| outputs.iter().map(Value::to_bytes).collect())
            .map_err(|error| {
                BackendError::new(format!(
                    "cpu-ref reference dispatch failed: {error}. Fix: validate the Program and input buffer ABI before dispatch."
                ))
            })
    }

    fn supported_ops(&self) -> &std::collections::HashSet<vyre_foundation::ir::OpId> {
        core_supported_ops()
    }

    fn max_workgroup_size(&self) -> [u32; 3] {
        [1024, 1, 1]
    }

    fn max_compute_workgroups_per_dimension(&self) -> u32 {
        u32::MAX
    }
}

fn reference_values(program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Value>, BackendError> {
    let mut next_input = 0usize;
    let mut values = Vec::new();
    for buffer in program.buffers() {
        if buffer.access() == BufferAccess::Workgroup {
            continue;
        }
        let bytes = if buffer.is_output() {
            synthesized_zero_buffer(buffer, "output")?
        } else if let Some(input) = inputs.get(next_input) {
            next_input += 1;
            input.clone()
        } else {
            synthesized_zero_buffer(buffer, "missing input")?
        };
        values.push(Value::Bytes(Arc::from(bytes)));
    }
    if next_input != inputs.len() {
        return Err(BackendError::new(format!(
            "cpu-ref received {} extra input buffer(s). Fix: pass inputs in Program::buffers order without trailing buffers.",
            inputs.len() - next_input
        )));
    }
    Ok(values)
}

fn synthesized_zero_buffer(buffer: &BufferDecl, role: &'static str) -> Result<Vec<u8>, BackendError> {
    let element_size = buffer.element().size_bytes().ok_or_else(|| {
        BackendError::new(format!(
            "cpu-ref cannot synthesize {role} buffer `{}` because its element type is unsized. Fix: declare fixed-width buffers or pass an explicit input buffer.",
            buffer.name()
        ))
    })?;
    let byte_len = usize::try_from(buffer.count())
        .ok()
        .and_then(|count| count.checked_mul(element_size))
        .ok_or_else(|| {
            BackendError::new(format!(
                "cpu-ref {role} buffer `{}` size overflows usize. Fix: use a representable buffer size.",
                buffer.name()
            ))
        })?;
    Ok(vec![0u8; byte_len])
}

fn acquire_cpu_ref() -> Result<Box<dyn VyreBackend>, BackendError> {
    Ok(Box::new(CpuRefBackend))
}

inventory::submit! {
    BackendRegistration {
        id: CPU_REF_BACKEND_ID,
        factory: acquire_cpu_ref,
        supported_ops: core_supported_ops,
    }
}

inventory::submit! {
    BackendCapability {
        id: CPU_REF_BACKEND_ID,
        dispatches: true,
    }
}

inventory::submit! {
    BackendPrecedence {
        id: CPU_REF_BACKEND_ID,
        rank: 900,
    }
}
