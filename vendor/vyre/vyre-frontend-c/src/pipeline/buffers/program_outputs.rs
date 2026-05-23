pub(crate) fn mark_program_outputs(
    mut program: vyre_foundation::ir::Program,
    names: &[&str],
) -> vyre_foundation::ir::Program {
    use vyre_foundation::ir::BufferAccess;

    let mut result_marked = false;
    for buffer in std::sync::Arc::make_mut(&mut program.buffers) {
        if names.iter().any(|name| buffer.name.as_ref() == *name) {
            buffer.access = BufferAccess::ReadWrite;
            buffer.pipeline_live_out = true;
            if result_marked {
                buffer.is_output = false;
            } else {
                buffer.is_output = true;
                result_marked = true;
            }
        }
    }
    program
}

pub(crate) fn mark_program_outputs_readback(
    mut program: vyre_foundation::ir::Program,
    names: &[&str],
    readback: bool,
) -> vyre_foundation::ir::Program {
    use vyre_foundation::ir::BufferAccess;

    let mut result_marked = false;
    for buffer in std::sync::Arc::make_mut(&mut program.buffers) {
        if names.iter().any(|name| buffer.name.as_ref() == *name) {
            buffer.access = BufferAccess::ReadWrite;
            buffer.pipeline_live_out = true;
            if result_marked {
                buffer.is_output = false;
            } else {
                buffer.is_output = true;
                result_marked = true;
            }
            if !readback {
                buffer.output_byte_range = Some(0..0);
            }
        }
    }
    program
}

pub(crate) fn suppress_readwrite_readback(
    mut program: vyre_foundation::ir::Program,
    names: &[&str],
) -> vyre_foundation::ir::Program {
    for buffer in std::sync::Arc::make_mut(&mut program.buffers) {
        if names.iter().any(|name| buffer.name.as_ref() == *name) {
            buffer.output_byte_range = Some(0..0);
        }
    }
    program
}

pub(crate) fn drop_suppressed_readbacks(outputs: &mut Vec<Vec<u8>>) {
    outputs.retain(|output| !output.is_empty());
}

pub(crate) fn is_input_buffer(buf: &vyre_foundation::ir::BufferDecl) -> bool {
    use vyre_foundation::ir::BufferAccess;
    if buf.is_output {
        return false;
    }
    if buf.pipeline_live_out && buf.access == BufferAccess::ReadWrite {
        return false;
    }
    matches!(
        buf.access,
        BufferAccess::ReadOnly | BufferAccess::ReadWrite | BufferAccess::Uniform
    )
}
