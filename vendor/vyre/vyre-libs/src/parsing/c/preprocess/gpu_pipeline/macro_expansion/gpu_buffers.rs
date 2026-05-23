use super::*;

pub(crate) fn bytes_to_u32_word_bytes_into(out: &mut Vec<u8>, bytes: &[u8], pad_len: usize) {
    let word_count = pad_len.max(1);
    let byte_len = word_count.saturating_mul(4);
    out.clear();
    out.reserve(byte_len);
    if bytes.is_empty() {
        out.extend_from_slice(&0u32.to_le_bytes());
    } else {
        for byte in bytes {
            out.extend_from_slice(&u32::from(*byte).to_le_bytes());
        }
    }
    out.resize(byte_len, 0);
}

pub(crate) fn pad_u32_byte_buffer_into(out: &mut Vec<u8>, bytes: &[u8], word_count: usize) {
    let byte_len = word_count.saturating_mul(4);
    out.clear();
    out.reserve(byte_len);
    out.extend_from_slice(bytes);
    out.resize(byte_len, 0);
}

pub(crate) fn materialized_output_program(program: Program) -> Program {
    let buffers = program
        .buffers()
        .iter()
        .cloned()
        .map(|mut buffer| {
            if (17..=22).contains(&buffer.binding) {
                buffer.access = BufferAccess::WriteOnly;
                buffer.pipeline_live_out = true;
            }
            buffer
        })
        .collect::<Vec<_>>();
    program.with_rewritten_buffers(buffers)
}
