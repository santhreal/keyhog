use super::*;

pub(crate) fn bytes_to_u32_word_bytes_into(
    out: &mut Vec<u8>,
    bytes: &[u8],
    pad_len: usize,
) -> Result<(), String> {
    let word_count = pad_len.max(bytes.len()).max(1);
    let byte_len = checked_staging_word_bytes(word_count, "macro source byte word table")?;
    out.clear();
    reserve_staging_bytes(out, byte_len, "macro source byte word table")?;
    if bytes.is_empty() {
        out.extend_from_slice(&0u32.to_le_bytes());
    } else {
        for byte in bytes {
            out.extend_from_slice(&u32::from(*byte).to_le_bytes());
        }
    }
    out.resize(byte_len, 0);
    Ok(())
}

pub(crate) fn pad_u32_byte_buffer_into(
    out: &mut Vec<u8>,
    bytes: &[u8],
    word_count: usize,
) -> Result<(), String> {
    let min_words = bytes.len().div_ceil(4).max(1);
    let byte_len = checked_staging_word_bytes(
        word_count.max(min_words),
        "macro replacement byte word table",
    )?;
    out.clear();
    reserve_staging_bytes(out, byte_len, "macro replacement byte word table")?;
    out.extend_from_slice(bytes);
    out.resize(byte_len, 0);
    Ok(())
}

pub(crate) fn checked_staging_word_bytes(word_count: usize, label: &str) -> Result<usize, String> {
    word_count.checked_mul(4).ok_or_else(|| {
        format!(
            "vyre-libs::gpu_pipeline: {label} byte length overflowed. Fix: shard macro expansion staging before GPU dispatch."
        )
    })
}

pub(crate) fn reserve_staging_bytes(
    out: &mut Vec<u8>,
    byte_len: usize,
    label: &str,
) -> Result<(), String> {
    out.try_reserve_exact(byte_len).map_err(|error| {
        format!(
            "vyre-libs::gpu_pipeline: failed to reserve {byte_len} bytes for {label}: {error}. Fix: shard macro expansion staging before GPU dispatch."
        )
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_u32_word_bytes_never_truncates_when_pad_len_is_short() {
        let mut out = Vec::new();
        bytes_to_u32_word_bytes_into(&mut out, b"abc", 1)
            .expect("Fix: tiny macro source staging should reserve");
        assert_eq!(out.len(), 12);
        assert_eq!(&out[0..4], &u32::from(b'a').to_le_bytes());
        assert_eq!(&out[4..8], &u32::from(b'b').to_le_bytes());
        assert_eq!(&out[8..12], &u32::from(b'c').to_le_bytes());
    }

    #[test]
    fn pad_u32_byte_buffer_never_truncates_when_word_count_is_short() {
        let mut out = Vec::new();
        let bytes = [1u8, 2, 3, 4, 5];
        pad_u32_byte_buffer_into(&mut out, &bytes, 1)
            .expect("Fix: tiny replacement staging should reserve");
        assert_eq!(&out[0..bytes.len()], bytes.as_slice());
        assert_eq!(out.len(), 8);
        assert_eq!(&out[5..8], &[0, 0, 0]);
    }

    #[test]
    fn macro_expansion_staging_reports_word_byte_overflow() {
        let mut out = Vec::new();

        let err = bytes_to_u32_word_bytes_into(&mut out, &[], usize::MAX)
            .expect_err("absurd pad length must fail before staging allocation");

        assert!(err.contains("byte length overflowed"), "{err}");
        assert!(out.is_empty());
    }

    #[test]
    fn macro_expansion_staging_reports_reservation_failure() {
        let mut out = Vec::new();

        let err = reserve_staging_bytes(&mut out, usize::MAX, "generated staging")
            .expect_err("absurd staging allocation must be reported");

        assert!(err.contains("failed to reserve"), "{err}");
        assert!(out.is_empty());
    }
}
