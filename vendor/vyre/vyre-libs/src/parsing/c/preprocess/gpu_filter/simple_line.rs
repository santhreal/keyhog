use super::super::scan::{inclusive_prefix_scan_u32_into, PrefixScanScratch};
use super::host::read_output_u32;
use super::line_programs::{
    simple_line_comment_masks_program, simple_line_comment_starts_program,
    simple_line_newline_flags_program,
};
use super::program_helpers::byte_compact_program;
use super::FilteredBytes;
use crate::parsing::c::preprocess::gpu_pipeline::GpuDispatcher;

#[derive(Default)]
pub(super) struct SimpleLineScratch {
    zero_words: Vec<u8>,
    scalar_zero: Vec<u8>,
    scalar_ff: Vec<u8>,
    newline_flags_out: Vec<Vec<u8>>,
    newline_scan: Vec<u8>,
    row_comment_out: Vec<Vec<u8>>,
    masks_out: Vec<Vec<u8>>,
    offsets_bytes: Vec<u8>,
    compact_init: Vec<u8>,
    compact_out: Vec<Vec<u8>>,
}

impl SimpleLineScratch {
    fn prepare(&mut self, n_bucket: u32, byte_buf_pad: usize) {
        self.zero_words.clear();
        self.zero_words.resize(n_bucket as usize * 4, 0);
        self.scalar_zero.clear();
        self.scalar_zero.resize(4, 0);
        self.scalar_ff.clear();
        self.scalar_ff.resize(n_bucket as usize * 4, 0xFF);
        self.compact_init.clear();
        self.compact_init.resize(byte_buf_pad, 0);
    }
}

pub(super) fn gpu_filter_simple_line_comments(
    dispatcher: &dyn GpuDispatcher,
    raw: &[u8],
    splice_input: &[u8],
    n_bucket: u32,
    byte_buf_pad: usize,
    n_real_buf: &[u8],
    scratch: &mut SimpleLineScratch,
    scan_scratch: &mut PrefixScanScratch,
) -> Result<FilteredBytes, String> {
    scratch.prepare(n_bucket, byte_buf_pad);
    let newline_flags_prog = simple_line_newline_flags_program(n_bucket);
    dispatcher
        .dispatch_borrowed_into(
            &newline_flags_prog,
            &[splice_input, scratch.zero_words.as_slice(), n_real_buf],
            &mut scratch.newline_flags_out,
        )
        .map_err(|e| format!("simple line comments newline flags: {e}"))?;
    if scratch.newline_flags_out.len() != 1 {
        return Err(format!(
            "simple line comments newline flags: expected exactly 1 output, got {}. Fix: backend must return only newline_flags.",
            scratch.newline_flags_out.len()
        ));
    }
    inclusive_prefix_scan_u32_into(
        dispatcher,
        &scratch.newline_flags_out[0],
        n_bucket,
        scan_scratch,
        &mut scratch.newline_scan,
    )
    .map_err(|e| format!("simple line comments newline scan: {e}"))?;

    let row_comment_prog = simple_line_comment_starts_program(n_bucket);
    dispatcher
        .dispatch_borrowed_into(
            &row_comment_prog,
            &[
                splice_input,
                scratch.newline_flags_out[0].as_slice(),
                scratch.newline_scan.as_slice(),
                scratch.scalar_ff.as_slice(),
                n_real_buf,
            ],
            &mut scratch.row_comment_out,
        )
        .map_err(|e| format!("simple line comments row starts: {e}"))?;
    if scratch.row_comment_out.len() != 1 {
        return Err(format!(
            "simple line comments row starts: expected exactly 1 output, got {}. Fix: backend must return only row_comment_starts.",
            scratch.row_comment_out.len()
        ));
    }
    let masks_prog = simple_line_comment_masks_program(n_bucket);
    dispatcher
        .dispatch_borrowed_into(
            &masks_prog,
            &[
                splice_input,
                scratch.newline_flags_out[0].as_slice(),
                scratch.newline_scan.as_slice(),
                scratch.row_comment_out[0].as_slice(),
                scratch.zero_words.as_slice(),
                scratch.zero_words.as_slice(),
                n_real_buf,
            ],
            &mut scratch.masks_out,
        )
        .map_err(|e| format!("simple line comments masks: {e}"))?;
    if scratch.masks_out.len() != 2 {
        return Err(format!(
            "simple line comments masks: expected exactly 2 outputs, got {}. Fix: backend must return final_keep/comment_mask and no extras.",
            scratch.masks_out.len()
        ));
    }
    inclusive_prefix_scan_u32_into(
        dispatcher,
        &scratch.masks_out[0],
        n_bucket,
        scan_scratch,
        &mut scratch.offsets_bytes,
    )
    .map_err(|e| format!("simple line comments prefix scan: {e}"))?;

    dispatcher
        .dispatch_borrowed_into(
            &byte_compact_program(n_bucket),
            &[
                splice_input,
                scratch.masks_out[0].as_slice(),
                scratch.masks_out[1].as_slice(),
                scratch.offsets_bytes.as_slice(),
                scratch.compact_init.as_slice(),
                scratch.scalar_zero.as_slice(),
            ],
            &mut scratch.compact_out,
        )
        .map_err(|e| format!("simple line comments byte_compact: {e}"))?;
    if scratch.compact_out.len() != 2 {
        return Err(format!(
            "simple line comments byte_compact: expected exactly 2 outputs, got {}. Fix: backend must return compacted/live_count and no extras.",
            scratch.compact_out.len()
        ));
    }
    let compacted_buf = scratch
        .compact_out
        .first()
        .ok_or_else(|| "simple line comments byte_compact: missing compacted output".to_string())?;
    let live_buf = scratch.compact_out.get(1).ok_or_else(|| {
        "simple line comments byte_compact: missing live_count output".to_string()
    })?;
    let live = read_output_u32(&live_buf, "simple line comments byte_compact live_count")? as usize;
    let byte_len = live.min(raw.len()).min(compacted_buf.len());
    Ok(FilteredBytes {
        bytes: compacted_buf[..byte_len].to_vec(),
    })
}
