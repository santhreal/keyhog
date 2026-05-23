use vyre::ir::{BufferAccess, Program};
use vyre_primitives::reduce::multi_block_prefix_scan::{
    multi_block_prefix_scan_sum_u32, pass_a_local_scan, pass_c_broadcast_offsets, BLOCK_LANES,
};

use super::GpuDispatcher;

#[derive(Default)]
pub(super) struct PrefixScanScratch {
    small_zero: Vec<u8>,
    small_outputs: Vec<Vec<u8>>,
    pass_a_partials_zero: Vec<u8>,
    pass_a_totals_zero: Vec<u8>,
    pass_a_outputs: Vec<Vec<u8>>,
    block_totals_input: Vec<u8>,
    scanned_block_totals: Vec<u8>,
    nested: Option<Box<PrefixScanScratch>>,
    pass_c_zero: Vec<u8>,
    pass_c_outputs: Vec<Vec<u8>>,
}

impl PrefixScanScratch {
    fn prepare_zero(out: &mut Vec<u8>, byte_len: usize) {
        out.clear();
        out.resize(byte_len, 0);
    }
}

pub(super) fn inclusive_prefix_scan_u32_into(
    dispatcher: &dyn GpuDispatcher,
    input_words_le: &[u8],
    n: u32,
    scratch: &mut PrefixScanScratch,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    if n > BLOCK_LANES {
        return inclusive_prefix_scan_u32_large_into(dispatcher, input_words_le, n, scratch, out);
    }
    let scan = multi_block_prefix_scan_sum_u32("scan_in", "scan_out", n);
    if dispatcher.requires_output_inputs() {
        PrefixScanScratch::prepare_zero(&mut scratch.small_zero, n as usize * 4);
        dispatcher.dispatch_borrowed_into(
            &scan,
            &[input_words_le, scratch.small_zero.as_slice()],
            &mut scratch.small_outputs,
        )?;
        if scratch.small_outputs.len() != 1 {
            return Err(format!(
                "prefix scan: expected exactly 1 output, got {}. Fix: backend must return only scan_out.",
                scratch.small_outputs.len()
            ));
        }
    } else {
        dispatcher.dispatch_borrowed_into(&scan, &[input_words_le], &mut scratch.small_outputs)?;
        if scratch.small_outputs.len() != 1 {
            return Err(format!(
                "prefix scan: expected exactly 1 output, got {}. Fix: backend must return only scan_out.",
                scratch.small_outputs.len()
            ));
        }
    }
    out.clear();
    out.extend_from_slice(&scratch.small_outputs[0]);
    Ok(())
}

fn inclusive_prefix_scan_u32_large_into(
    dispatcher: &dyn GpuDispatcher,
    input_words_le: &[u8],
    n: u32,
    scratch: &mut PrefixScanScratch,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    let num_blocks = n.div_ceil(BLOCK_LANES);
    let total_partials = num_blocks.saturating_mul(BLOCK_LANES);
    let mut pass_a = pass_a_local_scan(
        "scan_in",
        "scan_partials",
        "scan_block_totals",
        n,
        num_blocks,
    );
    if dispatcher.requires_output_inputs() {
        pass_a = live_out_readwrite_buffers(pass_a, &["scan_partials", "scan_block_totals"]);
        PrefixScanScratch::prepare_zero(
            &mut scratch.pass_a_partials_zero,
            total_partials as usize * 4,
        );
        PrefixScanScratch::prepare_zero(&mut scratch.pass_a_totals_zero, num_blocks as usize * 4);
        dispatcher
            .dispatch_borrowed_into(
                &pass_a,
                &[
                    input_words_le,
                    scratch.pass_a_partials_zero.as_slice(),
                    scratch.pass_a_totals_zero.as_slice(),
                ],
                &mut scratch.pass_a_outputs,
            )
            .map_err(|e| format!("pass A: {e}"))?;
    } else {
        dispatcher
            .dispatch_borrowed_into(&pass_a, &[input_words_le], &mut scratch.pass_a_outputs)
            .map_err(|e| format!("pass A: {e}"))?;
    }
    if scratch.pass_a_outputs.len() != 2 {
        return Err(format!(
            "pass A: expected exactly 2 outputs, got {}. Fix: backend must return scan_partials/scan_block_totals and no extras.",
            scratch.pass_a_outputs.len()
        ));
    }

    scratch.block_totals_input.clear();
    scratch
        .block_totals_input
        .extend_from_slice(&scratch.pass_a_outputs[1]);
    let nested = scratch
        .nested
        .get_or_insert_with(|| Box::new(PrefixScanScratch::default()));
    inclusive_prefix_scan_u32_into(
        dispatcher,
        scratch.block_totals_input.as_slice(),
        num_blocks,
        nested,
        &mut scratch.scanned_block_totals,
    )?;

    let pass_c = pass_c_broadcast_offsets(
        "scan_partials",
        "scan_block_totals_scanned",
        "scan_out",
        n,
        num_blocks,
    );
    if dispatcher.requires_output_inputs() {
        PrefixScanScratch::prepare_zero(&mut scratch.pass_c_zero, n as usize * 4);
        dispatcher
            .dispatch_borrowed_into(
                &pass_c,
                &[
                    scratch.pass_a_outputs[0].as_slice(),
                    scratch.scanned_block_totals.as_slice(),
                    scratch.pass_c_zero.as_slice(),
                ],
                &mut scratch.pass_c_outputs,
            )
            .map_err(|e| format!("pass C: {e}"))?;
    } else {
        dispatcher
            .dispatch_borrowed_into(
                &pass_c,
                &[
                    scratch.pass_a_outputs[0].as_slice(),
                    scratch.scanned_block_totals.as_slice(),
                ],
                &mut scratch.pass_c_outputs,
            )
            .map_err(|e| format!("pass C: {e}"))?;
    }
    if scratch.pass_c_outputs.len() != 1 {
        return Err(format!(
            "pass C: expected exactly 1 output, got {}. Fix: backend must return only scan_out.",
            scratch.pass_c_outputs.len()
        ));
    }
    out.clear();
    out.extend_from_slice(&scratch.pass_c_outputs[0]);
    Ok(())
}

fn live_out_readwrite_buffers(program: Program, names: &[&str]) -> Program {
    let buffers = program
        .buffers()
        .iter()
        .map(|buffer| {
            let mut buffer = buffer.clone();
            if names.iter().any(|name| *name == buffer.name()) {
                buffer.is_output = false;
                buffer.pipeline_live_out = true;
                buffer.output_byte_range = None;
                buffer.access = BufferAccess::ReadWrite;
            }
            buffer
        })
        .collect();
    program.with_rewritten_buffers(buffers)
}
