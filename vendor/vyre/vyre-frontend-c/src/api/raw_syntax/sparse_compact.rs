use std::cell::RefCell;
use std::mem;

use super::*;

#[derive(Default)]
struct RawSparseCompactScratch {
    totals_outputs: Vec<Vec<u8>>,
    scan_outputs: Vec<Vec<u8>>,
    compact_outputs: Vec<Vec<u8>>,
    dense_types_init: Vec<u8>,
    dense_starts_init: Vec<u8>,
    dense_lens_init: Vec<u8>,
}

thread_local! {
    static RAW_SPARSE_COMPACT_SCRATCH: RefCell<RawSparseCompactScratch> =
        RefCell::new(RawSparseCompactScratch::default());
}

pub(super) fn compact_sparse_tokens_ordered_gpu(
    backend: &dyn vyre::VyreBackend,
    sparse_types: Vec<u8>,
    sparse_starts: Vec<u8>,
    sparse_lens: Vec<u8>,
    count: u32,
    config: &mut DispatchConfig,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    RAW_SPARSE_COMPACT_SCRATCH.with(|scratch| {
        let mut scratch = scratch.try_borrow_mut().map_err(|_| {
            "raw sparse token compaction scratch was re-entered on the same thread. Fix: call raw sparse compaction from a non-nested parser context or add explicit caller-owned scratch.".to_string()
        })?;
        compact_sparse_tokens_ordered_gpu_with_scratch(
            backend,
            sparse_types,
            sparse_starts,
            sparse_lens,
            count,
            config,
            &mut scratch,
        )
    })
}

fn compact_sparse_tokens_ordered_gpu_with_scratch(
    backend: &dyn vyre::VyreBackend,
    sparse_types: Vec<u8>,
    sparse_starts: Vec<u8>,
    sparse_lens: Vec<u8>,
    count: u32,
    config: &mut DispatchConfig,
    scratch: &mut RawSparseCompactScratch,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use vyre_primitives::reduce::multi_block_prefix_scan::BLOCK_LANES;

    let num_blocks = count.div_ceil(BLOCK_LANES).max(1);
    let totals_prog =
        sparse_token_block_totals_program("sparse_types", "block_totals", count, num_blocks);
    config.label = Some("vyre-frontend-c raw-byte sparse block totals".to_string());
    crate::pipeline::dispatch_borrowed_cached_into(
        backend,
        &totals_prog,
        &[&sparse_types],
        config,
        &mut scratch.totals_outputs,
    )
    .map_err(|e| format!("raw-byte sparse block-total dispatch failed: {e}"))?;
    if scratch.totals_outputs.len() != 1 {
        return Err(format!(
            "raw-byte sparse block-total dispatch returned {} outputs, expected exactly block_totals. Fix: backend must return the declared GPU block-total ABI output and no extras.",
            scratch.totals_outputs.len()
        ));
    }
    let block_totals = &scratch.totals_outputs[0];
    let scan_prog =
        vyre_primitives::reduce::multi_block_prefix_scan::multi_block_prefix_scan_sum_u32(
            "block_totals",
            "block_totals_scanned",
            num_blocks,
        );
    config.label = Some("vyre-frontend-c raw-byte sparse block scan".to_string());
    crate::pipeline::dispatch_borrowed_cached_into(
        backend,
        &scan_prog,
        &[block_totals],
        config,
        &mut scratch.scan_outputs,
    )
    .map_err(|e| format!("raw-byte sparse block scan dispatch failed: {e}"))?;
    if scratch.scan_outputs.len() != 1 {
        return Err(format!(
            "raw-byte sparse block scan returned {} outputs, expected exactly block_totals_scanned. Fix: backend must return the declared GPU prefix-scan ABI output and no extras.",
            scratch.scan_outputs.len()
        ));
    }
    let block_totals_scanned = &scratch.scan_outputs[0];
    let compact_prog = sparse_token_block_compact_program(
        "block_totals_scanned",
        "sparse_types",
        "sparse_starts",
        "sparse_lens",
        "out_tok_types",
        "out_tok_starts",
        "out_tok_lens",
        "out_counts",
        count,
        num_blocks,
    );
    let dense_bytes = (count as usize).checked_mul(4).ok_or_else(|| {
        "raw-byte sparse block compact dense byte length overflows usize. Fix: shard parser input."
            .to_string()
    })?;
    scratch.dense_types_init.clear();
    scratch.dense_types_init.resize(dense_bytes, 0);
    scratch.dense_starts_init.clear();
    scratch.dense_starts_init.resize(dense_bytes, 0);
    scratch.dense_lens_init.clear();
    scratch.dense_lens_init.resize(dense_bytes, 0);
    let compact_refs = [
        block_totals_scanned.as_slice(),
        sparse_types.as_slice(),
        sparse_starts.as_slice(),
        sparse_lens.as_slice(),
        scratch.dense_types_init.as_slice(),
        scratch.dense_starts_init.as_slice(),
        scratch.dense_lens_init.as_slice(),
    ];
    config.label = Some("vyre-frontend-c raw-byte sparse block compact".to_string());
    crate::pipeline::dispatch_borrowed_cached_into(
        backend,
        &compact_prog,
        &compact_refs,
        config,
        &mut scratch.compact_outputs,
    )
    .map_err(|e| format!("raw-byte sparse block compact dispatch failed: {e}"))?;
    if scratch.compact_outputs.len() != 4 {
        return Err(format!(
            "raw-byte sparse block compact returned {} outputs, expected exactly dense token type/start/len/count buffers. Fix: backend must return the declared GPU compaction ABI outputs and no extras.",
            scratch.compact_outputs.len()
        ));
    }
    let mut counts = Vec::new();
    let mut dense_types = Vec::new();
    mem::swap(&mut dense_types, &mut scratch.compact_outputs[0]);
    mem::swap(&mut counts, &mut scratch.compact_outputs[3]);
    Ok((dense_types, counts))
}

pub(super) fn compact_sparse_token_types_ordered_gpu(
    backend: &dyn vyre::VyreBackend,
    sparse_types: Vec<u8>,
    count: u32,
    config: &mut DispatchConfig,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    RAW_SPARSE_COMPACT_SCRATCH.with(|scratch| {
        let mut scratch = scratch.try_borrow_mut().map_err(|_| {
            "raw sparse type compaction scratch was re-entered on the same thread. Fix: call raw sparse compaction from a non-nested parser context or add explicit caller-owned scratch.".to_string()
        })?;
        compact_sparse_token_types_ordered_gpu_with_scratch(
            backend,
            sparse_types,
            count,
            config,
            &mut scratch,
        )
    })
}

fn compact_sparse_token_types_ordered_gpu_with_scratch(
    backend: &dyn vyre::VyreBackend,
    sparse_types: Vec<u8>,
    count: u32,
    config: &mut DispatchConfig,
    scratch: &mut RawSparseCompactScratch,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use vyre_primitives::reduce::multi_block_prefix_scan::BLOCK_LANES;

    let num_blocks = count.div_ceil(BLOCK_LANES).max(1);
    let totals_prog =
        sparse_token_block_totals_program("sparse_types", "block_totals", count, num_blocks);
    config.label = Some("vyre-frontend-c raw-byte sparse type block totals".to_string());
    crate::pipeline::dispatch_borrowed_cached_into(
        backend,
        &totals_prog,
        &[&sparse_types],
        config,
        &mut scratch.totals_outputs,
    )
    .map_err(|e| format!("raw-byte sparse type block-total dispatch failed: {e}"))?;
    if scratch.totals_outputs.len() != 1 {
        return Err(format!(
            "raw-byte sparse type block-total dispatch returned {} outputs, expected exactly block_totals. Fix: backend must return the declared GPU block-total ABI output and no extras.",
            scratch.totals_outputs.len()
        ));
    }
    let block_totals = &scratch.totals_outputs[0];
    let scan_prog =
        vyre_primitives::reduce::multi_block_prefix_scan::multi_block_prefix_scan_sum_u32(
            "block_totals",
            "block_totals_scanned",
            num_blocks,
        );
    config.label = Some("vyre-frontend-c raw-byte sparse type block scan".to_string());
    crate::pipeline::dispatch_borrowed_cached_into(
        backend,
        &scan_prog,
        &[block_totals],
        config,
        &mut scratch.scan_outputs,
    )
    .map_err(|e| format!("raw-byte sparse type block scan dispatch failed: {e}"))?;
    if scratch.scan_outputs.len() != 1 {
        return Err(format!(
            "raw-byte sparse type block scan returned {} outputs, expected exactly block_totals_scanned. Fix: backend must return the declared GPU prefix-scan ABI output and no extras.",
            scratch.scan_outputs.len()
        ));
    }
    let block_totals_scanned = &scratch.scan_outputs[0];
    let compact_prog = sparse_token_type_block_compact_program(
        "block_totals_scanned",
        "sparse_types",
        "out_tok_types",
        "out_counts",
        count,
        num_blocks,
    );
    let dense_bytes = (count as usize).checked_mul(4).ok_or_else(|| {
        "raw-byte sparse type compact dense byte length overflows usize. Fix: shard parser input."
            .to_string()
    })?;
    scratch.dense_types_init.clear();
    scratch.dense_types_init.resize(dense_bytes, 0);
    let compact_refs = [
        block_totals_scanned.as_slice(),
        sparse_types.as_slice(),
        scratch.dense_types_init.as_slice(),
    ];
    config.label = Some("vyre-frontend-c raw-byte sparse type block compact".to_string());
    crate::pipeline::dispatch_borrowed_cached_into(
        backend,
        &compact_prog,
        &compact_refs,
        config,
        &mut scratch.compact_outputs,
    )
    .map_err(|e| format!("raw-byte sparse type block compact dispatch failed: {e}"))?;
    if scratch.compact_outputs.len() != 2 {
        return Err(format!(
            "raw-byte sparse type block compact returned {} outputs, expected exactly dense token type/count buffers. Fix: backend must return the declared GPU type-compaction ABI outputs and no extras.",
            scratch.compact_outputs.len()
        ));
    }
    let mut counts = Vec::new();
    let mut dense_types = Vec::new();
    mem::swap(&mut dense_types, &mut scratch.compact_outputs[0]);
    mem::swap(&mut counts, &mut scratch.compact_outputs[1]);
    Ok((dense_types, counts))
}
