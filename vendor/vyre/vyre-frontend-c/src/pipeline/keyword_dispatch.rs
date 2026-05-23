use std::cell::RefCell;
use std::mem;

use super::*;

#[derive(Default)]
struct KeywordDispatchScratch {
    outputs: Vec<Vec<u8>>,
}

thread_local! {
    static KEYWORD_DISPATCH_SCRATCH: RefCell<KeywordDispatchScratch> =
        RefCell::new(KeywordDispatchScratch::default());
}

pub(in crate::pipeline) fn promote_c11_keywords(
    backend: &dyn VyreBackend,
    source: &str,
    dcfg: &mut DispatchConfig,
    expanded_haystack_cache: &mut Option<(Vec<u8>, u32)>,
    types: &mut Vec<u8>,
    starts: &[u8],
    lens: &[u8],
    counts: &[u8],
    n_tokens: u32,
    keyword_promoted: bool,
    cuda_keyword_haystack: Option<(&[u8], u32)>,
    dispatch_label: &str,
    mut log: impl FnMut(&str),
) -> Result<(), String> {
    KEYWORD_DISPATCH_SCRATCH.with(|scratch| {
        let mut scratch = scratch.try_borrow_mut().map_err(|_| {
            "c_keyword dispatch scratch was re-entered on the same thread. Fix: call keyword promotion from a non-nested parser context or add explicit caller-owned scratch.".to_string()
        })?;
        promote_c11_keywords_with_scratch(
            backend,
            source,
            dcfg,
            expanded_haystack_cache,
            types,
            starts,
            lens,
            counts,
            n_tokens,
            keyword_promoted,
            cuda_keyword_haystack,
            dispatch_label,
            &mut log,
            &mut scratch,
        )
    })
}

fn promote_c11_keywords_with_scratch(
    backend: &dyn VyreBackend,
    source: &str,
    dcfg: &mut DispatchConfig,
    expanded_haystack_cache: &mut Option<(Vec<u8>, u32)>,
    types: &mut Vec<u8>,
    starts: &[u8],
    lens: &[u8],
    counts: &[u8],
    n_tokens: u32,
    keyword_promoted: bool,
    cuda_keyword_haystack: Option<(&[u8], u32)>,
    dispatch_label: &str,
    mut log: impl FnMut(&str),
    scratch: &mut KeywordDispatchScratch,
) -> Result<(), String> {
    if keyword_promoted {
        log("skip c_keyword; lexer promoted keywords");
        return Ok(());
    }

    let keyword_map_bytes = keyword_map_bytes_cached();
    let (keyword_prog, keyword_haystack, keyword_stage) =
        if let Some((packed_haystack, packed_len)) = cuda_keyword_haystack {
            (
                c_keyword_packed_haystack(
                    "tok_types",
                    "tok_starts",
                    "tok_lens",
                    "counts",
                    "haystack",
                    "keyword_map",
                    n_tokens.max(1),
                    C_KEYWORDS.len() as u32,
                    packed_len.max(1),
                ),
                packed_haystack,
                "c_keyword_packed_haystack",
            )
        } else {
            let was_packed = expanded_haystack_cache.is_none();
            let (dense_haystack, dense_haystack_len) =
                expanded_haystack(expanded_haystack_cache, source)?;
            if was_packed {
                log("pack_haystack");
            }
            (
                c_keyword(
                    "tok_types",
                    "tok_starts",
                    "tok_lens",
                    "counts",
                    "haystack",
                    "keyword_map",
                    n_tokens.max(1),
                    C_KEYWORDS.len() as u32,
                    dense_haystack_len.max(1),
                ),
                dense_haystack,
                "c_keyword",
            )
        };
    validate_internal_stage(&keyword_prog, keyword_stage)?;
    dcfg.label = Some(dispatch_label.to_string());
    dispatch_borrowed_cached_into(
        backend,
        &keyword_prog,
        &[
            types,
            starts,
            lens,
            counts,
            keyword_haystack,
            keyword_map_bytes,
        ],
        dcfg,
        &mut scratch.outputs,
    )
    .map_err(|error| format!("{dispatch_label} c_keyword dispatch failed: {error}"))?;
    log("dispatch c_keyword");
    if scratch.outputs.len() != 1 {
        return Err(format!(
            "{dispatch_label}: expected exactly 1 keyword output buffer, got {}. Fix: backend must return promoted token types and no extras.",
            scratch.outputs.len()
        ));
    }
    mem::swap(types, &mut scratch.outputs[0]);
    Ok(())
}
