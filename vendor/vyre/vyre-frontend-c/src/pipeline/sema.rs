use std::path::Path;

use vyre::ir::Expr;
use vyre::{DispatchConfig, VyreBackend};

use vyre_libs::parsing::c::sema::registry::{c_sema_scope, reference_scope_tree};

#[allow(clippy::too_many_arguments)]
pub(super) fn build_sema_scope(
    backend: &dyn VyreBackend,
    path: &Path,
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
    source: &[u8],
    tok_types_bytes: &[u8],
    starts: &[u8],
    lens: &[u8],
    haystack: &[u8],
    haystack_len: u32,
    nt: u32,
) -> Result<Vec<u8>, String> {
    if nt <= 4096 && std::env::var_os("VYRE_FRONTEND_C_FORCE_GPU_SEMA_SCOPE").is_none() {
        let haystack_words: Vec<u32> = source.iter().map(|byte| u32::from(*byte)).collect();
        let scope_words = reference_scope_tree(tok_types, tok_starts, tok_lens, &haystack_words);
        return Ok(scope_words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect());
    }

    let sema_prog = c_sema_scope(
        "tok_types",
        "tok_starts",
        "tok_lens",
        "haystack",
        Expr::u32(haystack_len.max(1)),
        Expr::u32(nt.max(1)),
        "out_scope_tree",
    );
    super::validate_internal_stage(&sema_prog, "c_sema_scope")?;

    let out_scope_tree = vec![0u8; nt.max(1) as usize * 4 * 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(format!("vyre-frontend-c sema {}", path.display()));
    let sema_out = super::dispatch_borrowed_cached(
        backend,
            &sema_prog,
            &[
                tok_types_bytes,
                starts,
                lens,
                haystack,
                &out_scope_tree,
            ],
            &cfg,
        )
        .map_err(|e| format!("c_sema_scope dispatch failed: {e}"))?;

    sema_out
        .into_iter()
        .next()
        .ok_or_else(|| "c_sema_scope: missing scope tree output".to_string())
}
