use std::path::Path;

use vyre::ir::Expr;
use vyre::{DispatchConfig, VyreBackend};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::parsing::c::sema::registry::c_sema_scope;

use super::buffers::vec_u32_le_bytes;

#[allow(clippy::too_many_arguments)]
pub(super) fn build_sema_scope(
    backend: &WgpuBackend,
    path: &Path,
    tok_types: &[u32],
    starts: &[u8],
    lens: &[u8],
    haystack: &[u8],
    haystack_len: u32,
    nt: u32,
) -> Result<Vec<u8>, String> {
    let sema_prog = c_sema_scope(
        "tok_types",
        "tok_starts",
        "tok_lens",
        "haystack",
        Expr::u32(haystack_len.max(1)),
        Expr::u32(nt.max(1)),
        "out_scope_tree",
    );
    if !vyre::validate(&sema_prog).is_empty() {
        return Err("c_sema_scope IR validation failed".to_string());
    }

    let out_scope_tree = vec![0u8; nt.max(1) as usize * 4 * 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(format!("vyre-cc sema {}", path.display()));
    let sema_out = backend
        .dispatch(
            &sema_prog,
            &[
                vec_u32_le_bytes(tok_types),
                starts.to_vec(),
                lens.to_vec(),
                haystack.to_vec(),
                out_scope_tree,
            ],
            &cfg,
        )
        .map_err(|e| format!("c_sema_scope dispatch failed: {e}"))?;

    sema_out
        .first()
        .cloned()
        .ok_or_else(|| "c_sema_scope: missing scope tree output".to_string())
}
