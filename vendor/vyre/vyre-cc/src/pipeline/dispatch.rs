use vyre::ir::Expr;
use vyre::{DispatchConfig, VyreBackend};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::compiler::object_writer::opt_lower_elf;
use vyre_primitives::matching::bracket_match::{bracket_match, pack_u32};

use super::buffers::{match_none_init, read_u32_stream};
use super::BRACKET_MAX_DEPTH;

pub(super) fn dispatch_bracket_match(
    backend: &WgpuBackend,
    kinds: &[u32],
    label: &str,
) -> Result<Vec<u32>, String> {
    let n_u32 = u32::try_from(kinds.len()).unwrap_or(u32::MAX).max(1);
    let max_depth = n_u32.clamp(1, BRACKET_MAX_DEPTH);
    let prog = bracket_match("kinds", "stack", "match_pairs", n_u32, max_depth);
    if !vyre::validate(&prog).is_empty() {
        return Err("bracket_match IR validation failed".to_string());
    }
    let kinds_b = pack_u32(kinds);
    let stack_b = vec![0u8; max_depth as usize * 4];
    let pairs_init = match_none_init(kinds.len());
    let inputs = vec![kinds_b, stack_b, pairs_init];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(label.to_string());
    let outs = backend
        .dispatch(&prog, &inputs, &cfg)
        .map_err(|e| e.to_string())?;
    let pairs = outs
        .get(1)
        .ok_or_else(|| "bracket_match: missing match_pairs output".to_string())?;
    read_u32_stream(pairs, kinds.len(), "bracket_match pairs")
}

pub(super) fn try_dispatch_elf(
    backend: &WgpuBackend,
    compiler_words: &[u32],
) -> Result<Vec<u8>, String> {
    let node_count = u32::try_from(compiler_words.len())
        .map_err(|_| "ELF lowering input exceeds u32 word count".to_string())?
        .max(1);
    let prog = opt_lower_elf("ssa_nodes", "elf_out", Expr::u32(node_count));
    if !vyre::validate(&prog).is_empty() {
        return Err("opt_lower_elf validate failed".to_string());
    }
    let ssa = pack_u32(compiler_words);
    let elf_init = vec![0u8; 4096 * 4];
    let offsets_init = vec![0u8; 16 * 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some("vyre-cc opt_lower_elf".to_string());
    let outs = backend
        .dispatch(&prog, &[ssa, elf_init, offsets_init], &cfg)
        .map_err(|e| e.to_string())?;
    outs.first()
        .cloned()
        .ok_or_else(|| "ELF lowering: missing output buffer".to_string())
}
