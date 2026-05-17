use super::*;

pub(super) fn identifier_lexeme<'a>(
    vast_nodes: &[u32],
    node_idx: usize,
    haystack: &'a [u8],
) -> Option<&'a [u8]> {
    if kind_at(vast_nodes, node_idx) != TOK_IDENTIFIER {
        return None;
    }
    let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
    let start = vast_nodes.get(base + 5).copied().unwrap_or_default() as usize;
    let len = vast_nodes.get(base + 6).copied().unwrap_or_default() as usize;
    haystack.get(start..start.saturating_add(len))
}

pub(super) fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub(super) fn is_gnu_typeof_hash_raw(hash: u32) -> bool {
    C_GNU_TYPEOF_HASHES.contains(&hash)
}

pub(super) fn is_gnu_auto_type_hash_raw(hash: u32) -> bool {
    hash == C_GNU_AUTO_TYPE_HASH
}

pub(super) fn symbol_hash_at(vast_nodes: &[u32], node_idx: usize) -> u32 {
    vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + VAST_TYPEDEF_SYMBOL_FIELD as usize)
        .copied()
        .unwrap_or_default()
}

pub(super) fn is_typeof_operator_raw(kind: u32, symbol_hash: u32) -> bool {
    matches!(kind, TOK_GNU_TYPEOF | TOK_GNU_TYPEOF_UNQUAL)
        || (kind == TOK_IDENTIFIER && is_gnu_typeof_hash_raw(symbol_hash))
}

pub(super) fn is_decl_prefix_at(vast_nodes: &[u32], node_idx: usize) -> bool {
    let kind = kind_at(vast_nodes, node_idx);
    let symbol_hash = symbol_hash_at(vast_nodes, node_idx);
    is_decl_prefix_raw(kind)
        || is_typeof_operator_raw(kind, symbol_hash)
        || (kind == TOK_IDENTIFIER && is_gnu_auto_type_hash_raw(symbol_hash))
}
