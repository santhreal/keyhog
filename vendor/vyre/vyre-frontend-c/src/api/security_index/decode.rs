use super::*;
/// Decode the complete static-analysis index from object bytes.
pub fn decode_object_security_index(object_bytes: &[u8]) -> Result<CObjectSecurityIndex, String> {
    let container = parse_embedded_vyrecob2(object_bytes)?;
    let index = CObjectSecurityIndex {
        ast: decode_object_ast_from_container(&container)?,
        lex: decode_object_lex_index_from_container(&container)?,
        semantic_graph: decode_object_semantic_graph_from_container(&container)?,
        sema_scope: decode_object_sema_scope_from_container(&container)?,
        abi_layout: decode_object_abi_layout_from_container(&container)?,
        structure: decode_object_structure_index_from_container(&container)?,
    };
    validate_security_cross_sections(&index)?;
    Ok(index)
}

/// Read and decode the complete static-analysis index from an object file.
pub fn decode_object_security_index_file(path: &Path) -> Result<CObjectSecurityIndex, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("vyre-frontend-c: read object {}: {error}", path.display()))?;
    decode_object_security_index(&bytes)
}
