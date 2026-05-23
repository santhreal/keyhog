use super::*;

/// Records provenance for a segment copied unchanged into the output stream.
pub(crate) fn record_direct_token_provenance(
    file_path: &std::path::Path,
    include_stack: &[std::path::PathBuf],
    classified: &ClassifiedTokens,
    output_base: usize,
    token_provenance_events: &mut Vec<TokenProvenanceEvent>,
) -> Result<(), String> {
    token_provenance_events.reserve(replacement_token_count(classified));
    for (idx, token_kind) in classified.tok_types.iter().enumerate() {
        if *token_kind == 0 {
            continue;
        }
        let start = token_start(classified, idx)?;
        let len = token_len(classified, idx)?;
        token_provenance_events.push(TokenProvenanceEvent {
            file: file_path.to_path_buf(),
            output_start: checked_output_offset(output_base, start, "direct token output start")?,
            output_len: len,
            spelling_file: file_path.to_path_buf(),
            spelling_start: start,
            spelling_len: len,
            expansion_file: file_path.to_path_buf(),
            expansion_start: start,
            expansion_len: len,
            include_stack: include_stack.to_vec(),
            macro_symbol_id: None,
            macro_name: Vec::new(),
            gpu_resident: true,
        });
    }
    Ok(())
}
