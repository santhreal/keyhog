//! Multi-section container for GPU compiler artifacts (`VYRECOB2` payloads).
//!
//! Forward-compatible: older readers skip unknown `SectionTag` values via length fields.

/// File magic: `VYREC02\0`
pub const VYRECOB2_MAGIC: &[u8; 8] = b"VYREC02\0";
/// Bumped when new sections are added; still uses the same magic.
pub const VYRECOB2_VERSION: u32 = 7;

/// Discriminant of the per-section payload kind in a `VYRECOB2` container.
///
/// The integer value is the on-disk tag; readers MUST round-trip unknown tags
/// using their length prefix so older readers can skip newer payloads.
#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum SectionTag {
    /// Token type / start / length streams (the GPU lex output).
    Lex = 1,
    /// Paren-balanced span table.
    ParenPairs = 2,
    /// Brace-balanced span table.
    BracePairs = 3,
    /// Function shape table emitted from the AST.
    Functions = 4,
    /// Call-site table emitted from the AST.
    Calls = 5,
    /// Embedded Linux ET_REL `.o` payload.
    Elf = 6,
    /// `opt_conditional_mask` output (u32 per token).
    PreprocMask = 7,
    /// `opt_dynamic_macro_expansion` token stream (types buffer).
    MacroTypes = 8,
    /// `c11_compute_alignments` (`sizes` || `aligns`).
    AbiLayout = 9,
    /// `ast_shunting_yard` flat AST pool + roots (concatenated blobs).
    Ast = 10,
    /// `c11_build_cfg_and_gotos` (`cfg` || `labels` || label tables).
    Cfg = 11,
    /// `vyre_runtime::megakernel::protocol` fingerprint (fixed header).
    Megakernel = 12,
    /// Token-level VAST node table emitted by the C parser.
    Vast = 13,
    /// ProgramGraph node rows lowered from VAST.
    ProgramGraph = 14,
    /// `c_sema_scope` records: scope id, parent scope id, declaration kind, identifier id.
    SemaScope = 15,
    /// `c11_build_expression_shape_nodes` rows derived from raw + typed VAST.
    ExpressionShape = 16,
    /// Semantic ProgramGraph node rows: base PG fields plus category, role, and attributes.
    SemanticProgramGraphNodes = 17,
    /// Semantic ProgramGraph edge rows, including resolved expression/statement control edges.
    SemanticProgramGraphEdges = 18,
}

/// Append a single tagged section (`u32` tag, `u32` payload length, payload bytes) to `out`.
pub fn push_section(out: &mut Vec<u8>, tag: SectionTag, payload: &[u8]) -> Result<(), String> {
    out.extend_from_slice(&(tag as u32).to_le_bytes());
    let section_len = u32::try_from(payload.len()).map_err(|_| {
        format!(
            "section `{tag:?}` length {} exceeds u32::MAX. Fix: split this vyre-frontend-c object section.",
            payload.len()
        )
    })?;
    out.extend_from_slice(&section_len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Build a self-contained `VYRECOB1` lex blob for `source_path` from the type/start/length
/// streams emitted by the GPU C lexer.
///
/// Returns an error if `types`, `starts`, or `lens` is shorter than `n_tokens` u32 words.
pub fn build_vyrecob1_lex_section(
    source_path: &std::path::Path,
    types: &[u8],
    starts: &[u8],
    lens: &[u8],
    n_tokens: u32,
) -> Result<Vec<u8>, String> {
    let n = n_tokens as usize;
    let stream_bytes = n.saturating_mul(4);
    require_prefix(types, stream_bytes, "token type stream")?;
    require_prefix(starts, stream_bytes, "token start stream")?;
    require_prefix(lens, stream_bytes, "token length stream")?;

    let path_bytes = source_path.to_string_lossy();
    let p = path_bytes.as_bytes();
    let header_len = 8 + 4 + 4 + p.len();
    let aligned_header_len = (header_len + 7) & !7;
    let mut file = Vec::with_capacity(
        aligned_header_len
            .saturating_add(4)
            .saturating_add(n.saturating_mul(12)),
    );
    file.extend_from_slice(b"VYRECOB1");
    file.extend_from_slice(&1u32.to_le_bytes());
    let path_len = u32::try_from(p.len()).map_err(|_| {
        format!(
            "source path length {} exceeds u32::MAX. Fix: compile from a shorter path or canonicalize through a shorter build root.",
            p.len()
        )
    })?;
    file.extend_from_slice(&path_len.to_le_bytes());
    file.extend_from_slice(p);
    while file.len() % 8 != 0 {
        file.push(0);
    }
    file.extend_from_slice(&n_tokens.to_le_bytes());
    for i in 0..n {
        let o = i.saturating_mul(4);
        file.extend_from_slice(&types[o..o + 4]);
        file.extend_from_slice(&starts[o..o + 4]);
        file.extend_from_slice(&lens[o..o + 4]);
    }
    Ok(file)
}

fn require_prefix(buf: &[u8], bytes: usize, label: &str) -> Result<(), String> {
    if bytes > buf.len() {
        return Err(format!(
            "{label}: buffer too short: need {bytes} bytes, have {}",
            buf.len()
        ));
    }
    Ok(())
}

/// Serialize a `VYRECOB2` container into memory (same layout as on-disk).
pub fn serialize_vyrecob2(sections: &[(SectionTag, &[u8])]) -> Result<Vec<u8>, String> {
    let section_count = u32::try_from(sections.len()).map_err(|_| {
        format!(
            "VYRECOB2 section count {} exceeds u32::MAX. Fix: split this object container.",
            sections.len()
        )
    })?;
    let payload_bytes = sections
        .iter()
        .try_fold(0usize, |acc, (_, payload)| {
            acc.checked_add(8)?.checked_add(payload.len())
        })
        .ok_or_else(|| {
            "VYRECOB2 total payload length overflows usize. Fix: split this object container."
                .to_string()
        })?;
    let mut out = Vec::with_capacity(16usize.saturating_add(payload_bytes));
    out.extend_from_slice(VYRECOB2_MAGIC);
    out.extend_from_slice(&VYRECOB2_VERSION.to_le_bytes());
    out.extend_from_slice(&section_count.to_le_bytes());
    for (tag, payload) in sections {
        push_section(&mut out, *tag, payload)?;
    }
    Ok(out)
}

/// Serialize `sections` into a `VYRECOB2` blob and write it to `path`, replacing any existing file.
pub fn write_vyrecob2(
    path: &std::path::Path,
    sections: &[(SectionTag, &[u8])],
) -> Result<(), String> {
    let out = serialize_vyrecob2(sections)?;
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}
