//! Multi-section container for GPU compiler artifacts (`VYRECOB2` payloads).
//!
//! Forward-compatible: older readers skip unknown `SectionTag` values via length fields.

/// File magic: `VYREC02\0`
pub const VYRECOB2_MAGIC: &[u8; 8] = b"VYREC02\0";
/// Bumped when new sections are added; still uses the same magic.
pub const VYRECOB2_VERSION: u32 = 7;

#[repr(u32)]
#[derive(Clone, Copy, Debug)]
pub enum SectionTag {
    Lex = 1,
    ParenPairs = 2,
    BracePairs = 3,
    Functions = 4,
    Calls = 5,
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

pub fn push_section(out: &mut Vec<u8>, tag: SectionTag, payload: &[u8]) {
    out.extend_from_slice(&(tag as u32).to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("section length fits u32")
            .to_le_bytes(),
    );
    out.extend_from_slice(payload);
}

pub fn build_vyrecob1_lex_section(
    source_path: &std::path::Path,
    types: &[u8],
    starts: &[u8],
    lens: &[u8],
    n_tokens: u32,
) -> Result<Vec<u8>, String> {
    let mut file = Vec::new();
    file.extend_from_slice(b"VYRECOB1");
    file.extend_from_slice(&1u32.to_le_bytes());
    let p = source_path.to_string_lossy().as_bytes().to_vec();
    file.extend_from_slice(&(p.len() as u32).to_le_bytes());
    file.extend_from_slice(&p);
    while file.len() % 8 != 0 {
        file.push(0);
    }
    file.extend_from_slice(&n_tokens.to_le_bytes());
    let n = n_tokens as usize;
    for i in 0..n {
        let o = i.saturating_mul(4);
        file.extend_from_slice(
            &read_u32_bytes(types, o)
                .map_err(|error| format!("token type stream: {error}"))?
                .to_le_bytes(),
        );
        file.extend_from_slice(
            &read_u32_bytes(starts, o)
                .map_err(|error| format!("token start stream: {error}"))?
                .to_le_bytes(),
        );
        file.extend_from_slice(
            &read_u32_bytes(lens, o)
                .map_err(|error| format!("token length stream: {error}"))?
                .to_le_bytes(),
        );
    }
    Ok(file)
}

fn read_u32_bytes(buf: &[u8], off: usize) -> Result<u32, String> {
    let end = off.saturating_add(4);
    if end > buf.len() {
        return Err(format!(
            "buffer too short for u32 read at byte {off}: need {end} bytes, have {}",
            buf.len()
        ));
    }
    let bytes: [u8; 4] = buf[off..end]
        .try_into()
        .map_err(|_| format!("failed to decode u32 at byte {off}"))?;
    Ok(u32::from_le_bytes(bytes))
}

/// Serialize a `VYRECOB2` container into memory (same layout as on-disk).
#[must_use]
pub fn serialize_vyrecob2(sections: &[(SectionTag, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(VYRECOB2_MAGIC);
    out.extend_from_slice(&VYRECOB2_VERSION.to_le_bytes());
    out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    for (tag, payload) in sections {
        push_section(&mut out, *tag, payload);
    }
    out
}

pub fn write_vyrecob2(
    path: &std::path::Path,
    sections: &[(SectionTag, &[u8])],
) -> Result<(), String> {
    let out = serialize_vyrecob2(sections);
    std::fs::write(path, out).map_err(|e| format!("write {}: {e}", path.display()))
}
