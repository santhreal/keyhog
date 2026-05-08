use keyhog_core::{Chunk, ChunkMetadata};

/// Extract strings from specific binary sections (ELF .rodata/.data, PE .rdata/.data).
/// These sections are the most likely to contain embedded secrets.
pub(crate) fn extract_sections(bytes: &[u8], path: &str) -> Option<Vec<Chunk>> {
    use goblin::Object;

    let obj = match Object::parse(bytes) {
        Ok(o) => o,
        Err(_) => return None,
    };

    let mut chunks = Vec::new();

    // High-value section names where secrets are commonly embedded
    let target_sections = &[
        ".rodata",
        ".rdata",
        ".data",
        ".const",
        ".cstring",
        "__cstring",
        "__const",
        "__data",
    ];

    match obj {
        Object::Elf(elf) => {
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if target_sections.contains(&name) {
                    let start = sh.sh_offset as usize;
                    let end = (start + sh.sh_size as usize).min(bytes.len());
                    if start < end {
                        let section_bytes = &bytes[start..end];
                        let strings = crate::binary::extract_printable_strings(
                            section_bytes,
                            crate::binary::MIN_STRING_LEN,
                        );
                        if !strings.is_empty() {
                            chunks.push(Chunk {
                                data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                metadata: ChunkMetadata {
                                    base_offset: 0,
                                    source_type: format!("binary:elf:{name}"),
                                    path: Some(path.to_string()),
                                    commit: None,
                                    author: None,
                                    date: None,
                                    mtime_ns: None,
                                    size_bytes: None,
                                },
                            });
                        }
                    }
                }
            }
        }
        Object::PE(pe) => {
            for section in &pe.sections {
                let name = std::str::from_utf8(&section.name)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                if target_sections.contains(&name) {
                    let start = section.pointer_to_raw_data as usize;
                    let end = (start + section.size_of_raw_data as usize).min(bytes.len());
                    if start < end {
                        let section_bytes = &bytes[start..end];
                        let strings = crate::binary::extract_printable_strings(
                            section_bytes,
                            crate::binary::MIN_STRING_LEN,
                        );
                        if !strings.is_empty() {
                            chunks.push(Chunk {
                                data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                metadata: ChunkMetadata {
                                    base_offset: 0,
                                    source_type: format!("binary:pe:{name}"),
                                    path: Some(path.to_string()),
                                    commit: None,
                                    author: None,
                                    date: None,
                                    mtime_ns: None,
                                    size_bytes: None,
                                },
                            });
                        }
                    }
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            for seg in &macho.segments {
                for (section, _) in seg.sections().unwrap_or_default() {
                    let name = section.name().unwrap_or("");
                    if target_sections.contains(&name) {
                        let start = section.offset as usize;
                        let end = (start + section.size as usize).min(bytes.len());
                        if start < end {
                            let section_bytes = &bytes[start..end];
                            let strings = crate::binary::extract_printable_strings(
                                section_bytes,
                                crate::binary::MIN_STRING_LEN,
                            );
                            if !strings.is_empty() {
                                chunks.push(Chunk {
                                    data: keyhog_core::SensitiveString::join(&strings, "\n"),
                                    metadata: ChunkMetadata {
                                        base_offset: 0,
                                        source_type: format!("binary:macho:{name}"),
                                        path: Some(path.to_string()),
                                        commit: None,
                                        author: None,
                                        date: None,
                                        mtime_ns: None,
                                        size_bytes: None,
                                    },
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    if chunks.is_empty() {
        None
    } else {
        Some(chunks)
    }
}
