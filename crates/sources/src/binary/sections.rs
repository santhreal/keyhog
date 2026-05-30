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
                    // `start + sh_size` can overflow on a malformed ELF whose
                    // header advertises a section offset/size near usize::MAX;
                    // overflow panics in debug builds. saturating_add keeps the
                    // result in-bounds and the `start < end` guard below then
                    // drops the bogus section instead of crashing the scan.
                    let end = start.saturating_add(sh.sh_size as usize).min(bytes.len());
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
                    // saturating_add: a malformed PE can claim a raw-data
                    // pointer/size that overflows usize and would panic the
                    // `start + size` add in debug builds. Clamp instead.
                    let end = start
                        .saturating_add(section.size_of_raw_data as usize)
                        .min(bytes.len());
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
                        // saturating_add: a malformed Mach-O section can claim
                        // an offset/size that overflows usize and would panic
                        // the `start + size` add in debug builds. Clamp instead.
                        let end = start.saturating_add(section.size as usize).min(bytes.len());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A scanner must never crash on bad input. Garbage bytes are not a
    /// parseable object file: `Object::parse` returns `Err` and we must
    /// return `None`, not panic.
    #[test]
    fn returns_none_on_garbage_bytes() {
        let junk = [0x12u8, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        assert!(extract_sections(&junk, "junk.bin").is_none());
    }

    /// Empty input also parses to no object and yields `None`.
    #[test]
    fn returns_none_on_empty_input() {
        assert!(extract_sections(&[], "empty.bin").is_none());
    }

    /// Regression for the section offset/size overflow guard: an input
    /// starting with the ELF magic but otherwise truncated/corrupt must be
    /// handled without panicking. Whatever goblin makes of these bytes,
    /// the saturating_add on `start + size` keeps every slice in-bounds.
    #[test]
    fn truncated_elf_magic_does_not_panic() {
        // ELF magic followed by 64-bit/little-endian class bytes then a
        // run of 0xFF that, if interpreted as a section offset/size, would
        // overflow usize on the `start + size` add the guard now saturates.
        let mut bytes = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
        bytes.extend(std::iter::repeat(0xFF).take(120));
        // Must return without panicking; result shape is irrelevant.
        let _ = extract_sections(&bytes, "trunc.elf");
    }
}
