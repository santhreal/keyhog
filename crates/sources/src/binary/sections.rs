use keyhog_core::{Chunk, ChunkMetadata};

/// Resolve an ELF section name from a `shdr_strtab.get_at(..)` result.
///
/// LAW10 (loud recall guard): goblin returns `None` when the `sh_name` index
/// points OUTSIDE the section-name string table — a corrupt/truncated strtab.
/// A section header with a non-zero `sh_name` that fails to resolve is a parse
/// anomaly: the section could be a high-value `.rodata`/`.data` blob whose name
/// we simply could not read, and substituting `""` would silently drop it from
/// the high-value scan list. We bump `BINARY_SECTION_NAME_UNRESOLVED` so the
/// partial parse is operator-visible, then return `""`. A `sh_name == 0` (the
/// strtab's mandatory empty first entry, i.e. a legitimately unnamed section)
/// resolves to `""` WITHOUT bumping the counter — that is normal, not an error.
pub(crate) fn resolve_section_name(resolved: Option<&str>, sh_name: usize) -> &str {
    match resolved {
        Some(n) => n,
        None => {
            if sh_name != 0 {
                let _event =
                    crate::record_skip_event(crate::SourceSkipEvent::BinarySectionNameUnresolved);
            }
            ""
        }
    }
}

/// Extract strings from specific binary sections (ELF .rodata/.data, PE .rdata/.data).
/// These sections are the most likely to contain embedded secrets.
pub(crate) fn extract_sections(bytes: &[u8], path: &str) -> Option<Vec<Chunk>> {
    use goblin::Object;

    let obj = match Object::parse(bytes) {
        Ok(o) => o,
        // Law 10: recall-safe — bytes that aren't a recognized object format return
        // `None` here, and the caller falls back to whole-file printable-string
        // extraction (`extract_printable_strings`), so the binary is still scanned.
        Err(_) => return None, // LAW10: unrecognized/partial => caller scans whole-file/recovered prefix; recall-preserving
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
                let name = resolve_section_name(elf.shdr_strtab.get_at(sh.sh_name), sh.sh_name);
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
                                    base_line: 0,
                                    source_type: format!("binary:elf:{name}"),
                                    path: Some(path.to_string()),
                                    commit: None,
                                    author: None,
                                    date: None,
                                    mtime_ns: None,
                                    size_bytes: None,
                                    decoded_span: None,
                                },
                            });
                        }
                    }
                }
            }
        }
        Object::PE(pe) => {
            for section in &pe.sections {
                let name = match std::str::from_utf8(&section.name) {
                    Ok(n) => n.trim_end_matches('\0'),
                    Err(_error) => {
                        // Law 10: loud — bumps BINARY_SECTION_NAME_UNRESOLVED, never a silent drop
                        // Law 10: loud — a non-UTF-8 PE section name means the
                        // section table is corrupt; we cannot tell whether this is
                        // a high-value `.rdata`/`.data` section, so bump the
                        // partial-parse counter instead of silently treating it as
                        // an unnamed (and therefore skipped) section.
                        let _event = crate::record_skip_event(
                            crate::SourceSkipEvent::BinarySectionNameUnresolved,
                        );
                        ""
                    }
                };
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
                                    base_line: 0,
                                    source_type: format!("binary:pe:{name}"),
                                    path: Some(path.to_string()),
                                    commit: None,
                                    author: None,
                                    date: None,
                                    mtime_ns: None,
                                    size_bytes: None,
                                    decoded_span: None,
                                },
                            });
                        }
                    }
                }
            }
        }
        Object::Mach(goblin::mach::Mach::Binary(macho)) => {
            for seg in &macho.segments {
                // Law 10: a corrupt Mach-O segment whose section list cannot be
                // parsed bumps the partial-parse counter (loud), then yields an
                // empty section iterator — we do NOT silently treat the whole
                // segment as section-free, which would hide a `__cstring`/`__data`
                // section holding embedded secrets.
                let sections = match seg.sections() {
                    Ok(s) => s,
                    Err(_error) => {
                        // Law 10: loud — bumps BINARY_SECTION_NAME_UNRESOLVED, never a silent drop
                        let _event = crate::record_skip_event(
                            crate::SourceSkipEvent::BinarySectionNameUnresolved,
                        );
                        Vec::new()
                    }
                };
                for (section, _) in sections {
                    let name = match section.name() {
                        Ok(n) => n,
                        Err(_error) => {
                            // Law 10: loud — bumps BINARY_SECTION_NAME_UNRESOLVED, never a silent drop
                            let _event = crate::record_skip_event(
                                crate::SourceSkipEvent::BinarySectionNameUnresolved,
                            );
                            ""
                        }
                    };
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
                                        base_line: 0,
                                        source_type: format!("binary:macho:{name}"),
                                        path: Some(path.to_string()),
                                        commit: None,
                                        author: None,
                                        date: None,
                                        mtime_ns: None,
                                        size_bytes: None,
                                        decoded_span: None,
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
