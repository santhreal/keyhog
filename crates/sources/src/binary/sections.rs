use goblin::mach::{MachO, SingleArch};
use keyhog_core::{Chunk, ChunkMetadata};

/// Resolve an ELF section name from a `shdr_strtab.get_at(..)` result.
///
/// LAW10 (loud recall guard): goblin returns `None` when the `sh_name` index
/// points OUTSIDE the section-name string table (a corrupt/truncated strtab).
/// A section header with a non-zero `sh_name` that fails to resolve is a parse
/// anomaly: the section could be a high-value `.rodata`/`.data` blob whose name
/// we simply could not read, and substituting `""` would silently drop it from
/// the high-value scan list. We bump `BINARY_SECTION_NAME_UNRESOLVED` so the
/// partial parse is operator-visible, then return `""`. A `sh_name == 0` (the
/// strtab's mandatory empty first entry, i.e. a legitimately unnamed section)
/// resolves to `""` WITHOUT bumping the counter (that is normal, not an error).
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
        // Law 10: recall-safe, bytes that aren't a recognized object format return
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
                            crate::strings::MIN_PRINTABLE_STRING_LEN,
                        );
                        if !strings.is_empty() {
                            chunks.push(Chunk {
                                data: crate::strings::join_sensitive_strings(&strings, "\n"),
                                metadata: ChunkMetadata {
                                    base_offset: 0,
                                    base_line: 0,
                                    source_type: format!("binary:elf:{name}").into(),
                                    path: Some(path.into()),
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
                        // Law 10: loud, bumps BINARY_SECTION_NAME_UNRESOLVED, never a silent drop
                        // Law 10: loud, a non-UTF-8 PE section name means the
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
                            crate::strings::MIN_PRINTABLE_STRING_LEN,
                        );
                        if !strings.is_empty() {
                            chunks.push(Chunk {
                                data: crate::strings::join_sensitive_strings(&strings, "\n"),
                                metadata: ChunkMetadata {
                                    base_offset: 0,
                                    base_line: 0,
                                    source_type: format!("binary:pe:{name}").into(),
                                    path: Some(path.into()),
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
            append_macho_sections(&mut chunks, &macho, bytes, path, target_sections);
        }
        Object::Mach(goblin::mach::Mach::Fat(fat)) => {
            let arches = match fat.arches() {
                Ok(arches) => arches,
                Err(_error) => {
                    let _event = crate::record_skip_event(
                        crate::SourceSkipEvent::BinarySectionNameUnresolved,
                    );
                    Vec::new()
                }
            };
            for (index, arch) in arches.iter().enumerate() {
                let Some(arch_bytes) = checked_fat_arch_slice(bytes, arch.offset, arch.size) else {
                    let _event = crate::record_skip_event(
                        crate::SourceSkipEvent::BinarySectionNameUnresolved,
                    );
                    continue;
                };
                match fat.get(index) {
                    Ok(SingleArch::MachO(macho)) => append_macho_sections(
                        &mut chunks,
                        &macho,
                        arch_bytes,
                        path,
                        target_sections,
                    ),
                    Ok(SingleArch::Archive(_)) => {}
                    Err(_error) => {
                        let _event = crate::record_skip_event(
                            crate::SourceSkipEvent::BinarySectionNameUnresolved,
                        );
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

fn append_macho_sections(
    chunks: &mut Vec<Chunk>,
    macho: &MachO<'_>,
    bytes: &[u8],
    path: &str,
    target_sections: &[&str],
) {
    for seg in &macho.segments {
        // Law 10: a corrupt Mach-O segment whose section list cannot be
        // parsed bumps the partial-parse counter (loud), then yields an
        // empty section iterator. This avoids silently treating the whole
        // segment as section-free when it may hold embedded secrets.
        let sections = match seg.sections() {
            Ok(s) => s,
            Err(_error) => {
                let _event =
                    crate::record_skip_event(crate::SourceSkipEvent::BinarySectionNameUnresolved);
                Vec::new()
            }
        };
        for (section, _) in sections {
            let name = match section.name() {
                Ok(n) => n,
                Err(_error) => {
                    let _event = crate::record_skip_event(
                        crate::SourceSkipEvent::BinarySectionNameUnresolved,
                    );
                    ""
                }
            };
            if target_sections.contains(&name) {
                let start = section.offset as usize;
                // saturating_add: a malformed Mach-O section can claim an
                // offset/size that overflows usize and would panic the scan.
                let end = start.saturating_add(section.size as usize).min(bytes.len());
                if start < end {
                    let section_bytes = &bytes[start..end];
                    let strings = crate::binary::extract_printable_strings(
                        section_bytes,
                        crate::strings::MIN_PRINTABLE_STRING_LEN,
                    );
                    if !strings.is_empty() {
                        chunks.push(Chunk {
                            data: crate::strings::join_sensitive_strings(&strings, "\n"),
                            metadata: ChunkMetadata {
                                base_offset: 0,
                                base_line: 0,
                                source_type: format!("binary:macho:{name}").into(),
                                path: Some(path.into()),
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

fn checked_fat_arch_slice(bytes: &[u8], offset: u32, size: u32) -> Option<&[u8]> {
    let start = offset as usize;
    start
        .checked_add(size as usize)
        .and_then(|end| bytes.get(start..end))
}
