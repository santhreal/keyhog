//! Bounded Android resource-table and binary-XML expansion.

use keyhog_core::{Chunk, ChunkMetadata, SourceCoverageGapKind, SourceError};
use std::collections::HashSet;

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const UTF8_FLAG: u32 = 0x0000_0100;
const NO_INDEX: u32 = u32::MAX;
const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
const TYPE_FLAG_SPARSE: u8 = 0x01;
const TYPE_FLAG_OFFSET16: u8 = 0x02;
const VALUE_TYPE_REFERENCE: u8 = 0x01;
const VALUE_TYPE_STRING: u8 = 0x03;
const VALUE_TYPE_INT_DEC: u8 = 0x10;
const VALUE_TYPE_INT_HEX: u8 = 0x11;
const VALUE_TYPE_INT_BOOLEAN: u8 = 0x12;

#[derive(Clone, Copy)]
struct AndroidLimits {
    max_input_bytes: usize,
    max_chunks: usize,
    max_strings: usize,
    max_output_items: usize,
    max_output_bytes: usize,
    max_depth: usize,
    max_table_entries: usize,
    max_packages: usize,
}

const PRODUCTION_LIMITS: AndroidLimits = AndroidLimits {
    max_input_bytes: 64 * 1024 * 1024,
    max_chunks: 16_384,
    max_strings: 262_144,
    max_output_items: 262_144,
    max_output_bytes: 64 * 1024 * 1024,
    max_depth: 256,
    max_table_entries: 65_536,
    max_packages: 256,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AndroidErrorKind {
    Malformed,
    Limit,
}

#[derive(Debug, Eq, PartialEq)]
struct AndroidCompiledError {
    kind: AndroidErrorKind,
    offset: usize,
    detail: String,
}

impl AndroidCompiledError {
    fn malformed(offset: usize, detail: impl Into<String>) -> Self {
        Self {
            kind: AndroidErrorKind::Malformed,
            offset,
            detail: detail.into(),
        }
    }

    fn limit(offset: usize, detail: impl Into<String>) -> Self {
        Self {
            kind: AndroidErrorKind::Limit,
            offset,
            detail: detail.into(),
        }
    }

    fn coverage_kind(&self) -> SourceCoverageGapKind {
        match self.kind {
            AndroidErrorKind::Malformed => SourceCoverageGapKind::Inaccessible,
            AndroidErrorKind::Limit => SourceCoverageGapKind::Truncated,
        }
    }
}

#[derive(Clone, Copy)]
struct ChunkHeader {
    kind: u16,
    start: usize,
    header_size: usize,
    end: usize,
}

impl ChunkHeader {
    fn data_start(self) -> usize {
        self.start + self.header_size
    }
}

struct StringPool {
    strings: Vec<String>,
}

#[derive(Default)]
struct ParseBudget {
    chunks_seen: usize,
    table_entries_seen: usize,
}

impl StringPool {
    fn get(&self, index: u32, offset: usize) -> Result<&str, AndroidCompiledError> {
        self.strings
            .get(index as usize)
            .map(String::as_str)
            .ok_or_else(|| {
                AndroidCompiledError::malformed(
                    offset,
                    format!("string-pool index {index} is out of range"),
                )
            })
    }
}

struct OutputBuilder<'a> {
    archive_display: &'a str,
    entry_name: &'a str,
    source_type: &'static str,
    input_size: usize,
    limits: &'a AndroidLimits,
    output_bytes: usize,
    chunks: Vec<Chunk>,
}

impl<'a> OutputBuilder<'a> {
    fn new(
        archive_display: &'a str,
        entry_name: &'a str,
        source_type: &'static str,
        input_size: usize,
        limits: &'a AndroidLimits,
    ) -> Self {
        Self {
            archive_display,
            entry_name,
            source_type,
            input_size,
            limits,
            output_bytes: 0,
            chunks: Vec::new(),
        }
    }

    fn push(
        &mut self,
        offset: usize,
        provenance: &str,
        data: String,
    ) -> Result<(), AndroidCompiledError> {
        if self.chunks.len() >= self.limits.max_output_items {
            return Err(AndroidCompiledError::limit(
                offset,
                format!(
                    "Android compiled-resource output exceeded {} items",
                    self.limits.max_output_items
                ),
            ));
        }
        self.output_bytes = self.output_bytes.checked_add(data.len()).ok_or_else(|| {
            AndroidCompiledError::limit(offset, "Android compiled-resource output size overflow")
        })?;
        if self.output_bytes > self.limits.max_output_bytes {
            return Err(AndroidCompiledError::limit(
                offset,
                format!(
                    "Android compiled-resource output exceeded {} bytes",
                    self.limits.max_output_bytes
                ),
            ));
        }
        let path = format!(
            "{}//{}::{}",
            self.archive_display,
            self.entry_name,
            provenance.trim_matches('/')
        );
        self.chunks.push(Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                source_type: self.source_type.into(),
                path: Some(path.into()),
                size_bytes: Some(self.input_size as u64),
                ..Default::default()
            },
        });
        Ok(())
    }
}

#[derive(Debug)]
enum AndroidParseOutcome {
    NotApplicable,
    Parsed(Vec<Chunk>),
}

pub(super) fn emit_android_compiled_member(
    archive_display: &str,
    entry_name: &str,
    content: &[u8],
    emit: &mut dyn FnMut(Result<Chunk, SourceError>) -> bool,
) -> bool {
    match parse_member_with_limits(archive_display, entry_name, content, &PRODUCTION_LIMITS) {
        Ok(AndroidParseOutcome::NotApplicable) => true,
        Ok(AndroidParseOutcome::Parsed(chunks)) => {
            for chunk in chunks {
                if !emit(Ok(chunk)) {
                    return false;
                }
            }
            true
        }
        Err(error) => {
            let target = format!("{archive_display}//{entry_name}");
            emit(Err(SourceError::Coverage {
                adapter: "filesystem/archive/android".to_string(),
                surface: "compiled-resource".to_string(),
                target,
                kind: error.coverage_kind(),
                detail: format!(
                    "Android compiled-resource parse failed at byte {}: {}; the ordinary archive member scan continued",
                    error.offset, error.detail
                ),
            }))
        }
    }
}

fn parse_member_with_limits(
    archive_display: &str,
    entry_name: &str,
    content: &[u8],
    limits: &AndroidLimits,
) -> Result<AndroidParseOutcome, AndroidCompiledError> {
    if !archive_display
        .rsplit("//")
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".apk"))
    {
        return Ok(AndroidParseOutcome::NotApplicable);
    }
    let lower_name = entry_name.to_ascii_lowercase();
    let is_table = lower_name == "resources.arsc";
    let is_xml = lower_name.ends_with(".xml")
        && content
            .get(..2)
            .is_some_and(|prefix| read_u16_unchecked(prefix) == RES_XML_TYPE);
    if !is_table && !is_xml {
        return Ok(AndroidParseOutcome::NotApplicable);
    }
    if content.len() > limits.max_input_bytes {
        return Err(AndroidCompiledError::limit(
            0,
            format!(
                "Android compiled-resource member is {} bytes, above the {}-byte parser cap",
                content.len(),
                limits.max_input_bytes
            ),
        ));
    }
    if is_table {
        parse_resource_table(archive_display, entry_name, content, limits)
            .map(AndroidParseOutcome::Parsed)
    } else {
        parse_binary_xml(archive_display, entry_name, content, limits)
            .map(AndroidParseOutcome::Parsed)
    }
}

fn parse_resource_table(
    archive_display: &str,
    entry_name: &str,
    bytes: &[u8],
    limits: &AndroidLimits,
) -> Result<Vec<Chunk>, AndroidCompiledError> {
    let root = parse_header(bytes, 0, bytes.len())?;
    if root.kind != RES_TABLE_TYPE || root.header_size < 12 {
        return Err(AndroidCompiledError::malformed(
            0,
            "resources.arsc does not start with a valid resource-table header",
        ));
    }
    if root.end != bytes.len() {
        return Err(AndroidCompiledError::malformed(
            root.end,
            "resource-table root size does not cover the complete member",
        ));
    }
    let package_count = read_u32(bytes, 8)? as usize;
    if package_count > limits.max_packages {
        return Err(AndroidCompiledError::limit(
            8,
            format!(
                "resource-table package count {package_count} exceeds cap {}",
                limits.max_packages
            ),
        ));
    }
    let mut budget = ParseBudget::default();
    let children = child_headers(bytes, root, limits, &mut budget)?;
    let global_pool_header = children
        .iter()
        .copied()
        .find(|header| header.kind == RES_STRING_POOL_TYPE)
        .ok_or_else(|| {
            AndroidCompiledError::malformed(
                root.data_start(),
                "resource table has no value string pool",
            )
        })?;
    let global_pool = parse_string_pool(bytes, global_pool_header, limits)?;
    let packages: Vec<_> = children
        .iter()
        .copied()
        .filter(|header| header.kind == RES_TABLE_PACKAGE_TYPE)
        .collect();
    if packages.len() != package_count {
        return Err(AndroidCompiledError::malformed(
            8,
            format!(
                "resource-table header declares {package_count} package(s), found {}",
                packages.len()
            ),
        ));
    }

    let mut output = OutputBuilder::new(
        archive_display,
        entry_name,
        "filesystem/archive/android-resource",
        bytes.len(),
        limits,
    );
    let mut identities = HashSet::new();
    for package in packages {
        parse_package(
            bytes,
            package,
            &global_pool,
            limits,
            &mut budget,
            &mut identities,
            &mut output,
        )?;
    }
    Ok(output.chunks)
}

fn parse_package(
    bytes: &[u8],
    package: ChunkHeader,
    global_pool: &StringPool,
    limits: &AndroidLimits,
    budget: &mut ParseBudget,
    identities: &mut HashSet<(u32, String)>,
    output: &mut OutputBuilder<'_>,
) -> Result<(), AndroidCompiledError> {
    if package.header_size < 284 {
        return Err(AndroidCompiledError::malformed(
            package.start,
            "resource-table package header is shorter than 284 bytes",
        ));
    }
    let package_id = read_u32(bytes, package.start + 8)?;
    if package_id == 0 || package_id > u8::MAX as u32 {
        return Err(AndroidCompiledError::malformed(
            package.start + 8,
            format!("invalid resource package id {package_id}"),
        ));
    }
    let package_name = read_fixed_utf16(bytes, package.start + 12, 128)?;
    let type_pool_offset = read_u32(bytes, package.start + 268)? as usize;
    let key_pool_offset = read_u32(bytes, package.start + 276)? as usize;
    let type_id_offset = if package.header_size >= 288 {
        read_u32(bytes, package.start + 284)?
    } else {
        0
    };
    let type_pool_start = checked_relative(package, type_pool_offset, "type string pool")?;
    let key_pool_start = checked_relative(package, key_pool_offset, "key string pool")?;
    let type_pool_header = parse_header(bytes, type_pool_start, package.end)?;
    let key_pool_header = parse_header(bytes, key_pool_start, package.end)?;
    if type_pool_header.kind != RES_STRING_POOL_TYPE || key_pool_header.kind != RES_STRING_POOL_TYPE
    {
        return Err(AndroidCompiledError::malformed(
            package.start,
            "resource package string-pool offsets do not point to string pools",
        ));
    }
    let type_pool = parse_string_pool(bytes, type_pool_header, limits)?;
    let key_pool = parse_string_pool(bytes, key_pool_header, limits)?;

    for child in child_headers(bytes, package, limits, budget)? {
        if child.kind != RES_TABLE_TYPE_TYPE {
            continue;
        }
        parse_type_chunk(
            bytes,
            child,
            package_id,
            &package_name,
            type_id_offset,
            &type_pool,
            &key_pool,
            global_pool,
            limits,
            budget,
            identities,
            output,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_type_chunk(
    bytes: &[u8],
    chunk: ChunkHeader,
    package_id: u32,
    package_name: &str,
    type_id_offset: u32,
    type_pool: &StringPool,
    key_pool: &StringPool,
    global_pool: &StringPool,
    limits: &AndroidLimits,
    budget: &mut ParseBudget,
    identities: &mut HashSet<(u32, String)>,
    output: &mut OutputBuilder<'_>,
) -> Result<(), AndroidCompiledError> {
    if chunk.header_size < 20 {
        return Err(AndroidCompiledError::malformed(
            chunk.start,
            "resource type header is shorter than 20 bytes",
        ));
    }
    let raw_type_id = bytes[chunk.start + 8] as u32;
    let type_flags = bytes[chunk.start + 9];
    let effective_type_id = raw_type_id.checked_add(type_id_offset).ok_or_else(|| {
        AndroidCompiledError::malformed(chunk.start + 8, "resource type id overflow")
    })?;
    if raw_type_id == 0 || effective_type_id > u8::MAX as u32 {
        return Err(AndroidCompiledError::malformed(
            chunk.start + 8,
            format!("invalid resource type id {effective_type_id}"),
        ));
    }
    let entry_count = read_u32(bytes, chunk.start + 12)? as usize;
    if entry_count > limits.max_table_entries {
        return Err(AndroidCompiledError::limit(
            chunk.start + 12,
            format!(
                "resource type entry count {entry_count} exceeds cap {}",
                limits.max_table_entries
            ),
        ));
    }
    budget.table_entries_seen = budget
        .table_entries_seen
        .checked_add(entry_count)
        .ok_or_else(|| {
            AndroidCompiledError::limit(chunk.start + 12, "resource-table entry count overflow")
        })?;
    if budget.table_entries_seen > limits.max_table_entries {
        return Err(AndroidCompiledError::limit(
            chunk.start + 12,
            format!(
                "resource-table cumulative entry count {} exceeds cap {}",
                budget.table_entries_seen, limits.max_table_entries
            ),
        ));
    }
    let entries_start = read_u32(bytes, chunk.start + 16)? as usize;
    let entries_base = checked_relative(chunk, entries_start, "resource entries")?;
    let offset_width = if type_flags & TYPE_FLAG_OFFSET16 != 0 && type_flags & TYPE_FLAG_SPARSE == 0
    {
        2
    } else {
        4
    };
    let offsets_bytes = entry_count.checked_mul(offset_width).ok_or_else(|| {
        AndroidCompiledError::limit(chunk.start + 12, "resource entry offset table overflow")
    })?;
    let offsets_end = chunk
        .data_start()
        .checked_add(offsets_bytes)
        .ok_or_else(|| {
            AndroidCompiledError::limit(chunk.data_start(), "resource entry offset table overflow")
        })?;
    if offsets_end > entries_base || offsets_end > chunk.end {
        return Err(AndroidCompiledError::malformed(
            chunk.data_start(),
            "resource entry offset table crosses the entry payload",
        ));
    }
    let type_name = type_pool.get(raw_type_id - 1, chunk.start + 8)?;
    let qualifier = parse_locale_qualifier(bytes, chunk)?;
    let mut entry_offsets = Vec::new();
    entry_offsets.try_reserve(entry_count).map_err(|error| {
        AndroidCompiledError::limit(
            chunk.data_start(),
            format!("resource entry offset allocation failed: {error}"),
        )
    })?;
    for slot in 0..entry_count {
        let offset = chunk.data_start() + slot * offset_width;
        if type_flags & TYPE_FLAG_SPARSE != 0 {
            let entry_index = read_u16(bytes, offset)? as usize;
            let relative = (read_u16(bytes, offset + 2)? as usize)
                .checked_mul(4)
                .ok_or_else(|| {
                    AndroidCompiledError::malformed(offset + 2, "sparse entry offset overflow")
                })?;
            entry_offsets.push((entry_index, relative));
        } else if type_flags & TYPE_FLAG_OFFSET16 != 0 {
            let relative = read_u16(bytes, offset)?;
            if relative != u16::MAX {
                entry_offsets.push((slot, relative as usize * 4));
            }
        } else {
            let relative = read_u32(bytes, offset)?;
            if relative != NO_INDEX {
                entry_offsets.push((slot, relative as usize));
            }
        }
    }

    for (entry_index, relative) in entry_offsets {
        let entry_start = entries_base.checked_add(relative as usize).ok_or_else(|| {
            AndroidCompiledError::malformed(entries_base, "resource entry offset overflow")
        })?;
        let entry_size = read_u16(bytes, entry_start)? as usize;
        if entry_size < 8 || entry_start.saturating_add(entry_size) > chunk.end {
            return Err(AndroidCompiledError::malformed(
                entry_start,
                "resource entry header is truncated or has an invalid size",
            ));
        }
        let flags = read_u16(bytes, entry_start + 2)?;
        let key_index = read_u32(bytes, entry_start + 4)?;
        let key_name = key_pool.get(key_index, entry_start + 4)?;
        let resource_id = (package_id << 24)
            | (effective_type_id << 16)
            | u32::try_from(entry_index).map_err(|_| {
                AndroidCompiledError::limit(entry_start, "resource entry index exceeds u32")
            })?;
        let identity = (resource_id, qualifier.clone());
        if !identities.insert(identity) {
            return Err(AndroidCompiledError::malformed(
                entry_start,
                format!("duplicate resource id 0x{resource_id:08x} for configuration {qualifier}"),
            ));
        }
        let prefix = format!(
            "android/resource/{}/{}/{}/{}@0x{resource_id:08x}",
            safe_component(package_name),
            safe_component(type_name),
            safe_component(key_name),
            safe_component(&qualifier)
        );
        if flags & ENTRY_FLAG_COMPLEX != 0 {
            if entry_size < 16 {
                return Err(AndroidCompiledError::malformed(
                    entry_start,
                    "complex resource entry header is shorter than 16 bytes",
                ));
            }
            let map_count = read_u32(bytes, entry_start + 12)? as usize;
            if map_count > limits.max_table_entries {
                return Err(AndroidCompiledError::limit(
                    entry_start + 12,
                    format!(
                        "complex resource map count {map_count} exceeds cap {}",
                        limits.max_table_entries
                    ),
                ));
            }
            let maps_start = entry_start + entry_size;
            for map_index in 0..map_count {
                let map_start = maps_start
                    .checked_add(map_index.checked_mul(12).ok_or_else(|| {
                        AndroidCompiledError::limit(maps_start, "resource map offset overflow")
                    })?)
                    .ok_or_else(|| {
                        AndroidCompiledError::limit(maps_start, "resource map offset overflow")
                    })?;
                let map_name = read_u32(bytes, map_start)?;
                let value = parse_value(bytes, map_start + 4, chunk.end, global_pool)?;
                output.push(
                    map_start,
                    &format!("{prefix}/map-0x{map_name:08x}"),
                    resource_text(
                        resource_id,
                        package_name,
                        type_name,
                        key_name,
                        &qualifier,
                        &value,
                    ),
                )?;
            }
        } else {
            let value = parse_value(bytes, entry_start + entry_size, chunk.end, global_pool)?;
            output.push(
                entry_start,
                &prefix,
                resource_text(
                    resource_id,
                    package_name,
                    type_name,
                    key_name,
                    &qualifier,
                    &value,
                ),
            )?;
        }
    }
    Ok(())
}

fn resource_text(
    resource_id: u32,
    package: &str,
    type_name: &str,
    key: &str,
    qualifier: &str,
    value: &str,
) -> String {
    format!(
        "resource_id=0x{resource_id:08x}\npackage={package}\ntype={type_name}\nname={key}\nconfiguration={qualifier}\nvalue={value}"
    )
}

fn parse_binary_xml(
    archive_display: &str,
    entry_name: &str,
    bytes: &[u8],
    limits: &AndroidLimits,
) -> Result<Vec<Chunk>, AndroidCompiledError> {
    let root = parse_header(bytes, 0, bytes.len())?;
    if root.kind != RES_XML_TYPE {
        return Err(AndroidCompiledError::malformed(
            0,
            "binary XML does not start with an XML chunk header",
        ));
    }
    if root.end != bytes.len() {
        return Err(AndroidCompiledError::malformed(
            root.end,
            "binary XML root size does not cover the complete member",
        ));
    }
    let mut budget = ParseBudget::default();
    let children = child_headers(bytes, root, limits, &mut budget)?;
    let pool_header = children
        .iter()
        .copied()
        .find(|header| header.kind == RES_STRING_POOL_TYPE)
        .ok_or_else(|| {
            AndroidCompiledError::malformed(root.data_start(), "binary XML has no string pool")
        })?;
    let pool = parse_string_pool(bytes, pool_header, limits)?;
    let resource_map = children
        .iter()
        .copied()
        .find(|header| header.kind == RES_XML_RESOURCE_MAP_TYPE)
        .map(|header| parse_resource_map(bytes, header, limits))
        .transpose()?
        .unwrap_or_default();
    let mut output = OutputBuilder::new(
        archive_display,
        entry_name,
        "filesystem/archive/android-xml",
        bytes.len(),
        limits,
    );
    let mut elements: Vec<String> = Vec::new();

    for child in children {
        match child.kind {
            RES_XML_START_ELEMENT_TYPE => {
                if child.header_size < 36 {
                    return Err(AndroidCompiledError::malformed(
                        child.start,
                        "binary XML start-element header is shorter than 36 bytes",
                    ));
                }
                if elements.len() >= limits.max_depth {
                    return Err(AndroidCompiledError::limit(
                        child.start,
                        format!("binary XML nesting exceeds depth cap {}", limits.max_depth),
                    ));
                }
                let name_index = read_u32(bytes, child.start + 20)?;
                let element_name = pool.get(name_index, child.start + 20)?.to_string();
                elements.push(element_name.clone());
                let attribute_start = read_u16(bytes, child.start + 24)? as usize;
                let attribute_size = read_u16(bytes, child.start + 26)? as usize;
                let attribute_count = read_u16(bytes, child.start + 28)? as usize;
                if attribute_size < 20 {
                    return Err(AndroidCompiledError::malformed(
                        child.start + 26,
                        "binary XML attribute size is smaller than 20 bytes",
                    ));
                }
                if attribute_count > limits.max_output_items {
                    return Err(AndroidCompiledError::limit(
                        child.start + 28,
                        format!(
                            "binary XML attribute count {attribute_count} exceeds cap {}",
                            limits.max_output_items
                        ),
                    ));
                }
                let attributes = child
                    .start
                    .checked_add(16)
                    .and_then(|offset| offset.checked_add(attribute_start))
                    .ok_or_else(|| {
                        AndroidCompiledError::malformed(
                            child.start + 24,
                            "binary XML attribute offset overflow",
                        )
                    })?;
                if attributes < child.data_start() {
                    return Err(AndroidCompiledError::malformed(
                        child.start + 24,
                        "binary XML attributes begin inside the element header",
                    ));
                }
                for index in 0..attribute_count {
                    let attribute = attributes
                        .checked_add(index.checked_mul(attribute_size).ok_or_else(|| {
                            AndroidCompiledError::limit(
                                attributes,
                                "binary XML attribute offset overflow",
                            )
                        })?)
                        .ok_or_else(|| {
                            AndroidCompiledError::limit(
                                attributes,
                                "binary XML attribute offset overflow",
                            )
                        })?;
                    let attribute_end = attribute.checked_add(attribute_size).ok_or_else(|| {
                        AndroidCompiledError::limit(
                            attribute,
                            "binary XML attribute end offset overflow",
                        )
                    })?;
                    if attribute_end > child.end {
                        return Err(AndroidCompiledError::malformed(
                            attribute,
                            "binary XML attribute is truncated",
                        ));
                    }
                    let attribute_name_index = read_u32(bytes, attribute + 4)?;
                    let raw_value_index = read_u32(bytes, attribute + 8)?;
                    let attribute_name = pool.get(attribute_name_index, attribute + 4)?;
                    let value = if raw_value_index != NO_INDEX {
                        pool.get(raw_value_index, attribute + 8)?.to_string()
                    } else {
                        parse_value(bytes, attribute + 12, attribute_end, &pool)?
                    };
                    let resource_id = resource_map
                        .get(attribute_name_index as usize)
                        .copied()
                        .unwrap_or(0);
                    let element_path = elements
                        .iter()
                        .map(|part| safe_component(part))
                        .collect::<Vec<_>>()
                        .join("/");
                    let provenance = format!(
                        "android/xml/{element_path}/{}@0x{resource_id:08x}",
                        safe_component(attribute_name)
                    );
                    output.push(
                        attribute,
                        &provenance,
                        format!(
                            "element={element_name}\nattribute={attribute_name}\nresource_id=0x{resource_id:08x}\nvalue={value}"
                        ),
                    )?;
                }
            }
            RES_XML_END_ELEMENT_TYPE => {
                if child.header_size < 24 {
                    return Err(AndroidCompiledError::malformed(
                        child.start,
                        "binary XML end-element header is shorter than 24 bytes",
                    ));
                }
                let closing_index = read_u32(bytes, child.start + 20)?;
                let closing_name = pool.get(closing_index, child.start + 20)?;
                let Some(open_name) = elements.pop() else {
                    return Err(AndroidCompiledError::malformed(
                        child.start,
                        "binary XML closes an element when none is open",
                    ));
                };
                if closing_name != open_name {
                    return Err(AndroidCompiledError::malformed(
                        child.start + 20,
                        format!(
                            "binary XML closes element {closing_name} while {open_name} is open"
                        ),
                    ));
                }
            }
            RES_XML_CDATA_TYPE => {
                if child.header_size < 28 {
                    return Err(AndroidCompiledError::malformed(
                        child.start,
                        "binary XML CDATA header is shorter than 28 bytes",
                    ));
                }
                let data_index = read_u32(bytes, child.start + 16)?;
                let value = pool.get(data_index, child.start + 16)?;
                let element_path = if elements.is_empty() {
                    "root".to_string()
                } else {
                    elements
                        .iter()
                        .map(|part| safe_component(part))
                        .collect::<Vec<_>>()
                        .join("/")
                };
                output.push(
                    child.start,
                    &format!("android/xml/{element_path}/cdata"),
                    format!("element={element_path}\nvalue={value}"),
                )?;
            }
            _ => {}
        }
    }
    if !elements.is_empty() {
        return Err(AndroidCompiledError::malformed(
            root.end,
            format!(
                "binary XML ended with {} unclosed element(s)",
                elements.len()
            ),
        ));
    }
    Ok(output.chunks)
}

fn parse_resource_map(
    bytes: &[u8],
    header: ChunkHeader,
    limits: &AndroidLimits,
) -> Result<Vec<u32>, AndroidCompiledError> {
    let bytes_len = header.end - header.data_start();
    if bytes_len % 4 != 0 {
        return Err(AndroidCompiledError::malformed(
            header.data_start(),
            "binary XML resource map is not u32-aligned",
        ));
    }
    let count = bytes_len / 4;
    if count > limits.max_strings {
        return Err(AndroidCompiledError::limit(
            header.data_start(),
            format!(
                "binary XML resource map exceeds {} items",
                limits.max_strings
            ),
        ));
    }
    (0..count)
        .map(|index| read_u32(bytes, header.data_start() + index * 4))
        .collect()
}

fn parse_string_pool(
    bytes: &[u8],
    header: ChunkHeader,
    limits: &AndroidLimits,
) -> Result<StringPool, AndroidCompiledError> {
    if header.kind != RES_STRING_POOL_TYPE || header.header_size < 28 {
        return Err(AndroidCompiledError::malformed(
            header.start,
            "invalid Android string-pool header",
        ));
    }
    let string_count = read_u32(bytes, header.start + 8)? as usize;
    let style_count = read_u32(bytes, header.start + 12)? as usize;
    let flags = read_u32(bytes, header.start + 16)?;
    let strings_start = read_u32(bytes, header.start + 20)? as usize;
    let styles_start = read_u32(bytes, header.start + 24)? as usize;
    if string_count > limits.max_strings || style_count > limits.max_strings {
        return Err(AndroidCompiledError::limit(
            header.start + 8,
            format!(
                "Android string pool declares {string_count} strings and {style_count} styles, above cap {}",
                limits.max_strings
            ),
        ));
    }
    let offset_items = string_count.checked_add(style_count).ok_or_else(|| {
        AndroidCompiledError::limit(header.start + 8, "string-pool offset count overflow")
    })?;
    let offsets_end = header
        .data_start()
        .checked_add(offset_items.checked_mul(4).ok_or_else(|| {
            AndroidCompiledError::limit(header.data_start(), "string-pool offset bytes overflow")
        })?)
        .ok_or_else(|| {
            AndroidCompiledError::limit(header.data_start(), "string-pool offset bytes overflow")
        })?;
    let strings_base = checked_relative(header, strings_start, "string data")?;
    if offsets_end > strings_base || offsets_end > header.end {
        return Err(AndroidCompiledError::malformed(
            header.data_start(),
            "string-pool offsets overlap string data",
        ));
    }
    let string_data_end = if styles_start == 0 {
        header.end
    } else {
        checked_relative(header, styles_start, "style data")?
    };
    if string_data_end < strings_base {
        return Err(AndroidCompiledError::malformed(
            header.start + 24,
            "string-pool style data precedes string data",
        ));
    }
    for index in 0..style_count {
        let relative = read_u32(bytes, header.data_start() + (string_count + index) * 4)?;
        if relative == NO_INDEX {
            continue;
        }
        if styles_start == 0
            || string_data_end
                .checked_add(relative as usize)
                .is_none_or(|offset| offset >= header.end)
        {
            return Err(AndroidCompiledError::malformed(
                header.data_start() + (string_count + index) * 4,
                format!("string-pool style {index} points outside style data"),
            ));
        }
    }
    let mut strings = Vec::new();
    strings.try_reserve(string_count).map_err(|error| {
        AndroidCompiledError::limit(
            header.start + 8,
            format!("string-pool allocation failed: {error}"),
        )
    })?;
    for index in 0..string_count {
        let relative = read_u32(bytes, header.data_start() + index * 4)? as usize;
        let start = strings_base.checked_add(relative).ok_or_else(|| {
            AndroidCompiledError::malformed(strings_base, "string-pool string offset overflow")
        })?;
        if start >= string_data_end {
            return Err(AndroidCompiledError::malformed(
                header.data_start() + index * 4,
                format!("string-pool string {index} points outside string data"),
            ));
        }
        let value = if flags & UTF8_FLAG != 0 {
            parse_utf8_string(bytes, start, string_data_end)?
        } else {
            parse_utf16_string(bytes, start, string_data_end)?
        };
        strings.push(value);
    }
    Ok(StringPool { strings })
}

fn parse_utf8_string(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<String, AndroidCompiledError> {
    let (utf16_len, after_utf16_len) = read_length8(bytes, start, end)?;
    let (byte_len, data_start) = read_length8(bytes, after_utf16_len, end)?;
    let data_end = data_start.checked_add(byte_len).ok_or_else(|| {
        AndroidCompiledError::malformed(data_start, "UTF-8 string length overflow")
    })?;
    if data_end >= end || bytes.get(data_end) != Some(&0) {
        return Err(AndroidCompiledError::malformed(
            data_start,
            "UTF-8 string is truncated or lacks a terminator",
        ));
    }
    let value = std::str::from_utf8(slice(bytes, data_start, data_end)?).map_err(|error| {
        AndroidCompiledError::malformed(data_start, format!("invalid UTF-8 string: {error}"))
    })?;
    if value.encode_utf16().count() != utf16_len {
        return Err(AndroidCompiledError::malformed(
            start,
            "UTF-8 string UTF-16 and byte lengths disagree",
        ));
    }
    Ok(value.to_owned())
}

fn parse_utf16_string(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<String, AndroidCompiledError> {
    let (unit_len, data_start) = read_length16(bytes, start, end)?;
    let byte_len = unit_len.checked_mul(2).ok_or_else(|| {
        AndroidCompiledError::malformed(data_start, "UTF-16 string length overflow")
    })?;
    let data_end = data_start.checked_add(byte_len).ok_or_else(|| {
        AndroidCompiledError::malformed(data_start, "UTF-16 string length overflow")
    })?;
    if data_end.checked_add(2).is_none_or(|value| value > end)
        || bytes.get(data_end..data_end + 2) != Some(&[0, 0])
    {
        return Err(AndroidCompiledError::malformed(
            data_start,
            "UTF-16 string is truncated or lacks a terminator",
        ));
    }
    let raw = slice(bytes, data_start, data_end)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units).map_err(|error| {
        AndroidCompiledError::malformed(data_start, format!("invalid UTF-16 string: {error}"))
    })
}

fn read_length8(
    bytes: &[u8],
    offset: usize,
    end: usize,
) -> Result<(usize, usize), AndroidCompiledError> {
    let first = *bytes
        .get(offset)
        .filter(|_| offset < end)
        .ok_or_else(|| AndroidCompiledError::malformed(offset, "truncated UTF-8 length"))?;
    if first & 0x80 == 0 {
        Ok((first as usize, offset + 1))
    } else {
        let second_offset = offset + 1;
        let second = *bytes
            .get(second_offset)
            .filter(|_| second_offset < end)
            .ok_or_else(|| {
                AndroidCompiledError::malformed(second_offset, "truncated UTF-8 length")
            })?;
        Ok((((first as usize & 0x7f) << 8) | second as usize, offset + 2))
    }
}

fn read_length16(
    bytes: &[u8],
    offset: usize,
    end: usize,
) -> Result<(usize, usize), AndroidCompiledError> {
    if offset.saturating_add(2) > end {
        return Err(AndroidCompiledError::malformed(
            offset,
            "truncated UTF-16 length",
        ));
    }
    let first = read_u16(bytes, offset)?;
    if first & 0x8000 == 0 {
        Ok((first as usize, offset + 2))
    } else {
        if offset.saturating_add(4) > end {
            return Err(AndroidCompiledError::malformed(
                offset,
                "truncated UTF-16 length",
            ));
        }
        let second = read_u16(bytes, offset + 2)?;
        Ok((
            (((first & 0x7fff) as usize) << 16) | second as usize,
            offset + 4,
        ))
    }
}

fn parse_value(
    bytes: &[u8],
    offset: usize,
    parent_end: usize,
    strings: &StringPool,
) -> Result<String, AndroidCompiledError> {
    let value_size = read_u16(bytes, offset)? as usize;
    if value_size != 8 || offset.saturating_add(value_size) > parent_end {
        return Err(AndroidCompiledError::malformed(
            offset,
            "Android typed value is truncated or does not have the required 8-byte size",
        ));
    }
    let data_type = *bytes
        .get(offset + 3)
        .ok_or_else(|| AndroidCompiledError::malformed(offset, "truncated Android typed value"))?;
    let data = read_u32(bytes, offset + 4)?;
    match data_type {
        VALUE_TYPE_STRING => strings.get(data, offset + 4).map(str::to_owned),
        VALUE_TYPE_REFERENCE => Ok(format!("@0x{data:08x}")),
        VALUE_TYPE_INT_DEC => Ok(data.to_string()),
        VALUE_TYPE_INT_HEX => Ok(format!("0x{data:08x}")),
        VALUE_TYPE_INT_BOOLEAN => Ok(if data == 0 { "false" } else { "true" }.to_string()),
        _ => Ok(format!("type=0x{data_type:02x},data=0x{data:08x}")),
    }
}

fn parse_locale_qualifier(
    bytes: &[u8],
    chunk: ChunkHeader,
) -> Result<String, AndroidCompiledError> {
    if chunk.header_size < 32 {
        return Ok("default".to_string());
    }
    let config_start = chunk.start + 20;
    let config_size = read_u32(bytes, config_start)? as usize;
    if config_size < 12 || config_start.saturating_add(config_size) > chunk.data_start() {
        return Err(AndroidCompiledError::malformed(
            config_start,
            "resource configuration header has an invalid size",
        ));
    }
    let language = decode_locale_part(&bytes[config_start + 8..config_start + 10]);
    let country = decode_locale_part(&bytes[config_start + 10..config_start + 12]);
    match (language, country) {
        (Some(language), Some(country)) => Ok(format!("{language}-r{country}")),
        (Some(language), None) => Ok(language),
        (None, Some(country)) => Ok(format!("und-r{country}")),
        (None, None) => Ok("default".to_string()),
    }
}

fn decode_locale_part(bytes: &[u8]) -> Option<String> {
    if bytes == [0, 0] {
        return None;
    }
    if bytes[0] & 0x80 != 0 {
        return Some(format!("packed-{:02x}{:02x}", bytes[0], bytes[1]));
    }
    bytes
        .iter()
        .all(u8::is_ascii_alphabetic)
        .then(|| String::from_utf8_lossy(bytes).into_owned())
}

fn child_headers(
    bytes: &[u8],
    parent: ChunkHeader,
    limits: &AndroidLimits,
    budget: &mut ParseBudget,
) -> Result<Vec<ChunkHeader>, AndroidCompiledError> {
    let mut headers = Vec::new();
    let mut offset = parent.data_start();
    while offset < parent.end {
        if budget.chunks_seen >= limits.max_chunks {
            return Err(AndroidCompiledError::limit(
                offset,
                format!("Android chunk count exceeds cap {}", limits.max_chunks),
            ));
        }
        let header = parse_header(bytes, offset, parent.end)?;
        offset = header.end;
        budget.chunks_seen += 1;
        headers.push(header);
    }
    Ok(headers)
}

fn parse_header(
    bytes: &[u8],
    offset: usize,
    parent_end: usize,
) -> Result<ChunkHeader, AndroidCompiledError> {
    if offset.saturating_add(8) > parent_end || parent_end > bytes.len() {
        return Err(AndroidCompiledError::malformed(
            offset,
            "truncated Android chunk header",
        ));
    }
    let kind = read_u16(bytes, offset)?;
    let header_size = read_u16(bytes, offset + 2)? as usize;
    let size = read_u32(bytes, offset + 4)? as usize;
    if header_size < 8 || size < header_size {
        return Err(AndroidCompiledError::malformed(
            offset,
            format!("invalid Android chunk sizes header={header_size}, total={size}"),
        ));
    }
    let end = offset.checked_add(size).ok_or_else(|| {
        AndroidCompiledError::malformed(offset, "Android chunk end offset overflow")
    })?;
    if end > parent_end {
        return Err(AndroidCompiledError::malformed(
            offset,
            format!("Android chunk extends to byte {end}, past parent end {parent_end}"),
        ));
    }
    Ok(ChunkHeader {
        kind,
        start: offset,
        header_size,
        end,
    })
}

fn checked_relative(
    header: ChunkHeader,
    relative: usize,
    label: &str,
) -> Result<usize, AndroidCompiledError> {
    let absolute = header.start.checked_add(relative).ok_or_else(|| {
        AndroidCompiledError::malformed(header.start, format!("{label} offset overflow"))
    })?;
    if absolute < header.data_start() || absolute > header.end {
        return Err(AndroidCompiledError::malformed(
            header.start,
            format!("{label} offset {relative} points outside its chunk"),
        ));
    }
    Ok(absolute)
}

fn read_fixed_utf16(
    bytes: &[u8],
    offset: usize,
    units: usize,
) -> Result<String, AndroidCompiledError> {
    let byte_len = units
        .checked_mul(2)
        .ok_or_else(|| AndroidCompiledError::malformed(offset, "fixed UTF-16 length overflow"))?;
    let raw = slice(bytes, offset, offset.saturating_add(byte_len))?;
    let values: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&values).map_err(|error| {
        AndroidCompiledError::malformed(offset, format!("invalid package UTF-16 name: {error}"))
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AndroidCompiledError> {
    let raw = slice(bytes, offset, offset.saturating_add(2))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AndroidCompiledError> {
    let raw = slice(bytes, offset, offset.saturating_add(4))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u16_unchecked(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn slice(bytes: &[u8], start: usize, end: usize) -> Result<&[u8], AndroidCompiledError> {
    bytes.get(start..end).ok_or_else(|| {
        AndroidCompiledError::malformed(start, format!("byte range {start}..{end} is truncated"))
    })
}

fn safe_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(128));
    for character in value.chars().take(128) {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            output.push(character);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        "unnamed".to_string()
    } else {
        output
    }
}

#[cfg(test)]
#[path = "../../../../tests/unit/android_compiled_resources.rs"]
mod tests;
