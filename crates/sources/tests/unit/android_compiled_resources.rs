use super::*;
use keyhog_core::{Chunk, Source, SourceCoverageGapKind, SourceError};
use std::io::Write;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn chunk(kind: u16, header_size: usize, mut data: Vec<u8>) -> Vec<u8> {
    let mut bytes = vec![0u8; header_size];
    bytes.append(&mut data);
    let size = bytes.len() as u32;
    put_u16(&mut bytes, 0, kind);
    put_u16(&mut bytes, 2, header_size as u16);
    put_u32(&mut bytes, 4, size);
    bytes
}

fn string_pool(strings: &[&str], utf8: bool) -> Vec<u8> {
    let mut payload = vec![0u8; strings.len() * 4];
    let mut string_data = Vec::new();
    for (index, value) in strings.iter().enumerate() {
        put_u32(&mut payload, index * 4, string_data.len() as u32);
        if utf8 {
            assert!(value.len() < 128);
            string_data.push(value.encode_utf16().count() as u8);
            string_data.push(value.len() as u8);
            string_data.extend_from_slice(value.as_bytes());
            string_data.push(0);
        } else {
            let units: Vec<_> = value.encode_utf16().collect();
            assert!(units.len() < 0x8000);
            string_data.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for unit in units {
                string_data.extend_from_slice(&unit.to_le_bytes());
            }
            string_data.extend_from_slice(&[0, 0]);
        }
    }
    payload.extend_from_slice(&string_data);
    let mut pool = chunk(RES_STRING_POOL_TYPE, 28, payload);
    put_u32(&mut pool, 8, strings.len() as u32);
    put_u32(&mut pool, 12, 0);
    put_u32(&mut pool, 16, if utf8 { UTF8_FLAG } else { 0 });
    put_u32(&mut pool, 20, (28 + strings.len() * 4) as u32);
    put_u32(&mut pool, 24, 0);
    pool
}

fn typed_string_value(index: u32) -> [u8; 8] {
    let mut value = [0u8; 8];
    put_u16(&mut value, 0, 8);
    value[3] = VALUE_TYPE_STRING;
    put_u32(&mut value, 4, index);
    value
}

fn xml_start_element(element: u32, attributes: &[(u32, u32)]) -> Vec<u8> {
    let mut extension = vec![0u8; 20];
    put_u32(&mut extension, 0, NO_INDEX);
    put_u32(&mut extension, 4, element);
    put_u16(&mut extension, 8, 20);
    put_u16(&mut extension, 10, 20);
    put_u16(&mut extension, 12, attributes.len() as u16);
    for &(name, value) in attributes {
        let mut attribute = vec![0u8; 20];
        put_u32(&mut attribute, 0, NO_INDEX);
        put_u32(&mut attribute, 4, name);
        put_u32(&mut attribute, 8, value);
        attribute[12..20].copy_from_slice(&typed_string_value(value));
        extension.extend_from_slice(&attribute);
    }
    let mut start = chunk(RES_XML_START_ELEMENT_TYPE, 16, extension);
    put_u32(&mut start, 8, 1);
    put_u32(&mut start, 12, NO_INDEX);
    start
}

fn xml_end_element(element: u32) -> Vec<u8> {
    let mut extension = vec![0u8; 8];
    put_u32(&mut extension, 0, NO_INDEX);
    put_u32(&mut extension, 4, element);
    let mut end = chunk(RES_XML_END_ELEMENT_TYPE, 16, extension);
    put_u32(&mut end, 8, 1);
    put_u32(&mut end, 12, NO_INDEX);
    end
}

fn xml_cdata(value: u32) -> Vec<u8> {
    let mut extension = vec![0u8; 12];
    put_u32(&mut extension, 0, value);
    extension[4..12].copy_from_slice(&typed_string_value(value));
    let mut cdata = chunk(RES_XML_CDATA_TYPE, 16, extension);
    put_u32(&mut cdata, 8, 1);
    put_u32(&mut cdata, 12, NO_INDEX);
    cdata
}

fn binary_xml(strings: &[&str], attributes: &[(u32, u32)]) -> Vec<u8> {
    let mut data = string_pool(strings, true);
    let mut map_data = vec![0u8; strings.len() * 4];
    if strings.len() > 1 {
        put_u32(&mut map_data, 4, 0x0101_0001);
    }
    data.extend_from_slice(&chunk(RES_XML_RESOURCE_MAP_TYPE, 8, map_data));
    data.extend_from_slice(&xml_start_element(0, attributes));
    data.extend_from_slice(&xml_end_element(0));
    chunk(RES_XML_TYPE, 8, data)
}

fn standard_config(locale: [u8; 2], country: [u8; 2]) -> Vec<u8> {
    let mut config = vec![0u8; 28];
    put_u32(&mut config, 0, 28);
    config[8..10].copy_from_slice(&locale);
    config[10..12].copy_from_slice(&country);
    config
}

fn full_entry(value_index: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 8];
    put_u16(&mut entry, 0, 8);
    put_u16(&mut entry, 2, 0);
    put_u32(&mut entry, 4, 0);
    entry.extend_from_slice(&typed_string_value(value_index));
    entry
}

fn compact_entry(data_type: u8, data: u32) -> Vec<u8> {
    let mut entry = vec![0u8; 8];
    put_u16(&mut entry, 0, 0);
    put_u16(
        &mut entry,
        2,
        ENTRY_FLAG_COMPACT | ((data_type as u16) << 8),
    );
    put_u32(&mut entry, 4, data);
    entry
}

fn type_chunk_with_config(config: Vec<u8>, entry: Vec<u8>) -> Vec<u8> {
    assert!(config.len() >= 28);
    assert_eq!(
        u32::from_le_bytes(config[..4].try_into().expect("config size bytes")) as usize,
        config.len()
    );
    let mut data = vec![0u8; 4];
    put_u32(&mut data, 0, 0);
    data.extend_from_slice(&entry);
    let header_size = 20 + config.len();
    let mut typed = chunk(RES_TABLE_TYPE_TYPE, header_size, data);
    typed[8] = 1;
    put_u32(&mut typed, 12, 1);
    put_u32(&mut typed, 16, (header_size + 4) as u32);
    typed[20..header_size].copy_from_slice(&config);
    typed
}

fn type_chunk(locale: [u8; 2], country: [u8; 2], value_index: u32) -> Vec<u8> {
    type_chunk_with_config(standard_config(locale, country), full_entry(value_index))
}

fn resource_table(type_chunks: &[Vec<u8>]) -> Vec<u8> {
    let global = string_pool(
        &[
            "https://api.example.test/v1?token=sk_live_android_utf16",
            "ghp_android_resource_variant_token",
        ],
        false,
    );
    let types = string_pool(&["string"], false);
    let keys = string_pool(&["api_endpoint"], false);
    let mut package_data = types.clone();
    package_data.extend_from_slice(&keys);
    for typed in type_chunks {
        package_data.extend_from_slice(typed);
    }
    let mut package = chunk(RES_TABLE_PACKAGE_TYPE, 288, package_data);
    put_u32(&mut package, 8, 0x7f);
    for (index, unit) in "com.example.app".encode_utf16().enumerate() {
        put_u16(&mut package, 12 + index * 2, unit);
    }
    put_u32(&mut package, 268, 288);
    put_u32(&mut package, 276, (288 + types.len()) as u32);
    put_u32(&mut package, 284, 0);

    let mut table_data = global;
    table_data.extend_from_slice(&package);
    let mut table = chunk(RES_TABLE_TYPE, 12, table_data);
    put_u32(&mut table, 8, 1);
    table
}

fn emit_archive_member(entry_name: &str, content: Vec<u8>) -> Vec<Result<Chunk, SourceError>> {
    let mut rows = Vec::new();
    let mut total = content.len() as u64;
    super::super::emit_archive_content_with_depth(
        "fixtures/app.apk",
        entry_name,
        content,
        u64::MAX,
        u64::MAX,
        &mut total,
        false,
        0,
        &mut |row| {
            rows.push(row);
            true
        },
    );
    rows
}

#[test]
fn filesystem_apk_path_emits_xml_table_and_original_members_end_to_end() {
    let directory = tempfile::tempdir().expect("temporary APK directory");
    let apk_path = directory.path().join("sample.apk");
    let file = std::fs::File::create(&apk_path).expect("create APK");
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let xml = binary_xml(&["manifest", "apiKey", "sk_live_android_e2e"], &[(1, 2)]);
    let table = resource_table(&[type_chunk(*b"en", *b"US", 0)]);
    zip.start_file("AndroidManifest.xml", options)
        .expect("manifest member");
    zip.write_all(&xml).expect("manifest bytes");
    zip.start_file("resources.arsc", options)
        .expect("resource member");
    zip.write_all(&table).expect("resource bytes");
    zip.finish().expect("finish APK");

    let source = crate::filesystem::FilesystemSource::new(directory.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();
    assert!(errors.is_empty(), "valid APK errors: {errors:?}");
    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "filesystem/archive/android-xml"
            && chunk.data.contains("sk_live_android_e2e")
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.source_type.as_ref() == "filesystem/archive/android-resource"
            && chunk.data.contains("sk_live_android_utf16")
    }));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.path.as_deref().is_some_and(|path| {
            path.ends_with("sample.apk//AndroidManifest.xml") && !path.contains("::android/")
        })
    }));
}

#[test]
fn utf8_binary_xml_emits_typed_provenance_and_keeps_raw_member_scan() {
    let xml = binary_xml(
        &["manifest", "apiKey", "sk_live_android_manifest_value"],
        &[(1, 2)],
    );
    let rows = emit_archive_member("AndroidManifest.xml", xml);
    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    let typed = chunks
        .iter()
        .find(|chunk| chunk.metadata.source_type.as_ref() == "filesystem/archive/android-xml")
        .expect("typed Android XML chunk");
    assert_eq!(
        typed.data.as_ref(),
        "element=manifest\nattribute=apiKey\nresource_id=0x01010001\nvalue=sk_live_android_manifest_value"
    );
    let path = typed.metadata.path.as_deref().expect("typed path");
    assert!(path.contains("app.apk//AndroidManifest.xml::android/xml/manifest/apiKey"));
    assert!(path.contains("/offset-0x"));
    assert!(chunks.iter().any(|chunk| {
        chunk.metadata.path.as_deref() == Some("fixtures/app.apk//AndroidManifest.xml")
            && chunk.metadata.source_type.as_ref() == "filesystem/archive-binary"
    }));
}

#[test]
fn canonical_xml_node_extensions_emit_cdata_and_collision_safe_sibling_paths() {
    let strings = [
        "root",
        "item",
        "apiKey",
        "sk_live_android_first",
        "sk_live_android_second",
        "ghp_android_cdata_token",
    ];
    let mut data = string_pool(&strings, true);
    data.extend_from_slice(&xml_start_element(0, &[]));
    data.extend_from_slice(&xml_start_element(1, &[(2, 3)]));
    data.extend_from_slice(&xml_end_element(1));
    data.extend_from_slice(&xml_start_element(1, &[(2, 4)]));
    data.extend_from_slice(&xml_cdata(5));
    data.extend_from_slice(&xml_end_element(1));
    data.extend_from_slice(&xml_end_element(0));
    let xml = chunk(RES_XML_TYPE, 8, data);

    let AndroidParseOutcome::Parsed(chunks) = parse_member_with_limits(
        "fixtures/app.apk",
        "AndroidManifest.xml",
        &xml,
        &PRODUCTION_LIMITS,
    )
    .expect("canonical binary XML") else {
        panic!("binary XML must be applicable");
    };
    assert_eq!(chunks.len(), 3);
    assert_eq!(
        chunks[0].data.lines().last(),
        Some("value=sk_live_android_first")
    );
    assert_eq!(
        chunks[1].data.lines().last(),
        Some("value=sk_live_android_second")
    );
    assert!(chunks[2].data.contains("value=ghp_android_cdata_token"));
    let first_path = chunks[0].metadata.path.as_deref().expect("first path");
    let second_path = chunks[1].metadata.path.as_deref().expect("second path");
    assert!(first_path.contains("android/xml/root/item/apiKey@0x00000000/offset-0x"));
    assert!(second_path.contains("android/xml/root/item/apiKey@0x00000000/offset-0x"));
    assert_ne!(first_path, second_path);
}

#[test]
fn utf16_resource_table_preserves_locale_variants_and_duplicate_resource_ids() {
    let mut sparse = type_chunk(*b"es", *b"MX", 0);
    sparse[9] = TYPE_FLAG_SPARSE;
    let mut offset16 = type_chunk(*b"de", *b"DE", 1);
    offset16[9] = TYPE_FLAG_OFFSET16;
    let table = resource_table(&[
        type_chunk(*b"en", *b"US", 0),
        type_chunk(*b"fr", *b"FR", 1),
        sparse,
        offset16,
    ]);
    let parsed = parse_member_with_limits(
        "fixtures/app.apk",
        "resources.arsc",
        &table,
        &PRODUCTION_LIMITS,
    )
    .expect("valid UTF-16 resource table");
    let AndroidParseOutcome::Parsed(chunks) = parsed else {
        panic!("resource table must be applicable");
    };
    assert_eq!(chunks.len(), 4);
    assert!(chunks[0].data.contains("configuration=en-rUS"));
    assert!(chunks[0].data.contains("sk_live_android_utf16"));
    assert!(chunks[1].data.contains("configuration=fr-rFR"));
    assert!(chunks[1]
        .data
        .contains("ghp_android_resource_variant_token"));
    assert!(chunks[2].data.contains("configuration=es-rMX"));
    assert!(chunks[2].data.contains("sk_live_android_utf16"));
    assert!(chunks[3].data.contains("configuration=de-rDE"));
    assert!(chunks[3]
        .data
        .contains("ghp_android_resource_variant_token"));
    assert!(chunks.iter().all(|chunk| chunk
        .metadata
        .path
        .as_deref()
        .is_some_and(|path| path.contains("@0x7f010000"))));
}

#[test]
fn resource_configuration_identity_preserves_density_night_and_forward_bytes() {
    let mut xhdpi = vec![0u8; 32];
    put_u32(&mut xhdpi, 0, 32);
    xhdpi[8..10].copy_from_slice(b"en");
    xhdpi[10..12].copy_from_slice(b"US");
    put_u16(&mut xhdpi, 14, 320);
    xhdpi[29] = 0x10;

    let mut xxhdpi_night = xhdpi.clone();
    put_u16(&mut xxhdpi_night, 14, 480);
    xxhdpi_night[29] = 0x20;

    let mut forward_a = vec![0u8; 64];
    put_u32(&mut forward_a, 0, 64);
    forward_a[8..10].copy_from_slice(b"en");
    forward_a[10..12].copy_from_slice(b"US");
    forward_a[61] = 1;
    let mut forward_b = forward_a.clone();
    forward_b[61] = 2;

    let table = resource_table(&[
        type_chunk_with_config(xhdpi, full_entry(0)),
        type_chunk_with_config(xxhdpi_night, full_entry(1)),
        type_chunk_with_config(forward_a, full_entry(0)),
        type_chunk_with_config(forward_b, full_entry(1)),
    ]);
    let AndroidParseOutcome::Parsed(chunks) = parse_member_with_limits(
        "fixtures/app.apk",
        "resources.arsc",
        &table,
        &PRODUCTION_LIMITS,
    )
    .expect("distinct exact configurations") else {
        panic!("resource table must be applicable");
    };
    assert_eq!(chunks.len(), 4);
    assert!(chunks[0]
        .data
        .contains("configuration=en-rUS-xhdpi-notnight"));
    assert!(chunks[1].data.contains("configuration=en-rUS-xxhdpi-night"));
    assert!(chunks.iter().all(|chunk| chunk
        .data
        .lines()
        .any(|line| line.starts_with("configuration_blake3=") && line.len() == 85)));
    let paths: std::collections::HashSet<_> = chunks
        .iter()
        .map(|chunk| chunk.metadata.path.as_deref().expect("resource path"))
        .collect();
    assert_eq!(paths.len(), 4);
    assert!(chunks[2].data.contains("configuration=en-rUS"));
    assert!(chunks[3].data.contains("configuration=en-rUS"));
}

#[test]
fn compact_string_and_reference_entries_emit_real_values() {
    let table = resource_table(&[
        type_chunk_with_config(
            standard_config(*b"en", *b"US"),
            compact_entry(VALUE_TYPE_STRING, 0),
        ),
        type_chunk_with_config(
            standard_config(*b"fr", *b"FR"),
            compact_entry(VALUE_TYPE_REFERENCE, 0x7f02_0042),
        ),
    ]);
    let AndroidParseOutcome::Parsed(chunks) = parse_member_with_limits(
        "fixtures/app.apk",
        "resources.arsc",
        &table,
        &PRODUCTION_LIMITS,
    )
    .expect("compact resource entries") else {
        panic!("resource table must be applicable");
    };
    assert_eq!(chunks.len(), 2);
    assert!(chunks[0]
        .data
        .contains("value=https://api.example.test/v1?token=sk_live_android_utf16"));
    assert!(chunks[1].data.contains("value=@0x7f020042"));
}

#[test]
fn compact_complex_entry_is_rejected_as_malformed() {
    let mut entry = compact_entry(VALUE_TYPE_STRING, 0);
    let flags = read_u16_unchecked(&entry[2..4]);
    put_u16(&mut entry, 2, flags | ENTRY_FLAG_COMPLEX);
    let table = resource_table(&[type_chunk_with_config(
        standard_config(*b"en", *b"US"),
        entry,
    )]);
    let error = parse_member_with_limits(
        "fixtures/app.apk",
        "resources.arsc",
        &table,
        &PRODUCTION_LIMITS,
    )
    .expect_err("compact complex resource entry");
    assert_eq!(error.kind, AndroidErrorKind::Malformed);
    assert!(error
        .detail
        .contains("compact resource entry cannot also be complex"));
}

#[test]
fn plain_xml_is_negative_and_only_uses_the_ordinary_member_path() {
    let rows = emit_archive_member(
        "res/xml/network_security_config.xml",
        b"<config endpoint=\"https://example.test\"/>".to_vec(),
    );
    assert!(rows.iter().all(Result::is_ok));
    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.source_type.as_ref(),
        "filesystem/archive"
    );
    assert!(chunks[0].data.contains("https://example.test"));
}

#[test]
fn corrupt_string_offset_is_a_typed_visible_gap_and_raw_scan_continues() {
    let mut xml = binary_xml(&["manifest", "apiKey", "sk_live_corrupt_offset"], &[(1, 2)]);
    put_u32(&mut xml, 8 + 28, u32::MAX);
    let rows = emit_archive_member("AndroidManifest.xml", xml);
    assert!(rows.iter().any(|row| matches!(
        row,
        Err(SourceError::Coverage {
            adapter,
            surface,
            kind: SourceCoverageGapKind::Inaccessible,
            detail,
            ..
        }) if adapter == "filesystem/archive/android"
            && surface == "compiled-resource"
            && detail.contains("points outside string data")
            && detail.contains("ordinary archive member scan continued")
    )));
    assert!(rows
        .iter()
        .any(|row| row.as_ref().ok().is_some_and(|chunk| {
            chunk.metadata.path.as_deref() == Some("fixtures/app.apk//AndroidManifest.xml")
        })));
}

#[test]
fn duplicate_id_in_the_same_configuration_is_a_visible_malformed_error() {
    let table = resource_table(&[type_chunk(*b"en", *b"US", 0), type_chunk(*b"en", *b"US", 1)]);
    let error = parse_member_with_limits(
        "fixtures/app.apk",
        "resources.arsc",
        &table,
        &PRODUCTION_LIMITS,
    )
    .expect_err("duplicate id and configuration must be rejected");
    assert_eq!(error.kind, AndroidErrorKind::Malformed);
    assert!(error.detail.contains("duplicate resource id 0x7f010000"));
}

#[test]
fn byte_item_string_and_depth_caps_fail_before_unbounded_work() {
    let xml = binary_xml(
        &["manifest", "apiKey", "one", "secondKey", "two"],
        &[(1, 2), (3, 4)],
    );
    let mut limits = PRODUCTION_LIMITS;
    limits.max_input_bytes = xml.len() - 1;
    let error = parse_member_with_limits("a.apk", "AndroidManifest.xml", &xml, &limits)
        .expect_err("byte cap");
    assert_eq!(error.kind, AndroidErrorKind::Limit);

    limits = PRODUCTION_LIMITS;
    limits.max_output_items = 1;
    let error = parse_member_with_limits("a.apk", "AndroidManifest.xml", &xml, &limits)
        .expect_err("item cap");
    assert!(error.detail.contains("exceeds cap 1"));

    limits = PRODUCTION_LIMITS;
    limits.max_strings = 4;
    let error = parse_member_with_limits("a.apk", "AndroidManifest.xml", &xml, &limits)
        .expect_err("string cap");
    assert!(error.detail.contains("above cap 4"));

    let pool = string_pool(&["outer", "inner"], true);
    let mut nested_data = pool;
    nested_data.extend_from_slice(&xml_start_element(0, &[]));
    nested_data.extend_from_slice(&xml_start_element(1, &[]));
    nested_data.extend_from_slice(&xml_end_element(1));
    nested_data.extend_from_slice(&xml_end_element(0));
    let nested = chunk(RES_XML_TYPE, 8, nested_data);
    limits = PRODUCTION_LIMITS;
    limits.max_depth = 1;
    let error = parse_member_with_limits("a.apk", "AndroidManifest.xml", &nested, &limits)
        .expect_err("depth cap");
    assert!(error.detail.contains("depth cap 1"));
}
