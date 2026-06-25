#![cfg(feature = "binary")]

use keyhog_sources::testing::{SourceTestApi, TestApi};

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_name<const N: usize>(bytes: &mut Vec<u8>, name: &[u8]) {
    let mut field = [0u8; N];
    field[..name.len()].copy_from_slice(name);
    bytes.extend_from_slice(&field);
}

fn minimal_macho64_with_cstring(secret: &[u8]) -> Vec<u8> {
    const MACH_HEADER_64_BYTES: usize = 32;
    const SEGMENT_COMMAND_64_BYTES: usize = 72;
    const SECTION_64_BYTES: usize = 80;
    const LC_SEGMENT_64: u32 = 0x19;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_SUBTYPE_X86_64_ALL: u32 = 3;
    const MH_EXECUTE: u32 = 2;

    let section_offset =
        (MACH_HEADER_64_BYTES + SEGMENT_COMMAND_64_BYTES + SECTION_64_BYTES) as u32;
    let cmdsize = (SEGMENT_COMMAND_64_BYTES + SECTION_64_BYTES) as u32;
    let mut bytes = Vec::new();

    push_u32(&mut bytes, 0xfeed_facf);
    push_u32(&mut bytes, CPU_TYPE_X86_64);
    push_u32(&mut bytes, CPU_SUBTYPE_X86_64_ALL);
    push_u32(&mut bytes, MH_EXECUTE);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, cmdsize);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);

    push_u32(&mut bytes, LC_SEGMENT_64);
    push_u32(&mut bytes, cmdsize);
    push_name::<16>(&mut bytes, b"__TEXT");
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, secret.len() as u64);
    push_u64(&mut bytes, section_offset as u64);
    push_u64(&mut bytes, secret.len() as u64);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 0);

    push_name::<16>(&mut bytes, b"__cstring");
    push_name::<16>(&mut bytes, b"__TEXT");
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, secret.len() as u64);
    push_u32(&mut bytes, section_offset);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);

    assert_eq!(bytes.len(), section_offset as usize);
    bytes.extend_from_slice(secret);
    bytes
}

fn universal_macho_with_arches(arches: &[&[u8]]) -> Vec<u8> {
    const FAT_HEADER_BYTES: u32 = 8;
    const FAT_ARCH_BYTES: u32 = 20;
    const CPU_TYPE_X86_64: u32 = 0x0100_0007;
    const CPU_SUBTYPE_X86_64_ALL: u32 = 3;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
    bytes.extend_from_slice(&(arches.len() as u32).to_be_bytes());
    let mut next_offset = FAT_HEADER_BYTES + FAT_ARCH_BYTES * arches.len() as u32;
    for arch in arches {
        bytes.extend_from_slice(&CPU_TYPE_X86_64.to_be_bytes());
        bytes.extend_from_slice(&CPU_SUBTYPE_X86_64_ALL.to_be_bytes());
        bytes.extend_from_slice(&next_offset.to_be_bytes());
        bytes.extend_from_slice(&(arch.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        next_offset += arch.len() as u32;
    }
    assert_eq!(
        bytes.len(),
        (FAT_HEADER_BYTES + FAT_ARCH_BYTES * arches.len() as u32) as usize
    );
    for arch in arches {
        bytes.extend_from_slice(arch);
    }
    bytes
}

#[test]
fn fat_macho_section_extraction_preserves_arch_section_chunks() {
    let first = minimal_macho64_with_cstring(b"SANTH_FAT_MACHO_SECRET_ONE");
    let second = minimal_macho64_with_cstring(b"SANTH_FAT_MACHO_SECRET_TWO");
    let universal = universal_macho_with_arches(&[&first, &second]);

    let chunks = TestApi
        .extract_sections(&universal, "fat-macho")
        .expect("universal Mach-O should yield section chunks");

    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "binary:macho:__cstring"
                && chunk.data.contains("SANTH_FAT_MACHO_SECRET_ONE")
        }),
        "Fat Mach-O must parse the first nested architecture section instead of falling through to strings-only extraction: {chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "binary:macho:__cstring"
                && chunk.data.contains("SANTH_FAT_MACHO_SECRET_TWO")
        }),
        "Fat Mach-O must continue across later nested architecture sections: {chunks:?}"
    );
}
