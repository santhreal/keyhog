//! R5-T archive adversarial: zip duplicate names handled without panic.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_zip_duplicate_entry_names_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("dup.zip");
    std::fs::write(
        &zip_path,
        stored_zip_with_duplicate_names(&[
            ("dup.txt", b"DUPLICATE_FIRST=1\n".as_slice()),
            ("dup.txt", b"DUPLICATE_SECOND=1\n".as_slice()),
        ]),
    )
    .expect("write duplicate-name zip");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .map(|chunk| chunk.expect("duplicate-name zip must not emit source errors"))
        .map(|chunk| chunk.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|body| body.contains("DUPLICATE_FIRST=1")),
        "first duplicate entry must be scanned; bodies={bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("DUPLICATE_SECOND=1")),
        "second duplicate entry must be scanned; bodies={bodies:?}"
    );
}

fn stored_zip_with_duplicate_names(entries: &[(&str, &[u8])]) -> Vec<u8> {
    #[derive(Clone)]
    struct CentralEntry {
        name: String,
        crc32: u32,
        size: u32,
        offset: u32,
    }

    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in entries {
        let offset = u32::try_from(out.len()).expect("small zip offset");
        let name_bytes = name.as_bytes();
        let size = u32::try_from(data.len()).expect("small zip size");
        let crc32 = crc32(data);
        write_u32(&mut out, 0x0403_4b50);
        write_u16(&mut out, 20);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, crc32);
        write_u32(&mut out, size);
        write_u32(&mut out, size);
        write_u16(
            &mut out,
            u16::try_from(name_bytes.len()).expect("small zip name"),
        );
        write_u16(&mut out, 0);
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);
        central.push(CentralEntry {
            name: (*name).to_string(),
            crc32,
            size,
            offset,
        });
    }

    let central_offset = u32::try_from(out.len()).expect("small central offset");
    for entry in &central {
        let name_bytes = entry.name.as_bytes();
        write_u32(&mut out, 0x0201_4b50);
        write_u16(&mut out, 20);
        write_u16(&mut out, 20);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, entry.crc32);
        write_u32(&mut out, entry.size);
        write_u32(&mut out, entry.size);
        write_u16(
            &mut out,
            u16::try_from(name_bytes.len()).expect("small zip name"),
        );
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, 0);
        write_u32(&mut out, entry.offset);
        out.extend_from_slice(name_bytes);
    }
    let central_size = u32::try_from(out.len())
        .expect("small zip")
        .checked_sub(central_offset)
        .expect("central size");
    write_u32(&mut out, 0x0605_4b50);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, u16::try_from(central.len()).expect("entry count"));
    write_u16(&mut out, u16::try_from(central.len()).expect("entry count"));
    write_u32(&mut out, central_size);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0);
    out
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
