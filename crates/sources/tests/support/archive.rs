//! Shared archive fixture builders for source-container tests.

use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::io::{Cursor, Write};
use xz2::write::XzEncoder;

pub fn zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, content) in entries {
        writer.start_file(*name, options).expect("start zip entry");
        writer.write_all(content).expect("write zip entry");
    }
    writer.finish().expect("finish zip").into_inner()
}

pub fn crx_with_zip_payload(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"Cr24");
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn stored_zip_with_duplicate_names(entries: &[(&str, &[u8])]) -> Vec<u8> {
    stored_zip_with_duplicate_names_and_comment(entries, &[])
}

pub fn stored_zip_with_duplicate_names_and_comment(
    entries: &[(&str, &[u8])],
    comment: &[u8],
) -> Vec<u8> {
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
    write_u16(
        &mut out,
        u16::try_from(comment.len()).expect("zip comment length"),
    );
    out.extend_from_slice(comment);
    out
}

pub fn build_seven_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(cursor).expect("create 7z writer");
    writer.set_encrypt_header(false);
    for (name, content) in entries {
        let entry = ArchiveEntry::new_file(name);
        writer
            .push_archive_entry(entry, Some(Cursor::new(*content)))
            .expect("push 7z entry");
    }
    writer.finish().expect("finish 7z").into_inner()
}

pub fn encode_xz(plaintext: &[u8]) -> Vec<u8> {
    let mut encoder = XzEncoder::new(Vec::new(), 6);
    encoder.write_all(plaintext).expect("write xz input");
    encoder.finish().expect("finish xz")
}

pub fn tar_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (name, content) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, *name, *content)
                .expect("append tar entry");
        }
        builder.finish().expect("finish tar");
    }
    tar_bytes
}

pub fn tar_with_file(name: &str, content: &[u8]) -> Vec<u8> {
    tar_with_entries(&[(name, content)])
}

/// gzip-compress raw bytes (for bare `.gz` fixtures, e.g. a gzipped PEM file).
pub fn gzip_bytes(plaintext: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(plaintext).expect("write gzip input");
    encoder.finish().expect("finish gzip")
}

/// Build a gzipped tarball (`.tgz` / `.tar.gz`) from named entries, the dominant
/// real-world package/release container (npm tarballs, source releases).
pub fn tgz_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    gzip_bytes(&tar_with_entries(entries))
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
