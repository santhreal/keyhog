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
