//! Shared archive fixture builders for source-container tests.

use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::io::Cursor;

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
