//! R5-T archive adversarial: zip duplicate names handled without panic.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

use crate::support::archive::{
    stored_zip_with_duplicate_names, stored_zip_with_duplicate_names_and_comment,
};

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

#[test]
fn duplicate_zip_with_fake_eocd_in_comment_scans_both_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("dup-comment.zip");
    let mut fake_eocd = Vec::new();
    fake_eocd.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    fake_eocd.extend_from_slice(&[0u8; 18]);
    std::fs::write(
        &zip_path,
        stored_zip_with_duplicate_names_and_comment(
            &[
                ("dup.txt", b"DUPLICATE_COMMENT_FIRST=1\n".as_slice()),
                ("dup.txt", b"DUPLICATE_COMMENT_SECOND=1\n".as_slice()),
            ],
            &fake_eocd,
        ),
    )
    .expect("write duplicate-name zip with fake EOCD comment");

    let bodies: Vec<String> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .map(|chunk| chunk.expect("fake-comment duplicate zip must not emit source errors"))
        .map(|chunk| chunk.data.to_string())
        .collect();
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("DUPLICATE_COMMENT_FIRST=1")),
        "first duplicate entry must be scanned despite fake EOCD comment; bodies={bodies:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("DUPLICATE_COMMENT_SECOND=1")),
        "second duplicate entry must be scanned despite fake EOCD comment; bodies={bodies:?}"
    );
}
