//! Caesar decoder must not run on source/config paths that lack common extensions.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::decode_chunk;
use keyhog_scanner::testing::is_source_code_path;

#[test]
fn kconfig_and_syscall_tables_are_source_paths_for_caesar() {
    assert!(is_source_code_path(Some("net/sched/Kconfig")));
    assert!(is_source_code_path(Some("arch/arm/tools/syscall.tbl")));
    assert!(is_source_code_path(Some(r"drivers\foo\Makefile")));
    assert!(!is_source_code_path(Some("config/secrets.env")));
}

#[test]
fn kconfig_path_produces_no_caesar_chunks() {
    let chunk = Chunk {
        data: "comment BLJBRS4EFGHIJKLM2345".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "filesystem".into(),
            path: Some("net/sched/Kconfig".into()),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    assert!(
        decoded
            .iter()
            .all(|c| !c.metadata.source_type.contains("/caesar")),
        "Caesar decoder must not run on Kconfig source paths; got {:?}",
        decoded
            .iter()
            .map(|c| &c.metadata.source_type)
            .collect::<Vec<_>>()
    );
}
