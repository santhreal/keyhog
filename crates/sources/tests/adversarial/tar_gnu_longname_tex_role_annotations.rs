//! TeX role annotations must survive GNU long member names.
//!
//! REGRESSION (Devin #41): the header-name TeX gate only inspected the 100-byte
//! ustar name field, so packages whose `.tex` path lived in a GNU long-link /
//! pax extended header returned default analysis and lost role annotations.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn tar_gnu_longname_tex_keeps_role_annotations() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("paper.tar");

    // Longer than the ustar 100-byte name field so GNU tar emits a long-link.
    let long = format!(
        "chapters/{}/main.tex",
        "very_long_segment/".repeat(8).trim_end_matches('/')
    );
    assert!(
        long.len() > 100,
        "fixture path must exceed ustar name field ({})",
        long.len()
    );
    let main = b"\\documentclass{article}\n\\begin{document}\nHello\n\\end{document}\n";

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(main.len() as u64);
    header.set_mode(0o644);
    // Do not call set_path for long names; append_data emits the GNU long-link.
    builder
        .append_data(&mut header, long.as_str(), &main[..])
        .unwrap();
    let bytes = builder.into_inner().unwrap();
    std::fs::write(&archive, bytes).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "healthy long-name TeX tar must not error; {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/archive/tex-root"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.contains("main.tex"))
        }),
        "long GNU tar TeX path must keep tex-root role annotations; chunks={chunks:?}"
    );
}
