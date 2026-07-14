use crate::support::split_chunk_results;
use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;
use std::io::Write;

fn scan_archive(path: &std::path::Path) -> Vec<Chunk> {
    let source = FilesystemSource::new(path.parent().expect("archive parent").to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(errors.is_empty(), "valid source package errors: {errors:?}");
    chunks.into_iter().cloned().collect()
}

fn write_zip(path: &std::path::Path, members: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).expect("create source zip");
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in members {
        writer.start_file(*name, options).expect("start member");
        writer.write_all(body).expect("write member");
    }
    writer.finish().expect("finish source zip");
}

fn chunk_for<'a>(chunks: &'a [Chunk], suffix: &str, source_type: &str) -> &'a Chunk {
    chunks
        .iter()
        .find(|chunk| {
            chunk.metadata.source_type.as_ref() == source_type
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with(suffix))
        })
        .unwrap_or_else(|| panic!("missing {source_type} chunk ending in {suffix}: {chunks:?}"))
}

#[test]
fn zip_tex_graph_preserves_roots_references_orphans_comments_and_all_member_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("paper.zip");
    let main = concat!(
        "\\documentclass{article}\n",
        "\\input{chapters/a}\n",
        "\\includegraphics[width=2cm]{figs/plot}\n",
        "\\bibliography{refs/library}\n",
        "\\input{section.1}\n",
        "% COMMENT_TOKEN=AKIAQYLPMN5HFIQR7XYA\n",
        "\\input{../../escape}\n",
        "\\input{malformed\n",
        "\\includegraphics[width=2cm][unclosed\n",
        "\\begin{document}\n"
    );
    write_zip(
        &archive,
        &[
            ("main.tex", main.as_bytes()),
            (
                "chapters/a.tex",
                b"\\input{../shared}\nCHAPTER_TOKEN=visible\n",
            ),
            ("shared.tex", b"\\input{chapters/a}\nSHARED_TOKEN=visible\n"),
            ("figs/plot.png", b"PLOT_TOKEN=visible\n"),
            ("refs/library.bib", b"BIB_TOKEN=visible\n"),
            ("section.1.tex", b"DOTTED_BASENAME_TOKEN=visible\n"),
            (
                "[width=2cm][unclosed",
                b"MALFORMED_OPTION_TARGET_TOKEN=still-scanned\n",
            ),
            ("escape.tex", b"TRAVERSAL_TARGET_TOKEN=still-scanned\n"),
            ("unused.env", b"ORPHAN_TOKEN=still-scanned\n"),
        ],
    );

    let chunks = scan_archive(&archive);
    let root = chunk_for(
        &chunks,
        "paper.zip//main.tex",
        "filesystem/archive/tex-root",
    );
    assert_eq!(
        root.data.as_ref(),
        main,
        "root bytes must reach the normal scanner unchanged"
    );
    for suffix in [
        "paper.zip//chapters/a.tex",
        "paper.zip//shared.tex",
        "paper.zip//figs/plot.png",
        "paper.zip//refs/library.bib",
        "paper.zip//section.1.tex",
    ] {
        chunk_for(&chunks, suffix, "filesystem/archive/tex-referenced");
    }
    let traversal = chunk_for(
        &chunks,
        "paper.zip//escape.tex",
        "filesystem/archive/tex-orphaned",
    );
    assert!(traversal.data.contains("TRAVERSAL_TARGET_TOKEN"));
    let orphan = chunk_for(
        &chunks,
        "paper.zip//unused.env",
        "filesystem/archive/tex-orphaned",
    );
    assert!(orphan.data.contains("ORPHAN_TOKEN"));
    let malformed = chunk_for(
        &chunks,
        "paper.zip//[width=2cm][unclosed",
        "filesystem/archive/tex-orphaned",
    );
    assert!(malformed.data.contains("MALFORMED_OPTION_TARGET_TOKEN"));

    let comment = chunk_for(
        &chunks,
        "paper.zip//main.tex",
        "filesystem/archive/tex-comment/root",
    );
    let comment_start = main.find("% COMMENT_TOKEN").expect("comment offset");
    assert_eq!(comment.metadata.base_offset, comment_start);
    assert_eq!(comment.metadata.base_line, 5);
    assert_eq!(
        comment.data.as_ref(),
        "% COMMENT_TOKEN=AKIAQYLPMN5HFIQR7XYA"
    );
}

#[test]
fn tar_tex_cycles_terminate_and_escaped_percent_is_not_comment_provenance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("submission.tar");
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        let members: &[(&str, &[u8])] = &[
            (
                "paper/main.tex",
                b"\\documentclass{article}\n\\input{a}\nprice=100\\%\n% TAR_COMMENT_TOKEN=visible\n",
            ),
            ("paper/a.tex", b"\\include{main}\nA_TOKEN=visible\n"),
            ("paper/unused.txt", b"UNUSED_TAR_TOKEN=still-scanned\n"),
        ];
        for (name, body) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).expect("tar path");
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, *body).expect("append tar member");
        }
        builder.finish().expect("finish tar");
    }
    std::fs::write(&archive, bytes).expect("write tar");

    let chunks = scan_archive(&archive);
    chunk_for(
        &chunks,
        "submission.tar//paper/main.tex",
        "filesystem/archive/tex-root",
    );
    chunk_for(
        &chunks,
        "submission.tar//paper/a.tex",
        "filesystem/archive/tex-referenced",
    );
    let orphan = chunk_for(
        &chunks,
        "submission.tar//paper/unused.txt",
        "filesystem/archive/tex-orphaned",
    );
    assert!(orphan.data.contains("UNUSED_TAR_TOKEN"));

    let comments: Vec<_> = chunks
        .iter()
        .filter(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/archive/tex-comment/root"
        })
        .collect();
    assert_eq!(
        comments.len(),
        1,
        "escaped percent must not start a comment"
    );
    assert_eq!(comments[0].data.as_ref(), "% TAR_COMMENT_TOKEN=visible");
}

#[test]
fn oversized_tex_provenance_is_loud_while_the_member_remains_scannable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("large-paper.zip");
    let mut main = b"\\documentclass{article}\n".to_vec();
    main.resize(2 * 1024 * 1024 + 1, b'x');
    main.extend_from_slice(b"\nOVERSIZE_SOURCE_TOKEN=still-scanned\n");
    write_zip(&archive, &[("main.tex", &main)]);

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.iter().any(|error| {
            let message = error.to_string();
            message.contains("TeX provenance analysis")
                && message.contains("every archive member is still scanned")
        }),
        "bounded provenance loss must be operator-visible: {errors:?}"
    );
    let chunks: Vec<_> = chunks.into_iter().cloned().collect();
    let chunk = chunk_for(&chunks, "large-paper.zip//main.tex", "filesystem/archive");
    assert!(chunk.data.contains("OVERSIZE_SOURCE_TOKEN"));
}

#[test]
fn duplicate_tex_member_names_report_ambiguous_roles_and_scan_each_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = dir.path().join("duplicate-paper.zip");
    let bytes = crate::support::archive::stored_zip_with_duplicate_names(&[
        (
            "main.tex",
            b"\\documentclass{article}\nFIRST_DUPLICATE_TOKEN=visible\n",
        ),
        (
            "main.tex",
            b"\\documentclass{article}\nSECOND_DUPLICATE_TOKEN=visible\n",
        ),
    ]);
    std::fs::write(&archive, bytes).expect("write duplicate zip");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.iter().any(|error| error
            .to_string()
            .contains("repeated member names have distinct payloads")),
        "ambiguous dependency identity must be visible: {errors:?}"
    );
    assert!(chunks
        .iter()
        .any(|chunk| chunk.data.contains("FIRST_DUPLICATE_TOKEN")));
    assert!(chunks
        .iter()
        .any(|chunk| chunk.data.contains("SECOND_DUPLICATE_TOKEN")));
}
