#![allow(dead_code)]

pub mod archive;
#[cfg(feature = "git")]
pub mod git;
pub mod pdf;

use keyhog_core::{Chunk, Source, SourceError};

pub const CLOUD_PREFILTER_BINARY_EXTS: &[&str] = &[
    "zip", "rar", "bz2", "xz", "zst", "lz4", "sz", "exe", "class", "wasm", "pyc", "sqlite", "svg",
];

pub fn collect_chunks<S: Source + ?Sized>(source: &S) -> Vec<Chunk> {
    let source_name = source.name().to_string();
    source
        .chunks()
        .map(|result| {
            result.unwrap_or_else(|error| {
                panic!("{source_name} source emitted unexpected SourceError: {error}")
            })
        })
        .collect()
}

pub fn count_chunks<S: Source + ?Sized>(source: &S) -> usize {
    collect_chunks(source).len()
}

pub fn split_chunk_results(
    rows: &[Result<Chunk, SourceError>],
) -> (Vec<&Chunk>, Vec<&SourceError>) {
    let mut chunks = Vec::new();
    let mut errors = Vec::new();
    for row in rows {
        match row {
            Ok(chunk) => chunks.push(chunk),
            Err(error) => errors.push(error),
        }
    }
    (chunks, errors)
}
