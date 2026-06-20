#![allow(dead_code)]

pub mod archive;
#[cfg(feature = "git")]
pub mod git;
pub mod pdf;

use keyhog_core::{Chunk, Source};

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
