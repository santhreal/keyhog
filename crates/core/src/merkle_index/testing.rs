use std::path::PathBuf;

pub fn empty_index() -> super::MerkleIndex {
    super::MerkleIndex::empty()
}

pub fn record_content_hash(index: &super::MerkleIndex, path: PathBuf, content_hash: [u8; 32]) {
    index.record(path, content_hash);
}

pub fn hash_content(content: &[u8]) -> [u8; 32] {
    super::MerkleIndex::hash_content(content)
}

pub fn unchanged(
    index: &super::MerkleIndex,
    path: &std::path::Path,
    content_hash: &[u8; 32],
) -> bool {
    index.unchanged(path, content_hash)
}

pub fn metadata_unchanged(
    index: &super::MerkleIndex,
    path: &std::path::Path,
    mtime_ns: u64,
    size: u64,
) -> bool {
    index.metadata_unchanged(path, mtime_ns, size)
}

pub fn record_with_metadata(
    index: &super::MerkleIndex,
    path: PathBuf,
    mtime_ns: u64,
    size: u64,
    content_hash: [u8; 32],
) {
    index.record_with_metadata(path, mtime_ns, size, content_hash);
}

pub fn len(index: &super::MerkleIndex) -> usize {
    index.len()
}
