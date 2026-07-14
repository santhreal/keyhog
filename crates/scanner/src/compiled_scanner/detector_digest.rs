pub(super) fn from_pattern_sources(patterns: &[&str]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    update(&mut hasher, b"domain", b"keyhog-scanner-detector-digest-v1");
    update_u64(&mut hasher, b"pattern_count", patterns.len() as u64);
    for source in patterns {
        update(&mut hasher, b"regex", source.as_bytes());
    }

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn update(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn update_u64(hasher: &mut blake3::Hasher, tag: &[u8], value: u64) {
    update(hasher, tag, &value.to_le_bytes());
}
