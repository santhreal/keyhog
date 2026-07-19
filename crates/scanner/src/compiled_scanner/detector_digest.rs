pub(super) fn from_execution_plan(spec_hash: [u8; 32], decoder_plan_identity: u64) -> u64 {
    let mut hasher = blake3::Hasher::new();
    update(&mut hasher, b"domain", b"keyhog-scanner-detector-digest-v3");
    update(&mut hasher, b"spec_hash", &spec_hash);
    update(
        &mut hasher,
        b"decoder_plan",
        &decoder_plan_identity.to_le_bytes(),
    );

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
