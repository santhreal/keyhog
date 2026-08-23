/// The canonical route identity of a detector corpus: exactly the compiled plan
/// digest an execution pack built from that corpus carries. A caller that routes
/// on corpus identity (autoroute) needs one value whether the scanner compiled
/// the specs or hydrated a pack, and only this normalized form is shared by
/// both. Self-test fixtures and declaration order are excluded, as they are from
/// the pack's own IR.
pub fn corpus_route_identity(
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<[u8; 32], crate::execution_pack::ExecutionPackError> {
    let spec_hash =
        crate::execution_pack::CanonicalDetectorExecutionIr::canonical_spec_hash(detectors)?;
    let decoder_plan = crate::decode::CompiledDecoderPlan::snapshot().map_err(|error| {
        crate::execution_pack::ExecutionPackError::InvalidCompilerInput(error.to_string())
    })?;
    Ok(from_execution_plan(spec_hash, decoder_plan.identity()))
}

pub(crate) fn from_execution_plan(spec_hash: [u8; 32], decoder_plan_identity: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    update(&mut hasher, b"domain", b"keyhog-scanner-detector-digest-v3");
    update(&mut hasher, b"spec_hash", &spec_hash);
    update(
        &mut hasher,
        b"decoder_plan",
        &decoder_plan_identity.to_le_bytes(),
    );
    *hasher.finalize().as_bytes()
}

pub(crate) fn projection(digest: [u8; 32]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

fn update(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}
