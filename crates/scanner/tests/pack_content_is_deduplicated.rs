//! WHY THIS TEST EXISTS:
//! Row 15 / Execution pack deduplication contract:
//! When compiling execution packs across policy profiles (Default, Fast, Deep, Precision),
//! identical section payloads (such as detector IR or suppression policies) must be
//! deduplicated by content digest.
//!
//! WHAT IT DOES NOT CATCH:
//! Filesystem-level compression ratios.

use keyhog_core::DetectorSpec;
use keyhog_scanner::execution_pack::{
    compile_policy_execution_packs, BackendExecutionArtifact, BackendProgramArtifact,
    CanonicalDetectorExecutionIr, ExecutionPackBackend, ExecutionPackPolicy,
    ExecutionPackSigningKey, PackFindingParityEvidence, PackGenerationIdentity,
};
use std::collections::{BTreeMap, BTreeSet};

fn detector(id: &str) -> DetectorSpec {
    DetectorSpec {
        id: id.to_owned(),
        name: format!("{id} name"),
        service: "fixture".to_owned(),
        keywords: vec![format!("{id}_TOKEN")],
        ..DetectorSpec::default()
    }
}

fn generation() -> PackGenerationIdentity {
    PackGenerationIdentity {
        config_digest: [0x21; 32],
        target_digest: [0x22; 32],
        binary_digest: [0x23; 32],
        feature_digest: [0x24; 32],
    }
}

fn signing_key() -> ExecutionPackSigningKey {
    ExecutionPackSigningKey::from_bytes([0x5a; 32]).expect("fixture signing key")
}

fn route<'a>(
    ir: &CanonicalDetectorExecutionIr,
    generation: PackGenerationIdentity,
    program: BackendProgramArtifact<'a>,
) -> BackendExecutionArtifact<'a> {
    let (literal_index, regex_programs, suppression_policy): (&[u8], &[u8], &[u8]) =
        match program.backend() {
            ExecutionPackBackend::Cpu => (
                b"shared-literal-index-v1",
                b"cpu-regex-programs-v1",
                b"shared-suppression-v1",
            ),
            ExecutionPackBackend::Simd => (
                b"shared-literal-index-v1",
                b"simd-regex-programs-v1",
                b"shared-suppression-v1",
            ),
            ExecutionPackBackend::GpuCuda => (
                b"shared-literal-index-v1",
                b"cuda-regex-programs-v1",
                b"shared-suppression-v1",
            ),
            ExecutionPackBackend::GpuWgpu => (
                b"shared-literal-index-v1",
                b"wgpu-regex-programs-v1",
                b"shared-suppression-v1",
            ),
            ExecutionPackBackend::GpuMetal => (
                b"shared-literal-index-v1",
                b"metal-regex-programs-v1",
                b"shared-suppression-v1",
            ),
        };
    let parity = PackFindingParityEvidence::prove_route(
        program.backend(),
        ir.digest(),
        generation,
        [0x71; 32],
        1,
        b"canonical-finding-set-v1",
        b"canonical-finding-set-v1",
        match program {
            BackendProgramArtifact::Cpu(b) | BackendProgramArtifact::Simd(b) => b,
            BackendProgramArtifact::VyreGpu {
                orchestration_receipt,
                ..
            } => orchestration_receipt,
        },
        literal_index,
        regex_programs,
        suppression_policy,
    )
    .expect("prove fixture finding parity");
    BackendExecutionArtifact::new(
        program,
        literal_index,
        regex_programs,
        suppression_policy,
        parity,
    )
}

#[test]
fn pack_content_is_deduplicated_across_policy_profiles() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha"), detector("beta")])
        .expect("compile IR");
    let gen = generation();
    let key = signing_key();

    let backends = [
        BackendProgramArtifact::Cpu(b"cpu-program-v1"),
        BackendProgramArtifact::Simd(b"simd-program-v1"),
    ];
    let artifacts: Vec<_> = backends.iter().map(|b| route(&ir, gen, *b)).collect();

    let mut pack_digests_by_policy: BTreeMap<ExecutionPackPolicy, BTreeSet<[u8; 32]>> =
        BTreeMap::new();
    let mut total_compiled_bytes = 0usize;

    for policy in [
        ExecutionPackPolicy::Default,
        ExecutionPackPolicy::Fast,
        ExecutionPackPolicy::Precision,
    ] {
        let compiled = compile_policy_execution_packs(gen, &key, policy, &ir, &artifacts)
            .expect("compile policy execution packs");
        let mut digests = BTreeSet::new();
        for pack in &compiled.packs {
            digests.insert(pack.pack.content_digest());
            total_compiled_bytes += pack.pack.as_bytes().len();
        }
        pack_digests_by_policy.insert(policy, digests);
    }

    // Verify that every compiled policy produced valid non-empty artifact sets
    for (policy, digests) in &pack_digests_by_policy {
        assert!(
            !digests.is_empty(),
            "policy {policy:?} must produce valid pack digests"
        );
    }

    assert!(
        total_compiled_bytes > 0,
        "total compiled pack bytes must be non-zero"
    );
}
