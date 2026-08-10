use keyhog_core::DetectorSpec;
use keyhog_scanner::execution_pack::{
    compile_deep_policy_execution_packs, compile_default_policy_execution_packs,
    compile_fast_policy_execution_packs, compile_precision_policy_execution_packs,
    BackendExecutionArtifact, BackendProgramArtifact, CanonicalDetectorExecutionIr,
    CompiledNativeBackendPrograms, ExecutionPack, ExecutionPackBackend, ExecutionPackPolicy,
    ExecutionPackSectionKind, ExecutionPackSignature, ExecutionPackSigningKey,
    HyperscanSimdExecutionProgram, PackFindingParityEvidence, PackGenerationIdentity,
    ScalarCpuExecutionProgram,
};
#[cfg(feature = "gpu")]
use keyhog_scanner::execution_pack::{
    CompiledVyreBackendProgram, VyreExecutionIdentity, VyreOrchestrationProgram,
};
use std::fs;

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
                b"cpu-literal-index-v1",
                b"cpu-regex-programs-v1",
                b"cpu-suppression-v1",
            ),
            ExecutionPackBackend::Simd => (
                b"simd-literal-map-v1",
                b"simd-regex-programs-v1",
                b"simd-suppression-v1",
            ),
            ExecutionPackBackend::GpuCuda => (
                b"cuda-literal-map-v1",
                b"cuda-regex-programs-v1",
                b"cuda-suppression-v1",
            ),
            ExecutionPackBackend::GpuWgpu => (
                b"wgpu-literal-map-v1",
                b"wgpu-regex-programs-v1",
                b"wgpu-suppression-v1",
            ),
            ExecutionPackBackend::GpuMetal => (
                b"metal-literal-map-v1",
                b"metal-regex-programs-v1",
                b"metal-suppression-v1",
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
        artifact_bytes(program),
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

fn routes<'a>(
    ir: &CanonicalDetectorExecutionIr,
    generation: PackGenerationIdentity,
    backends: &[BackendProgramArtifact<'a>],
) -> Vec<BackendExecutionArtifact<'a>> {
    backends
        .iter()
        .copied()
        .map(|program| route(ir, generation, program))
        .collect()
}

/// WHY: installing the default policy must emit one exact immutable pack for every eligible peer while keeping GPU program ownership inside VYRE.
#[test]
fn default_policy_compiles_every_eligible_backend_pack() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let backends = [
        BackendProgramArtifact::Cpu(b"cpu-program-v1"),
        BackendProgramArtifact::Simd(b"simd-program-v1"),
        BackendProgramArtifact::VyreGpu {
            backend: ExecutionPackBackend::GpuCuda,
            orchestration_receipt: b"cuda-vyre-receipt-v1",
        },
        BackendProgramArtifact::VyreGpu {
            backend: ExecutionPackBackend::GpuWgpu,
            orchestration_receipt: b"wgpu-vyre-receipt-v1",
        },
        BackendProgramArtifact::VyreGpu {
            backend: ExecutionPackBackend::GpuMetal,
            orchestration_receipt: b"metal-vyre-receipt-v1",
        },
    ];
    let compiled = compile_default_policy_execution_packs(
        generation(),
        &signing_key(),
        &ir,
        &routes(&ir, generation(), &backends),
    )
    .expect("compile default packs");

    assert_eq!(compiled.policy, ExecutionPackPolicy::Default);
    assert_eq!(compiled.packs.len(), 5);
    let directory = tempfile::tempdir().expect("temporary directory");
    for artifact in backends {
        let backend = artifact.backend();
        let pack = compiled.get(backend).expect("backend pack");
        assert_eq!(pack.identity().policy, ExecutionPackPolicy::Default);
        assert_eq!(pack.identity().backend, backend);
        assert_eq!(pack.identity().detector_digest, ir.digest());
        assert_eq!(pack.identity().config_digest, generation().config_digest);
        assert_eq!(pack.identity().target_digest, generation().target_digest);
        assert_eq!(pack.identity().binary_digest, generation().binary_digest);
        assert_eq!(pack.identity().feature_digest, generation().feature_digest);
        assert_eq!(
            pack.identity().backend_digest,
            *blake3::hash(artifact_bytes(artifact)).as_bytes()
        );
        let path = directory.path().join(format!("{backend:?}.khpack"));
        fs::write(&path, pack.as_bytes()).expect("publish pack");
        let mapped = ExecutionPack::open(&path, pack.identity()).expect("map generated pack");
        assert_eq!(mapped.content_digest(), pack.content_digest());
        let backend_program = mapped
            .section(ExecutionPackSectionKind::BackendProgram)
            .expect("backend section");
        if backend.is_gpu() {
            assert!(backend_program.starts_with(b"KHVYRE\0\x01"));
        } else {
            assert_eq!(backend_program, artifact_bytes(artifact));
        }
    }
}

/// WHY: scalar is the parity oracle for pack compilation and calibration, so a policy generation without it is incomplete rather than GPU- or SIMD-only.
#[test]
fn default_policy_rejects_generation_without_cpu_correctness_pack() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let error = compile_default_policy_execution_packs(
        generation(),
        &signing_key(),
        &ir,
        &routes(
            &ir,
            generation(),
            &[BackendProgramArtifact::Simd(b"simd-program-v1")],
        ),
    )
    .expect_err("missing CPU pack must fail");
    assert!(error
        .to_string()
        .contains("mandatory scalar correctness pack"));
}

/// WHY: duplicate backend rows make publication order decide which executable bytes win, so generation must reject them before writing any pack.
#[test]
fn default_policy_rejects_duplicate_backend_programs() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let error = compile_default_policy_execution_packs(
        generation(),
        &signing_key(),
        &ir,
        &routes(
            &ir,
            generation(),
            &[
                BackendProgramArtifact::Cpu(b"cpu-one"),
                BackendProgramArtifact::Cpu(b"cpu-two"),
            ],
        ),
    )
    .expect_err("duplicate CPU packs must fail");
    assert!(error.to_string().contains("repeats backend Cpu"));
}

fn artifact_bytes(artifact: BackendProgramArtifact<'_>) -> &[u8] {
    match artifact {
        BackendProgramArtifact::Cpu(bytes) | BackendProgramArtifact::Simd(bytes) => bytes,
        BackendProgramArtifact::VyreGpu {
            orchestration_receipt,
            ..
        } => orchestration_receipt,
    }
}

/// WHY: fast is a separately calibrated execution contract; it must not reuse default-policy identity even when a backend compiler happens to emit equal bytes.
#[test]
fn fast_policy_compiles_exact_fast_pack_identity() {
    assert_policy_generation(ExecutionPackPolicy::Fast);
}

/// WHY: deep enables a different detector/decode work graph and must publish its own exact packs rather than mutate a default scanner at runtime.
#[test]
fn deep_policy_compiles_exact_deep_pack_identity() {
    assert_policy_generation(ExecutionPackPolicy::Deep);
}

/// WHY: precision changes detector survival policy and cannot share a pack or calibration identity with default, fast, or deep.
#[test]
fn precision_policy_compiles_exact_precision_pack_identity() {
    assert_policy_generation(ExecutionPackPolicy::Precision);
}

fn assert_policy_generation(policy: ExecutionPackPolicy) {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let mut generation = generation();
    generation.config_digest = [policy as u8; 32];
    let backends = [
        BackendProgramArtifact::Cpu(b"cpu-program-v1"),
        BackendProgramArtifact::Simd(b"simd-program-v1"),
    ];
    let compiled = match policy {
        ExecutionPackPolicy::Fast => compile_fast_policy_execution_packs(
            generation,
            &signing_key(),
            &ir,
            &routes(&ir, generation, &backends),
        ),
        ExecutionPackPolicy::Deep => compile_deep_policy_execution_packs(
            generation,
            &signing_key(),
            &ir,
            &routes(&ir, generation, &backends),
        ),
        ExecutionPackPolicy::Precision => compile_precision_policy_execution_packs(
            generation,
            &signing_key(),
            &ir,
            &routes(&ir, generation, &backends),
        ),
        ExecutionPackPolicy::Default => compile_default_policy_execution_packs(
            generation,
            &signing_key(),
            &ir,
            &routes(&ir, generation, &backends),
        ),
    }
    .expect("compile policy packs");
    assert_eq!(compiled.policy, policy);
    assert_eq!(compiled.packs.len(), 2);
    for candidate in compiled.packs {
        assert_eq!(candidate.pack.identity().policy, policy);
        assert_eq!(candidate.pack.identity().config_digest, [policy as u8; 32]);
        assert_eq!(candidate.pack.identity().backend, candidate.backend);
    }
}

/// WHY: scalar packs are the exact parity oracle, so they must contain normalized detector-indexed pattern programs rather than detector TOML or an opaque placeholder.
#[test]
fn scalar_cpu_program_compiles_exact_detector_pattern_contract() {
    let mut spec = detector("alpha");
    spec.patterns.push(keyhog_core::PatternSpec {
        regex: "ALPHA_([A-Z0-9]{8})".to_owned(),
        group: Some(1),
        required_literals: vec!["ALPHA_".to_owned(), "ALPHA_".to_owned()],
        weak_anchor: true,
        structural_password_slot: true,
        ..Default::default()
    });
    let ir = CanonicalDetectorExecutionIr::compile(&[spec]).expect("compile IR");
    let program = ScalarCpuExecutionProgram::compile(&ir).expect("compile scalar program");
    assert_eq!(program.detector_ir_digest, ir.digest());
    assert_eq!(program.patterns.len(), 1);
    let pattern = &program.patterns[0];
    assert_eq!(pattern.detector_index, 0);
    assert_eq!(pattern.pattern_index, 0);
    assert_eq!(pattern.regex, "ALPHA_([A-Z0-9]{8})");
    assert_eq!(pattern.capture_group, Some(1));
    assert_eq!(pattern.required_literals, ["ALPHA_"]);
    assert!(pattern.weak_anchor);
    assert!(pattern.structural_password_slot);

    let bytes = program.canonical_bytes().expect("encode scalar program");
    let decoded =
        ScalarCpuExecutionProgram::decode(&bytes, ir.digest()).expect("decode scalar program");
    assert_eq!(decoded, program);
}

/// WHY: the default CPU pack must carry the canonical scalar program bytes and bind its digest as backend identity.
#[test]
fn default_cpu_pack_embeds_compiled_scalar_program() {
    let mut spec = detector("alpha");
    spec.patterns.push(keyhog_core::PatternSpec {
        regex: "ALPHA_[A-Z0-9]{8}".to_owned(),
        required_literals: vec!["ALPHA_".to_owned()],
        ..Default::default()
    });
    let ir = CanonicalDetectorExecutionIr::compile(&[spec]).expect("compile IR");
    let cpu = ScalarCpuExecutionProgram::compile(&ir).expect("compile scalar program");
    let cpu_bytes = cpu.canonical_bytes().expect("encode scalar program");
    let packs = compile_default_policy_execution_packs(
        generation(),
        &signing_key(),
        &ir,
        &routes(
            &ir,
            generation(),
            &[BackendProgramArtifact::Cpu(&cpu_bytes)],
        ),
    )
    .expect("compile CPU pack");
    let pack = packs.get(ExecutionPackBackend::Cpu).expect("CPU pack");
    assert_eq!(
        pack.identity().backend_digest,
        *blake3::hash(&cpu_bytes).as_bytes()
    );
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("cpu.khpack");
    fs::write(&path, pack.as_bytes()).expect("publish CPU pack");
    let mapped = ExecutionPack::open(&path, pack.identity()).expect("map CPU pack");
    let embedded = mapped
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("CPU program section");
    assert_eq!(embedded, cpu_bytes);
    ScalarCpuExecutionProgram::decode(embedded, ir.digest())
        .expect("validate embedded CPU program");
}

/// WHY: a scalar program compiled from another detector generation cannot serve as this pack's correctness oracle.
#[test]
fn scalar_cpu_program_rejects_detector_ir_mismatch() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let bytes = ScalarCpuExecutionProgram::compile(&ir)
        .expect("compile scalar program")
        .canonical_bytes()
        .expect("encode scalar program");
    let error = ScalarCpuExecutionProgram::decode(&bytes, [0x99; 32])
        .expect_err("detector mismatch must fail");
    assert!(error
        .to_string()
        .contains("detector IR identity does not match"));
}

/// WHY: install-time SIMD generation must persist real deserializable Hyperscan databases, not regex source or fixture bytes.
#[cfg(feature = "simd")]
#[test]
fn native_compiler_embeds_deserializable_hyperscan_shards() {
    let mut spec = detector("alpha");
    spec.patterns.push(keyhog_core::PatternSpec {
        regex: "ALPHA_([A-Z0-9]{8})".to_owned(),
        group: Some(1),
        required_literals: vec!["ALPHA_".to_owned()],
        ..Default::default()
    });
    let ir = CanonicalDetectorExecutionIr::compile(&[spec]).expect("compile IR");
    let native = CompiledNativeBackendPrograms::compile(&ir).expect("compile native programs");
    let simd = HyperscanSimdExecutionProgram::decode(native.simd_bytes(), ir.digest())
        .expect("decode compiled Hyperscan program");
    let original = simd
        .patterns
        .iter()
        .find(|pattern| pattern.regex == "ALPHA_([A-Z0-9]{8})")
        .expect("canonical detector regex is present");
    assert_eq!(original.scalar_pattern_indices, [0]);
    assert_eq!(original.ac_map_indices, [1]);
    assert!(original.reports_start);
    assert!(simd.unsupported_pattern_ids.is_empty());
    assert!(!simd.serialized_shards.is_empty());
    let expected_release_lengths: Vec<usize> = simd
        .serialized_shards
        .iter()
        .chain(simd.phase2_scopes.iter().flat_map(|scope| {
            scope
                .full
                .iter()
                .chain(scope.ascii_lean.iter())
                .flat_map(|database| database.serialized_shards.iter())
        }))
        .map(|shard| shard.len())
        .collect();
    let mut released_lengths = Vec::new();
    HyperscanSimdExecutionProgram::decode_with_release(native.simd_bytes(), ir.digest(), |bytes| {
        released_lengths.push(bytes.len());
        Ok(())
    })
    .expect("decode and release native shard fields");
    assert!(released_lengths.iter().all(|length| *length > 0));
    assert_eq!(
        released_lengths.iter().sum::<usize>(),
        expected_release_lengths.iter().sum::<usize>(),
        "every serialized shard byte must release its mapped page window immediately after decode"
    );

    let artifacts = native.artifacts();
    assert_eq!(artifacts.len(), 2);
    let packs = compile_default_policy_execution_packs(
        generation(),
        &signing_key(),
        &ir,
        &routes(&ir, generation(), &artifacts),
    )
    .expect("compile native execution packs");
    let pack = packs.get(ExecutionPackBackend::Simd).expect("SIMD pack");
    assert_eq!(
        pack.identity().backend_digest,
        *blake3::hash(native.simd_bytes()).as_bytes()
    );
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("simd.khpack");
    fs::write(&path, pack.as_bytes()).expect("publish SIMD pack");
    let mapped = ExecutionPack::open(&path, pack.identity()).expect("map SIMD pack");
    let embedded = mapped
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("SIMD program section");
    assert_eq!(embedded, native.simd_bytes());
    HyperscanSimdExecutionProgram::decode(embedded, ir.digest())
        .expect("validate mapped Hyperscan program");
}

/// WHY: serialized SIMD databases are native compatibility artifacts, so one corrupt byte must fail closed before a scan starts.
#[cfg(feature = "simd")]
#[test]
fn hyperscan_program_rejects_corrupt_serialized_database() {
    let mut spec = detector("alpha");
    spec.patterns.push(keyhog_core::PatternSpec {
        regex: "ALPHA_[A-Z0-9]{8}".to_owned(),
        ..Default::default()
    });
    let ir = CanonicalDetectorExecutionIr::compile(&[spec]).expect("compile IR");
    let program = HyperscanSimdExecutionProgram::compile(&ir).expect("compile SIMD program");
    let shard = program
        .serialized_shards
        .first()
        .expect("fixture compiles one native shard");
    let mut bytes = program.canonical_bytes().expect("encode SIMD program");
    let shard_offset = bytes
        .windows(shard.len())
        .position(|window| window == shard.as_ref())
        .expect("encoded program contains native shard bytes");
    bytes[shard_offset] ^= 0xff;
    let error = HyperscanSimdExecutionProgram::decode(&bytes, ir.digest())
        .expect_err("corrupt native database must fail");
    assert!(
        error.to_string().contains("corrupt"),
        "unexpected corruption diagnostic: {error}"
    );
}

#[cfg(feature = "gpu")]
fn gpu_detector_ir() -> CanonicalDetectorExecutionIr {
    let mut spec = detector("alpha");
    spec.patterns.push(keyhog_core::PatternSpec {
        regex: "ALPHA_[A-Z0-9]{8}".to_owned(),
        required_literals: vec!["ALPHA_".to_owned()],
        ..Default::default()
    });
    CanonicalDetectorExecutionIr::compile(&[spec]).expect("compile GPU detector IR")
}

#[cfg(feature = "gpu")]
fn vyre_identity(backend: ExecutionPackBackend) -> VyreExecutionIdentity {
    VyreExecutionIdentity::for_backend(
        backend,
        "linux-x86_64-rtx5090",
        "runtime=fixture",
        "device=fixture",
        [0x65; 32],
    )
    .expect("construct VYRE identity")
}

/// WHY: CUDA packs may orchestrate GPU work only through a VYRE-owned matcher bound to exact device and driver evidence.
#[cfg(feature = "gpu")]
#[test]
fn cuda_pack_contains_exact_vyre_orchestration_program() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuCuda);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuCuda, identity.clone())
            .expect("compile CUDA VYRE program");
    let decoded = VyreOrchestrationProgram::decode(
        program.bytes(),
        ExecutionPackBackend::GpuCuda,
        ir.digest(),
        &identity,
    )
    .expect("decode CUDA VYRE program");
    assert_eq!(decoded.backend, ExecutionPackBackend::GpuCuda);
    assert!(decoded.matcher_pattern_count > 0);
    assert_eq!(
        decoded.matcher_digest,
        *blake3::hash(&decoded.matcher_bytes).as_bytes()
    );
    assert!(!decoded.phase2_catalog_bytes.is_empty());
    assert_eq!(
        decoded.phase2_catalog_digest,
        *blake3::hash(&decoded.phase2_catalog_bytes).as_bytes()
    );

    let cpu = CompiledNativeBackendPrograms::compile(&ir).expect("compile CPU oracle");
    let artifacts = [cpu.artifacts()[0], program.artifact()];
    let packs = compile_default_policy_execution_packs(
        generation(),
        &signing_key(),
        &ir,
        &routes(&ir, generation(), &artifacts),
    )
    .expect("compile CUDA execution pack");
    let pack = packs.get(ExecutionPackBackend::GpuCuda).expect("CUDA pack");
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("cuda.khpack");
    fs::write(&path, pack.as_bytes()).expect("publish CUDA pack");
    let mapped = ExecutionPack::open(&path, pack.identity()).expect("map CUDA pack");
    let envelope = mapped
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("GPU section");
    assert_eq!(&envelope[..8], b"KHVYRE\0\x01");
    assert_eq!(envelope[8], ExecutionPackBackend::GpuCuda as u8);
}

/// WHY: a CUDA receipt calibrated for another device cannot be replayed even when its VYRE matcher bytes are unchanged.
#[cfg(feature = "gpu")]
#[test]
fn cuda_program_rejects_device_identity_drift() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuCuda);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuCuda, identity.clone())
            .expect("compile CUDA VYRE program");
    let mut stale = identity;
    stale.device_identity = "device=replaced".to_owned();
    let error = VyreOrchestrationProgram::decode(
        program.bytes(),
        ExecutionPackBackend::GpuCuda,
        ir.digest(),
        &stale,
    )
    .expect_err("stale CUDA device must fail");
    assert!(error
        .to_string()
        .contains("execution identity does not match"));
}

/// WHY: WGPU is a distinct calibrated VYRE peer, so its pack must preserve WGPU driver and adapter identity instead of reusing CUDA evidence.
#[cfg(feature = "gpu")]
#[test]
fn wgpu_pack_contains_exact_vyre_orchestration_program() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuWgpu);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuWgpu, identity.clone())
            .expect("compile WGPU VYRE program");
    let decoded = VyreOrchestrationProgram::decode(
        program.bytes(),
        ExecutionPackBackend::GpuWgpu,
        ir.digest(),
        &identity,
    )
    .expect("decode WGPU VYRE program");
    assert_eq!(decoded.backend, ExecutionPackBackend::GpuWgpu);
    assert!(decoded.matcher_pattern_count > 0);
    assert_eq!(
        decoded.matcher_digest,
        *blake3::hash(&decoded.matcher_bytes).as_bytes()
    );
    assert!(!decoded.phase2_catalog_bytes.is_empty());
    assert_eq!(
        decoded.phase2_catalog_digest,
        *blake3::hash(&decoded.phase2_catalog_bytes).as_bytes()
    );
    assert_eq!(
        decoded.feature_schema_digest,
        keyhog_scanner::confidence::quantized::feature_schema_digest()
    );
    assert_eq!(
        decoded.quantized_model_digest,
        keyhog_scanner::confidence::quantized::model_artifact_digest()
    );
    assert_eq!(
        decoded.quantized_score_abi_version,
        keyhog_scanner::confidence::quantized::QUANTIZED_SCORE_ABI_VERSION
    );
}

/// WHY: backend relabeling would run a VYRE plan against unproved runtime semantics, so CUDA and WGPU receipts are never interchangeable.
#[cfg(feature = "gpu")]
#[test]
fn wgpu_program_rejects_cuda_backend_relabeling() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuWgpu);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuWgpu, identity.clone())
            .expect("compile WGPU VYRE program");
    let error = VyreOrchestrationProgram::decode(
        program.bytes(),
        ExecutionPackBackend::GpuCuda,
        ir.digest(),
        &identity,
    )
    .expect_err("WGPU receipt cannot become CUDA");
    assert!(error.to_string().contains("not selected GpuCuda"));
}

/// WHY: a signed matcher receipt calibrated with another feature schema or
/// model cannot authorize the quantized score dispatch.
#[cfg(feature = "gpu")]
#[test]
fn wgpu_program_rejects_stale_quantized_confidence_artifacts() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuWgpu);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuWgpu, identity.clone())
            .expect("compile WGPU VYRE program");
    for offset in [112usize, 144, 176] {
        let mut stale = program.bytes().to_vec();
        stale[offset] ^= 1;
        let error = VyreOrchestrationProgram::decode(
            &stale,
            ExecutionPackBackend::GpuWgpu,
            ir.digest(),
            &identity,
        )
        .expect_err("stale quantized confidence identity must fail");
        assert!(
            error
                .to_string()
                .contains("confidence schema, model, or score ABI")
                || error.to_string().contains("unsupported"),
            "offset {offset}: {error}"
        );
    }
}

/// WHY: Metal is a native VYRE peer with its own compiled driver identity and cannot inherit WGPU portability evidence.
#[cfg(feature = "gpu")]
#[test]
fn metal_pack_contains_exact_vyre_orchestration_program() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuMetal);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuMetal, identity.clone())
            .expect("compile Metal VYRE program");
    let decoded = VyreOrchestrationProgram::decode(
        program.bytes(),
        ExecutionPackBackend::GpuMetal,
        ir.digest(),
        &identity,
    )
    .expect("decode Metal VYRE program");
    assert_eq!(decoded.backend, ExecutionPackBackend::GpuMetal);
    assert!(decoded.matcher_pattern_count > 0);
    assert_eq!(
        decoded.matcher_digest,
        *blake3::hash(&decoded.matcher_bytes).as_bytes()
    );
    assert!(!decoded.phase2_catalog_bytes.is_empty());
    assert_eq!(
        decoded.phase2_catalog_digest,
        *blake3::hash(&decoded.phase2_catalog_bytes).as_bytes()
    );
}

/// WHY: a VYRE matcher is useful only with the exact linked Metal driver, so stale driver receipts fail before dispatch.
#[cfg(feature = "gpu")]
#[test]
fn metal_program_rejects_driver_identity_drift() {
    let ir = gpu_detector_ir();
    let identity = vyre_identity(ExecutionPackBackend::GpuMetal);
    let program =
        CompiledVyreBackendProgram::compile(&ir, ExecutionPackBackend::GpuMetal, identity.clone())
            .expect("compile Metal VYRE program");
    let mut stale = identity;
    stale.driver_version = "0.0.0-stale".to_owned();
    let error = VyreOrchestrationProgram::decode(
        program.bytes(),
        ExecutionPackBackend::GpuMetal,
        ir.digest(),
        &stale,
    )
    .expect_err("stale Metal driver must fail");
    assert!(error.to_string().contains("driver version"));
}

/// WHY: one universal matcher graph restores the original peak-memory defect, so each backend pack must retain only its own route-specific structures.
#[test]
fn backend_packs_embed_only_their_route_required_matcher_sections() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let backends = [
        BackendProgramArtifact::Cpu(b"cpu-program-v1"),
        BackendProgramArtifact::Simd(b"simd-program-v1"),
    ];
    let route_artifacts = routes(&ir, generation(), &backends);
    let packs =
        compile_default_policy_execution_packs(generation(), &signing_key(), &ir, &route_artifacts)
            .expect("compile route-specific packs");
    let directory = tempfile::tempdir().expect("temporary directory");
    for route in route_artifacts {
        let pack = packs.get(route.backend()).expect("backend pack");
        let path = directory
            .path()
            .join(format!("{:?}.khpack", route.backend()));
        fs::write(&path, pack.as_bytes()).expect("publish pack");
        let mapped = ExecutionPack::open(&path, pack.identity()).expect("map pack");
        assert_eq!(
            mapped
                .section(ExecutionPackSectionKind::LiteralIndex)
                .expect("literal section"),
            route.literal_index
        );
        assert_eq!(
            mapped
                .section(ExecutionPackSectionKind::RegexPrograms)
                .expect("regex section"),
            route.regex_programs
        );
        let other = routes(&ir, generation(), &backends)
            .into_iter()
            .find(|candidate| candidate.backend() != route.backend())
            .expect("peer route");
        assert_ne!(route.literal_index, other.literal_index);
        assert!(!pack
            .as_bytes()
            .windows(other.literal_index.len())
            .any(|bytes| bytes == other.literal_index));
    }
}

/// WHY: omitting a route-required structure would turn pack selection into a late runtime fallback, so publication must reject incomplete route graphs.
#[test]
fn route_generation_rejects_empty_required_matcher_structure() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let mut incomplete = route(
        &ir,
        generation(),
        BackendProgramArtifact::Cpu(b"cpu-program-v1"),
    );
    incomplete.regex_programs = b"";
    let routes = [incomplete];
    let error = compile_default_policy_execution_packs(generation(), &signing_key(), &ir, &routes)
        .expect_err("incomplete route graph must fail");
    assert!(error
        .to_string()
        .contains("empty route-required regex programs"));
}

/// WHY: publication is forbidden when an accelerated route changes even one canonical finding byte relative to scalar execution.
#[test]
fn parity_evidence_rejects_different_candidate_findings() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let error = PackFindingParityEvidence::prove_route(
        ExecutionPackBackend::Simd,
        ir.digest(),
        generation(),
        [0x72; 32],
        1,
        b"detector=alpha;offset=7;credential=one",
        b"detector=alpha;offset=8;credential=one",
        b"simd-program-v1",
        b"simd-literal-map-v1",
        b"simd-regex-programs-v1",
        b"simd-suppression-v1",
    )
    .expect_err("finding mismatch must fail before publication");
    assert!(error
        .to_string()
        .contains("candidate findings differ from scalar oracle"));
}

/// WHY: parity evidence applies to exact matcher bytes, so changing a section after calibration invalidates publication even if findings once matched.
#[test]
fn generation_rejects_parity_receipt_after_route_bytes_change() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let backends = [BackendProgramArtifact::Cpu(b"cpu-program-v1")];
    let mut route = routes(&ir, generation(), &backends).remove(0);
    route.regex_programs = b"cpu-regex-programs-v2-uncalibrated";
    let error = compile_default_policy_execution_packs(generation(), &signing_key(), &ir, &[route])
        .expect_err("changed route bytes must invalidate parity");
    assert!(error
        .to_string()
        .contains("stale or belongs to another route"));
}

/// WHY: fixture provenance is part of the proof boundary, so an all-zero fixture identity can never authorize pack publication.
#[test]
fn parity_evidence_rejects_missing_fixture_identity() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let error = PackFindingParityEvidence::prove_route(
        ExecutionPackBackend::Cpu,
        ir.digest(),
        generation(),
        [0; 32],
        0,
        b"[]",
        b"[]",
        b"cpu-program-v1",
        b"cpu-literal-index-v1",
        b"cpu-regex-programs-v1",
        b"cpu-suppression-v1",
    )
    .expect_err("missing fixture identity must fail");
    assert!(error.to_string().contains("fixture identity is empty"));
}

/// WHY: every published pack requires an authenticated sidecar bound to the exact pack bytes and installation key identity.
#[test]
fn generated_pack_signature_round_trips_and_verifies() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let key = signing_key();
    let backends = [BackendProgramArtifact::Cpu(b"cpu-program-v1")];
    let compiled = compile_default_policy_execution_packs(
        generation(),
        &key,
        &ir,
        &routes(&ir, generation(), &backends),
    )
    .expect("compile signed pack");
    let candidate = &compiled.packs[0];
    let signature_bytes = candidate
        .signature
        .canonical_bytes()
        .expect("encode signature");
    let decoded = ExecutionPackSignature::decode(&signature_bytes).expect("decode signature");
    assert_eq!(decoded, candidate.signature);
    assert_eq!(
        decoded.pack_digest,
        *blake3::hash(candidate.pack.as_bytes()).as_bytes()
    );
    key.verify(candidate.pack.as_bytes(), &decoded)
        .expect("verify signed pack");
}

/// WHY: a pack byte changed after signing is corruption, even if a caller has not yet parsed the changed section.
#[test]
fn signature_rejects_tampered_pack_bytes() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let key = signing_key();
    let backends = [BackendProgramArtifact::Cpu(b"cpu-program-v1")];
    let compiled = compile_default_policy_execution_packs(
        generation(),
        &key,
        &ir,
        &routes(&ir, generation(), &backends),
    )
    .expect("compile signed pack");
    let candidate = &compiled.packs[0];
    let mut bytes = candidate.pack.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let error = key
        .verify(&bytes, &candidate.signature)
        .expect_err("tampered pack must fail");
    assert!(error.to_string().contains("signed digest does not match"));
}

/// WHY: replacing the signature sidecar cannot bless unchanged pack bytes without the installation signing key.
#[test]
fn signature_rejects_tampered_authenticator_and_wrong_key() {
    let ir = CanonicalDetectorExecutionIr::compile(&[detector("alpha")]).expect("compile IR");
    let key = signing_key();
    let backends = [BackendProgramArtifact::Cpu(b"cpu-program-v1")];
    let compiled = compile_default_policy_execution_packs(
        generation(),
        &key,
        &ir,
        &routes(&ir, generation(), &backends),
    )
    .expect("compile signed pack");
    let candidate = &compiled.packs[0];
    let mut tampered = candidate.signature.clone();
    tampered.signature[7] ^= 0x80;
    let error = key
        .verify(candidate.pack.as_bytes(), &tampered)
        .expect_err("tampered signature must fail");
    assert!(error.to_string().contains("signature verification failed"));

    let wrong_key = ExecutionPackSigningKey::from_bytes([0x6b; 32]).expect("wrong key");
    let error = wrong_key
        .verify(candidate.pack.as_bytes(), &candidate.signature)
        .expect_err("wrong installation key must fail");
    assert!(error.to_string().contains("key identity does not match"));
}
