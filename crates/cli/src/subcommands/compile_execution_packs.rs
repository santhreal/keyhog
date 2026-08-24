use crate::args::CompileExecutionPacksArgs;
use crate::execution_pack_install::{
    ExecutionPackIdentityBinding as InstallPackManifestEntry, InstallPackManifest, MANIFEST_VERSION,
};
use anyhow::{bail, Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, RawMatch};
use keyhog_scanner::execution_pack::{
    compile_policy_execution_packs, BackendExecutionArtifact, BackendProgramArtifact,
    CanonicalDetectorExecutionIr, CompiledNativeBackendPrograms, CompiledRouteMatcherSections,
    ExecutionPackBackend, ExecutionPackPolicy, ExecutionPackSigningKey, PackFindingParityEvidence,
    PackGenerationIdentity,
};
#[cfg(feature = "gpu")]
use keyhog_scanner::execution_pack::{CompiledVyreBackendProgram, VyreExecutionIdentity};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

enum InstallBackendProgram<'a> {
    Native(BackendProgramArtifact<'a>),
    #[cfg(feature = "gpu")]
    Vyre(CompiledVyreBackendProgram),
}

impl InstallBackendProgram<'_> {
    fn backend(&self) -> ExecutionPackBackend {
        match self {
            Self::Native(artifact) => artifact.backend(),
            #[cfg(feature = "gpu")]
            Self::Vyre(program) => program.backend(),
        }
    }

    fn artifact(&self) -> BackendProgramArtifact<'_> {
        match self {
            Self::Native(artifact) => *artifact,
            #[cfg(feature = "gpu")]
            Self::Vyre(program) => program.artifact(),
        }
    }
}

struct InstallBackendInput<'a> {
    program: InstallBackendProgram<'a>,
    sections: CompiledRouteMatcherSections,
    candidate_findings: Vec<u8>,
}

pub(crate) fn run(args: CompileExecutionPacksArgs) -> Result<()> {
    keyhog_profile::set_compile_phase(keyhog_profile::CompilePhase::Install);
    let signing_key = read_signing_key(&args.signing_key)?;
    let detectors = keyhog_core::embedded_detector_specs();
    let ir = CanonicalDetectorExecutionIr::embedded()
        .map_err(anyhow::Error::msg)
        .context("compiling canonical detector execution IR")?;
    let native = CompiledNativeBackendPrograms::compile(&ir)
        .map_err(anyhow::Error::msg)
        .context("compiling native backend programs")?;
    let fixture = parity_fixture(&detectors)?;
    let fixture_digest = *blake3::hash(fixture.data.as_bytes()).as_bytes();
    let cpu_findings = scan_canonical(&detectors, &fixture, ScanBackend::CpuFallback)?;

    let binary_digest = crate::execution_pack_install::current_binary_digest()?;
    let target_digest = crate::execution_pack_install::current_target_digest();
    let feature_digest = crate::execution_pack_install::current_feature_digest();

    let parent = args.output_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "execution-pack output directory {} has no parent",
            args.output_dir.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating execution-pack parent {}", parent.display()))?;
    reap_stale_generation_siblings(&args.output_dir)?;
    let stage = unique_sibling(&args.output_dir, "stage");
    let backup = unique_sibling(&args.output_dir, "backup");
    if stage.exists() || backup.exists() {
        bail!(
            "execution-pack staging paths already exist; remove stale install artifacts and retry"
        );
    }
    fs::create_dir(&stage).with_context(|| {
        format!(
            "creating execution-pack staging directory {}",
            stage.display()
        )
    })?;

    let result = compile_generation(
        &stage,
        &signing_key,
        &ir,
        &native,
        &detectors,
        &fixture,
        &cpu_findings,
        fixture_digest,
        PackGenerationIdentity {
            config_digest: [0; 32],
            target_digest,
            binary_digest,
            feature_digest,
        },
    );
    let manifest = match result {
        Ok(manifest) => manifest,
        Err(error) => {
            let _ = fs::remove_dir_all(&stage); // LAW10: best-effort staging cleanup cannot hide the compilation error returned immediately below.
            return Err(error);
        }
    };
    write_sync(
        &stage.join("manifest.json"),
        &serde_json::to_vec(&manifest).context("serializing execution-pack manifest")?,
    )?;
    sync_directory(&stage)?;

    let had_previous = args.output_dir.exists();
    if had_previous {
        fs::rename(&args.output_dir, &backup).with_context(|| {
            format!(
                "moving previous execution-pack generation {} to {}",
                args.output_dir.display(),
                backup.display()
            )
        })?;
    }
    if let Err(error) = fs::rename(&stage, &args.output_dir) {
        if had_previous {
            let _ = fs::rename(&backup, &args.output_dir); // LAW10: best-effort rollback cannot hide the install error returned below with the affected paths.
        }
        let _ = fs::remove_dir_all(&stage); // LAW10: best-effort staging cleanup cannot hide the install error returned immediately below.
        return Err(error).with_context(|| {
            format!(
                "publishing execution-pack generation {}",
                args.output_dir.display()
            )
        });
    }
    sync_directory(parent)?;
    if had_previous {
        fs::remove_dir_all(&backup).with_context(|| {
            format!(
                "removing replaced execution-pack generation {}",
                backup.display()
            )
        })?;
        sync_directory(parent)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_generation(
    stage: &Path,
    signing_key: &ExecutionPackSigningKey,
    ir: &CanonicalDetectorExecutionIr,
    native: &CompiledNativeBackendPrograms,
    detectors: &[DetectorSpec],
    fixture: &Chunk,
    cpu_findings: &[u8],
    fixture_digest: [u8; 32],
    base_generation: PackGenerationIdentity,
) -> Result<InstallPackManifest> {
    let mut backend_inputs = Vec::new();
    for artifact in native.artifacts() {
        let backend = artifact.backend();
        let scan_backend = backend.scan_backend();
        if scan_backend.is_gpu() {
            continue;
        }
        let candidate_findings = if backend == ExecutionPackBackend::Cpu {
            cpu_findings.to_vec()
        } else {
            scan_canonical(detectors, fixture, scan_backend)?
        };
        let sections = compile_route_sections(ir, backend)?;
        backend_inputs.push(InstallBackendInput {
            program: InstallBackendProgram::Native(artifact),
            sections,
            candidate_findings,
        });
    }
    #[cfg(feature = "gpu")]
    compile_gpu_inputs(&mut backend_inputs, ir, detectors, fixture, base_generation)?;
    if !backend_inputs
        .iter()
        .any(|input| input.program.backend() == ExecutionPackBackend::Cpu)
    {
        bail!("fresh-install execution-pack generation has no scalar correctness backend");
    }

    let mut manifest_entries = Vec::new();
    for policy in ExecutionPackPolicy::ALL {
        let mut generation = base_generation;
        generation.config_digest = digest_parts(&[policy.lowercase_name().as_bytes()]);
        let mut routes = Vec::with_capacity(backend_inputs.len());
        for input in &backend_inputs {
            let program = input.program.artifact();
            let sections = &input.sections;
            let candidate_findings = &input.candidate_findings;
            let parity = PackFindingParityEvidence::prove_route(
                program.backend(),
                ir.digest(),
                generation,
                fixture_digest,
                finding_count(cpu_findings)?,
                cpu_findings,
                candidate_findings,
                artifact_bytes(program),
                &sections.literal_index,
                &sections.regex_programs,
                &sections.suppression_policy,
            )
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("proving {:?} finding parity", program.backend()))?;
            routes.push(BackendExecutionArtifact::new(
                program,
                &sections.literal_index,
                &sections.regex_programs,
                &sections.suppression_policy,
                parity,
            ));
        }
        let packs = compile_policy_execution_packs(generation, signing_key, policy, ir, &routes)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("compiling {policy:?} execution packs"))?;
        for candidate in packs.packs {
            let stem = format!(
                "{}-{}",
                policy.lowercase_name(),
                candidate.backend.lowercase_name()
            );
            let pack_file = format!("{stem}.khpack");
            let signature_file = format!("{stem}.sig");
            write_sync(&stage.join(&pack_file), candidate.pack.as_bytes())?;
            write_sync(
                &stage.join(&signature_file),
                &candidate
                    .signature
                    .canonical_bytes()
                    .map_err(anyhow::Error::msg)?,
            )?;
            manifest_entries.push(InstallPackManifestEntry {
                policy: policy.lowercase_name().to_owned(),
                backend: candidate.backend.lowercase_name().to_owned(),
                file: pack_file,
                signature_file,
                identity_digest: keyhog_core::hex_encode(&candidate.pack.identity().digest()),
                content_digest: keyhog_core::hex_encode(&candidate.pack.content_digest()),
                signed_pack_digest: keyhog_core::hex_encode(&candidate.signature.pack_digest),
                bytes: candidate.pack.as_bytes().len(),
            });
        }
    }
    Ok(InstallPackManifest {
        version: MANIFEST_VERSION,
        detector_digest: keyhog_core::hex_encode(&ir.digest()),
        target_digest: keyhog_core::hex_encode(&base_generation.target_digest),
        binary_digest: keyhog_core::hex_encode(&base_generation.binary_digest),
        feature_digest: keyhog_core::hex_encode(&base_generation.feature_digest),
        fixture_digest: keyhog_core::hex_encode(&fixture_digest),
        packs: manifest_entries,
    })
}

fn compile_route_sections(
    ir: &CanonicalDetectorExecutionIr,
    backend: ExecutionPackBackend,
) -> Result<CompiledRouteMatcherSections> {
    let sections = CompiledRouteMatcherSections::compile(ir, backend)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("compiling {backend:?} route matcher sections"))?;
    sections
        .validate_canonical()
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("validating {backend:?} route matcher sections"))?;
    Ok(sections)
}

#[cfg(feature = "gpu")]
fn compile_gpu_inputs<'a>(
    inputs: &mut Vec<InstallBackendInput<'a>>,
    ir: &CanonicalDetectorExecutionIr,
    detectors: &[DetectorSpec],
    fixture: &Chunk,
    generation: PackGenerationIdentity,
) -> Result<()> {
    for pack_backend in ExecutionPackBackend::ALL
        .into_iter()
        .filter(|backend| backend.is_gpu())
    {
        let scan_backend = pack_backend.scan_backend();
        let scanner = CompiledScanner::compile_for_backend(detectors.to_vec(), scan_backend)
            .with_context(|| format!("censusing {scan_backend:?} for install pack compilation"))?;
        let status = scanner
            .gpu_backend_candidates()
            .into_iter()
            .find(|candidate| candidate.backend == scan_backend)
            .with_context(|| format!("{scan_backend:?} census returned no candidate status"))?;
        if !status.available || status.is_software {
            continue;
        }
        if !status.has_complete_identity() {
            bail!(
                "eligible {scan_backend:?} route has incomplete VYRE identity: {}",
                status
                    .acquisition_error
                    .as_deref()
                    .unwrap_or("missing driver, runtime, or device identity") // LAW10: absent optional acquisition detail uses a diagnostic placeholder; pack compilation remains blocked.
            );
        }
        let runtime_identity = status
            .runtime_identity
            .as_deref()
            .context("missing VYRE runtime identity")?;
        let device_identity = status
            .device_identity
            .as_deref()
            .context("missing VYRE device identity")?;
        let limits_digest = digest_parts(&[
            status.driver_id.unwrap_or_default().as_bytes(), // LAW10: absent optional driver ID is represented in a digest whose required runtime and device identities are already validated.
            status.driver_version.unwrap_or_default().as_bytes(), // LAW10: absent optional driver version is represented in a digest whose required runtime and device identities are already validated.
            runtime_identity.as_bytes(),
            device_identity.as_bytes(),
            format!("{:?}", keyhog_scanner::probe_hardware()).as_bytes(),
        ]);
        let identity = VyreExecutionIdentity::for_backend(
            pack_backend,
            keyhog_core::hex_encode(&generation.target_digest),
            runtime_identity,
            device_identity,
            limits_digest,
        )
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("binding {scan_backend:?} VYRE execution identity"))?;
        let program = CompiledVyreBackendProgram::compile(ir, pack_backend, identity)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("compiling {scan_backend:?} VYRE orchestration program"))?;
        let candidate_findings = canonical_scan_with_scanner(&scanner, fixture, scan_backend)?;
        let sections = compile_route_sections(ir, pack_backend)?;
        inputs.push(InstallBackendInput {
            program: InstallBackendProgram::Vyre(program),
            sections,
            candidate_findings,
        });
    }
    Ok(())
}

fn parity_fixture(detectors: &[DetectorSpec]) -> Result<Chunk> {
    let mut data = String::new();
    for detector in detectors {
        for test in &detector.tests {
            if let Some(positive) = &test.test_positive {
                data.push_str(positive);
                data.push('\n');
            }
            if let Some(negative) = &test.test_negative {
                data.push_str(negative);
                data.push('\n');
            }
        }
    }
    if data.is_empty() {
        bail!("embedded detector corpus has no self-test fixtures for pack parity");
    }
    Ok(Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "execution-pack-install-parity".into(),
            path: Some(std::sync::Arc::from("embedded-detector-self-tests")),
            ..ChunkMetadata::default()
        },
    })
}

fn scan_canonical(
    detectors: &[DetectorSpec],
    chunk: &Chunk,
    backend: ScanBackend,
) -> Result<Vec<u8>> {
    let scanner = CompiledScanner::compile_for_backend(detectors.to_vec(), backend)
        .with_context(|| format!("compiling {backend:?} parity scanner"))?;
    canonical_scan_with_scanner(&scanner, chunk, backend)
}

fn canonical_scan_with_scanner(
    scanner: &CompiledScanner,
    chunk: &Chunk,
    backend: ScanBackend,
) -> Result<Vec<u8>> {
    let findings = scanner
        .scan_with_backend(chunk, backend)
        .with_context(|| format!("executing {backend:?} pack parity fixture"))?;
    canonical_findings(&findings)
}

fn canonical_findings(findings: &[RawMatch]) -> Result<Vec<u8>> {
    let mut rows = Vec::with_capacity(findings.len());
    for finding in findings {
        let mut companions: Vec<_> = finding.companions.iter().collect();
        companions.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut companion_hasher = blake3::Hasher::new();
        for (name, value) in companions {
            companion_hasher.update(&(name.len() as u64).to_le_bytes());
            companion_hasher.update(name.as_bytes());
            companion_hasher.update(&(value.len() as u64).to_le_bytes());
            companion_hasher.update(value.as_bytes());
        }
        let row = serde_json::json!({
            "detector_id": finding.detector_id,
            "detector_name": finding.detector_name,
            "service": finding.service,
            "severity": finding.severity,
            "credential_hash": keyhog_core::hex_encode(finding.credential_hash.as_bytes()),
            "companion_digest": keyhog_core::hex_encode(companion_hasher.finalize().as_bytes()),
            "location": finding.location,
            "entropy_bits": finding.entropy.map(f64::to_bits),
            "confidence_bits": finding.confidence.map(f64::to_bits),
            "evidence_tier": finding.evidence.tier().as_str(),
            "evidence_reason_code": finding.evidence.reason_code().as_str(),
            "evidence_provenance": finding.evidence.provenance(),
        });
        rows.push(serde_json::to_vec(&row).context("serializing redacted pack parity finding")?);
    }
    rows.sort_unstable();
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend_from_slice(&(row.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&row);
    }
    Ok(bytes)
}

fn finding_count(bytes: &[u8]) -> Result<u64> {
    let mut offset = 0usize;
    let mut count = 0u64;
    while offset < bytes.len() {
        let end = offset
            .checked_add(8)
            .context("finding count length overflow")?;
        let length = u64::from_le_bytes(
            bytes
                .get(offset..end)
                .context("truncated canonical finding length")?
                .try_into()
                .expect("fixed length"),
        );
        offset = end
            .checked_add(usize::try_from(length).context("finding row exceeds usize")?)
            .context("finding row offset overflow")?;
        if offset > bytes.len() {
            bail!("truncated canonical finding row");
        }
        count += 1;
    }
    Ok(count)
}

fn read_signing_key(path: &Path) -> Result<ExecutionPackSigningKey> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspecting execution-pack signing key {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() != 32 {
        bail!(
            "execution-pack signing key {} must be an exact 32-byte regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            bail!(
                "execution-pack signing key {} must not grant group or other permissions; run chmod 600 {}",
                path.display(),
                path.display()
            );
        }
    }
    let bytes = fs::read(path)
        .with_context(|| format!("reading execution-pack signing key {}", path.display()))?;
    ExecutionPackSigningKey::from_bytes(bytes.try_into().expect("validated key length"))
        .map_err(anyhow::Error::msg)
}

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
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

fn write_sync(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    use std::os::windows::fs::OpenOptionsExt;
    // FlushFileBuffers requires GENERIC_WRITE on the handle, and Windows only
    // grants a directory handle that access when it is opened with
    // FILE_FLAG_BACKUP_SEMANTICS. Read mode alone fails sync_all with
    // "Access is denied" (os error 5).
    #[cfg(target_os = "windows")]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(0x0200_0000)
        .open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?;
    #[cfg(not(target_os = "windows"))]
    let file = File::open(path)
        .with_context(|| format!("opening directory {} for sync", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing directory {}", path.display()))
}

fn reap_stale_generation_siblings(output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .context("execution-pack output has no parent directory")?;
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("execution-packs"); // LAW10: non-Unicode or absent output basename affects only temporary-file naming, not the target path or compile result.
    let stage_prefix = format!(".{name}.stage.");
    let backup_prefix = format!(".{name}.backup.");
    let mut stale_backups = Vec::new();
    for entry in fs::read_dir(parent)
        .with_context(|| format!("reading execution-pack parent {}", parent.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", parent.display()))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let (kind, raw_pid) = if let Some(pid) = file_name.strip_prefix(&stage_prefix) {
            ("stage", pid)
        } else if let Some(pid) = file_name.strip_prefix(&backup_prefix) {
            ("backup", pid)
        } else {
            continue;
        };
        let Ok(pid) = raw_pid.parse::<u32>() else {
            continue;
        };
        if crate::installer::process_is_running(pid) {
            continue;
        }
        let file_type = entry.file_type().with_context(|| {
            format!(
                "inspecting stale execution-pack artifact {}",
                entry.path().display()
            )
        })?;
        if !file_type.is_dir() {
            bail!(
                "stale execution-pack {kind} artifact {} is not a real directory; remove it manually",
                entry.path().display()
            );
        }
        if kind == "stage" {
            fs::remove_dir_all(entry.path()).with_context(|| {
                format!(
                    "removing stale execution-pack stage {}",
                    entry.path().display()
                )
            })?;
        } else {
            stale_backups.push(entry.path());
        }
    }
    if output.exists() {
        for backup in stale_backups {
            fs::remove_dir_all(&backup).with_context(|| {
                format!(
                    "removing replaced execution-pack backup {}",
                    backup.display()
                )
            })?;
        }
    } else if stale_backups.len() == 1 {
        fs::rename(&stale_backups[0], output).with_context(|| {
            format!(
                "recovering interrupted execution-pack publication from {}",
                stale_backups[0].display()
            )
        })?;
        sync_directory(parent)?;
    } else if stale_backups.len() > 1 {
        bail!(
            "multiple stale execution-pack backups exist while {} is missing; refusing to guess which generation to recover",
            output.display()
        );
    }
    Ok(())
}

fn unique_sibling(output: &Path, suffix: &str) -> PathBuf {
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("execution-packs"); // LAW10: non-Unicode or absent output basename affects only rollback-path naming, not the target path or compile result.
    output.with_file_name(format!(".{name}.{suffix}.{}", std::process::id()))
}

#[cfg(test)]
#[path = "../../tests/unit/execution_pack_generation_cleanup.rs"]
mod cleanup_tests;
