//! Install-time VYRE orchestration receipt compiler.

use super::{CanonicalDetectorExecutionIr, ExecutionPackBackend, ExecutionPackError};

const MAGIC: &[u8; 8] = b"KHVPACK\x02";
pub const VYRE_ORCHESTRATION_PROGRAM_VERSION: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VyreExecutionIdentity {
    pub target_identity: String,
    pub runtime_identity: String,
    pub device_identity: String,
    pub driver_version: String,
    pub device_limits_digest: [u8; 32],
}

impl VyreExecutionIdentity {
    /// Binds calibration evidence to the VYRE driver version linked into this binary.
    pub fn for_backend(
        backend: ExecutionPackBackend,
        target_identity: impl Into<String>,
        runtime_identity: impl Into<String>,
        device_identity: impl Into<String>,
        device_limits_digest: [u8; 32],
    ) -> Result<Self, ExecutionPackError> {
        let driver_version = match backend {
            ExecutionPackBackend::GpuCuda => env!("KEYHOG_VYRE_CUDA_VERSION"),
            ExecutionPackBackend::GpuWgpu => env!("KEYHOG_VYRE_WGPU_VERSION"),
            ExecutionPackBackend::GpuMetal => env!("KEYHOG_VYRE_METAL_VERSION"),
            _ => {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "cannot construct a VYRE identity for a non-GPU backend".into(),
                ));
            }
        };
        let identity = Self {
            target_identity: target_identity.into(),
            runtime_identity: runtime_identity.into(),
            device_identity: device_identity.into(),
            driver_version: driver_version.to_owned(),
            device_limits_digest,
        };
        validate_backend_and_identity(backend, &identity)?;
        Ok(identity)
    }
    /// Reconstructs the install-time identity for the selected acquired peer.
    ///
    /// `hardware_identity` is the canonical debug projection used by pack
    /// generation. Length-prefixing every field keeps the digest unambiguous.
    #[doc(hidden)]
    pub fn for_selected_peer(
        backend: ExecutionPackBackend,
        target_digest: [u8; 32],
        runtime_identity: impl Into<String>,
        device_identity: impl Into<String>,
        hardware_identity: &str,
    ) -> Result<Self, ExecutionPackError> {
        let runtime_identity = runtime_identity.into();
        let device_identity = device_identity.into();
        let driver_id = match backend {
            ExecutionPackBackend::GpuCuda => "cuda",
            ExecutionPackBackend::GpuWgpu => "wgpu",
            ExecutionPackBackend::GpuMetal => "metal",
            _ => {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "cannot construct a VYRE peer identity for a non-GPU backend".into(),
                ));
            }
        };
        let driver_version = match backend {
            ExecutionPackBackend::GpuCuda => env!("KEYHOG_VYRE_CUDA_VERSION"),
            ExecutionPackBackend::GpuWgpu => env!("KEYHOG_VYRE_WGPU_VERSION"),
            ExecutionPackBackend::GpuMetal => env!("KEYHOG_VYRE_METAL_VERSION"),
            _ => unreachable!("GPU backend checked above"),
        };
        let device_limits_digest = digest_parts(&[
            driver_id.as_bytes(),
            driver_version.as_bytes(),
            runtime_identity.as_bytes(),
            device_identity.as_bytes(),
            hardware_identity.as_bytes(),
        ]);
        Self::for_backend(
            backend,
            keyhog_core::hex_encode(&target_digest),
            runtime_identity,
            device_identity,
            device_limits_digest,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VyreOrchestrationProgram {
    pub version: u16,
    pub backend: ExecutionPackBackend,
    pub detector_ir_digest: [u8; 32],
    pub execution_identity: VyreExecutionIdentity,
    pub matcher_cache_key: String,
    pub matcher_pattern_count: u32,
    pub matcher_wire_magic: [u8; 4],
    pub matcher_wire_version: u32,
    pub matcher_digest: [u8; 32],
    pub matcher_bytes: Vec<u8>,
    pub phase2_catalog_digest: [u8; 32],
    pub phase2_catalog_bytes: Vec<u8>,
}

impl VyreOrchestrationProgram {
    /// Compiles VYRE's canonical literal matcher and binds it to one calibrated device route.
    pub fn compile(
        detector_ir: &CanonicalDetectorExecutionIr,
        backend: ExecutionPackBackend,
        execution_identity: VyreExecutionIdentity,
    ) -> Result<Self, ExecutionPackError> {
        validate_backend_and_identity(backend, &execution_identity)?;
        let artifacts = crate::gpu_literal_artifacts::compile_gpu_literal_artifacts_default(
            detector_ir.detectors(),
        )
        .map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "VYRE matcher compilation failed for {backend:?}: {error}"
            ))
        })?;
        if artifacts.positioned_literal.is_some() {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "VYRE compiler emitted a retired separate positioned matcher; the fused matcher is required"
                    .into(),
            ));
        }
        let matcher = artifacts.literal.ok_or_else(|| {
            ExecutionPackError::InvalidCompilerInput(
                "VYRE compiler emitted no fused literal matcher".into(),
            )
        })?;
        let matcher_pattern_count = u32::try_from(matcher.pattern_count).map_err(|_| {
            ExecutionPackError::InvalidCompilerInput(
                "VYRE matcher pattern count exceeds the execution-pack u32 limit".into(),
            )
        })?;
        let matcher_digest = *blake3::hash(&matcher.bytes).as_bytes();
        #[cfg(not(feature = "gpu"))]
        return Err(ExecutionPackError::InvalidCompilerInput(
            "VYRE phase-2 catalog compilation requires the scanner GPU feature".into(),
        ));
        #[cfg(feature = "gpu")]
        let backend_id = match backend {
            ExecutionPackBackend::GpuCuda => Some("cuda"),
            ExecutionPackBackend::GpuWgpu => Some("wgpu"),
            ExecutionPackBackend::GpuMetal => Some("metal"),
            _ => {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "phase-2 GPU catalog requires a GPU backend".into(),
                ));
            }
        };
        #[cfg(feature = "gpu")]
        let phase2_catalog_bytes =
            crate::engine::compile_phase2_gpu_catalog_artifact(detector_ir.detectors(), backend_id)
                .map_err(ExecutionPackError::InvalidCompilerInput)?;
        #[cfg(feature = "gpu")]
        let phase2_catalog_digest = *blake3::hash(&phase2_catalog_bytes).as_bytes();
        Ok(Self {
            version: VYRE_ORCHESTRATION_PROGRAM_VERSION,
            backend,
            detector_ir_digest: detector_ir.digest(),
            execution_identity,
            matcher_cache_key: matcher.cache_key,
            matcher_pattern_count,
            matcher_wire_magic: matcher.wire_magic,
            matcher_wire_version: matcher.wire_version,
            matcher_digest,
            matcher_bytes: matcher.bytes,
            phase2_catalog_digest,
            phase2_catalog_bytes,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ExecutionPackError> {
        validate_backend_and_identity(self.backend, &self.execution_identity)?;
        if self.matcher_bytes.is_empty() || self.matcher_cache_key.is_empty() {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "VYRE orchestration program has no matcher artifact".into(),
            ));
        }
        if *blake3::hash(&self.matcher_bytes).as_bytes() != self.matcher_digest {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "VYRE matcher digest does not match its bytes".into(),
            ));
        }
        if self.phase2_catalog_bytes.is_empty()
            || *blake3::hash(&self.phase2_catalog_bytes).as_bytes() != self.phase2_catalog_digest
        {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "phase-2 GPU catalog digest does not match its bytes".into(),
            ));
        }
        validate_wire_header(
            &self.matcher_bytes,
            self.matcher_wire_magic,
            self.matcher_wire_version,
        )?;

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.push(self.backend as u8);
        out.extend_from_slice(&[0; 5]);
        out.extend_from_slice(&self.detector_ir_digest);
        out.extend_from_slice(&self.matcher_digest);
        out.extend_from_slice(&self.phase2_catalog_digest);
        out.extend_from_slice(&self.execution_identity.device_limits_digest);
        out.extend_from_slice(&self.matcher_pattern_count.to_le_bytes());
        out.extend_from_slice(&self.matcher_wire_magic);
        out.extend_from_slice(&self.matcher_wire_version.to_le_bytes());
        write_bytes(&mut out, self.execution_identity.target_identity.as_bytes())?;
        write_bytes(
            &mut out,
            self.execution_identity.runtime_identity.as_bytes(),
        )?;
        write_bytes(&mut out, self.execution_identity.device_identity.as_bytes())?;
        write_bytes(&mut out, self.execution_identity.driver_version.as_bytes())?;
        write_bytes(&mut out, self.matcher_cache_key.as_bytes())?;
        write_bytes(&mut out, &self.matcher_bytes)?;
        write_bytes(&mut out, &self.phase2_catalog_bytes)?;
        Ok(out)
    }

    pub fn decode(
        bytes: &[u8],
        expected_backend: ExecutionPackBackend,
        expected_ir_digest: [u8; 32],
        expected_identity: &VyreExecutionIdentity,
    ) -> Result<Self, ExecutionPackError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != MAGIC {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE orchestration program magic is invalid".into(),
            ));
        }
        let version = cursor.u16()?;
        if version != VYRE_ORCHESTRATION_PROGRAM_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "VYRE orchestration program version {version} is unsupported; this binary requires {VYRE_ORCHESTRATION_PROGRAM_VERSION}"
            )));
        }
        let backend_byte = cursor.take(1)?[0];
        let backend = ExecutionPackBackend::from_u8(backend_byte).ok_or_else(|| {
            ExecutionPackError::InvalidPack(format!(
                "VYRE orchestration backend byte {backend_byte} is invalid"
            ))
        })?;
        if cursor.take(5)?.iter().any(|byte| *byte != 0) {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE orchestration program reserved bytes are nonzero".into(),
            ));
        }
        if backend != expected_backend {
            return Err(ExecutionPackError::Incompatible(format!(
                "VYRE orchestration backend is {backend:?}, not selected {expected_backend:?}; reinstall and recalibrate"
            )));
        }
        let detector_ir_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed digest");
        if detector_ir_digest != expected_ir_digest {
            return Err(ExecutionPackError::Incompatible(
                "VYRE orchestration detector IR identity is stale; reinstall and recalibrate"
                    .into(),
            ));
        }
        let matcher_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed digest");
        let phase2_catalog_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed digest");
        let device_limits_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed digest");
        let matcher_pattern_count = cursor.u32()?;
        let matcher_wire_magic: [u8; 4] = cursor.take(4)?.try_into().expect("fixed magic");
        let matcher_wire_version = cursor.u32()?;
        let execution_identity = VyreExecutionIdentity {
            target_identity: cursor.string()?,
            runtime_identity: cursor.string()?,
            device_identity: cursor.string()?,
            driver_version: cursor.string()?,
            device_limits_digest,
        };
        validate_backend_and_identity(backend, expected_identity)?;
        validate_backend_and_identity(backend, &execution_identity)?;
        if &execution_identity != expected_identity {
            return Err(ExecutionPackError::Incompatible(
                "VYRE execution identity does not match the calibrated target, runtime, driver, device, or limits; reinstall and recalibrate"
                    .into(),
            ));
        }
        let matcher_cache_key = cursor.string()?;
        let matcher_bytes = cursor.bytes()?.to_vec();
        let phase2_catalog_bytes = cursor.bytes()?.to_vec();
        if !cursor.is_empty() {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE orchestration program has trailing bytes".into(),
            ));
        }
        if *blake3::hash(&matcher_bytes).as_bytes() != matcher_digest {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE matcher artifact is corrupt; its content digest does not match".into(),
            ));
        }
        if phase2_catalog_bytes.is_empty()
            || *blake3::hash(&phase2_catalog_bytes).as_bytes() != phase2_catalog_digest
        {
            return Err(ExecutionPackError::InvalidPack(
                "phase-2 GPU catalog artifact is corrupt; its content digest does not match".into(),
            ));
        }
        validate_wire_header(&matcher_bytes, matcher_wire_magic, matcher_wire_version)?;
        let program = Self {
            version,
            backend,
            detector_ir_digest,
            execution_identity,
            matcher_cache_key,
            matcher_pattern_count,
            matcher_wire_magic,
            matcher_wire_version,
            matcher_digest,
            matcher_bytes,
            phase2_catalog_digest,
            phase2_catalog_bytes,
        };
        if program.canonical_bytes()?.as_slice() != bytes {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE orchestration program is not canonically encoded".into(),
            ));
        }
        Ok(program)
    }
    /// Return the canonical VYRE receipt carried by an execution-pack backend envelope.
    pub fn backend_section_receipt(
        bytes: &[u8],
        expected_backend: ExecutionPackBackend,
    ) -> Result<&[u8], ExecutionPackError> {
        const HEADER_LEN: usize = 17;
        if bytes.len() < HEADER_LEN || &bytes[..8] != b"KHVYRE\0\x01" {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE backend-program envelope is invalid or truncated".into(),
            ));
        }
        if bytes[8] != expected_backend as u8 {
            return Err(ExecutionPackError::Incompatible(
                "VYRE backend-program envelope does not name the selected backend".into(),
            ));
        }
        let receipt_len =
            u64::from_le_bytes(bytes[9..17].try_into().expect("fixed receipt length"));
        let receipt_len = usize::try_from(receipt_len).map_err(|_| {
            ExecutionPackError::InvalidPack(
                "VYRE backend-program receipt length does not fit this target".into(),
            )
        })?;
        if bytes.len().checked_sub(HEADER_LEN) != Some(receipt_len) {
            return Err(ExecutionPackError::InvalidPack(
                "VYRE backend-program receipt length does not match its bytes".into(),
            ));
        }
        Ok(&bytes[HEADER_LEN..])
    }

    /// Decode the VYRE receipt carried by an execution-pack backend envelope.
    pub fn decode_backend_section(
        bytes: &[u8],
        expected_backend: ExecutionPackBackend,
        expected_ir_digest: [u8; 32],
        expected_identity: &VyreExecutionIdentity,
    ) -> Result<Self, ExecutionPackError> {
        Self::decode(
            Self::backend_section_receipt(bytes, expected_backend)?,
            expected_backend,
            expected_ir_digest,
            expected_identity,
        )
    }
}

fn validate_backend_and_identity(
    backend: ExecutionPackBackend,
    identity: &VyreExecutionIdentity,
) -> Result<(), ExecutionPackError> {
    if !backend.is_gpu() {
        return Err(ExecutionPackError::InvalidCompilerInput(
            "VYRE orchestration program names a non-GPU backend".into(),
        ));
    }
    let required_driver = match backend {
        ExecutionPackBackend::GpuCuda => env!("KEYHOG_VYRE_CUDA_VERSION"),
        ExecutionPackBackend::GpuWgpu => env!("KEYHOG_VYRE_WGPU_VERSION"),
        ExecutionPackBackend::GpuMetal => env!("KEYHOG_VYRE_METAL_VERSION"),
        _ => unreachable!("GPU backend checked above"),
    };
    if identity.driver_version != required_driver {
        return Err(ExecutionPackError::Incompatible(format!(
            "VYRE {backend:?} driver version {} does not match this binary's {required_driver}; reinstall and recalibrate",
            identity.driver_version
        )));
    }
    for (name, value) in [
        ("target", identity.target_identity.as_str()),
        ("runtime", identity.runtime_identity.as_str()),
        ("device", identity.device_identity.as_str()),
    ] {
        if value.is_empty() {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "VYRE orchestration {name} identity is empty"
            )));
        }
    }
    Ok(())
}

fn validate_wire_header(
    bytes: &[u8],
    expected_magic: [u8; 4],
    expected_version: u32,
) -> Result<(), ExecutionPackError> {
    let header = bytes.get(..8).ok_or_else(|| {
        ExecutionPackError::InvalidPack("VYRE matcher artifact is truncated".into())
    })?;
    if header[..4] != expected_magic
        || u32::from_le_bytes(header[4..8].try_into().expect("fixed version")) != expected_version
    {
        return Err(ExecutionPackError::InvalidPack(
            "VYRE matcher wire header does not match its orchestration receipt".into(),
        ));
    }
    Ok(())
}

fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ExecutionPackError> {
    let len = u64::try_from(bytes.len())
        .map_err(|_| ExecutionPackError::InvalidCompilerInput("VYRE field exceeds u64".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ExecutionPackError> {
        let end = self.offset.checked_add(len).ok_or_else(|| {
            ExecutionPackError::InvalidPack("VYRE orchestration length overflow".into())
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            ExecutionPackError::InvalidPack("VYRE orchestration program is truncated".into())
        })?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ExecutionPackError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("fixed u16"),
        ))
    }

    fn u32(&mut self) -> Result<u32, ExecutionPackError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("fixed u32"),
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], ExecutionPackError> {
        let len = usize::try_from(u64::from_le_bytes(
            self.take(8)?.try_into().expect("fixed u64"),
        ))
        .map_err(|_| ExecutionPackError::InvalidPack("VYRE byte length exceeds usize".into()))?;
        self.take(len)
    }

    fn string(&mut self) -> Result<String, ExecutionPackError> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|error| {
            ExecutionPackError::InvalidPack(format!("VYRE identity is not UTF-8: {error}"))
        })
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
