use super::{CompiledExecutionPack, ExecutionPackError};

const SIGNATURE_MAGIC: &[u8; 8] = b"KHSIGN\0\x02";
pub const EXECUTION_PACK_SIGNATURE_VERSION: u16 = 2;
const SIGNATURE_DOMAIN: &[u8] = b"keyhog-execution-pack-signature-v2\0";

#[derive(Clone)]
pub struct ExecutionPackSigningKey([u8; 32]);

impl std::fmt::Debug for ExecutionPackSigningKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutionPackSigningKey")
            .field("key_id", &hex::encode(self.key_id()))
            .finish_non_exhaustive()
    }
}

impl ExecutionPackSigningKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ExecutionPackError> {
        if bytes == [0; 32] {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "execution-pack signing key is all zeroes".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn key_id(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }

    pub fn sign(&self, pack: &CompiledExecutionPack) -> ExecutionPackSignature {
        let pack_digest = *blake3::hash(pack.as_bytes()).as_bytes();
        let signature = signature_bytes(&self.0, pack_digest);
        ExecutionPackSignature {
            version: EXECUTION_PACK_SIGNATURE_VERSION,
            key_id: self.key_id(),
            pack_digest,
            signature,
        }
    }

    pub fn verify(
        &self,
        pack_bytes: &[u8],
        signature: &ExecutionPackSignature,
    ) -> Result<(), ExecutionPackError> {
        self.verify_digest(signature, *blake3::hash(pack_bytes).as_bytes())
    }

    pub(crate) fn verify_digest(
        &self,
        signature: &ExecutionPackSignature,
        pack_digest: [u8; 32],
    ) -> Result<(), ExecutionPackError> {
        signature.validate_shape()?;
        if !constant_time_eq(&signature.key_id, &self.key_id()) {
            return Err(ExecutionPackError::Incompatible(
                "execution-pack signature key identity does not match this installation; reinstall and recalibrate"
                    .into(),
            ));
        }
        if !constant_time_eq(&signature.pack_digest, &pack_digest) {
            return Err(ExecutionPackError::InvalidPack(
                "execution-pack signed digest does not match the pack bytes".into(),
            ));
        }
        let expected = signature_bytes(&self.0, pack_digest);
        if !constant_time_eq(&signature.signature, &expected) {
            return Err(ExecutionPackError::InvalidPack(
                "execution-pack signature verification failed".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for ExecutionPackSigningKey {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // Prevent the compiler from proving the key wipe dead.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPackSignature {
    pub version: u16,
    pub key_id: [u8; 32],
    pub pack_digest: [u8; 32],
    pub signature: [u8; 32],
}

impl ExecutionPackSignature {
    pub fn canonical_bytes(&self) -> Result<[u8; 112], ExecutionPackError> {
        self.validate_shape()?;
        let mut bytes = [0u8; 112];
        bytes[..8].copy_from_slice(SIGNATURE_MAGIC);
        bytes[8..10].copy_from_slice(&self.version.to_le_bytes());
        bytes[16..48].copy_from_slice(&self.key_id);
        bytes[48..80].copy_from_slice(&self.pack_digest);
        bytes[80..112].copy_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ExecutionPackError> {
        if bytes.len() != 112 || &bytes[..8] != SIGNATURE_MAGIC {
            return Err(ExecutionPackError::InvalidPack(
                "execution-pack signature envelope is invalid".into(),
            ));
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed version"));
        if bytes[10..16].iter().any(|byte| *byte != 0) {
            return Err(ExecutionPackError::InvalidPack(
                "execution-pack signature reserved bytes are nonzero".into(),
            ));
        }
        let value = Self {
            version,
            key_id: bytes[16..48].try_into().expect("fixed key id"),
            pack_digest: bytes[48..80].try_into().expect("fixed pack digest"),
            signature: bytes[80..112].try_into().expect("fixed signature"),
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), ExecutionPackError> {
        if self.version != EXECUTION_PACK_SIGNATURE_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "execution-pack signature version {} is unsupported; this binary requires {}",
                self.version, EXECUTION_PACK_SIGNATURE_VERSION
            )));
        }
        if self.key_id == [0; 32] || self.pack_digest == [0; 32] || self.signature == [0; 32] {
            return Err(ExecutionPackError::InvalidPack(
                "execution-pack signature has an empty identity, digest, or authenticator".into(),
            ));
        }
        Ok(())
    }
}

fn signature_bytes(key: &[u8; 32], pack_digest: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update(&pack_digest);
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}
