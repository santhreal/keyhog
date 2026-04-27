//! On-disk compiled-pipeline cache.
//!
//! Content-addressed by `blake3(program_bytes)` XOR-mixed with a
//! `DeviceFingerprint { vendor, device, driver }` so two adapters with
//! different driver revisions don't share cache entries.
//!
//! Cold compile on a fresh machine; warm compile on every subsequent run.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Device fingerprint — participates in the cache key so adapters don't
/// collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeviceFingerprint {
    /// Vendor id (from wgpu adapter info).
    pub vendor: u32,
    /// Device id.
    pub device: u32,
    /// Driver info hash (u32 digest of the driver version string).
    pub driver: u32,
}

impl DeviceFingerprint {
    /// Fold into the cache key.
    #[must_use]
    pub fn fold_into(&self, mut digest: [u8; 32]) -> [u8; 32] {
        digest[0] ^= self.vendor.to_le_bytes()[0];
        digest[1] ^= self.vendor.to_le_bytes()[1];
        digest[2] ^= self.vendor.to_le_bytes()[2];
        digest[3] ^= self.vendor.to_le_bytes()[3];
        digest[4] ^= self.device.to_le_bytes()[0];
        digest[5] ^= self.device.to_le_bytes()[1];
        digest[6] ^= self.device.to_le_bytes()[2];
        digest[7] ^= self.device.to_le_bytes()[3];
        digest[8] ^= self.driver.to_le_bytes()[0];
        digest[9] ^= self.driver.to_le_bytes()[1];
        digest[10] ^= self.driver.to_le_bytes()[2];
        digest[11] ^= self.driver.to_le_bytes()[3];
        digest
    }
}

/// Disk cache for pipeline blobs keyed by `(program_blake3, device_fingerprint)`.
pub struct DiskPipelineCache {
    root: PathBuf,
}

impl DiskPipelineCache {
    /// Construct a disk cache rooted at the given directory.
    ///
    /// Creates the directory if it does not exist.
    ///
    /// # Errors
    /// Returns the io error when the directory cannot be created.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root: PathBuf = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Default cache directory: `$XDG_CACHE_HOME/vyre/pipelines/` on
    /// Linux, `~/Library/Caches/vyre/pipelines` on macOS, and
    /// `%LOCALAPPDATA%\vyre\pipelines` on Windows. Falls back to
    /// `./vyre-cache/pipelines` when none of those are set.
    #[must_use]
    pub fn default_root() -> PathBuf {
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            return PathBuf::from(xdg).join("vyre").join("pipelines");
        }
        if let Ok(home) = std::env::var("HOME") {
            #[cfg(target_os = "macos")]
            {
                return PathBuf::from(home)
                    .join("Library")
                    .join("Caches")
                    .join("vyre")
                    .join("pipelines");
            }
            #[cfg(not(target_os = "macos"))]
            {
                return PathBuf::from(home)
                    .join(".cache")
                    .join("vyre")
                    .join("pipelines");
            }
        }
        if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(appdata).join("vyre").join("pipelines");
        }
        PathBuf::from("./vyre-cache/pipelines")
    }

    /// Derive the cache path for a given program digest + fingerprint.
    pub fn path_for(&self, program_blake3: [u8; 32], fp: DeviceFingerprint) -> PathBuf {
        let key = fp.fold_into(program_blake3);
        let hex = hex_encode(&key);
        self.root.join(&hex[..2]).join(format!("{hex}.bin"))
    }

    /// Read a cached pipeline blob. Returns `None` when absent.
    ///
    /// # Errors
    /// Returns the io error when the entry exists but cannot be read.
    pub fn read(
        &self,
        program_blake3: [u8; 32],
        fp: DeviceFingerprint,
    ) -> io::Result<Option<Vec<u8>>> {
        let path = self.path_for(program_blake3, fp);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write a cached pipeline blob.
    ///
    /// # Errors
    /// Returns the io error when the directory or file cannot be written.
    pub fn write(
        &self,
        program_blake3: [u8; 32],
        fp: DeviceFingerprint,
        bytes: &[u8],
    ) -> io::Result<()> {
        let path = self.path_for(program_blake3, fp);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("bin.tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Root dir of this cache (used for diagnostics).
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_fold_is_deterministic() {
        let a = DeviceFingerprint {
            vendor: 0x10DE,
            device: 0x2684,
            driver: 0xABCD,
        };
        let digest = [0xFFu8; 32];
        assert_eq!(a.fold_into(digest), a.fold_into(digest));
    }

    #[test]
    fn fingerprint_different_devices_diverge() {
        let a = DeviceFingerprint {
            vendor: 0x10DE,
            device: 0x2684,
            driver: 0xABCD,
        };
        let b = DeviceFingerprint {
            vendor: 0x10DE,
            device: 0x2685,
            driver: 0xABCD,
        };
        let digest = [0u8; 32];
        assert_ne!(a.fold_into(digest), b.fold_into(digest));
    }

    #[test]
    fn round_trip_on_disk() -> io::Result<()> {
        let tmp = std::env::temp_dir().join(format!("vyre-cache-test-{}", std::process::id()));
        let cache = DiskPipelineCache::open(&tmp)?;
        let fp = DeviceFingerprint {
            vendor: 1,
            device: 2,
            driver: 3,
        };
        let key = [7u8; 32];
        assert!(cache.read(key, fp)?.is_none());
        cache.write(key, fp, b"compiled pipeline bytes")?;
        assert_eq!(
            cache.read(key, fp)?.as_deref(),
            Some(&b"compiled pipeline bytes"[..])
        );
        std::fs::remove_dir_all(&tmp).ok();
        Ok(())
    }
}
