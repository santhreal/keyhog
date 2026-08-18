//! Host capability classes (H0–H5) and detection logic.

use serde::{Deserialize, Serialize};

/// Host capability classes defined across the test and execution matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HostClass {
    /// H0: No accelerator: no GPU adapter, no Hyperscan, scalar CPU only (hosted PR CI, minimal containers).
    H0,
    /// H1: SIMD only: Hyperscan or Vectorscan present, no usable GPU adapter (hosted CI with SIMD action, Linux servers).
    H1,
    /// H2: GPU present and healthy: at least one adapter passes region-presence self-test (self-hosted release runner, workstations).
    H2,
    /// H3: GPU present and broken: adapter enumerates but fails self-test, or driver is stale (fault injection / broken drivers).
    H3,
    /// H4: Non-Linux: Windows and macOS, including Metal as the GPU driver on macOS (release matrix).
    H4,
    /// H5: Non-x86: aarch64, where AVX paths do not exist at all (release matrix, Apple silicon, containers).
    H5,
}

impl HostClass {
    pub const ALL: [Self; 6] = [Self::H0, Self::H1, Self::H2, Self::H3, Self::H4, Self::H5];

    /// Stable two-letter label for this host class.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::H0 => "H0",
            Self::H1 => "H1",
            Self::H2 => "H2",
            Self::H3 => "H3",
            Self::H4 => "H4",
            Self::H5 => "H5",
        }
    }

    /// Detect the host class of the current execution environment.
    #[must_use]
    pub fn detect() -> Self {
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            return Self::H5;
        }

        #[cfg(not(target_os = "linux"))]
        {
            return Self::H4;
        }

        #[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
        {
            let hw = crate::hw_probe::probe_hardware();
            if hw.gpu_available && !hw.gpu_is_software {
                Self::H2
            } else if hw.gpu_available && hw.gpu_is_software {
                Self::H3
            } else if hw.hyperscan_available {
                Self::H1
            } else {
                Self::H0
            }
        }
    }
}
