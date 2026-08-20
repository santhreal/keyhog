use crate::{
    BuildIdentityV2, ConfigIdentityV2, DetectorIdentityV2, Evidence, EvidenceGap, HostIdentityV2,
    SourceIdentityV2, WorkloadIdentityV2,
};

const HOST_IDENTITY_VERSION: u16 = 1;

fn unavailable<T>(reason: EvidenceGap) -> Evidence<T> {
    Evidence::unavailable(reason)
}

#[cfg(feature = "host-identity")]
fn read_text(path: &str) -> Result<String, EvidenceGap> {
    std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            EvidenceGap::PermissionDenied
        } else {
            EvidenceGap::Unavailable
        }
    })
}

#[cfg(any(feature = "build-identity", feature = "host-identity"))]
fn digest_text(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(all(feature = "host-identity", target_os = "linux"))]
fn linux_cpu_identity() -> (Evidence<String>, Evidence<u32>, Evidence<String>) {
    let cpuinfo = match read_text("/proc/cpuinfo") {
        Ok(cpuinfo) => cpuinfo,
        Err(reason) => {
            return (
                unavailable(reason),
                unavailable(reason),
                unavailable(reason),
            )
        }
    };
    let model = cpuinfo
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.trim() == "model name")
        })
        .map(|(_, value)| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map_or_else(|| unavailable(EvidenceGap::Unavailable), Evidence::recorded);

    let mut cores = std::collections::BTreeSet::new();
    for processor in cpuinfo.split("\n\n") {
        let physical = processor.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.trim() == "physical id")
                .map(|(_, value)| value.trim())
        });
        let core = processor.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.trim() == "core id")
                .map(|(_, value)| value.trim())
        });
        if let (Some(physical), Some(core)) = (physical, core) {
            cores.insert((physical.to_owned(), core.to_owned()));
        }
    }
    let physical_cores = if cores.is_empty() {
        unavailable(EvidenceGap::Unavailable)
    } else {
        Evidence::recorded(u32::try_from(cores.len()).unwrap_or(u32::MAX))
    };

    let features = cpuinfo
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| matches!(key.trim(), "flags" | "Features"))
                .map(|(_, value)| value)
        })
        .map(|features| {
            let mut features = features.split_whitespace().collect::<Vec<_>>();
            features.sort_unstable();
            features.dedup();
            digest_text(&features.join("\n"))
        })
        .map_or_else(|| unavailable(EvidenceGap::Unavailable), Evidence::recorded);
    (model, physical_cores, features)
}

#[cfg(all(feature = "host-identity", target_os = "linux"))]
fn linux_affinity_digest() -> Evidence<String> {
    match read_text("/proc/self/status") {
        Ok(status) => status
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(digest_text)
            .map_or_else(|| unavailable(EvidenceGap::Unavailable), Evidence::recorded),
        Err(reason) => unavailable(reason),
    }
}

#[cfg(all(feature = "host-identity", target_os = "linux"))]
fn linux_numa_digest() -> Evidence<String> {
    match read_text("/sys/devices/system/node/online") {
        Ok(nodes) => {
            let nodes = nodes.trim();
            if nodes.is_empty() {
                unavailable(EvidenceGap::Unavailable)
            } else {
                Evidence::recorded(digest_text(nodes))
            }
        }
        Err(reason) => unavailable(reason),
    }
}

impl HostIdentityV2 {
    /// Capture the timing-relevant host identity without recording hostnames or environment values.
    pub fn capture() -> Self {
        let logical_cpus = crate::host_parallelism::logical_cpus();
        #[cfg(not(feature = "host-identity"))]
        {
            let disabled = EvidenceGap::CollectorDisabled;
            Self {
                version: HOST_IDENTITY_VERSION,
                operating_system: Evidence::recorded(std::env::consts::OS.to_owned()),
                kernel_version: unavailable(disabled),
                architecture: Evidence::recorded(std::env::consts::ARCH.to_owned()),
                cpu_model: unavailable(disabled),
                logical_cpus,
                physical_cores: unavailable(disabled),
                cpu_features_digest: unavailable(disabled),
                affinity_digest: unavailable(disabled),
                numa_digest: unavailable(disabled),
            }
        }
        #[cfg(all(feature = "host-identity", target_os = "linux"))]
        {
            let (cpu_model, physical_cores, cpu_features_digest) = linux_cpu_identity();
            let kernel_version = match read_text("/proc/sys/kernel/osrelease") {
                Ok(value) if !value.trim().is_empty() => {
                    Evidence::recorded(value.trim().to_owned())
                }
                Ok(_) => unavailable(EvidenceGap::Unavailable),
                Err(reason) => unavailable(reason),
            };
            Self {
                version: HOST_IDENTITY_VERSION,
                operating_system: Evidence::recorded(std::env::consts::OS.to_owned()),
                kernel_version,
                architecture: Evidence::recorded(std::env::consts::ARCH.to_owned()),
                cpu_model,
                logical_cpus,
                physical_cores,
                cpu_features_digest,
                affinity_digest: linux_affinity_digest(),
                numa_digest: linux_numa_digest(),
            }
        }
        #[cfg(all(feature = "host-identity", not(target_os = "linux")))]
        {
            Self {
                version: HOST_IDENTITY_VERSION,
                operating_system: Evidence::recorded(std::env::consts::OS.to_owned()),
                kernel_version: unavailable(EvidenceGap::Unsupported),
                architecture: Evidence::recorded(std::env::consts::ARCH.to_owned()),
                cpu_model: unavailable(EvidenceGap::Unsupported),
                logical_cpus,
                physical_cores: unavailable(EvidenceGap::Unsupported),
                cpu_features_digest: unavailable(EvidenceGap::Unsupported),
                affinity_digest: unavailable(EvidenceGap::Unsupported),
                numa_digest: unavailable(EvidenceGap::Unsupported),
            }
        }
    }
}

/// Detector-specific values supplied after the scanner compiles its effective corpus.
pub struct DetectorIdentityInput<'a> {
    pub corpus_digest: &'a str,
    pub compiled_plan_digest: Option<&'a str>,
    pub enabled_detector_digest: Option<&'a str>,
    pub backend_database_digest: Option<&'a str>,
    pub external_provenance_digest: Option<&'a str>,
}

impl DetectorIdentityV2 {
    /// Capture exact corpus and compiled-plan identities with explicit gaps for unavailable peers.
    pub fn capture(input: DetectorIdentityInput<'_>) -> Self {
        fn optional(value: Option<&str>) -> Evidence<String> {
            value
                .filter(|value| !value.is_empty())
                .map(|value| Evidence::recorded(value.to_owned()))
                .unwrap_or_else(|| unavailable(EvidenceGap::Unavailable))
        }

        Self {
            version: 1,
            corpus_digest: input.corpus_digest.to_owned(),
            compiled_plan_digest: optional(input.compiled_plan_digest),
            enabled_detector_digest: optional(input.enabled_detector_digest),
            backend_database_digest: optional(input.backend_database_digest),
            external_provenance_digest: optional(input.external_provenance_digest),
        }
    }
}

/// Canonical resolved configuration values supplied by the final operator.
pub struct ConfigIdentityInput<'a> {
    pub resolved_config_digest: &'a str,
    pub policy_digest: Option<&'a str>,
    pub preset: Option<&'a str>,
    pub protection_state: Option<&'a str>,
}

impl ConfigIdentityV2 {
    /// Capture resolved policy identity without storing raw configuration values.
    pub fn capture(input: ConfigIdentityInput<'_>) -> Self {
        fn optional(value: Option<&str>) -> Evidence<String> {
            value
                .filter(|value| !value.is_empty())
                .map(|value| Evidence::recorded(value.to_owned()))
                .unwrap_or_else(|| unavailable(EvidenceGap::Unavailable))
        }

        Self {
            version: 1,
            resolved_config_digest: input.resolved_config_digest.to_owned(),
            policy_digest: optional(input.policy_digest),
            preset: optional(input.preset),
            protection_state: optional(input.protection_state),
        }
    }
}

/// Safe source adapter names and hashed target values supplied by the operator.
pub struct SourceIdentityInput<'a> {
    pub adapters: Vec<String>,
    pub target_digest: Option<&'a str>,
    pub partition_digest: Option<&'a str>,
}

impl SourceIdentityV2 {
    /// Capture source identity while storing no paths, URLs, credentials, or target labels.
    pub fn capture(input: SourceIdentityInput<'_>) -> Self {
        fn optional(value: Option<&str>) -> Evidence<String> {
            value
                .filter(|value| !value.is_empty())
                .map(|value| Evidence::recorded(value.to_owned()))
                .unwrap_or_else(|| unavailable(EvidenceGap::Unavailable))
        }

        let mut adapters = input.adapters;
        adapters.sort_unstable();
        adapters.dedup();
        Self {
            version: 1,
            adapters,
            target_digest: optional(input.target_digest),
            partition_digest: optional(input.partition_digest),
        }
    }
}

/// Measured byte and unit totals used to classify comparable workload shapes.
pub struct WorkloadIdentityInput<'a> {
    pub class: &'a str,
    pub raw_source_bytes: u64,
    pub source_units: u64,
    pub container_bytes: Option<u64>,
    pub expanded_payload_bytes: Option<u64>,
    pub derived_decoder_bytes: Option<u64>,
    pub backend_dispatched_bytes: Option<u64>,
}

impl WorkloadIdentityV2 {
    /// Capture exact byte domains and deterministic size and fanout buckets.
    pub fn capture(input: WorkloadIdentityInput<'_>) -> Self {
        fn optional(value: Option<u64>) -> Evidence<u64> {
            value.map_or_else(|| unavailable(EvidenceGap::Unavailable), Evidence::recorded)
        }
        let size_bucket = match input.raw_source_bytes {
            0 => "empty",
            1..=4_096 => "tiny",
            4_097..=1_048_576 => "small",
            1_048_577..=67_108_864 => "medium",
            67_108_865..=1_073_741_824 => "large",
            _ => "huge",
        };
        let fanout_bucket = match input.source_units {
            0 => "empty",
            1 => "single",
            2..=16 => "low",
            17..=1_024 => "medium",
            _ => "high",
        };
        Self {
            version: 1,
            class: input.class.to_owned(),
            raw_source_bytes: input.raw_source_bytes,
            source_units: input.source_units,
            container_bytes: optional(input.container_bytes),
            expanded_payload_bytes: optional(input.expanded_payload_bytes),
            derived_decoder_bytes: optional(input.derived_decoder_bytes),
            backend_dispatched_bytes: optional(input.backend_dispatched_bytes),
            size_bucket: Evidence::recorded(size_bucket.to_owned()),
            fanout_bucket: Evidence::recorded(fanout_bucket.to_owned()),
        }
    }
}

/// Build-specific values supplied by the final binary crate.
pub struct BuildIdentityInput<'a> {
    pub binary_version: &'a str,
    pub enabled_features: &'a [&'a str],
    pub allocator: &'a str,
    pub linked_backends: &'a [(&'a str, &'a str)],
}

#[cfg(feature = "build-identity")]
fn digest_current_executable() -> Evidence<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return unavailable(EvidenceGap::Unavailable),
    };
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => {
            return unavailable(if error.kind() == std::io::ErrorKind::PermissionDenied {
                EvidenceGap::PermissionDenied
            } else {
                EvidenceGap::Unavailable
            });
        }
    };
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(error) => {
                return unavailable(if error.kind() == std::io::ErrorKind::PermissionDenied {
                    EvidenceGap::PermissionDenied
                } else {
                    EvidenceGap::Unavailable
                });
            }
        }
    }
    Evidence::recorded(hex::encode(digest.finalize()))
}

#[cfg(feature = "build-identity")]
fn canonical_pairs_digest(values: &[(&str, &str)]) -> Evidence<String> {
    if values.is_empty() {
        return unavailable(EvidenceGap::Unavailable);
    }
    let mut values = values
        .iter()
        .map(|(name, version)| format!("{name}={version}"))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    Evidence::recorded(digest_text(&values.join("\n")))
}

impl BuildIdentityV2 {
    /// Capture the final executable plus feature, allocator, toolchain, and backend identity.
    pub fn capture(input: BuildIdentityInput<'_>) -> Self {
        #[cfg(feature = "build-identity")]
        {
            let mut features = input.enabled_features.to_vec();
            features.sort_unstable();
            features.dedup();
            let feature_digest = if features.is_empty() {
                unavailable(EvidenceGap::Unavailable)
            } else {
                Evidence::recorded(digest_text(&features.join("\n")))
            };
            let source_revision = option_env!("KEYHOG_SOURCE_REVISION")
                .filter(|value| !value.is_empty())
                .map(|value| Evidence::recorded(value.to_owned()))
                .unwrap_or_else(|| unavailable(EvidenceGap::Unavailable));
            let compiler = env!("KEYHOG_PROFILE_RUSTC");
            Self {
                version: 1,
                binary_version: input.binary_version.to_owned(),
                binary_digest: digest_current_executable(),
                source_revision,
                build_profile: Evidence::recorded(env!("KEYHOG_PROFILE_BUILD_PROFILE").to_owned()),
                target_triple: Evidence::recorded(env!("KEYHOG_PROFILE_BUILD_TARGET").to_owned()),
                feature_digest,
                compiler_identity: if compiler == "unavailable" {
                    unavailable(EvidenceGap::Unavailable)
                } else {
                    Evidence::recorded(compiler.to_owned())
                },
                allocator_identity: if input.allocator.is_empty() {
                    unavailable(EvidenceGap::Unavailable)
                } else {
                    Evidence::recorded(input.allocator.to_owned())
                },
                linked_backend_digest: canonical_pairs_digest(input.linked_backends),
            }
        }
        #[cfg(not(feature = "build-identity"))]
        {
            let disabled = EvidenceGap::CollectorDisabled;
            Self {
                version: 1,
                binary_version: input.binary_version.to_owned(),
                binary_digest: unavailable(disabled),
                source_revision: unavailable(disabled),
                build_profile: unavailable(disabled),
                target_triple: unavailable(disabled),
                feature_digest: unavailable(disabled),
                compiler_identity: unavailable(disabled),
                allocator_identity: unavailable(disabled),
                linked_backend_digest: unavailable(disabled),
            }
        }
    }

    pub(crate) fn capture_legacy(binary_version: &str) -> Self {
        Self::capture(BuildIdentityInput {
            binary_version,
            enabled_features: &[],
            allocator: "",
            linked_backends: &[],
        })
    }
}
