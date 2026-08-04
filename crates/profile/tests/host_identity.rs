use keyhog_profile::{Evidence, HostIdentityV2};

fn recorded<T>(evidence: &Evidence<T>) -> Option<&T> {
    match evidence {
        Evidence::Recorded { value } => Some(value),
        Evidence::Unavailable { .. } => None,
    }
}

/// Host identity must record stable operating and architecture values without persisting a hostname.
#[test]
fn host_identity_records_operating_system_architecture_and_parallelism() {
    let identity = HostIdentityV2::capture();
    assert_eq!(
        recorded(&identity.operating_system).map(String::as_str),
        Some(std::env::consts::OS)
    );
    assert_eq!(
        recorded(&identity.architecture).map(String::as_str),
        Some(std::env::consts::ARCH)
    );
    assert_eq!(
        identity.logical_cpus,
        std::thread::available_parallelism()
            .map(|count| u32::try_from(count.get()).unwrap_or(u32::MAX))
            .unwrap_or(1)
    );
    let json = serde_json::to_string(&identity).expect("serialize host identity");
    assert!(!json.contains("hostname"));
    assert!(!json.contains("nodename"));
}

/// Linux host capture must report exact kernel and CPU identity plus canonical 256-bit digests.
#[cfg(all(feature = "host-identity", target_os = "linux"))]
#[test]
fn linux_host_identity_records_kernel_cpu_topology_and_digests() {
    let identity = HostIdentityV2::capture();
    assert!(recorded(&identity.kernel_version).is_some_and(|value| !value.is_empty()));
    assert!(recorded(&identity.cpu_model).is_some_and(|value| !value.is_empty()));
    assert!(recorded(&identity.physical_cores).is_some_and(|cores| *cores > 0));
    for digest in [
        &identity.cpu_features_digest,
        &identity.affinity_digest,
        &identity.numa_digest,
    ] {
        let digest = recorded(digest).expect("Linux host digest available");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}

/// Repeated capture on an unchanged host must produce byte-identical comparison identity.
#[cfg(feature = "host-identity")]
#[test]
fn repeated_host_identity_capture_is_deterministic() {
    let first = HostIdentityV2::capture();
    let second = HostIdentityV2::capture();
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).expect("serialize first host identity"),
        serde_json::to_vec(&second).expect("serialize second host identity")
    );
}

/// Disabling host collection must keep static platform identity and type every unavailable detail as disabled.
#[cfg(not(feature = "host-identity"))]
#[test]
fn disabled_host_identity_reports_typed_capability_gaps() {
    let identity = HostIdentityV2::capture();
    for evidence in [
        &identity.kernel_version,
        &identity.cpu_model,
        &identity.cpu_features_digest,
        &identity.affinity_digest,
        &identity.numa_digest,
    ] {
        assert!(matches!(
            evidence,
            Evidence::Unavailable {
                reason: EvidenceGap::CollectorDisabled
            }
        ));
    }
    assert!(matches!(
        identity.physical_cores,
        Evidence::Unavailable {
            reason: EvidenceGap::CollectorDisabled
        }
    ));
}
