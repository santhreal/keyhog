use keyhog_profile::{BuildIdentityInput, BuildIdentityV2, Evidence, EvidenceGap};

fn recorded<T>(evidence: &Evidence<T>) -> Option<&T> {
    match evidence {
        Evidence::Recorded { value } => Some(value),
        Evidence::Unavailable { .. } => None,
    }
}

fn capture(features: &[&str], backends: &[(&str, &str)]) -> BuildIdentityV2 {
    BuildIdentityV2::capture(BuildIdentityInput {
        binary_version: "0.5.49",
        enabled_features: features,
        allocator: "mimalloc",
        linked_backends: backends,
    })
}

/// Build identity must hash the exact running executable rather than a package name or version string.
#[cfg(feature = "build-identity")]
#[test]
fn binary_digest_matches_running_test_executable_bytes() {
    use sha2::{Digest, Sha256};

    let identity = capture(&["portable", "simd"], &[("hyperscan", "5.4.2")]);
    let executable = std::fs::read(std::env::current_exe().expect("current test executable"))
        .expect("read current test executable");
    let expected = hex::encode(Sha256::digest(&executable));
    assert_eq!(recorded(&identity.binary_digest), Some(&expected));
    assert_eq!(identity.binary_version, "0.5.49");
}

/// Feature and linked-backend digests must be canonical across caller ordering and duplicates.
#[cfg(feature = "build-identity")]
#[test]
fn build_feature_and_backend_digests_are_order_independent() {
    let first = capture(
        &["simd", "portable", "simd"],
        &[("vectorscan", "5.4.11"), ("cuda", "13.0")],
    );
    let second = capture(
        &["portable", "simd"],
        &[("cuda", "13.0"), ("vectorscan", "5.4.11")],
    );
    assert_eq!(first.feature_digest, second.feature_digest);
    assert_eq!(first.linked_backend_digest, second.linked_backend_digest);
    assert_eq!(recorded(&first.feature_digest).map(String::len), Some(64));
    assert_eq!(
        recorded(&first.linked_backend_digest).map(String::len),
        Some(64)
    );
}

/// A materially different feature set must produce a different comparison identity.
#[cfg(feature = "build-identity")]
#[test]
fn different_feature_sets_produce_different_digests() {
    let portable = capture(&["portable"], &[("scalar", "builtin")]);
    let accelerated = capture(&["portable", "simd"], &[("scalar", "builtin")]);
    assert_ne!(portable.feature_digest, accelerated.feature_digest);
}

/// Build profile, target, compiler, allocator, and backend versions must all be operator-comparable evidence.
#[cfg(feature = "build-identity")]
#[test]
fn build_identity_records_toolchain_target_profile_allocator_and_backends() {
    let identity = capture(&["portable"], &[("scalar", "builtin")]);
    assert!(recorded(&identity.build_profile).is_some_and(|value| !value.is_empty()));
    assert!(recorded(&identity.target_triple).is_some_and(|value| value.contains('-')));
    assert!(recorded(&identity.compiler_identity).is_some_and(|value| value.contains("rustc")));
    assert_eq!(
        recorded(&identity.allocator_identity).map(String::as_str),
        Some("mimalloc")
    );
    assert!(recorded(&identity.linked_backend_digest).is_some());
}

/// Missing final-binary feature or backend input must stay unavailable instead of hashing an empty list.
#[cfg(feature = "build-identity")]
#[test]
fn absent_final_binary_metadata_is_typed_unavailable() {
    let identity = BuildIdentityV2::capture(BuildIdentityInput {
        binary_version: "0.5.49",
        enabled_features: &[],
        allocator: "",
        linked_backends: &[],
    });
    for evidence in [
        &identity.feature_digest,
        &identity.allocator_identity,
        &identity.linked_backend_digest,
    ] {
        assert!(matches!(
            evidence,
            Evidence::Unavailable {
                reason: EvidenceGap::Unavailable
            }
        ));
    }
}

/// Disabling build collection must retain the semantic version and type every unavailable detail as disabled.
#[cfg(not(feature = "build-identity"))]
#[test]
fn disabled_build_identity_reports_typed_gaps() {
    let identity = capture(&["portable"], &[("scalar", "builtin")]);
    assert_eq!(identity.binary_version, "0.5.49");
    for evidence in [
        &identity.binary_digest,
        &identity.source_revision,
        &identity.build_profile,
        &identity.target_triple,
        &identity.feature_digest,
        &identity.compiler_identity,
        &identity.allocator_identity,
        &identity.linked_backend_digest,
    ] {
        assert!(matches!(
            evidence,
            Evidence::Unavailable {
                reason: EvidenceGap::CollectorDisabled
            }
        ));
    }
}
