use keyhog_scanner::execution_pack::{ExecutionPackBackend, ExecutionPackPolicy};

#[test]
fn execution_pack_identity_names_and_scan_conversions_round_trip_exhaustively() {
    for backend in ExecutionPackBackend::ALL {
        assert_eq!(
            ExecutionPackBackend::from_lowercase_name(backend.lowercase_name()),
            Some(backend)
        );
        assert_eq!(
            ExecutionPackBackend::from_pascal_name(backend.pascal_name()),
            Some(backend)
        );
        assert_eq!(
            ExecutionPackBackend::from_scan_backend(backend.scan_backend()),
            Some(backend)
        );
    }
    for policy in ExecutionPackPolicy::ALL {
        assert_eq!(
            ExecutionPackPolicy::from_lowercase_name(policy.lowercase_name()),
            Some(policy)
        );
    }
    assert_eq!(ExecutionPackBackend::from_lowercase_name("GPU-CUDA"), None);
    assert_eq!(ExecutionPackBackend::from_pascal_name("GPUCuda"), None);
    assert_eq!(ExecutionPackPolicy::from_lowercase_name("DEFAULT"), None);
    assert_eq!(
        ExecutionPackPolicy::ALL.map(ExecutionPackPolicy::lowercase_name),
        ["default", "fast", "deep", "precision"]
    );
}
