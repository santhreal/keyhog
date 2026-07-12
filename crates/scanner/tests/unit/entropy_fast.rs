use keyhog_scanner::testing::entropy_fast::shannon_entropy_scalar;

#[test]
fn test_entropy_known_values() {
    // Uniform distribution: log2(256) = 8.0
    let uniform: Vec<u8> = (0..=255).collect();
    let ent = shannon_entropy_scalar(&uniform);
    assert!(
        (ent - 8.0).abs() < 0.01,
        "Uniform entropy should be ~8.0, got {}",
        ent
    );

    // Constant: 0.0
    let constant = vec![0x41u8; 100];
    let ent = shannon_entropy_scalar(&constant);
    assert_eq!(ent, 0.0, "Constant entropy should be 0.0");

    // Binary: ~1.0
    let binary = vec![0x00u8, 0xFF].repeat(50);
    let ent = shannon_entropy_scalar(&binary);
    assert!(
        (ent - 1.0).abs() < 0.1,
        "Binary entropy should be ~1.0, got {}",
        ent
    );
}
