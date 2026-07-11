use keyhog_scanner::{CompiledScanner, ScannerConfig};

#[test]
fn strict_scanner_config_rejects_invalid_bpe_bound() {
    let mut config = ScannerConfig::default();
    config.entropy_bpe_max_bytes_per_token = 0.0;
    let result = CompiledScanner::compile(Vec::new())
        .expect("empty detector corpus is a valid library scanner")
        .try_with_config(config);
    let error = match result {
        Ok(_) => panic!("zero BPE ceiling must fail before scanner installation"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("entropy_bpe_max_bytes_per_token"));
}

#[test]
fn strict_scanner_config_accepts_canonical_defaults() {
    CompiledScanner::compile(Vec::new())
        .expect("empty detector corpus is a valid library scanner")
        .try_with_config(ScannerConfig::default())
        .expect("canonical scanner defaults must validate");
}
