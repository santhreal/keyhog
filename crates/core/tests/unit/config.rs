use keyhog_core::{ScanConfig, MAX_DECODE_DEPTH_LIMIT};

#[test]
fn default_config_valid() {
    let config = ScanConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn fast_config_valid() {
    let config = ScanConfig::fast();
    assert!(config.validate().is_ok());
    assert_eq!(config.max_decode_depth, 2);
    assert!(!config.entropy_enabled);
}

#[test]
fn thorough_config_valid() {
    let config = ScanConfig::thorough();
    assert!(config.validate().is_ok());
    assert_eq!(config.max_decode_depth, 8);
    assert!(config.entropy_in_source_files);
}

#[test]
fn paranoid_config_valid() {
    let config = ScanConfig::paranoid();
    assert!(config.validate().is_ok());
    assert_eq!(config.max_decode_depth, MAX_DECODE_DEPTH_LIMIT);
}

#[test]
fn invalid_depth_rejected() {
    let config = ScanConfig {
        max_decode_depth: 100,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn invalid_confidence_rejected() {
    let config = ScanConfig {
        min_confidence: 1.5,
        ..Default::default()
    };
    assert!(config.validate().is_err());
}
