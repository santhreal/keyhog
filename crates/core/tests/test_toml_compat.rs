use keyhog_core::DetectorFile;

#[test]
fn test_single_companion_table() {
    let toml1 = r#"
[detector]
id = "test"
name = "Test"
service = "test"
severity = "critical"
keywords = []

[detector.companion]
name = "test"
regex = ".*"
within_lines = 5
"#;
    let result: Result<DetectorFile, _> = toml::from_str(toml1);
    println!("Single companion: {:?}", result.is_ok());
}

#[test]
fn test_verify_without_service() {
    let toml2 = r#"
[detector]
id = "test"
name = "Test"
service = "test"
severity = "critical"
keywords = []

[detector.verify]
method = "GET"
url = "https://example.com"
"#;
    let result: Result<DetectorFile, _> = toml::from_str(toml2);
    println!("Verify without service: {:?}", result);
}
