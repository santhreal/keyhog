use keyhog_scanner::hw_probe::testing::parse_backend_str;

#[test]
fn retired_megascan_spellings_are_not_operator_backends() {
    for retired in ["mega-scan", "megascan", "gpu-mega-scan", "rule-pipeline"] {
        assert_eq!(parse_backend_str(retired), None);
    }
}
