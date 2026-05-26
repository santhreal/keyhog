use keyhog_scanner::engine::build_rule_pipeline;
#[test]
fn build_rule_pipeline_rejects_backreference() {
    assert!(build_rule_pipeline(&[r"(a)\1"], 1024).is_err());
}
