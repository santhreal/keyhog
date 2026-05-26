use keyhog_scanner::engine::build_rule_pipeline;
#[test]
fn build_rule_pipeline_literal_ok() {
    assert!(build_rule_pipeline(&["abc"], 512).is_ok());
}
