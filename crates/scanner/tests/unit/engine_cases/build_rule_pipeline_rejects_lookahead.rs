use keyhog_scanner::engine::build_rule_pipeline;
#[test]
fn build_rule_pipeline_rejects_lookahead() {
    assert!(build_rule_pipeline(&["(?=abc)"], 1024).is_err());
}
