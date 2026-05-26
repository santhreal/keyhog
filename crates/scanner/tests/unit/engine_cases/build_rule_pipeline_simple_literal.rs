use keyhog_scanner::engine::build_rule_pipeline;
#[test]
fn build_rule_pipeline_simple_literal() {
    let _pipe = build_rule_pipeline(&["abc"], 1024).expect("compile literal pattern");
}
