use keyhog_scanner::context::infer_context;

#[test]
fn context_anchor_case_18() {
    let line = format!("export TOKEN=secret_{:04}_value", 18);
    let lines = vec![line.as_str()];
    let ctx = infer_context(&lines, 0, None);
    assert_ne!(format!("{ctx:?}"), "Documentation");
}
