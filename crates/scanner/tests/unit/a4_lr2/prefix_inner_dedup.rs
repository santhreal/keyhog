use keyhog_scanner::compiler::extract_inner_literals;

#[test]
fn prefix_inner_dedup() {
    let lits = keyhog_scanner::compiler::extract_inner_literals(r"(?:KEYY|KEYY|other)foo");
    assert!(lits.iter().filter(|s| *s == "KEYY").count() <= 1);
}
