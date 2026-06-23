//! Gate `rate_limit`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn rate_limit_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/rate_limit.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "rate_limit: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "rate_limit: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("self.services.get(service)")
            && prod.contains("self.services.entry(service.to_string()).or_insert_with(")
            && !prod.contains("let entry = self.services.entry(service.to_string()).or_insert_with("),
        "rate limiter wait() must use a borrowed DashMap lookup before allocating a String for cold service insertion"
    );
    assert!(
        prod.contains("fn reserve_service_slot("),
        "rate limiter slot math must stay in one helper shared by warm and cold service paths"
    );
}
