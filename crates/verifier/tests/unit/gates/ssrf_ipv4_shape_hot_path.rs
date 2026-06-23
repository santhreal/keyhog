#[test]
fn ssrf_ipv4_shape_checks_do_not_collect_dot_parts() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ssrf.rs"))
        .expect("ssrf source readable");

    let short_form = src
        .split("fn canonicalize_short_form_ipv4(")
        .nth(1)
        .expect("short-form IPv4 canonicalizer exists")
        .split("/// Parse a single dotted-IP field")
        .next()
        .expect("short-form body bounded");
    assert!(
        !short_form.contains("Vec<&str>") && !short_form.contains("Option<Vec<u32>>"),
        "short-form IPv4 canonicalization must use stack storage, not heap Vecs"
    );
    assert!(
        short_form.contains("let mut values = [0u32; 3];")
            && short_form.contains("for part in domain.split('.')"),
        "short-form IPv4 canonicalization should stream dot parts into a fixed array"
    );

    let malformed = src
        .split("fn looks_like_malformed_ip(")
        .nth(1)
        .expect("malformed-IP heuristic exists")
        .split("false")
        .next()
        .expect("malformed-IP body bounded");
    assert!(
        !malformed.contains("Vec<&str>") && !malformed.contains(".collect()"),
        "malformed-IP heuristic must not allocate dot-part collections"
    );
    assert!(
        malformed.contains("let mut part_count = 0usize;")
            && malformed.contains("for part in domain.split('.')"),
        "malformed-IP heuristic should classify dot parts in one streaming pass"
    );
}
