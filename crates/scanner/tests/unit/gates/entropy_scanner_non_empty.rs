//! Gate `entropy::scanner`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn entropy_scanner_non_empty() {
    let scanner_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/scanner.rs");
    let isolated_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/isolated.rs");
    let mod_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/entropy/mod.rs");
    let src = std::fs::read_to_string(scanner_path).expect("scanner source readable");
    let isolated = std::fs::read_to_string(isolated_path).expect("isolated source readable");
    let module_map = std::fs::read_to_string(mod_path).expect("entropy module map readable");
    assert!(
        src.trim().len() >= 20,
        "entropy::scanner: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    assert!(
        isolated.trim().len() >= 20,
        "entropy::isolated: expected substantive source, got {} trimmed bytes",
        isolated.trim().len()
    );
    assert!(
        module_map.contains("mod isolated;"),
        "entropy module map must keep isolated token recovery in its own owner module"
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let isolated_prod = isolated
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "entropy::scanner: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        !isolated_prod.contains("todo!()") && !isolated_prod.contains("unimplemented!()"),
        "entropy::isolated: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        !prod.contains("fn isolated_bare_candidate(")
            && !prod.contains("fn visit_isolated_bare_candidates")
            && !prod.contains("fn isolated_bare_entropy_threshold("),
        "entropy::scanner must not re-own isolated token parsing/threshold helpers"
    );
    assert!(
        prod.contains("collect_isolated_bare_candidates_inner(")
            && prod.contains("isolated_bare_keyword_context_with_shape("),
        "entropy::scanner must delegate isolated token recovery through entropy::isolated"
    );
    assert!(
        isolated_prod.contains("fn isolated_bare_candidate(")
            && isolated_prod.contains("fn visit_isolated_bare_candidates")
            && isolated_prod.contains("fn isolated_bare_entropy_threshold("),
        "entropy::isolated must own isolated token parsing and threshold helpers"
    );
    assert!(
        !isolated_prod.contains("!seen.insert(candidate.to_string())"),
        "entropy::isolated must borrow-check isolated dedup before allocating"
    );
    assert!(
        !prod.contains("!seen.insert(candidate.clone())"),
        "entropy::scanner must borrow-check line dedup before allocating"
    );
    assert!(
        isolated_prod.contains("seen.contains(candidate)"),
        "entropy::isolated must keep borrow-first isolated dedup check"
    );
    assert!(
        prod.contains("seen.contains(candidate.as_str())"),
        "entropy::scanner must keep borrow-first line dedup check"
    );
}
