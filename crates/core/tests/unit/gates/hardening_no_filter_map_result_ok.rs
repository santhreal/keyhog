//! Gate `hardening`: security filesystem scans must not hide per-entry errors.

#[test]
fn hardening_no_filter_map_result_ok() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/hardening.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let offenders: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let trimmed = line.trim();
            let offender = trimmed.contains("filter_map(Result::ok)")
                || trimmed.contains(".filter_map(|") && trimmed.contains(".ok()");
            offender.then_some((i + 1, line))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "hardening must inspect iterator errors explicitly; offenders: {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
