//! WHY: Closes the defect class where byte size parsing was implemented across three sites
//! with divergent error semantics and suffix tables (Row 112).
//! Without cross-entry-point canonicalization, daemon and CLI disagree on valid syntax,
//! causing silent acceptance or unexplained rejections depending on entry path.
//!
//! What this does NOT catch: non-UTF-8 command line argument decoding at the OS shell boundary.

use keyhog::testing::ByteSizeParserDoor;

#[test]
fn row_112_valid_inputs_agree_across_all_doors() {
    let test_cases = [
        ("0B", 0usize),
        ("512B", 512),
        ("1K", 1024),
        ("1KB", 1024),
        ("1KiB", 1024),
        ("1k", 1024),
        ("1kb", 1024),
        ("1kib", 1024),
        ("10M", 10 * 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
        ("10MiB", 10 * 1024 * 1024),
        ("2G", 2 * 1024 * 1024 * 1024),
        ("2GB", 2 * 1024 * 1024 * 1024),
        ("2GiB", 2 * 1024 * 1024 * 1024),
        ("1.5M", (1.5 * 1024.0 * 1024.0) as usize),
        ("0.5G", (0.5 * 1024.0 * 1024.0 * 1024.0) as usize),
    ];

    for (input, expected) in test_cases {
        for door in ByteSizeParserDoor::ALL {
            let res = door.parse(input);
            assert!(
                res.is_ok(),
                "door {:?} failed to parse valid input '{}': {:?}",
                door,
                input,
                res
            );
            assert_eq!(
                res.unwrap(),
                expected,
                "door {:?} produced wrong value for '{}'",
                door,
                input
            );
        }
    }
}

#[test]
fn row_112_invalid_inputs_rejected_across_all_doors() {
    let invalid_cases = [
        "10",            // Bare number missing unit
        "100",           // Bare number missing unit
        "10XYZ",         // Unknown suffix
        "10MB_extra",    // Trailing junk
        "-5MB",          // Negative number
        "10 20 MB",      // Disjoint numbers
        "MB",            // Suffix without number
        "NaN MB",        // Non-numeric
        "inf MB",        // Infinity
        "-inf GB",       // Negative infinity
    ];

    for input in invalid_cases {
        for door in ByteSizeParserDoor::ALL {
            let res = door.parse(input);
            assert!(
                res.is_err(),
                "door {:?} must reject invalid input '{}', got Ok({})",
                door,
                input,
                res.unwrap()
            );
        }
    }
}

#[test]
fn row_112_error_text_equivalence_across_direct_doors() {
    // Assert error text consistency for direct parse doors
    let invalid = "10XYZ";
    let err_cli = ByteSizeParserDoor::CliValueParser.parse(invalid).unwrap_err();
    let err_test = ByteSizeParserDoor::TestingApi.parse(invalid).unwrap_err();
    assert_eq!(err_cli, err_test);
    assert!(err_cli.contains("unknown size suffix"));
}
