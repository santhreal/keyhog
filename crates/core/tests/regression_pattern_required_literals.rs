use keyhog_core::PatternSpec;

fn pattern(regex: &str, literals: &[&str]) -> PatternSpec {
    PatternSpec {
        regex: regex.into(),
        required_literals: literals.iter().map(|literal| (*literal).into()).collect(),
        ..Default::default()
    }
}

#[test]
fn required_literals_prove_infix_and_required_repetition_routes() {
    pattern(
        r"[a-z][a-z0-9+.-]*://[^/@\s:]*:([^/@\s<>]{6,128})@[a-z0-9._-]",
        &["://"],
    )
    .validate_required_literals()
    .expect("URL scheme separator is required");
    pattern(r"(?:token_)+[A-Z0-9]{8}", &["token_"])
        .validate_required_literals()
        .expect("one-or-more repetition requires its literal");
}

#[test]
fn required_literal_alternatives_must_cover_every_regex_branch() {
    pattern(
        r"(?:alpha_key|beta_key)[A-Z0-9]{8}",
        &["alpha_key", "beta_key"],
    )
    .validate_required_literals()
    .expect("the OR-set covers both branches");
    let error = pattern(r"(?:alpha_key|public)[A-Z0-9]{8}", &["alpha_key"])
        .validate_required_literals()
        .expect_err("one uncovered branch makes the routing claim unsound");
    assert!(error.contains("necessary OR-condition"));
}

#[test]
fn optional_duplicate_empty_and_non_ascii_required_literals_are_rejected() {
    for (candidate, expected) in [
        (
            pattern(r"(?:token_)?[A-Z0-9]{8}", &["token_"]),
            "necessary OR-condition",
        ),
        (
            pattern(r"token_[A-Z0-9]{8}", &["token_", "TOKEN_"]),
            "duplicate",
        ),
        (pattern(r"token_[A-Z0-9]{8}", &[""]), "non-empty ASCII"),
        (pattern(r"tök_[A-Z0-9]{8}", &["tök_"]), "non-empty ASCII"),
    ] {
        let error = candidate
            .validate_required_literals()
            .expect_err("invalid routing literal declaration must fail closed");
        assert!(
            error.contains(expected),
            "{error:?} did not contain {expected:?}"
        );
    }
}
