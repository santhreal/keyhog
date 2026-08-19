//! WHY: `keyhog update` and `keyhog repair` were REMOVED with the signed
//! binary-asset release channel they drove. That channel searched BACKWARD for
//! a release that still carried a complete bundle, so once releases stopped
//! carrying assets it did not fail: it silently installed a binary 33 versions
//! stale. Reintroducing either subcommand without a workflow that produces and
//! signs assets recreates exactly that silent-staleness bug.
//!
//! Absence is the product contract here, so absence is what these assert.
//! `scripts/gates/release_channel_coherence.py` covers the other half: code
//! that consumes release assets no workflow produces.
//!
//! Does not catch a self-updater added under a different subcommand name; the
//! gate catches that one, because any such command must consume release assets.

/// Every retired maintenance subcommand must fail to parse. Parameterized so a
/// third retired name is one row, not another test.
#[test]
fn retired_maintenance_subcommands_do_not_parse() {
    for name in ["update", "repair"] {
        let parsed = keyhog::args::try_parse_from(["keyhog", name]);
        assert!(
            parsed.is_err(),
            "`keyhog {name}` was retired with the binary-asset release channel \
             and must not parse"
        );
    }
}

/// The root `--version` flag is identity output, not a release selector. It
/// carried that second meaning only inside the retired subcommands; nothing
/// may quietly restore the overload.
#[test]
fn root_version_flag_is_identity_output_only() {
    let cli =
        keyhog::args::try_parse_from(["keyhog", "--version"]).expect("root --version must parse");
    assert!(
        cli.build_version,
        "root --version must select identity output"
    );
    assert!(
        cli.command.is_none(),
        "root --version must not select a subcommand"
    );
}
