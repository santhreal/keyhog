//! WHY: Closes the defect class where operational performance/throughput constants
//! were compiled as fixed literals in source code without configuration schema integration (Row 113).
//! Without full 3-layer configuration governance (Default < TOML < CLI), operators cannot
//! tune KeyHog for non-standard host topologies, container limits, or memory constraints.
//!
//! What this does NOT catch: dynamic runtime operating system cgroup memory notifications.

use keyhog::testing::OperationalKnob;

#[test]
fn row_113_operational_knobs_schema_and_precedence_totality() {
    let knobs = OperationalKnob::enumerate_all();
    assert!(
        !knobs.is_empty(),
        "operational constants must be enumerated at run time from the schema"
    );

    for knob in knobs {
        // 1. Knob metadata completeness
        assert!(!knob.toml_key.is_empty(), "knob must have a TOML key");
        assert!(
            knob.min_val <= knob.max_val,
            "{}: min_val ({}) must be <= max_val ({})",
            knob.toml_key,
            knob.min_val,
            knob.max_val
        );
        assert!(
            knob.default_val >= knob.min_val && knob.default_val <= knob.max_val,
            "{}: default_val ({}) must be within [{}, {}]",
            knob.toml_key,
            knob.default_val,
            knob.min_val,
            knob.max_val
        );

        // 2. Precedence totality: Default
        let resolved_default = knob
            .resolve_precedence(None, None)
            .expect("default must resolve");
        assert_eq!(
            resolved_default, knob.default_val,
            "{}: resolution without overrides must produce default",
            knob.toml_key
        );

        // 3. Precedence totality: TOML overrides Default
        let toml_val = if knob.default_val < knob.max_val {
            knob.default_val + 1
        } else {
            knob.default_val - 1
        };
        let resolved_toml = knob
            .resolve_precedence(Some(toml_val), None)
            .expect("toml override must resolve");
        assert_eq!(
            resolved_toml, toml_val,
            "{}: TOML override must take precedence over default",
            knob.toml_key
        );

        // 4. Precedence totality: CLI overrides TOML and Default
        let cli_val = if toml_val < knob.max_val {
            toml_val + 1
        } else {
            toml_val - 1
        };
        let resolved_cli = knob
            .resolve_precedence(Some(toml_val), Some(cli_val))
            .expect("cli override must resolve");
        assert_eq!(
            resolved_cli, cli_val,
            "{}: CLI override must take precedence over TOML and default",
            knob.toml_key
        );

        // 5. Out-of-range rejection: below min
        if knob.min_val > 0 {
            let underflow = knob.min_val - 1;
            assert!(
                knob.resolve_precedence(Some(underflow), None).is_err(),
                "{}: value below min ({}) must be rejected",
                knob.toml_key,
                underflow
            );
            assert!(
                knob.resolve_precedence(None, Some(underflow)).is_err(),
                "{}: CLI value below min ({}) must be rejected",
                knob.toml_key,
                underflow
            );
        }

        // 6. Out-of-range rejection: above max
        if knob.max_val < u64::MAX {
            let overflow = knob.max_val + 1;
            assert!(
                knob.resolve_precedence(Some(overflow), None).is_err(),
                "{}: value above max ({}) must be rejected",
                knob.toml_key,
                overflow
            );
            assert!(
                knob.resolve_precedence(None, Some(overflow)).is_err(),
                "{}: CLI value above max ({}) must be rejected",
                knob.toml_key,
                overflow
            );
        }
    }
}
