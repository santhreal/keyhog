    use super::plausibility::{
        LEADING_SLASH_BASE64_ENTROPY_FLOOR, SECOND_HALF_ENTROPY_FLOOR,
        SYMBOLIC_CREDENTIAL_ENTROPY_FLOOR,
    };
    use super::{
        operator_entropy_override, FIRST_SOURCE_LINE_NUMBER, HIGH_ENTROPY_THRESHOLD,
        LOW_ENTROPY_THRESHOLD, MIXED_ALNUM_TOKEN_THRESHOLD,
    };

    /// The shared `> HIGH` override owner: only a finite value STRICTLY above the
    /// blanket high floor overrides the anchored floor (honored verbatim); the
    /// default 4.5 (== HIGH), every value in the recall band, and non-finite
    /// inputs all decline (`None`) so each caller keeps its own anchored floor.
    /// Pinning every band here is what makes this a policy, not a silent clamp.
    #[test]
    fn operator_override_engages_only_strictly_above_the_high_floor() {
        // Strictly-above-HIGH: honored verbatim.
        assert_eq!(operator_entropy_override(4.6), Some(4.6));
        assert_eq!(operator_entropy_override(5.8), Some(5.8));
        assert_eq!(operator_entropy_override(8.0), Some(8.0));
        // The default threshold sits exactly ON the high floor: it does NOT
        // override, so the keyword path stays at its LOW recall floor.
        assert_eq!(operator_entropy_override(HIGH_ENTROPY_THRESHOLD), None);
        // Recall band (LOW, HIGH] and below-LOW: no override.
        assert_eq!(operator_entropy_override(4.0), None);
        assert_eq!(operator_entropy_override(LOW_ENTROPY_THRESHOLD), None);
        assert_eq!(operator_entropy_override(0.0), None);
        // Non-finite is never an override: NaN AND ±infinity all fail the
        // `is_finite()` guard (an infinite entropy threshold is a nonsensical
        // override input (nothing could ever exceed it), so all return None).
        assert_eq!(operator_entropy_override(f64::NAN), None);
        assert_eq!(operator_entropy_override(f64::INFINITY), None);
        assert_eq!(operator_entropy_override(f64::NEG_INFINITY), None);
    }

    /// The two anchored floor sites compose the shared override with their own
    /// default floors: the keyword path with [`LOW_ENTROPY_THRESHOLD`] (via
    /// `min`), the isolated path with [`MIXED_ALNUM_TOKEN_THRESHOLD`]. Reproduce
    /// each site's resolution to prove the dedup preserved both behaviors byte
    /// for byte.
    #[test]
    fn anchored_floor_sites_compose_the_shared_override() {
        let keyword_floor = |t: f64| match operator_entropy_override(t) {
            Some(threshold) => threshold,
            None if t.is_finite() => t.min(LOW_ENTROPY_THRESHOLD),
            None => LOW_ENTROPY_THRESHOLD,
        };
        let isolated_floor = |t: f64| {
            operator_entropy_override(t).map_or(MIXED_ALNUM_TOKEN_THRESHOLD, |threshold| threshold)
        };

        // Default 4.5: keyword path floors to LOW (3.0), isolated to MIXED (4.0).
        assert_eq!(keyword_floor(4.5), LOW_ENTROPY_THRESHOLD);
        assert_eq!(isolated_floor(4.5), MIXED_ALNUM_TOKEN_THRESHOLD);
        // A stricter operator bar overrides both floors verbatim.
        assert_eq!(keyword_floor(6.0), 6.0);
        assert_eq!(isolated_floor(6.0), 6.0);
        // A below-LOW request loosens only the keyword path (min), never lifts
        // the isolated path above its MIXED floor.
        assert_eq!(keyword_floor(2.0), 2.0);
        assert_eq!(isolated_floor(2.0), MIXED_ALNUM_TOKEN_THRESHOLD);
    }

    /// The three entropy floors hoisted out of `plausibility.rs` keep their exact
    /// tuned values. These are the single named owners for the literals that were
    /// pasted inline (`3.5`, `4.8`, `2.5`); a drift here is a detection-behavior
    /// change, so pin the bytes.
    #[test]
    fn plausibility_entropy_floors_have_their_tuned_values() {
        assert_eq!(SYMBOLIC_CREDENTIAL_ENTROPY_FLOOR, 3.5);
        assert_eq!(LEADING_SLASH_BASE64_ENTROPY_FLOOR, 4.8);
        assert_eq!(SECOND_HALF_ENTROPY_FLOOR, 2.5);
    }

    /// Ordering contract among the plausibility floors and the shared thresholds.
    /// The symbolic-credential relaxation is only coherent as a floor BELOW the
    /// blanket high floor; the second-half tail floor sits well below the
    /// whole-token mixed-alnum floor; and the anchor-free leading-slash base64
    /// blob must clear the STRICTEST bar (above the high floor). If any of these
    /// inversions ever holds, the relaxation/gate logic is broken.
    #[test]
    fn plausibility_entropy_floors_are_ordered_coherently() {
        assert!(
            SYMBOLIC_CREDENTIAL_ENTROPY_FLOOR < HIGH_ENTROPY_THRESHOLD,
            "symbolic-credential relaxation must be a LOWER floor than the 4.5 blanket floor",
        );
        assert!(
            SECOND_HALF_ENTROPY_FLOOR < MIXED_ALNUM_TOKEN_THRESHOLD,
            "the second-half tail floor must sit below the whole-token mixed-alnum floor",
        );
        assert!(
            LEADING_SLASH_BASE64_ENTROPY_FLOOR > HIGH_ENTROPY_THRESHOLD,
            "the anchor-free leading-slash base64 floor must be the strictest",
        );
    }

    /// The hoisted canonical is the one-based origin: a zero-based `.lines()`
    /// index of 0 must resolve to source line 1, and the offset must add exactly
    /// one at every position (this is the arithmetic both `scanner` and
    /// `isolated` perform as `line_idx + FIRST_SOURCE_LINE_NUMBER`).
    #[test]
    fn first_source_line_number_is_the_one_based_origin() {
        assert_eq!(FIRST_SOURCE_LINE_NUMBER, 1);
        // Exactly the production expression: `line_idx + FIRST_SOURCE_LINE_NUMBER`.
        let line_of = |zero_based_index: usize| zero_based_index + FIRST_SOURCE_LINE_NUMBER;
        assert_eq!(line_of(0), 1);
        assert_eq!(line_of(9), 10);
        assert_eq!(line_of(41), 42);
    }

    /// End-to-end shape of the shared convention: enumerating lines and adding
    /// the canonical offset maps a three-line buffer onto the exact one-based
    /// numbers `[1, 2, 3]`, so the last line (`gamma`) reports line 3.
    #[test]
    fn line_base_maps_enumerated_lines_to_one_based_numbers() {
        let numbered: Vec<(usize, &str)> = "alpha\nbeta\ngamma"
            .lines()
            .enumerate()
            .map(|(idx, line)| (idx + FIRST_SOURCE_LINE_NUMBER, line))
            .collect();

        assert_eq!(
            numbered,
            vec![(1, "alpha"), (2, "beta"), (3, "gamma")],
            "enumerated line index + FIRST_SOURCE_LINE_NUMBER must yield 1-based line numbers",
        );
        assert_eq!(numbered.last().map(|&(line, _)| line), Some(3));
    }
