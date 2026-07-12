//! Property invariants for `compiler_build::split_leading_inline_flag`, the hot
//! compile-path parser that peels a leading `(?ims)` / `(?ims:`… inline-flag
//! head off a detector regex. `compiler_split_flag_i` / `compiler_split_no_flag`
//! pin specific inputs; this sweeps thousands of adversarial strings and asserts
//! the two contracts every caller depends on:
//!
//!   1. PARTITION: `flag_prefix + body == input`, ALWAYS. Callers reassemble the
//!      regex as `format!("{flag_prefix}{body}")` (see `rewrite_homoglyph_literal_prefix`
//!      / `split_leading_inline_flag` uses), so a split that drops or duplicates a
//!      byte would silently corrupt the compiled pattern.
//!   2. TOTALITY: never panics — including on inputs where the byte after the flag
//!      chars is the lead of a multi-byte UTF-8 char (the fn indexes `s.as_bytes()`
//!      and slices `s[..=i]`/`s[i+1..]`; those slices must always land on char
//!      boundaries).
//!   3. FLAG-SHAPE: a non-empty flag head is a well-formed `(?<flags>)` group whose
//!      middle is drawn only from the `imsxuU-` flag alphabet.
//!
//! Plus a constructive direction: a genuine `(?<flags>)<body>` is split into
//! exactly its flag head and its body, for any flag subset and any body.

use keyhog_scanner::testing::split_leading_inline_flag;
use proptest::prelude::*;

/// The exact flag alphabet the parser accepts between `(?` and `)`.
const FLAG_CHARS: &[char] = &['i', 'm', 's', 'x', 'u', 'U', '-'];

/// Alphabet biased toward the flag-parsing branch (`(`, `?`, `)`, flag chars) and
/// including a 2-byte char (`é`) + a newline to stress char-boundary slicing.
const FUZZ_CHARS: &[char] = &[
    '(', '?', ')', 'i', 'm', 's', 'x', 'u', 'U', '-', 'a', '1', 'é', '\n',
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Arbitrary input: the split always partitions the string exactly and, when a
    /// flag head is peeled, that head is a well-formed `(?<flags>)` group.
    #[test]
    fn split_leading_inline_flag_partitions_any_input(
        idx in prop::collection::vec(0..FUZZ_CHARS.len(), 0..20usize),
    ) {
        let s: String = idx.iter().map(|&i| FUZZ_CHARS[i]).collect();

        let (flag_prefix, body) = split_leading_inline_flag(&s);

        // 1. PARTITION — the pieces reconstruct the input byte-for-byte.
        let mut recombined = String::with_capacity(flag_prefix.len() + body.len());
        recombined.push_str(flag_prefix);
        recombined.push_str(body);
        prop_assert_eq!(recombined.as_str(), s.as_str());

        // 3. FLAG-SHAPE — a non-empty head is `(?` … `)` with a flag-only middle.
        if !flag_prefix.is_empty() {
            prop_assert!(
                flag_prefix.starts_with("(?"),
                "flag head must start with (?: {flag_prefix:?}"
            );
            prop_assert!(
                flag_prefix.ends_with(')'),
                "flag head must end with ): {flag_prefix:?}"
            );
            let middle = &flag_prefix[2..flag_prefix.len() - 1];
            prop_assert!(
                middle.chars().all(|c| FLAG_CHARS.contains(&c)),
                "flag head middle has a non-flag char: {flag_prefix:?}"
            );
        }
    }

    /// Constructive: a real `(?<flags>)<body>` splits into exactly that head and
    /// that body — for any flag subset (incl. empty) and any body (incl. one that
    /// itself contains `)` or multi-byte chars).
    #[test]
    fn split_leading_inline_flag_extracts_the_exact_flag_head(
        flag_idx in prop::collection::vec(0..FLAG_CHARS.len(), 0..8usize),
        body in prop::collection::vec(any::<char>(), 0..12usize),
    ) {
        let flags: String = flag_idx.iter().map(|&i| FLAG_CHARS[i]).collect();
        let body: String = body.into_iter().collect();
        let input = format!("(?{flags}){body}");

        let (flag_prefix, rest) = split_leading_inline_flag(&input);

        let expected_head = format!("(?{flags})");
        prop_assert_eq!(flag_prefix, expected_head.as_str());
        prop_assert_eq!(rest, body.as_str());
    }
}
