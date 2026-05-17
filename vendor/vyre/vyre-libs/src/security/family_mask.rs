//! Family name → tag-bit mask allocation.
//!
//! Canonical bit allocation for every `@family` predicate label that
//! appears in surge rules. Shared across consumers so the predicate-
//! side `@family` resolver and the source-side classifier agree on
//! which bit a family lives at.
//!
//! Every family used in any rule must be represented explicitly in
//! [`CANONICAL_BITS`]. There is no synthetic-bit fallback — a family
//! without an entry is a compile-time error.
//!
//! # Bit layout
//!
//! - bits 0..15  — canonical security families (ALLOCATOR, RECEIVE,
//!   SANITIZER, etc.).
//! - bits 16..18 — reserved for structural families (FUNCTION, FILE,
//!   PACKAGE) declared by consumers.
//! - bits 19..23 — reserved for consumer extension tags (e.g.
//!   STRING_LITERAL, STACK_ARRAY).
//! - bits 24..31 — launch-family unique bits.

/// Canonical family → tag-bit mask. Returns `None` for any family
/// without an explicit allocation.
#[must_use]
pub fn canonical_family_mask(family: &str) -> Option<u32> {
    CANONICAL_BITS
        .iter()
        .find_map(|(name, bit)| (*name == family).then_some(*bit))
}

/// Strict resolution: returns the canonical bit allocation, or an
/// actionable error string for any family without an explicit entry
/// in [`CANONICAL_BITS`]. Callers that have their own error type
/// should wrap this `String` into their domain error.
///
/// # Errors
///
/// Returns `Err` when `family` is not registered in [`CANONICAL_BITS`].
pub fn resolve_label_family_mask(family: &str) -> Result<u32, String> {
    canonical_family_mask(family).ok_or_else(|| {
        format!(
            "label family `@{family}` has no canonical bit allocation. \
             Fix: declare the family in vyre_libs::security::family_mask::CANONICAL_BITS."
        )
    })
}

// ────────────────────────────────────────────────────────────────────
// Canonical security families — bits 0..15.
// ────────────────────────────────────────────────────────────────────

pub const ALLOCATOR: u32 = 1 << 0;
pub const RECEIVE: u32 = 1 << 1;
pub const OVERFLOW_CHECK: u32 = 1 << 2;
pub const SANITIZER: u32 = 1 << 3;
pub const SOURCE_NETWORK: u32 = 1 << 4;
pub const SINK_FILESYSTEM: u32 = 1 << 5;
pub const SINK_PROCESS: u32 = 1 << 6;
pub const COPY_TO_USER: u32 = 1 << 7;
pub const FREE: u32 = 1 << 8;
pub const COMPARISON_OP: u32 = 1 << 9;
pub const DECODE: u32 = 1 << 10;
pub const INFLATE: u32 = 1 << 11;
pub const TYPE_CAST_UNCHECKED: u32 = 1 << 12;
pub const PRIVILEGE_CHECK: u32 = 1 << 13;
pub const PRIVILEGE_USE: u32 = 1 << 14;

// ────────────────────────────────────────────────────────────────────
// Launch-family unique bits — bits 24..31. 8 slots; each is OR'd onto
// a node alongside any canonical bit it semantically inherits, so
// `call_to(@receive_family)` continues to match every receive call
// (broad) while `call_to(@gets_family)` matches only `gets`-shaped
// calls (narrow).
// ────────────────────────────────────────────────────────────────────

pub const GETS_LAUNCH: u32 = 1 << 24;
pub const PRINTF_LAUNCH: u32 = 1 << 25;
pub const UNBOUNDED_COPY_LAUNCH: u32 = 1 << 26;
pub const UNBOUNDED_SPRINTF_LAUNCH: u32 = 1 << 27;
pub const POINTER_USE_LAUNCH: u32 = 1 << 28;
pub const TYPE_TAG_CHECK_LAUNCH: u32 = 1 << 29;
pub const REASSIGN_NULL_AFTER_FREE_LAUNCH: u32 = 1 << 30;
pub const BOUNDED_COPY_OR_LENGTH_CHECK_LAUNCH: u32 = 1 << 31;

/// Canonical family allocation table.
///
/// Every family that appears in a `@family` predicate or in
/// classifier labels must be represented explicitly here. Adding a
/// new family is a one-line append; running out of low-32 room
/// requires widening `pg_node_tags` to two words and lifting this
/// table to `u64`.
pub const CANONICAL_BITS: &[(&str, u32)] = &[
    // Canonical security families.
    ("allocator_family", ALLOCATOR),
    ("deallocator_family", FREE),
    ("free_family", FREE),
    ("buffer_source_family", RECEIVE),
    ("buffer_source", RECEIVE),
    ("user_input_family", RECEIVE),
    ("untrusted_input_family", RECEIVE),
    ("receive_family", RECEIVE),
    ("untrusted_input", RECEIVE),
    ("overflow_check_family", OVERFLOW_CHECK),
    ("range_check_family", OVERFLOW_CHECK),
    ("length_clamp_family", OVERFLOW_CHECK),
    ("bounded_check_family", OVERFLOW_CHECK),
    ("checked_arith_or_size_clamp", OVERFLOW_CHECK),
    ("sanitizer_family", SANITIZER),
    ("html_escape_family", SANITIZER),
    ("shell_escape_family", SANITIZER),
    ("sql_escape_family", SANITIZER),
    ("url_validation_family", SANITIZER),
    ("auth_check_family", SANITIZER),
    ("authz_check_family", SANITIZER),
    ("password_check_family", SANITIZER),
    ("comparison_family", SANITIZER),
    ("prefix_guard_family", SANITIZER),
    ("pathname_sanitize_family", SANITIZER),
    ("path_canonicalize_family", SANITIZER),
    ("regex_safety_family", SANITIZER),
    ("crlf_sanitizer_family", SANITIZER),
    ("proto_key_sanitizer_family", SANITIZER),
    ("verify_arg_slot", SANITIZER),
    ("bounded_by_array_capacity", SANITIZER),
    ("bounded_sprintf_or_length_check", SANITIZER),
    ("network_input_source", SOURCE_NETWORK),
    ("http_input_family", SOURCE_NETWORK),
    ("http_client_family", SOURCE_NETWORK),
    ("file_sink", SINK_FILESYSTEM),
    ("file_open_family", SINK_FILESYSTEM),
    ("filesystem_open_family", SINK_FILESYSTEM),
    ("exec_family", SINK_PROCESS),
    ("exec_sink", SINK_PROCESS),
    ("copy_to_user_family", COPY_TO_USER),
    ("comparison_op_family", COMPARISON_OP),
    ("decoder_family", DECODE),
    ("decompressor_family", DECODE),
    ("inflate_family", INFLATE),
    ("decompression_cap_family", INFLATE),
    ("narrow_cast_family", TYPE_CAST_UNCHECKED),
    ("narrowing_cast_family", TYPE_CAST_UNCHECKED),
    ("pointer_cast_family", TYPE_CAST_UNCHECKED),
    ("type_cast_unchecked_family", TYPE_CAST_UNCHECKED),
    ("privilege_check_family", PRIVILEGE_CHECK),
    ("privilege_use_family", PRIVILEGE_USE),
    ("privileged_op_family", PRIVILEGE_USE),
    // Launch families.
    ("sized_input_read_family", RECEIVE),
    ("sized_memory_copy_family", UNBOUNDED_COPY_LAUNCH),
    ("reallocator_family", ALLOCATOR),
    ("null_check_family", SANITIZER),
    ("pointer_assignment_family", ALLOCATOR),
    ("gets_family", GETS_LAUNCH),
    ("gets", GETS_LAUNCH),
    ("printf_family", PRINTF_LAUNCH),
    ("printf", PRINTF_LAUNCH),
    ("unbounded_string_copy_family", UNBOUNDED_COPY_LAUNCH),
    ("unbounded_string_copy", UNBOUNDED_COPY_LAUNCH),
    ("unbounded_sprintf_family", UNBOUNDED_SPRINTF_LAUNCH),
    ("unbounded_sprintf", UNBOUNDED_SPRINTF_LAUNCH),
    ("pointer_use_family", POINTER_USE_LAUNCH),
    ("type_tag_check", TYPE_TAG_CHECK_LAUNCH),
    ("reassign_or_null_after_free", REASSIGN_NULL_AFTER_FREE_LAUNCH),
    ("bounded_copy_or_length_check", BOUNDED_COPY_OR_LENGTH_CHECK_LAUNCH),
    ("allocator", ALLOCATOR),
    ("deallocator", FREE),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_family_mask_returns_explicit_bit() {
        assert_eq!(canonical_family_mask("allocator_family"), Some(ALLOCATOR));
        assert_eq!(canonical_family_mask("gets_family"), Some(GETS_LAUNCH));
        assert_eq!(canonical_family_mask("not_a_family"), None);
    }

    #[test]
    fn resolve_errors_for_unknown_family() {
        let err = resolve_label_family_mask("unregistered").expect_err("must error");
        assert!(err.contains("unregistered"));
        assert!(err.contains("Fix:"));
    }

    #[test]
    fn launch_bits_are_unique() {
        let launch = [
            GETS_LAUNCH,
            PRINTF_LAUNCH,
            UNBOUNDED_COPY_LAUNCH,
            UNBOUNDED_SPRINTF_LAUNCH,
            POINTER_USE_LAUNCH,
            TYPE_TAG_CHECK_LAUNCH,
            REASSIGN_NULL_AFTER_FREE_LAUNCH,
            BOUNDED_COPY_OR_LENGTH_CHECK_LAUNCH,
        ];
        let mut seen = 0u32;
        for &b in &launch {
            assert_eq!(seen & b, 0, "launch bit collision at 0x{b:08x}");
            seen |= b;
        }
    }
}
