//! Regression coverage for the core provenance types: `Chunk`,
//! `ChunkMetadata`, and the `SensitiveString` redaction contract.
//!
//! These assert CONCRETE expected values (exact strings, byte counts,
//! span tuples, serialized JSON shapes) so a regression in redaction,
//! source-type propagation, or decoded-span accounting fails loudly.
//!
//! Standalone integration test: sees only the crate's public API
//! (`keyhog_core::*`). `SensitiveString::as_str` is `pub(crate)`, so the
//! bytes are reached through `Deref<Target = str>` (`&*value`) / `Display`,
//! never that private accessor.

use keyhog_core::{Chunk, ChunkMetadata, SensitiveString, SourceError};

/// The exact decoder-child `source_type` convention used by the decode
/// splice path: `format!("{}/{}", parent_source_type, decoder_name)`.
fn decoded_child_source_type(parent: &str, decoder: &str) -> String {
    format!("{parent}/{decoder}")
}

#[test]
fn chunk_from_str_carries_data_and_default_metadata() {
    let chunk = Chunk::from("API_KEY=sk_live_example");

    // Data round-trips through the SensitiveString Deref to the real bytes.
    assert_eq!(&*chunk.data, "API_KEY=sk_live_example");
    // Default metadata: empty source_type, no path, zeroed offsets.
    assert_eq!(chunk.metadata.source_type.as_ref(), "");
    assert_eq!(chunk.metadata.path, None);
    assert_eq!(chunk.metadata.base_offset, 0);
    assert_eq!(chunk.metadata.base_line, 0);
    assert_eq!(chunk.metadata.mtime_ns, None);
    assert_eq!(chunk.metadata.size_bytes, None);
    // A plain (non-decode) chunk never carries a decoded span.
    assert_eq!(chunk.metadata.decoded_span, None);
}

#[test]
fn chunk_explicit_metadata_records_source_type_path_and_line() {
    let chunk = Chunk {
        data: "TOKEN=value".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config/app.env".into()),
            base_offset: 1024,
            base_line: 42,
            ..Default::default()
        },
    };

    assert_eq!(chunk.metadata.source_type.as_ref(), "filesystem");
    assert_eq!(chunk.metadata.path.as_deref(), Some("config/app.env"));
    assert_eq!(chunk.metadata.base_offset, 1024);
    assert_eq!(chunk.metadata.base_line, 42);
    assert_eq!(&*chunk.data, "TOKEN=value");
}

#[test]
fn sensitive_string_debug_redacts_bytes_and_hides_secret() {
    // "sk_live_" (8) + "DEADBEEF01" (10) = 18 bytes.
    let secret: SensitiveString = "sk_live_DEADBEEF01".into();

    let dbg = format!("{secret:?}");
    assert_eq!(dbg, "SensitiveString(<redacted 18 bytes>)");
    // The raw secret must never appear in the Debug rendering.
    assert!(!dbg.contains("sk_live"));
    assert!(!dbg.contains("DEADBEEF01"));
}

#[test]
fn sensitive_string_deref_exposes_real_bytes() {
    let secret: SensitiveString = "sk_live_DEADBEEF01".into();

    // Deref to &str exposes the genuine content and length.
    assert_eq!(&*secret, "sk_live_DEADBEEF01");
    assert_eq!(secret.len(), 18);
    assert_eq!(secret.as_bytes()[0], b's');
    assert_eq!(secret.as_bytes()[17], b'1');
}

#[test]
fn sensitive_string_display_exposes_bytes() {
    // Display is the deliberate auditable surface (unlike Debug).
    let secret: SensitiveString = "ghp_realTokenBytes".into();
    let shown = format!("{secret}");
    assert_eq!(shown, "ghp_realTokenBytes");
}

#[test]
fn chunk_debug_does_not_leak_credential_material() {
    let chunk = Chunk {
        // "glpat-" (6) + "ABCDEFGHIJKLMNOPQRST" (20) = 26 bytes.
        data: "glpat-ABCDEFGHIJKLMNOPQRST".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            ..Default::default()
        },
    };

    let dbg = format!("{chunk:?}");
    // The derived Chunk Debug surfaces the metadata source_type...
    assert!(dbg.contains("source_type: \"filesystem\""));
    // ...but the sensitive payload is redacted to a byte count.
    assert!(dbg.contains("SensitiveString(<redacted 26 bytes>)"));
    assert!(!dbg.contains("glpat-ABCDEFGHIJKLMNOPQRST"));
}

#[test]
fn spliced_decoded_child_records_decoder_in_source_type() {
    let parent = ChunkMetadata {
        source_type: "filesystem".into(),
        path: Some("secrets.b64".into()),
        base_offset: 100,
        base_line: 3,
        ..Default::default()
    };

    let text = "AKIAIOSFODNN7EXAMPLE"; // decoded plaintext, 20 bytes
    let child = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: decoded_child_source_type(&parent.source_type, "base64").into(),
            path: parent.path.clone(),
            base_offset: parent.base_offset,
            base_line: parent.base_line,
            decoded_span: Some((0, text.len())),
            ..Default::default()
        },
    };

    // The decoder name is appended after a `/`, so the leaf segment names it.
    assert_eq!(child.metadata.source_type.as_ref(), "filesystem/base64");
    assert_eq!(
        child.metadata.source_type.rsplit('/').next(),
        Some("base64")
    );
    assert!(child.metadata.source_type.contains("base64"));
    // Provenance path is inherited from the parent chunk.
    assert_eq!(child.metadata.path.as_deref(), Some("secrets.b64"));
    // A decode sub-chunk always carries a decoded_span; here it spans all 20 bytes.
    assert_eq!(child.metadata.decoded_span, Some((0, 20)));
}

#[test]
fn decoded_span_records_exact_splice_window() {
    // A decoded blob spliced into a parent window at byte offset 5.
    let decoded_at = 5usize;
    let text_len = 14usize;
    let child = ChunkMetadata {
        source_type: "http/gzip".into(),
        decoded_span: Some((decoded_at, decoded_at + text_len)),
        ..Default::default()
    };
    assert_eq!(child.decoded_span, Some((5, 19)));

    // Whole-file chunks never carry a span.
    let whole = ChunkMetadata {
        source_type: "filesystem".into(),
        ..Default::default()
    };
    assert_eq!(whole.decoded_span, None);
}

#[test]
fn metadata_serializes_source_type_and_skips_absent_optionals() {
    let metadata = ChunkMetadata {
        source_type: "git-diff".into(),
        path: Some("src/lib.rs".into()),
        commit: Some("abc123".into()),
        author: Some("Dev".into()),
        date: Some("2026-03-26T00:00:00Z".into()),
        ..Default::default()
    };

    let value = serde_json::to_value(&metadata).expect("metadata serializes");
    assert_eq!(value["source_type"], "git-diff");
    assert_eq!(value["path"], "src/lib.rs");
    assert_eq!(value["commit"], "abc123");
    assert_eq!(value["author"], "Dev");
    assert_eq!(value["date"], "2026-03-26T00:00:00Z");
    assert_eq!(value["base_offset"], 0);
    assert_eq!(value["base_line"], 0);
    // `skip_serializing_if = "Option::is_none"` drops these keys entirely.
    assert!(value.get("mtime_ns").is_none());
    assert!(value.get("size_bytes").is_none());
    assert!(value.get("decoded_span").is_none());
}

#[test]
fn metadata_serializes_decoded_span_as_two_element_array() {
    let metadata = ChunkMetadata {
        source_type: "filesystem/base64".into(),
        decoded_span: Some((3, 9)),
        mtime_ns: Some(1_700_000_000_000_000_000),
        size_bytes: Some(4096),
        ..Default::default()
    };

    let value = serde_json::to_value(&metadata).expect("metadata serializes");
    assert_eq!(value["decoded_span"], serde_json::json!([3, 9]));
    assert_eq!(value["mtime_ns"], 1_700_000_000_000_000_000u64);
    assert_eq!(value["size_bytes"], 4096);
}

/// Pins the serialization CONTRACT that the `Arc<str>` migration had to preserve
/// (and did — the pre-migration `Option<String>` fields carried NO
/// `skip_serializing_if` either): `path`/`commit`/`author`/`date` serialize an
/// ABSENT value as JSON `null` (present key, null value), while
/// `mtime_ns`/`size_bytes`/`decoded_span` (which DO carry `skip_serializing_if`)
/// drop out of the object entirely. Nothing else pins the null-for-absent half
/// of that intentional asymmetry, so a stray `skip_serializing_if` added to a
/// provenance field — or a serde-helper that emitted absent-as-omitted — would
/// silently change the wire shape without this guard.
#[test]
fn absent_provenance_optionals_serialize_as_null_while_capped_optionals_are_skipped() {
    let value =
        serde_json::to_value(ChunkMetadata::default()).expect("default metadata serializes");

    // Provenance optionals via serde_arc_str_opt: present-as-null (no skip).
    for field in ["path", "commit", "author", "date"] {
        assert_eq!(
            value[field],
            serde_json::Value::Null,
            "absent `{field}` must serialize as null (matching the pre-Arc<str> Option<String>), not be skipped"
        );
    }
    // Cheap-telemetry optionals: skip_serializing_if omits them entirely.
    for field in ["mtime_ns", "size_bytes", "decoded_span"] {
        assert!(
            value.get(field).is_none(),
            "`{field}` carries skip_serializing_if, so an absent value must be OMITTED, not null"
        );
    }
    // The non-optional Arc<str> source_type: an empty default serializes as "".
    assert_eq!(value["source_type"], "");
    // The numeric fields keep their zero defaults on the wire.
    assert_eq!(value["base_offset"], 0);
    assert_eq!(value["base_line"], 0);
}

#[test]
fn sensitive_string_empty_reports_zero_bytes() {
    let empty: SensitiveString = "".into();
    assert_eq!(format!("{empty:?}"), "SensitiveString(<redacted 0 bytes>)");
    assert_eq!(&*empty, "");
    assert_eq!(empty.len(), 0);
}

#[test]
fn sensitive_string_redaction_counts_bytes_not_chars() {
    // "café🔑": c,a,f = 3 bytes, é (U+00E9) = 2 bytes, 🔑 (U+1F511) = 4 bytes => 9 bytes.
    let s: SensitiveString = "café🔑".into();
    assert_eq!(s.len(), 9); // byte length
    assert_eq!(s.chars().count(), 5); // char count differs
    assert_eq!(format!("{s:?}"), "SensitiveString(<redacted 9 bytes>)");
}

#[test]
fn sensitive_string_equality_and_ordering_follow_content() {
    let a: SensitiveString = "aaa".into();
    let a2: SensitiveString = "aaa".into();
    let b: SensitiveString = "bbb".into();

    assert_eq!(a, a2);
    assert_ne!(a, b);
    assert!(a < b);
    assert!(b > a2);
}

#[test]
fn chunk_clone_preserves_data_and_metadata() {
    let original = Chunk {
        data: "sk_live_CLONETEST".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("a.env".into()),
            base_line: 7,
            ..Default::default()
        },
    };

    let cloned = original.clone();
    assert_eq!(&*cloned.data, "sk_live_CLONETEST");
    assert_eq!(cloned.data, original.data);
    assert_eq!(&*cloned.metadata.source_type.as_ref(), "filesystem");
    assert_eq!(cloned.metadata.path.as_deref(), Some("a.env"));
    assert_eq!(cloned.metadata.base_line, 7);
}

/// The POINT of the `ChunkMetadata` `Arc<str>` migration (2026-07-07): cloning a
/// chunk's metadata must be a refcount BUMP, not a heap alloc + memcpy of the
/// five provenance strings. The decode splice path clones parent metadata once
/// per decoded sub-chunk (`decode/pipeline/splice.rs`), so a copy here would be a
/// per-blob allocation on the hottest decode path. This pins the shared-pointer
/// guarantee: after `clone()`, every `Arc<str>` field points at the SAME
/// allocation as the original — proven by pointer identity, not value equality
/// (value equality would still pass if the migration had silently reverted to a
/// copying `String`, so it cannot prove the perf property; `Arc::ptr_eq` can).
#[test]
fn chunk_metadata_clone_shares_arc_allocations_not_copies() {
    use std::sync::Arc;

    let original = ChunkMetadata {
        source_type: "filesystem".into(),
        path: Some("deep/nested/config/app.env".into()),
        commit: Some("deadbeefcafebabe0123456789abcdef".into()),
        author: Some("Provenance Author".into()),
        date: Some("2026-07-07T00:00:00Z".into()),
        base_offset: 4096,
        base_line: 128,
        ..Default::default()
    };

    // Sole owner before any clone.
    assert_eq!(Arc::strong_count(&original.source_type), 1);

    let cloned = original.clone();

    // Every Arc<str> field in the clone points at the SAME heap allocation as the
    // original — a refcount bump, not a copy. `Arc<str>` never uses inline
    // storage, so pointer identity is the exact "did we avoid the alloc" proof.
    assert!(
        Arc::ptr_eq(&original.source_type, &cloned.source_type),
        "clone must SHARE the source_type allocation, not copy it"
    );
    assert!(
        Arc::ptr_eq(
            original.path.as_ref().unwrap(),
            cloned.path.as_ref().unwrap()
        ),
        "clone must SHARE the path allocation"
    );
    assert!(Arc::ptr_eq(
        original.commit.as_ref().unwrap(),
        cloned.commit.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        original.author.as_ref().unwrap(),
        cloned.author.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        original.date.as_ref().unwrap(),
        cloned.date.as_ref().unwrap()
    ));

    // The shared allocation is now referenced twice; dropping the clone returns
    // the count to 1 (no leak, no premature free — the Arc bookkeeping is sound).
    assert_eq!(Arc::strong_count(&original.source_type), 2);
    drop(cloned);
    assert_eq!(Arc::strong_count(&original.source_type), 1);

    // Sharing carries no aliasing hazard (`Arc<str>` is immutable) and the values
    // remain exactly correct after the clone/drop cycle.
    assert_eq!(original.source_type.as_ref(), "filesystem");
    assert_eq!(original.path.as_deref(), Some("deep/nested/config/app.env"));
}

/// Mirrors the decode splice hot path (`decode/pipeline/splice.rs`): a decoded
/// sub-chunk inherits the parent's provenance by CLONING each `Arc<str>` field
/// while rebuilding `source_type` as `parent/decoder`. This pins that the
/// inherited path/commit/author/date SHARE the parent's allocations (the
/// per-sub-chunk win) while the freshly-built `source_type` is a DISTINCT
/// allocation (correct — it differs per decoder, so it cannot be shared).
#[test]
fn decoded_child_shares_parent_provenance_but_owns_fresh_source_type() {
    use std::sync::Arc;

    let parent = ChunkMetadata {
        source_type: "filesystem".into(),
        path: Some("archive/secrets.b64".into()),
        commit: Some("feedface".into()),
        author: Some("Author".into()),
        date: Some("2026-07-07T00:00:00Z".into()),
        ..Default::default()
    };

    // The exact splice construction: inherited fields are Arc clones,
    // source_type is rebuilt via `format!("{parent}/{decoder}")`.
    let child = ChunkMetadata {
        source_type: decoded_child_source_type(&parent.source_type, "base64").into(),
        path: parent.path.clone(),
        commit: parent.commit.clone(),
        author: parent.author.clone(),
        date: parent.date.clone(),
        decoded_span: Some((0, 20)),
        ..Default::default()
    };

    // Inherited provenance shares the parent's allocations (refcount bumps).
    assert!(Arc::ptr_eq(
        parent.path.as_ref().unwrap(),
        child.path.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        parent.commit.as_ref().unwrap(),
        child.commit.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        parent.author.as_ref().unwrap(),
        child.author.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        parent.date.as_ref().unwrap(),
        child.date.as_ref().unwrap()
    ));
    // source_type is a fresh "parent/decoder" string — necessarily a DISTINCT
    // allocation, since it is not equal to the parent's.
    assert_eq!(child.source_type.as_ref(), "filesystem/base64");
    assert!(!Arc::ptr_eq(&parent.source_type, &child.source_type));
}

#[test]
fn source_error_display_includes_actionable_fix() {
    let other = SourceError::Other("bad input".into());
    let other_msg = other.to_string();
    assert_eq!(
        other_msg,
        "failed to read source: bad input. Fix: adjust the source settings or input so KeyHog can read plain text safely"
    );

    let git = SourceError::Git("no HEAD".into());
    let git_msg = git.to_string();
    assert!(git_msg.contains("valid git repository"));
    assert!(git_msg.contains("no HEAD"));
}
