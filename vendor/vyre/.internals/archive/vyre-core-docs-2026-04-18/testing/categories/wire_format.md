# Wire format tests

## IR wire format

The IR wire format is the serialized form of an `ir::Program`. It is
how Programs are stored to disk, transmitted over the wire,
exchanged between processes, and archived for long-term
reproducibility. The IR wire format is not an executable; it is not
interpreted directly; there is no wire-format VM. It is a
compact binary representation that can be decoded back into an
`ir::Program` value, and once decoded it goes through the same
pipeline as any freshly built Program.

The decision to make the IR wire format a serialization rather than an
executable is architectural and is described in vyre's IR and
wire format docs. The short version: every execution path in vyre
goes through `ir::Program`. The IR wire format is optional — a convenience
for serialization — but when used, it must be a lossless encoding
of the IR. A round-trip through wire format must produce exactly the
original Program, bit-for-bit, forever.

The wire format test category verifies this property. It ensures
every wire-format variant has a correct decoder, every IR shape has a
correct encoder, and the round-trip on any valid Program produces
byte-identical bytes. Invariant I4 is the formal statement of
this property.

## The structure of the category

```
tests/integration/wire_format/
├── from_wire.rs        One test per wire variant, converting bytes to IR
├── to_wire.rs          One test per IR shape, converting IR to bytes
├── roundtrip.rs        Program → wire format → Program identity
├── tag_coverage.rs     Exhaustiveness meta-test on wire tags
├── malformed.rs        Decoding malformed wire-format bytes produces errors
└── corpus_roundtrip.rs Round-trip against the wire format corpus
```

Each file has a single concern, the same pattern as lowering
tests. The exhaustiveness meta-test forces new wire tags to come
with tests; the corpus file replays a committed set of Programs
for regression protection.

## Round-trip identity

The strongest property in wire format testing is round-trip
identity: encoding a Program to wire format and decoding the
wire format back produces the same Program. "Same" here means
byte-identical when compared field by field, with no tolerance.
If any bit changes, the round-trip is broken, and the broken
round-trip means stored Programs silently change meaning when
loaded.

```rust
/// Round-trip identity for a canonical Program.
/// Oracle: I4 (IR wire format round-trip identity).
#[test]
fn test_roundtrip_canonical_add_program() {
    let original = build_single_binop(BinOp::Add, 1u32, 2u32);

    let bytes = Program::to_wire(&original);
    let decoded = Program::from_wire(&bytes).expect("decode");

    assert_eq!(original, decoded);
}
```

The assertion uses `assert_eq!` on the whole Program, which
requires `ir::Program` to implement `PartialEq` and `Debug`. Both
traits are implemented deliberately for exactly this use case.
The comparison walks every field recursively: buffer list, entry
node, workgroup size, all of it.

The canonical program is a specific Program with a specific
shape chosen to exercise common cases. Similar tests exist for
more complex shapes:

- A Program with loops.
- A Program with conditionals.
- A Program with atomic operations.
- A Program with workgroup memory.
- A Program with the maximum allowed node count.
- A Program with deeply nested control flow.

Each of these is a separate test in `roundtrip.rs`, and each is a
specific input test — not a proptest. The generalization to
arbitrary programs happens in the property test file
`tests/property/wire_format_roundtrip.rs`, which generates random
Programs and asserts round-trip identity over thousands of cases.

## The wire-tag coverage meta-test

Every wire tag in the IR wire format must have a decoder test.
The meta-test enumerates the `WireTag` enum and checks that each
variant has been exercised:

```rust
/// Every WireTag variant has a decoder test.
#[test]
fn test_every_wire_tag_has_a_decode_test() {
    #[allow(dead_code)]
    fn exhaustive(tag: WireTag) {
        match tag {
            WireTag::Program    => verify(test_decode_program),
            WireTag::BufferDecl => verify(test_decode_buffer_decl),
            WireTag::Node       => verify(test_decode_node),
            WireTag::Expr       => verify(test_decode_expr),
            WireTag::BinOp      => verify(test_decode_binop),
            WireTag::DataType   => verify(test_decode_data_type),
            // ... every variant
        }
    }
}

fn verify(_test_fn: fn()) {}
```

Same pattern as the lowering coverage meta-test. Adding a new
`WireTag` variant without updating this match breaks the build,
which forces the contributor to write the decoder test before
the PR can land.

## A decoder test, in full

A decoder test constructs a specific wire-format buffer, decodes it,
and asserts the resulting IR Program matches expected:

```rust
/// A minimal Add Program decodes to the expected IR structure.
/// Oracle: IR wire format specification.
fn test_decode_minimal_add_program() {
    // Hand-constructed wire-format bytes for the minimal Add Program.
    // The exact byte layout is defined by the IR wire format specification.
    let bytes: &[u8] = &[
        0x01,  // WireTag::Program
        0x02,  // two inputs
        0x01,  // one output
    ];

    let decoded = Program::from_wire(bytes).expect("decode");

    assert_eq!(decoded, expected_minimal_add_program());
}
```

The test is narrow: one wire variant, one shape. A decoder bug that
affects only this variant would fail only this test, which is the
right scope for diagnosing the failure quickly.

## Encoder tests

Encoder tests are the mirror of decoder tests. They construct an
IR structure and assert it encodes to the expected bytes:

```rust
/// Expr::BinOp with BinOp::Add encodes to the expected bytes.
/// Oracle: IR wire format specification.
fn test_encode_add() {
    let expr = Expr::BinOp {
        op: BinOp::Add,
        lhs: Box::new(Expr::Local(1)),
        rhs: Box::new(Expr::Local(2)),
    };

    let bytes = vyre::ir::wire::encode_expr(&expr).expect("encode");

    assert_eq!(
        bytes,
        vec![0x05, 0x01, 0x02],
        "encoded bytes should match the IR wire format",
    );
}
```

Encoder tests pin down the exact byte layout. They are more
brittle than decoder tests (a change in byte layout breaks them)
but they are also the tests that guarantee the byte layout does
not change silently. If the layout is deliberately updated, the
encoder tests must be updated in the same PR, which forces the
change to be visible.

## Malformed input

Decoder behavior on malformed input is specified by the wire format
specification: the decoder returns a structured error, does not panic,
does not corrupt state. The malformed-input tests verify this
discipline:

```rust
/// Decoding truncated wire format returns a structured error.
/// Oracle: specification (no panic on malformed input).
#[test]
fn test_decode_truncated_wire_format_returns_error() {
    // Truncated input: wire tag followed by nothing.
    let bytes: &[u8] = &[0x05];

    let result = Program::from_wire(bytes);

    assert!(matches!(result, Err(DecodeError::Truncated { .. })));
}

/// Decoding an unknown wire tag returns a structured error.
/// Oracle: specification (no panic on malformed input).
#[test]
fn test_decode_unknown_wire_tag_returns_error() {
    let bytes: &[u8] = &[0xFF, 0x00, 0x00];

    let result = Program::from_wire(bytes);

    assert!(matches!(result, Err(DecodeError::UnknownTag(0xFF))));
}
```

These tests overlap conceptually with adversarial tests — they
test "code does not panic on hostile input" — but they live in
the wire format category because the assertion is specific to the
wire format decoder and uses the decoder's error types directly.
The general "no panic on any input" property is tested by the
adversarial category and by fuzzing.

## The corpus

`tests/integration/wire_format/corpus_roundtrip.rs` loads a set of
committed Programs from `tests/corpus/wire_format/` and round-trips
each one. The corpus is the regression suite for round-trip
identity: every Program in the corpus has been verified to
round-trip correctly, and any future change that breaks that
verification fails CI.

The corpus is committed as binary files (the wire format itself),
not as Rust source. Each file has a companion `.txt` file with a
description: where the Program came from, what it represents, why
it is in the corpus.

```
tests/corpus/wire_format/
├── minimal_add.wire
├── minimal_add.txt
├── loop_with_counter.wire
├── loop_with_counter.txt
├── diamond_dataflow.wire
├── diamond_dataflow.txt
└── ...
```

The `corpus_roundtrip.rs` test loads every `.wire` file in
the directory at test time and round-trips it:

```rust
/// Every Program in the corpus round-trips identity.
/// Oracle: I4 (IR wire format round-trip identity).
#[test]
fn test_corpus_roundtrip_identity() {
    for entry in fs::read_dir("tests/corpus/wire_format").expect("corpus exists") {
        let path = entry.unwrap().path();
        if path.extension() != Some(OsStr::new("wire")) {
            continue;
        }

        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).expect("read corpus");

        let decoded = Program::from_wire(&bytes)
            .unwrap_or_else(|e| panic!("decode {} failed: {}", name, e));

        let re_encoded = Program::to_wire(&decoded);

        assert_eq!(
            bytes, re_encoded,
            "corpus entry {} failed round-trip",
            name,
        );
    }
}
```

The corpus grows over time. Whenever a bug is found that
involves wire-format round-trip, the minimal reproducer is added to
the corpus as a permanent regression check. The corpus is also
seeded with canonical Programs representing common user patterns
so the round-trip test covers realistic shapes in addition to
adversarial ones.

## The version stability property

Invariant I13 (userspace stability) has a specific consequence
for wire format: a Program encoded by vyre v1.0 must decode correctly
by vyre v1.1 and produce a Program that dispatches to identical
output. This is the strict form of backwards compatibility, and
it is enforced by a cross-version test job.

The cross-version job is not strictly in `tests/integration/wire_format/`;
it lives in CI and replays old wire format files through the current
vyre version. But the integration test category is where the
canonical patterns are exercised, and the cross-version job is a
downstream consumer of those same patterns.

When a new wire format feature is added, the encoder must be
backwards compatible: old Programs encoded with the old schema
must continue to decode correctly. The new feature is introduced
as an additive extension, not a replacement. If the extension
requires a version bump, the old version's decoder is preserved
and the encoder defaults to the old version unless the new
feature is used.

See the wire format overview doc for the full backwards compatibility
discipline.

## The relationship with property tests

IR wire format integration tests cover specific inputs. They do not
cover arbitrary Programs. The general round-trip property —
"every valid Program round-trips" — is verified by
`tests/property/wire_format_roundtrip.rs`, which uses proptest to
generate random Programs and assert round-trip identity.

The property test is weaker than the integration test for any
specific Program (the integration test pins down the exact shape
and the exact bytes; the property test only asserts equality
after round-trip) but stronger for the general case (the property
test covers shapes the integration tests never thought of).
Both are needed.

## Summary

Wire format tests verify that vyre's IR wire format round-trips without
loss. Every wire tag has a decoder test (enforced by the
exhaustiveness meta-test). Every IR shape has an encoder test.
Specific Programs have round-trip tests; arbitrary Programs are
covered by the property test. A corpus of committed Programs
provides regression protection. Invariant I4 is the formal
statement of the contract, and this category is its primary
defense.

Next: [Adversarial tests](adversarial.md).
