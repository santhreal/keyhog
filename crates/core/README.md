# keyhog-core

Shared domain types for the KeyHog secret scanner: the detector spec model, the
embedded detector corpus, chunk and finding types, redaction, and the
report-safe boundary every other crate projects through.

Part of the [KeyHog](https://github.com/santhreal/keyhog) secret scanner.

```rust
use keyhog_core::{detector_spec_by_id, embedded_detector_count, redact};

// The compiled-in corpus. Every crate borrows this one materialized copy.
let count = embedded_detector_count();
assert!(count > 0);

// Detectors are addressable by their stable id. `aws-access-key` is in the
// shipped corpus, so this resolving is itself a check that the corpus loaded.
let spec = detector_spec_by_id("aws-access-key").expect("shipped detector");
assert_eq!(spec.id, "aws-access-key");

// Anything derived from scanned bytes is redacted before it can be printed.
// The control comes first: prove the needle is visible in the input, so a
// probe that can see nothing at all cannot pass this as a clean redaction.
let plaintext = "AKIAIOSFODNN7EXAMPLE";
assert!(plaintext.contains("IOSFODNN7"));
let safe = redact(plaintext);
assert!(!safe.contains("IOSFODNN7"));
```

## Public entry points

- `load_embedded_detectors_or_fail` parses the compiled-in corpus and returns a
  typed error naming every detector that failed. It never returns a partial set.
- `embedded_detector_specs` is the one materialized corpus. Borrow from it
  rather than re-parsing, and `detector_spec_by_id` indexes it.
- `embedded_detector_count`, `detector_digest`, and `git_hash` identify exactly
  which corpus and build you are running. Benchmarks and caches key on these.
- `Credential` and `SensitiveString` hold plaintext. `redact` and the report
  types in `report` are the projection you use before anything leaves the
  process.
- `spec` owns detector validation. A detector that does not validate is a build
  or authoring error, never a scan-time condition.

## Failure behavior

A corrupt compiled-in corpus stops startup with the exact parse error. The crate
does not substitute an empty or reduced detector set, because a scanner that
silently loads fewer detectors reports a clean result on a file that has a
secret in it.

## Features

The default build has no optional features and no native build prerequisite.
The detector corpus is compiled in by `build.rs` from the workspace `detectors/`
directory, so the crate needs no data files at runtime.

## Documentation

- [Detectors](https://santhreal.github.io/keyhog/detectors.html) describes the
  spec schema these types model.
- [Architecture](https://santhreal.github.io/keyhog/architecture.html) describes
  where this crate sits and which direction dependencies run.
- API documentation is on [docs.rs](https://docs.rs/keyhog-core).
