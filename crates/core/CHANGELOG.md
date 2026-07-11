# Changelog

## Unreleased

- Add the detector-owned `max_len` candidate ceiling, validate it with
  `min_len`, and bind it into detector digests so incremental caches and
  autoroute calibration cannot reuse evidence across different length policy.
  Rust callers using exhaustive `DetectorSpec` literals must set `max_len` or
  adopt `..DetectorSpec::default()` so subsequent additive policy fields remain
  source-compatible.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep detector specification, allowlist, reporting, and shared type APIs available for the 0.2 line.
