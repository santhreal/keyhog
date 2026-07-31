# Changelog

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the five-crate crates.io publication chain.

## 0.5.48 - 2026-07-28

- Bind the core package candidate to the exact validated release commit and its
  signed, feature-resolved SPDX dependency graph.


## 0.5.47 - 2026-07-26

- Bind the crate release identity to the KeyHog installer-recovery patch so
  exact internal dependency pins and the published package graph remain
  coherent.

## 0.5.46 - 2026-07-24

- Make implicit serde serialization of `Credential` and `SensitiveString`
  fail before emitting secret bytes. `RawMatch`, `DedupedMatch`, and `Chunk`
  therefore require an explicit protected conversion instead of serializing
  plaintext, while historical plaintext and tagged deserialization still work.
- Add canonical `corpus.toml` schema identity. Schema 1 keeps its conservative
  verifier-policy migration, schema 2 requires explicit policy, and forward or
  malformed schemas fail with typed errors. Detector digests and scan report
  metadata bind the manifest bytes and schema so caches, daemon evidence, and
  autoroute evidence cannot cross corpus semantics.
- Add `complete_after_recovery` as a complete scan terminal state and preserve
  bounded backend-recovery evidence across the current JSON and JSONL report
  contracts.

- Add detector-owned `plausibility.keyword_free_operator_margin`, validate it
  only for the `keyword-free` entropy role, and bind it into detector identity.

- Add an opt-in source ordering contract for contiguous chunk identities so
  dispatchers can split routing batches without assuming concrete source types.

- Add shared overflow-safe median and paired confidence primitives for
  autoroute calibration and release crossover evidence.

## 0.5.45 - 2026-07-22

- Republish the core library in the release chain whose signed asset
  publication addresses GitHub drafts by immutable release ID.

## 0.5.44 - 2026-07-22

- Republish the core library in the corrected five-crate release chain after
  the Windows GPU literal artifact generator fix.

## 0.5.43 - 2026-07-22

- Use one bounded detector TOML reader in both the runtime loader and the build
  script. Embedded-corpus generation now enforces the same 16 MiB per-file cap
  and detects files that grow past the cap during a read.
- Watch Git HEAD reflogs as well as loose and packed refs when stamping build
  provenance. A same-branch commit now invalidates stale candidate identity.
- Add detector-owned `decode_transforms` policy for reverse and Caesar
  admission, validate its literal prefixes, and bind it into detector identity.
- Bind non-default detector resolution priority into detector identity without
  changing the canonical digest of detectors that use the default policy.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep detector specification, allowlist, reporting, and shared type APIs available for the 0.2 line.
