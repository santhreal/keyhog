# Changelog

## 0.5.83 - 2026-08-24

- fix(ci): decouple action-e2e version pin from auto-release contract.

## 0.5.82 - 2026-08-24

- fix(cli): gate git-staged ScanArgs fields in hook run; enable futures-util sink.

## 0.5.81 - 2026-08-20

- bench(verifier): add criterion benchmarks for template interpolation, response classification, verification cache operations, SSRF/domain policy checks, and SigV4 canonicalization (Row 147).

## 0.5.80 - 2026-08-17

- style: format guard massive diff test and git sources modules.

## 0.5.79 - 2026-08-16

- ci(release): fallback token and sync floating major tag on release.

## 0.5.78 - 2026-08-16

- fix(scanner): gate expand_triggered_patterns independently of decode feature.

## 0.5.77 - 2026-08-16

- fix(ci): format scan_postprocess, update dogfood hashes for doc fixtures, and bump action version.

## 0.5.76 - 2026-08-16

- fix(core): rerun build script on GITHUB_SHA changes to prevent stale git hash in CI cache.

## 0.5.75 - 2026-08-14

- Merge remote-tracking branch 'origin/main'.

## 0.5.74 - 2026-08-14

- fix(release): ignore Marketplace-only tags.

## 0.5.73 - 2026-08-14

- fix(release): preflight registry dependencies.

## 0.5.72 - 2026-08-13

- release: publish the tag the bump job creates.

## 0.5.71 - 2026-08-13

- fix(release): consume legacy unreleased notes.

## 0.5.70 - 2026-08-10

- fix(profile): fail-closed overlapping allocation session peaks.

## 0.5.69 - 2026-08-10

- Out-of-band verification now polls only while callbacks are pending and uses a bounded three-request lifecycle burst while preserving the configured sustained collector rate.
- Out-of-band verification now overlaps its one-shot RSA session-key generation with scanning before collector registration.

- Delete 235 source-grep shape tests across the five crate test trees. Each read a .rs file at runtime and asserted only substring presence or absence on that text, so they pinned how the source is spelled rather than what the scanner does; the project standard bans them. 107 test files went away entirely, 57 files lost individual tests, and every mod registration plus three Cargo [[test]] entries went with them. Two ambient-env gates (KEYHOG_THREADS, KEYHOG_DETECTORS) became four behavioural tests that drive the binary and read `config --effective` and `detectors --format json`. Each is a negative assertion, so each is paired with a positive case on the same output field, and both oracles were ablated to confirm the comparison discriminates: KEYHOG_THREADS=99 leaves `threads = auto` while --threads 3 moves the same line to 3, and KEYHOG_DETECTORS pointing at a one-detector directory leaves the corpus intact while --detectors on that directory reduces it to one. 23 source pins for network and filesystem security boundaries are kept deliberately: verifier_safety_contracts.rs, the DNS-pin and no-auto-decompression gates, the verifier proxy owner, the git safe-bin and no-follow-symlink gates, and the hosted-Git credential temp-file permission contract. That last pin was repointed at the whole hosted_git module after the module split moved the code it reads out of hosted_git.rs, which had silently made its negative assertions vacuous, and it now asserts an anchor first so it fails loudly rather than passing for free the next time the module is reorganised.

- AWS STS HTTP 200 responses without parseable caller-identity metadata no longer report Live.
- Script auth verification requires exact STATUS: LIVE/DEAD lines and rejects ambiguous mixed output.

## 0.5.68 - 2026-08-05

- Scanner source files freed of large co-located test suites.

## 0.5.67 - 2026-08-05

- Filesystem enumeration-order contract.

## 0.5.66 - 2026-08-04

- Whole-tree GPU guidance in the backends guide.

## 0.5.65 - 2026-08-04

- Actionable GPU refusal diagnostics.

## 0.5.64 - 2026-08-04

- README evidence panels remeasured against the current detector corpus.

## 0.5.63 - 2026-08-04

- Mailchimp datacenter key routing.

## 0.5.62 - 2026-08-04

- Routing literals for every prefixless detector pattern.

## 0.5.61 - 2026-08-04

- Character-class token anchoring for short vendor prefixes.

## 0.5.60 - 2026-08-04

- Token-boundary anchoring for short vendor prefixes.

## 0.5.59 - 2026-08-04

- Token-boundary anchoring and an actionable autoroute parity rejection.

## 0.5.58 - 2026-08-04

- README evidence panels remeasured against the current binary.

## 0.5.57 - 2026-08-04

- Repeatable autoroute calibration.

## 0.5.56 - 2026-08-04

- Overlapping coalesced batches and autoroute classification for any batch size.

## 0.5.55 - 2026-08-04

- Idempotent source contract-test generator and a warning-free workspace build.

## 0.5.54 - 2026-08-04

- Skip homoglyph variants on chunks that provably contain no confusable glyph.

## 0.5.53 - 2026-08-04

- Make the coalesced batch pipeline eleven times faster and stop starving the accelerator.

## 0.5.52 - 2026-08-04

- Refuse configuration fields the scanner cannot honour and check every documented command against the real CLI.

## 0.5.51 - 2026-08-04

- Make the portable phase-two prefilter two to three times faster and repair ten red gates.

## 0.5.50 - 2026-08-02

- Publish a patch release to crates.io after every successful main CI run, with automatic version and changelog updates and no signing or release-asset gates.

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.

## 0.5.48 - 2026-07-28

- Preserve verifier isolation in its dedicated integration lane and bind the
  package candidate to the exact validated release commit and signed SPDX
  dependency graph.


## 0.5.47 - 2026-07-26

- Bind the crate release identity to the KeyHog installer-recovery patch so
  exact internal dependency pins and the published package graph remain
  coherent.

## 0.5.46 - 2026-07-24

- Normalize missing schema-1 verifier success policy to
  `status_with_error_backstop`, require an explicit policy in schema 2, and
  reject forward schema versions. Corpus identity binds the normalized schema
  so equivalent detector fields under different schemas remain distinct.
- Redact verifier proxy credentials, query parameters, percent-decoded secrets,
  and parser source text from invalid-URL errors. Diagnostics include only a
  safely parsed scheme and host or the generic invalid-proxy message.

## 0.5.45 - 2026-07-22

- Republish verifier backends in the release chain whose signed asset
  publication addresses GitHub drafts by immutable release ID.

## 0.5.44 - 2026-07-22

- Republish verifier backends in the corrected five-crate release chain after
  the Windows GPU literal artifact generator fix.

## 0.5.43 - 2026-07-22

- Preserve redacted response-stream and UTF-8 causes in verification errors
  while retaining the stable operator-guidance prefixes.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep live verification, response evaluation, cache, rate-limit, and SSRF protection APIs available for the 0.2 line.
