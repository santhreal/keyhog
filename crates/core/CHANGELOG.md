# Changelog

## 0.5.80 - 2026-08-17
- feat(guard): populate GuardPolicyIdentity with canonical default digests and digest calculation helpers for ignore files, suppressions, config, and source policy (Row 142).

- feat(core): export canonical DEFAULT_WINDOW_OVERLAP_BYTES and DEFAULT_WINDOW_SIZE_BYTES (Row 111).
- feat(allowlist): implement match attribution tracking and unused suppression entry reporting across detector, path, and hash rules (`AllowlistRule`, `UnusedAllowlistEntry`).
- feat(cache): add `cache_layout` module with canonical `CacheKind` enumeration, path classification, and `CacheEvictionPolicy` contracts.
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

- Added canonical `EvidenceTier`, `EvidenceReasonCode`, `EvidenceVerdict`, and `FindingProvenance` contracts. Findings, correlations, and report projections expose exact evidence tier and reason; JSON and JSONL also retain the detector-corpus digest, pattern ordinal, producer channel, source role, and pre-verification context class. Optional public scores are named `evidence_score`. JSON/JSONL report schema 2 rejects stale schema-1 findings, and deduplication preserves the strongest evidence and its provenance independently from internal scanner confidence.
- Detector TOML schema 4 adds typed capture, anchor, source-role, and required-evidence declarations with abstaining defaults, rejects them under older corpus manifests, rejects `unknown` inside allowed source-role lists, and round-trips non-default declarations through TOML.
- Detector TOML schema 5 adds exact pattern ownership and typed hard-negative classes to synthetic test evidence and rejects those fields under older corpus manifests. Corpus loading enforces complete per-pattern evidence only for schema 5; `validate_detector_for_corpus_schema` exposes the same versioned quality gate while schema-independent validation preserves schema-4 compatibility.
- Added independently versioned redacted triage, scoped runtime-suppression, and pattern-feedback schemas. Records consume exact public `FindingProvenance`; closed reasons, typed scopes, BLAKE3-only finding/context/scope identities, strict bounds, and active-corpus validation reject stale or secret-bearing input. Producer channels must match their detector owner, and the public reassembly suffix resolves only to its canonical embedded detector.
- Merge remote-tracking branch 'origin/main'.

## 0.5.74 - 2026-08-14

- fix(release): ignore Marketplace-only tags.

## 0.5.73 - 2026-08-14

- fix(release): preflight registry dependencies.

## 0.5.72 - 2026-08-13

- release: publish the tag the bump job creates.

## 0.5.71 - 2026-08-13

- Cold one-shot and incremental scans now reuse a persisted MatcherArtifact of the eager compiled matcher graph across process invocations (format v4), with CacheId hit/miss/invalidation in profile output, fail-closed identity checks, soft-fail when cache prep fails, and --lockdown disabling the cache.

## 0.5.70 - 2026-08-10

- fix(profile): fail-closed overlapping allocation session peaks.

## 0.5.69 - 2026-08-10

- `keyhog scan --access-targets` reports the resource each credential opens: account, tenant, endpoint, database, or resource. A finding says where a credential is, not what it reaches, and the address is usually next to the credential where no detector can see it, because a companion regex is bounded to a few lines and captures the other half of the credential rather than the resource. Providers live in Tier-B `crates/core/data/access-targets.toml`, so adding one is a data edit. Off by default: with the flag absent the report has no `access_targets` key and findings are byte-identical. With it, `--format json-envelope` gains an `access_targets` object and the envelope schema minor moves 9 to 10, which is additive and readable by any consumer accepting a minor under major 1. Values are addresses only, never authenticators: connection-string rules skip userinfo, a rule may not capture the whole match, and any candidate whose digest matches a credential in the same report is dropped. Coverage is explicit, so an empty target list is never mistaken for `this credential opens nothing`: a finding from git history, a container layer, stdin, an unreadable path, a decoded or windowed view, or a file past the index cap is counted in `coverage.gaps` with a named reason and `complete` goes false. Separately, `keyhog detectors --mechanisms` prints which recovery mechanisms each detector declares (regex, keywords, structure, entropy, BPE, decode, companions, relations, verification, suppression, source admission), derived from detector TOML with the field that proves each one, and reports a mechanism KeyHog cannot yet express as unavailable with the reason rather than omitting it. It does not scan.

- HTML reports now serialize findings directly to their output stream with bounded per-finding memory while preserving verification-error redaction and script-breakout protection.

- Delete 235 source-grep shape tests across the five crate test trees. Each read a .rs file at runtime and asserted only substring presence or absence on that text, so they pinned how the source is spelled rather than what the scanner does; the project standard bans them. 107 test files went away entirely, 57 files lost individual tests, and every mod registration plus three Cargo [[test]] entries went with them. Two ambient-env gates (KEYHOG_THREADS, KEYHOG_DETECTORS) became four behavioural tests that drive the binary and read `config --effective` and `detectors --format json`. Each is a negative assertion, so each is paired with a positive case on the same output field, and both oracles were ablated to confirm the comparison discriminates: KEYHOG_THREADS=99 leaves `threads = auto` while --threads 3 moves the same line to 3, and KEYHOG_DETECTORS pointing at a one-detector directory leaves the corpus intact while --detectors on that directory reduces it to one. 23 source pins for network and filesystem security boundaries are kept deliberately: verifier_safety_contracts.rs, the DNS-pin and no-auto-decompression gates, the verifier proxy owner, the git safe-bin and no-follow-symlink gates, and the hosted-Git credential temp-file permission contract. That last pin was repointed at the whole hosted_git module after the module split moved the code it reads out of hosted_git.rs, which had silently made its negative assertions vacuous, and it now asserts an anchor first so it fails loudly rather than passing for free the next time the module is reorganised.

- A scan that read zero bytes no longer reports as clean. A .keyhogignore containing `path:**` gave exit 0, scan_status success, zero bytes, zero chunks, an empty coverage_gap_summary, and the line `No secrets detected in the scanned files.` Every signal a consumer has said the tree was clean, and the scan had examined nothing at all. `--exclude-paths '**'`, an empty directory, an empty stdin stream, and a directory whose only entry is an unfollowed symlink all had the same shape. A scan that reads no source bytes now emits a FAIL-class `scan covered nothing` coverage-gap row and exits 13, and the text report states that the scan covered nothing instead of that nothing was detected. There are two such rows because the remedies differ: one for `no skip was counted` when nothing was there to read, and one for `every candidate was skipped by exclusion or skip policy` when policy hid it. THIS IS A USER-VISIBLE EXIT-CODE CHANGE. A target that legitimately holds nothing scannable moves from exit 0 to exit 13, including `keyhog scan --stdin` on an empty stream, an empty directory, a pure vendored tree, and a CI matrix partition with no files in its slice. That is intended: `git diff | keyhog scan --stdin` against the wrong base ref produces an empty diff, and reporting that as clean is the exact failure that makes mass scanning untrustworthy. Guard the producer, for example `[ -s changed.diff ]` before the pipe, rather than suppressing the exit code. There is deliberately no opt-out flag, because a flag that suppresses coverage failures would recreate the false affordance fixed alongside this. A scan that reads bytes and finds nothing is unaffected and still exits 0, and a scan that covered some input and failed on the rest still reports every finding it got alongside the gap, so exit 13 never means findings were discarded. Note that scan_status alone does not carry this: an ordinary git working-tree scan is already `partial` from its default-exclusion rows, so the usable signal is the FAIL/WARN class of the gap rows, which is what the exit code encodes.

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

- Refuse a non-default `max_file_size` or `dedup` on `ScanConfig` and name the surface that owns the behaviour, instead of accepting two documented no-op fields that gave a library caller the same scan they would have got by leaving them alone.

## 0.5.51 - 2026-08-04

- Make the portable phase-two prefilter two to three times faster and repair ten red gates.

## 0.5.50 - 2026-08-02

- Publish patch releases to crates.io through short-lived OIDC trusted publishing and bind deterministic six-crate integrity receipts to the exact workspace lockfile and commit.
- Add schema-v3 typed companion evidence and bounded cross-detector relation declarations, including their stable semantic digest fields.
- Add typed positive source-admission selectors and bind every selector to detector corpus identity.

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.
- Add confidence-gated fastest-candidate selection for benchmark and autoroute evidence. Statistically tied candidates keep deterministic order instead of changing routes on a point-median fluctuation.


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
