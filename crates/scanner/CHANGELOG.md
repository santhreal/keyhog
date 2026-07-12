# Changelog

## Unreleased

- Move generic-assignment candidate length bounds into each owning detector's
  TOML (`min_len` / `max_len`). The shared extractor derives its capture range
  from the detector corpus, applies the owning detector's inclusive ceiling,
  and rejects an overlength token whole instead of emitting a misleading
  truncated prefix.
- Skip repeated keyword-free entropy analysis for adjacent byte-identical
  lines after the first eligible copy; candidate-value deduplication already
  makes subsequent copies unable to add a finding, while generated sources and
  repeated log/config blocks avoid re-running the full entropy/shape pipeline.
- Reduce the operator backend surface to `auto`, `gpu`, `simd`, and `cpu`.
  Stable profile/evidence labels remain parseable by library and persistence
  paths, while MegaScan and implementation-name aliases no longer silently map
  to a live route. `ScanBackend::MegaScan` remains available to source-compatible
  library callers but is no longer produced by the parser.
- Make `CompiledScanner::scan` and `scan_coalesced` the deterministic portable CPU reference paths
  instead of an uncalibrated hardware heuristic. Accelerated library callers
  select a measured backend through `scan_with_backend`; the CLI continues to
  use persisted fastest-correct autoroute decisions.
- Add `CompiledScanner::try_with_config`, a fail-closed installation boundary
  for programmatic scanner configuration. It validates the complete shared
  `ScanConfig` before changing scanner state; both production CLI construction
  paths now use it. `with_config` remains available for source compatibility
  when callers already hold trusted, validated configuration.
- Add detector-owned BPE token-efficiency policy through
  `bpe_max_bytes_per_token` in detector TOML. Generic and entropy fallback
  paths resolve the same owning detector before applying the gate; detector
  policy takes precedence over the compiled fallback, while an explicitly set
  scan TOML/CLI value remains the final visible Tier-A override. Invalid
  non-positive/non-finite bounds fail closed,
  and the field participates in the detector digest used by caches and
  calibration identity. Opaque generic API-key/secret policies use the measured
  2.2 ceiling; password/passphrase-oriented policies explicitly disable the
  word-likeness rejection so human-chosen phrases do not become false negatives.
- Add the `aws-bedrock-api-key` detector (critical) — long-term AWS Bedrock
  API keys (`ABSK` prefix + the deterministic `QmVkcm9ja0FQSUtleS` base64
  anchor + 110-char body, 132 chars total; AWS's own published form). The
  anchor encodes "BedrockAPIKey" and is effectively unique, so precision is
  anchor-driven (defensive `min_confidence = 0.2` floor since the fixed anchor
  dilutes entropy scoring). Not checksum-gated. Detector count 900 → 901.
  Contract-locked by `crates/scanner/tests/contracts/aws-bedrock-api-key.toml`
  (positives, anchor/length negatives, header + comment evasions). Short-term
  `bedrock-api-key-` keys are deliberately omitted (their body is not
  authoritatively bounded — soundness over reach).
- Fix a dead contract gate: `every_contract_readme_claim_present` had been
  passing vacuously. A `readme_claim` written after a contract's `[perf]`/
  `[scale]` header binds to that TOML table, not the Contract, so serde
  silently dropped it and every contract's claim parsed as `None` — the gate
  checked nothing (and "stripe" never matched README's "Stripe"). Moved the
  six real `readme_claim`s to the top-level scalar position, corrected the
  `stripe`→`Stripe` claim, added `#[serde(deny_unknown_fields)]` to the perf
  and scale budget structs so a future misplacement is a loud parse error
  instead of a silent drop (Law 10), and added a liveness floor (`checked >=
  6`) so the gate can't regress to vacuous.
- De-duplicate the detector-count claim (was denormalized across 782 places):
  removed the `readme_claim = "900 service-specific detectors"` stamp from 781
  per-detector contracts and made the count derive from `load_detectors()` in
  one place — `readme_claims::readme_claim_detector_count` (README + banner),
  `contract::readme_detector_count` (disk == loader, no literal), and the
  `e2e_binary` banner test (binary == loaded corpus). Adding a detector now
  touches only the new TOMLs + the human-facing README/banner, with no
  test-literal or 781-file churn.
- Byte-cap the per-match context windows (`local_context_window` ML context to 8 KiB, `context::inference::surrounding_line_window` FP context to 2 KiB). Previously each candidate's context was the whole containing line; on a line with no `\n` for kilobytes (minified bundles, or a file that is one long run of credential-shaped tokens) the per-match ML feature / FP keyword scan was O(line_len), making a many-match scan quadratic (a 164 KiB single-line file with 8 K matches took ~18 s). The caps make per-match context O(1) and noticeably speed ordinary minified-bundle scans. Behavior-preserving for normal source — a short line hits its newline well before the cap — verified by byte-identical mirror-corpus findings (F1 0.9167, 2564 findings) and the full scanner suite. Regressioned by `unit/a3_pipeline/local_context_window_caps_long_line`. (A residual super-linear cost remains when a single file carries thousands of distinct credential-shaped matches; bounded in practice by `--timeout` and the 1M-iteration-per-pattern cap.)

- Fix windowed-scan line attribution: findings in files past the 1 MiB
  windowing threshold (`filesystem/windowed`) reported the per-window line
  instead of the absolute file line, so a secret on line 584307 of a 70 MiB
  file was reported at line ~2 (and reported lines were non-monotonic). Added
  `ChunkMetadata::base_line` (the line analog of `base_offset`), populated
  per-window by the filesystem source (mmap + buffered paths) and the
  cross-window boundary reassembler, and added it at every line emit site
  (primary, entropy fallback, generic-secret, multiline reassembly, decode
  pipeline, and the simdsieve hot path). Byte offsets were already absolute;
  this brings line numbers to parity. Regressioned by
  `cli/tests/regression/windowed_line_numbers.rs`.
- Remove the orphaned `pipeline/postprocess/raw_match.rs` — a never-compiled
  stale duplicate of `build_raw_match` (no `mod`/`#[path]` referenced it),
  superseded by the `pattern_client_safe`-aware constructor in
  `pipeline/postprocess/mod.rs`.
- Align Vyre usage docs with the workspace-pinned crates.io `vyre` 0.6.1 release and add a scanner gap test that fails on stale Vyre pin/documentation claims.
- Fix stale `RawMatch` scanner test fixtures to use the production `[u8; 32]` credential hash contract.
- Split structured parser implementations by format family and move remaining parser inline tests into the external scanner test harness.
- Add a GPU phase2 empty-hit fast path matching SIMD coalesced no-hit fallback admission, with a regression gate for the skip-before-prepare contract.
- Preserve detector regex case-insensitivity when lowering prefixless phase-2
  admission patterns into the GPU regex-DFA catalog; plain variants stay
  case-sensitive, and replay tests compare the lowered DFA admission result
  against the CPU `LazyRegex` policy.
- Select bounded GPU regex-DFA admission candidates by detector breadth before
  generated homoglyph variants instead of taking the first source-order slice;
  the catalog budget is now expressed as shard count x shard width.
- Tighten the GPU region-presence host lowercase staging helper to reserve once
  and write folded bytes directly into spare vector capacity, preserving
  `make_ascii_lowercase` semantics without a `Vec::push` per byte.
- Make the boolean no-hit phase-2 admission gate honor the proven ASCII
  homoglyph-variant skip, avoiding extra phase-2 work on pure-ASCII chunks that
  are already covered by the base AC path.
- Tighten GPU phase-2 DFA coalesced-region attribution so matches on or through
  the synthetic NUL separator between chunks cannot over-admit a neighboring
  chunk into the CPU phase-2 tail.
- Pack the GPU phase-2 DFA coalesced haystack once per batch and reuse it across
  DFA shards, removing duplicate O(input) host staging work from sharded
  admission dispatch.
- Mark GPU phase-2 DFA admission evidence incomplete when a backend hit cannot
  be safely attributed to a chunk, keeping `phase2_gpu_complete` honest for
  separator/cross-region output.
- Keep high-entropy base64-like secrets with internal `+`/`/` punctuation through generic and entropy fallbacks by bypassing binary-decoy suppression on the punctuation payload class, closing `encoded_binary`-driven false negatives.
- Add adversarial coverage for the base64 punctuated high-entropy class and a fixed-token regression for `TVo...+...` shape that previously dropped at `is_encoded_binary`.
- Detect current variable-length Clerk publishable keys by their documented
  base64-encoded FAPI URL form instead of requiring an obsolete exact 32-byte
  alphanumeric body; findings remain explicitly client-safe.
- Keep two S3-compatible access-key bodies case-sensitive inside their
  detector TOMLs while preserving case-insensitive environment-key anchors,
  preventing lowercase identifiers from satisfying documented uppercase
  credential alphabets.
- Apply the canonical Octopus Deploy key alphabet to assignment and header
  patterns too, so context cannot admit lowercase keys or pure documentation
  words that the bare-key pattern correctly rejects.
- Preserve Akoya client-credential findings for mixed-case config keys by
  declaring the required companion anchor caseless in its detector TOML;
  simplify the already-caseless primary regex to one canonical spelling.
- Preserve Twilio IoT credential pairs for lowercase config keys by applying
  case folding to the required companion anchor, while keeping the credential
  body alphabet detector-owned and simplifying redundant primary alternations.
- Preserve Twilio API-key pairs for mixed-case secret field names by folding
  only the detector-owned companion anchor, without widening the credential
  body's declared alphabet.
- Capture mixed-case AWS and GovCloud secret/session fields without widening
  their credential bodies, so temporary ASIA credentials reach SigV4 with the
  required session token; keep GovCloud access-key IDs uppercase-only and
  reject overlong runs instead of truncating them into findings.
- Make Spotify's companion secret-specific and capture only its value, so a
  client ID cannot attach itself as a credential pair; collapse redundant
  uppercase/lowercase primaries under the shared caseless compiler.
- Migrate the stale FedEx companion fixture into its normal detector contract
  and reject companion contracts whose detector declares no companions, so
  generated test shape cannot masquerade as production verification wiring.
- Make LiveKit's companion secret-specific so long API keys cannot self-attach
  as secrets, deduplicate caseless primary regexes, and let companion contracts
  explicitly declare when a companion shape is also a valid standalone primary.
- Make Ceph access keys self-delimiting so 40-character secret values cannot be
  truncated into 20-character access-key findings, while preserving Ceph's
  valid user-defined mixed-case access keys and correcting the contract prose.
- Model Five9 API secrets as intentional standalone primaries in the companion
  corpus, while proving API-key-only findings cannot fabricate the nearby
  secret required for credential-pair verification.
- Make AWS SES SMTP field anchors consistently caseless while preserving the
  uppercase access-key alphabet, reject overlong username/password prefixes
  instead of truncating them, and model password-only findings honestly.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep scanner compilation, scan execution, entropy, decode, and context scoring APIs available for the 0.2 line.
