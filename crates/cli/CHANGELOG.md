# Changelog

## 0.5.53 - 2026-08-04

- Include both published GitHub Action manifests in the release version transaction, so the minimum version they advertise cannot fall behind the workspace as it did for two releases.
- Track the accumulating batch's route class and chunk identities as chunks arrive instead of rescanning and rehashing the whole batch for every chunk. The coalesced pipeline's 4,096-chunk batches made that quadratic, which is why an explicit GPU backend measured slower than CPU while the accelerator sat idle.

## 0.5.52 - 2026-08-04

- Check every `keyhog` command in the README and the handbook against the compiled command model, so a documented subcommand or long flag that is renamed or removed fails the build instead of failing the reader who types it.

- Correct the system-wide triage example, which showed a `--exclude` flag `scan-system` does not have, and state the bound it actually applies: a total-bytes ceiling plus network filesystems skipped by default.

## 0.5.51 - 2026-08-04

- Assert JSON, JSONL, and SARIF stay completely parseable and ANSI-free across all sixteen hostile environment profiles, including CLICOLOR_FORCE, an unset HOME, an unwritable working directory, a missing TMPDIR, and a rejected backend request.

- Derive the subcommand help matrix from the compiled command model instead of a hand-kept list that had already drifted past `config` and `bloom-diagnostic`, and pin the advertised menu so a removal or rename stays a reviewed change.

- Fall back to the honest legacy identity gaps when a causal profile's detector, configuration, or source enrichment is absent, instead of panicking while rendering the report at the end of a completed scan.
- Run the 1,202-cell product-reliability matrix in CI and drive it on the portable scalar backend, so hostile-environment exit-code, output-format, and installer contracts can no longer rot unexecuted or fail closed on a Hyperscan-free build.
- Check the default-exclusion policy flag at each source factory call rather than at the first mention of a source name anywhere in the file, which reported a missing flag on a call that passes it.

## 0.5.50 - 2026-08-02

- Add low-overhead causal run profiling with fixed scanner stages, state transitions, process resource measurements, and explicit source and backend identity while keeping per-pattern diagnostics behind --perf-trace.
- Add `keyhog explain --compiled-plan` output for resolved companion and cross-detector evidence operations.
- Show detector-owned positive source-admission selectors in `keyhog explain`.
- Add `scan --github-all` as the concise complete-surface form of a GitHub collaboration scan while retaining independent surface selectors.

- Publish patch releases to crates.io through short-lived OIDC trusted publishing and upload a deterministic six-crate commit and lockfile integrity receipt without a long-lived registry token.

- Record scanner accelerator features from dependency-owned compile state so portable autoroute identities no longer claim unavailable GPU or SIMD backends.
- Bound scan-system metadata discovery by the remaining --space budget so small host-scan ceilings stop promptly and report partial coverage instead of traversing the entire filesystem first.
- Preserve valid `.keyhog.toml` detector-disable configurations by transitively removing detectors that require a disabled target and pruning inactive conflict or subsumption relations before scanner compilation.

## 0.5.49 - 2026-07-30

- A single resumable local or SSH command now refreshes benchmark evidence without invalidating candidate freshness, rebinds the exact canonical run-set after scoring, prepares every changelog and version surface, runs pre-tag gates with isolated full and ci-lean binary contracts, preserves exact Git path bytes, verifies the configured OpenPGP fingerprint before any tag push, and watches GitHub Pages, release assets, containers, and the six-crate crates.io publication chain.

- The README star viewer now uses a deterministic accessible SVG generated from repository-owned observations, records only real count transitions, handles same-day corrections and declines truthfully, writes atomically, and retries isolated metrics push races without depending on star-history.com.

## 0.5.48 - 2026-07-28

- Bind the CLI package and composite Action candidate to the exact validated
  release commit, signed SPDX dependency graph, and single post-release crate
  publication path.


## 0.5.47 - 2026-07-26

- Add the POSIX installer `--no-calibrate` override for deterministic
  explicit-backend automation while retaining signature, checksum, binary, and
  doctor verification.

## 0.5.46 - 2026-07-24

- Upgrade the daemon wire protocol to v8, keep request, response, frame, client,
  server, and plaintext match adapters crate-private, and expose only the
  non-secret default socket path. The strict Hello handshake rejects v7 peers.
- Allow a daemon scan to select an explicit replacement detector corpus when
  the client-derived rules identity exactly matches the warm daemon. Reports
  retain the replacement count, digest, source, and mode. Overlay composition
  and client-only detector policy remain fail-closed.
- Include exact static-recovery totals and per-reason rejections in JSON 1.8,
  JSONL 1.9, and daemon v8 report metadata. Daemon clients reject aggregates
  whose reason counts do not reconcile instead of substituting zeroes.
- Make `update` and `repair --version` accept only canonical SemVer, normalize
  it to one `v`-prefixed tag before HTTP, and require the same non-draft tag
  before downloading assets. Malformed or mismatched release metadata fails.
- Serialize concurrent autoroute calibration updates through the cache lock so
  distinct workload evidence is merged without torn reads. Unix cache, lock,
  and temporary files are private, and successful writes leave no temporary
  residue.
- Keep the daemon socket linked for the full accept-loop lifetime. Shutdown
  removes it only after the listener terminates.
- Bind every persisted GPU timing and parity receipt to the exact acquired
  execution peer. Route replay now rejects changed or missing adapter identity.
- Make the final backend summary identify invalid-autoroute scalar recovery and
  runtime-fault recovery directly. Recovered work is no longer
  described as a calibrated non-GPU winner.
- Let `calibrate-autoroute --policy` refresh one scan policy without rerunning
  every preset. The default remains the complete all-policy install sweep.
- Reject autoroute cache and runtime-health workload identities with impossible
  logarithmic ranges, phase-one subtotals, decoder bits, or decoder cost bands.
- Report automatic backend recovery as `complete_after_recovery` in JSON schema
  1.8 and JSONL schema 1.9, preserve the
  exact recovered ranges and byte totals across daemon responses, expose daemon
  recovery health, and persist the affected autoroute workload quarantine in a
  bounded artifact that survives restart, is visible in `backend --autoroute`
  and `doctor`, and clears through successful recalibration. Recovery replays
  stable bytes through the fastest remaining measured-correct peer resolved by
  the same workload evidence, rather than a hardcoded CPU backend.
- Measure every plain-pattern and keyword-anchor localization combination for
  every eligible backend, persist the fastest correct execution plan in cache
  schema 39, and carry both choices beside admission evidence through one-shot,
  fused, daemon, and automatic-recovery dispatch.

- Retain every exact calibration representative inside one canonical workload
  evidence envelope. A route class is reusable only when all points agree on
  the fastest-correct one-shot and daemon backends; inspection exposes each
  point's timings, confidence, and parity receipts, and calibration now probes
  both sides of the required 8 MiB crossover.
- Show the detector-owned keyword-free operator entropy margin in `explain`.
- Derive autoroute readiness and repair commands once from cache inspection,
  expose the repair command in `backend --autoroute --json`, and make `doctor`
  report scalar-only builds as direct-route ready instead of uncalibrated.
  Calibration now succeeds only when persisted readback is `ready` for the
  running build.
- Persist the resolved GPU batch-input byte cap in autoroute host identity and
  inspection, so a device-limit or configured-cap change cannot replay timing
  evidence measured with a different dispatch topology.
- Bind autoroute host identity to the live linked Hyperscan/Vectorscan runtime
  version, so a runtime replacement invalidates SIMD timing evidence and
  requires recalibration instead of replaying a stale winner.
- Split contiguous filesystem batches at safe source-family and size-provenance
  boundaries, extend the split to tracked and untracked git-diff inputs, and
  calibrate every default fused count for extracted tar members. Empty stdin is
  no longer reported as a calibrated workload. Current installers delegate this
  core sweep to the binary instead of maintaining a second matrix. Calibration
  output now calls the sweep count probes rather than unique workload buckets;
  it also reads back and reports both route classes measured by this sweep and
  the cache's total route-decision count. Installers still parse the earlier
  unified-command summary during migration.
- Rename the live GPU region-presence batch byte budget to
  `--gpu-batch-input-limit` / `gpu_batch_input_limit`; accept the retired
  MegaScan spelling as a hidden CLI/TOML migration alias.
- Include full-source-size provenance in autoroute workload keys so streamed or
  transformed payload sizes cannot silently reuse calibration measured from an
  equal numeric full-file-size bucket.
- Activate the CLI `simd` feature in default builds so the documented
  Hyperscan `--cache-dir` surface works whenever the default scanner includes
  Hyperscan instead of falsely reporting an accelerator-free binary.
- Stop prewarming an automatic backend from a zero-byte heuristic before the
  persisted workload-specific autoroute decision is known; explicit diagnostic
  backend overrides still prewarm directly.
- Report the configured backend policy at startup instead of claiming that a
  backend was selected before the persisted per-workload decision exists.
- Do not print end-of-run repeat summaries for dependency warnings hidden by
  the default log filter; summaries now describe only visible KeyHog warnings.
- Record the actual first GPU dispatch as autoroute cold-start evidence instead
  of discarding it and mislabelling an already-warm second dispatch as cold.
- Distinguish one-shot and persistent-daemon autorouting: one-shot scans include
  GPU cold cost, while the daemon initializes accelerator state before serving
  requests and selects from calibrated warm timing evidence.
- Replace autoroute cache writes through a synced same-directory temporary file
  so recalibration atomically replaces an existing cache path across supported
  operating systems.
- Route CLI report/cache writes through one atomic file replacement helper,
  including `scan-system --output`, to avoid truncated final-path artifacts.
- Refuse autoroute calibration on empty or zero-byte samples before timing so
  calibration cannot persist route decisions that the cache loader would later
  reject as missing sample evidence.
- Add `keyhog config --effective` and keep post-scan confidence filtering on the same resolved floor as the scanner.
- Update stale unit fixtures for the inline-byte credential-hash contract and removed duplicate startup-summary helper.
- Keep default `--git-diff HEAD` wired to worktree changes, honor CLI excludes for staged-only scans, and refresh git-mode e2e contracts for clean staged inputs and SARIF schema coherence.
- Move args, hook, and scan-system inline tests into registered aggregate unit modules, including scan-system redaction tests updated for the raw `[u8; 32]` hash contract.
- Refresh the dogfood detector-count oracle to 894 and keep the structured UUID named-detector default-recall e2e passing.
- Distinguish detector-TOML declarations from scan-time fallback policy in
  `keyhog explain`, using the same `scan-fallback` provenance label as effective
  configuration output.

## 0.5.45 - 2026-07-22

- Republish the CLI in the release chain whose signed asset publication
  addresses GitHub drafts by immutable release ID.

## 0.5.44 - 2026-07-22

- Republish the CLI in the corrected five-crate release chain after the
  Windows GPU literal artifact generator fix.

## 0.5.43 - 2026-07-22

- Compile the portable CLI on Windows by gating Unix daemon test seams, using
  the platform process-exit path, and importing drive constants from their
  generated windows-sys module.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep CLI orchestration, output modes, baseline filtering, and detector discovery behavior available for the 0.2 line.
