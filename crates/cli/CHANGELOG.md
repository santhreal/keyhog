# Changelog

## Unreleased

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

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep CLI orchestration, output modes, baseline filtering, and detector discovery behavior available for the 0.2 line.
