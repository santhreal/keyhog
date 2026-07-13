<!--
keyhog PR template. Fill out the sections that apply, delete the rest.
For drive-by typo fixes, the title and one-line summary are enough.
-->

## Summary

<!-- One or two sentences. What changes for the user, not what files moved. -->

## Why

<!-- Link the issue, the commit that introduced the bug, the upstream advisory,
     or the CVE if this is a security fix. If this is a refactor, say what
     the alternative looked like. -->

## Detector / scanner changes

<!-- Only fill out if this PR adds, removes, or changes a detector or the
     scan pipeline. -->

- Detector ID:
- Sample input (redacted if real):
- Adversarial twin shipped: yes / no (if no, why)?
- Recall delta (corpus run): +N / -N
- Precision delta (corpus run): +N / -N

## Test plan

<!-- Concrete commands a reviewer can run. Not "I tested it locally". -->

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Scan a known-leaky fixture and confirm exit code 1 + a finding for the
      claimed rule on the claimed line
- [ ] Scan a known-clean fixture and confirm exit code 0

## Risk

<!-- What could break? Does this touch the scan hot path, the GPU backend,
     install.sh, or release packaging? -->

## Backwards compatibility

<!-- Does this rename a flag, change a config key, change an exit code,
     or change SARIF/JSON output shape? If yes, call it out. -->

## Screenshots / output snippets

<!-- Optional but very welcome for CLI UX changes. -->
