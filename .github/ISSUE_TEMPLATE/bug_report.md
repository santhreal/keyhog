---
name: Bug report
about: keyhog produced the wrong output, crashed, or hung
title: "[bug] "
labels: ["bug", "needs-triage"]
---

<!-- Before filing: search existing issues to avoid duplicates.
     If this looks like a security issue, do NOT file it here. Use GitHub
     private vulnerability reporting first:
     https://github.com/santhreal/keyhog/security/advisories/new
     If that form is unavailable, email security@santh.dev; PGP is not required. -->

## Summary

<!-- One sentence: what did keyhog do that surprised you? -->

## Reproduction

```sh
# exact commands you ran
```

<!-- Paste the input or attach a minimal redacted fixture.
     Never paste real credentials. -->

## Expected vs actual

- Expected: …
- Actual: …
- Exit code: …

## Environment

- `keyhog --version`:
- OS + version:
- CPU (`uname -m` / Win arch):
- GPU (if relevant):
- Install method: install.sh / install.ps1 / cargo install / source / pre-built tarball

## Logs

<!-- Re-run with `RUST_LOG=keyhog=debug NO_COLOR=1 keyhog scan ...`.
     Use `keyhog backend` for backend probes. Redact credentials and sensitive
     paths before pasting the output between the fences. -->

```
```

## Anything else?

<!-- Stack traces, related issues, suspected root cause, your guess for the fix. -->
