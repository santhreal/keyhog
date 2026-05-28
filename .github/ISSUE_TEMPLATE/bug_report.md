---
name: Bug report
about: keyhog produced the wrong output, crashed, or hung
title: "[bug] "
labels: ["bug", "needs-triage"]
---

<!-- Before filing: search existing issues to avoid duplicates.
     If this looks like a security issue, do NOT file it here — open
     a private advisory at /security/advisories/new instead. -->

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

<!-- Re-run with NO_COLOR=1 and the most verbose flag that's relevant:
     `keyhog scan --verbose ...` or `keyhog backend` for backend probes.
     Paste between the fences. -->

```
```

## Anything else?

<!-- Stack traces, related issues, suspected root cause, your guess for the fix. -->
