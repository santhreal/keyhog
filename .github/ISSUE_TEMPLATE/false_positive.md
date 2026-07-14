---
name: False positive (or false negative)
about: keyhog flagged something that wasn't a secret, or missed something that was
title: "[fp] "
labels: ["false-positive", "detector"]
---

<!-- This is the highest-signal kind of issue we receive. Even a redacted
     two-line input is enough to ship a test. Never paste a live credential or
     security-sensitive material here. Report it privately first at
     https://github.com/santhreal/keyhog/security/advisories/new. If that form
     is unavailable, email security@santh.dev; PGP is not required. -->

## What kind?

- [ ] False positive (flagged something that isn't a real secret)
- [ ] False negative (missed something that is a real secret)
- [ ] Wrong severity / wrong detector ID

## Input

<!-- Minimal redacted snippet that reproduces. Replace real characters
     with `X` of the same case/class so the shape is preserved. -->

```
```

## Expected vs actual

- Expected: …
- Actual: keyhog reported … (or reported nothing)

## Detector ID

<!-- From the scan output or SARIF. Inspect it with `keyhog explain <id>`. -->

## Service / context

<!-- Which service does this credential format belong to?
     Where in real life would this string actually appear? -->

## Suggested fix

<!-- Optional. If you know the regex tweak, the suppression rule, or the
     entropy threshold change that would catch this, say so. -->

## Environment

- `keyhog --version`:
- OS:
