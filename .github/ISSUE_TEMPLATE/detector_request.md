---
name: Detector request
about: keyhog doesn't recognize a credential format you need it to catch
title: "[detector] "
labels: ["detector", "enhancement"]
---

<!-- Never paste a live credential or security-sensitive material here. Report
     it privately first at
     https://github.com/santhreal/keyhog/security/advisories/new. If that form
     is unavailable, email security@santh.dev; PGP is not required. -->

## Service / vendor

<!-- Cloud, SaaS, vendor, or protocol name. -->

## Credential format

<!-- Prefix, suffix, length, charset, version markers, anything distinctive.
     A public link to the vendor's documentation is ideal. -->

## Example shape (NOT a real key)

```
```

## Why does keyhog miss it today?

<!-- Optional. If you scanned and got nothing, paste the empty result. -->

## Verifier?

<!-- Is there a free public endpoint that returns 200 on a live key and
     401/403 on a revoked one? If so, paste the URL. This unlocks live
     verification, which can confirm the format match as a live credential. -->

## Severity

- [ ] Critical (root cloud account, prod database, payment processor)
- [ ] High (privileged service token, SaaS admin)
- [ ] Medium (limited-scope token)
- [ ] Info / discovery only
