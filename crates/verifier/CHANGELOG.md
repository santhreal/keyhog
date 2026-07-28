# Changelog

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
