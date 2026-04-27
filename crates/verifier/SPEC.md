# keyhog-verifier SPEC

`keyhog-verifier` checks whether detected credential candidates are live by applying detector verification definitions. It handles request construction, response evaluation, rate limiting, caching, and SSRF protections.

## Guarantees

- Verification requests are gated by detector configuration.
- Private, loopback, local, and malformed SSRF targets are blocked.
- Response success rules are evaluated against status, body, and JSON path conditions.
- Verification results distinguish valid, invalid, transient, and error states.

## Boundaries

This crate does not scan files or produce initial credential candidates. It verifies candidates emitted by `keyhog-scanner`.
