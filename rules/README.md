# `rules/`: Tier-B data files

This directory holds **data, not code**: small user-extensible rule files that
keyhog loads at runtime or compiles in. The schema for each file is documented
inside the file itself.

## Current files

| File | Purpose |
|------|---------|
| `aws-canary-accounts.toml` | AWS account IDs known to issue canary tokens. A detected AWS access key whose offline-decoded account ID matches is marked `metadata.is_canary=true`, and live verification refuses to probe it. |
| `default_excludes.toml` | Default source exclusion policy for binary extensions, generated/build directories, lockfiles, source maps, and related low-signal paths. |
| `json-error-keys.toml` | Error key names recognized inside a JSON response body during verifier API error detection. |
| `placeholder_words.toml` | Shared placeholder/sample words consumed by scanner surface, decoded, and doc-marker suppression paths. |
| `strong-hex-key-anchors.toml` | Compact credential keywords under which a canonical-length (32/48) pure-hex value is treated as a real key, not a hash digest, exempting it from the generic-bridge bare-hex-digest gate. |
| `encoded-text-secret-anchors.toml` | Compact credential keywords that let a base64/encoded value which decodes to printable text reach the scorer, rather than being suppressed as a binary/base64 blob. |

## Adding a new rule file

1. Create a TOML file here with a clear, kebab-case name.
2. Document the schema and semantics in a top-of-file comment.
3. If the rule is security-relevant, add a test in the appropriate crate that
   loads the file and asserts the expected behavior.
4. Update this README with a one-line description.

## Detector data lives elsewhere

Secret-type detectors are **not** here; they live in `detectors/` as
one TOML file per detector. This directory is for cross-cutting rules that do
not fit the per-detector schema.
