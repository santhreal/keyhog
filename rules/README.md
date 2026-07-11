# `rules/` — Tier-B data files

This directory holds **data, not code**: small user-extensible rule files that
keyhog loads at runtime or compiles in. The schema for each file is documented
inside the file itself.

## Current files

| File | Purpose |
|------|---------|
| `aws-canary-accounts.toml` | AWS account IDs known to issue canary tokens. A detected AWS access key whose offline-decoded account ID matches is marked `metadata.is_canary=true`, and live verification refuses to probe it. |
| `default_excludes.toml` | Default source exclusion policy for binary extensions, generated/build directories, lockfiles, source maps, and related low-signal paths. |
| `stripe-hot-confirmed-prefixes.toml` | Shared Stripe prefixes used to deduplicate confirmed extraction against the hot path. Detector properties live in detector TOMLs. |
| `placeholder_words.toml` | Shared placeholder/sample words consumed by scanner surface, decoded, and doc-marker suppression paths. |

## Adding a new rule file

1. Create a TOML file here with a clear, kebab-case name.
2. Document the schema and semantics in a top-of-file comment.
3. If the rule is security-relevant, add a test in the appropriate crate that
   loads the file and asserts the expected behavior.
4. Update this README with a one-line description.

## Detector data lives elsewhere

The 902 secret-type detectors are **not** here — they live in `detectors/` as
one TOML file per detector. This directory is for cross-cutting rules that do
not fit the per-detector schema.
