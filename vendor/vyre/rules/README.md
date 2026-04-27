# rules/ — Tier B Community Knowledge

This directory holds **Tier B** configuration: community-contributed detection
rules and fingerprints that vyre loads at runtime without recompiling Rust.

Tier A (operational flags, TOML defaults, CLI arguments) lives in the binary
and `vyre-config`.  Tier B lives here, in plain `.toml` files.  A billion-dollar
competitor can clone the Rust codebase, but they cannot clone ten thousand
community-tuned rules.

> Add a TOML rule (community knowledge, no Rust).  
> 1. Drop a file in `rules/{category}/{name}.toml`.  
> 2. Tool auto-loads on next scan.

---

## How to contribute

1. Pick the category that matches your rule.
2. Create a new `.toml` file in that directory.
3. Fill in the fields documented in `SCHEMA.md`.
4. Open a PR.  CI validates the schema; a human reviews the rule semantics.
5. No Rust code required.

Rules are versioned by file.  Modifying a rule is a PR against that file.
Removing a rule requires justification in the PR description.

---

## Current categories

| Directory     | Purpose |
|---------------|---------|
| `category_b/` | Cat B tripwires — forbidden runtime-abstraction patterns (e.g. `typetag`, `inventory::submit`, `Any::downcast_ref`). |
| `cve/`        | CVE signatures — known-vulnerable crate versions, suspicious imports, or dangerous API call patterns. |
| `waf/`        | WAF fingerprints — Web-Application-Firewall-style detections for common attack strings in input buffers. |

New top-level categories are added only by maintainers after an RFC.

---

## Schema

The authoritative schema is `SCHEMA.md`.  Every field, type constraint, and
validation rule is defined there.  Future automated validators enforce it
exactly.  If a field is not listed in `SCHEMA.md`, do not use it.

---

## File naming conventions

- Use `snake_case.toml`.
- The file name SHOULD match the rule `id`.
- One file = one rule.  Do not pack multiple rules into a single file.
- Maximum file size: 50 KiB.  Larger files are rejected by CI.

---

## Example: adding a new Cat B tripwire

Create `rules/category_b/my_tripwire.toml`:

```toml
# rules/category_b/my_tripwire.toml
id = "my_tripwire"
type = "text_scan"
patterns = ["forbidden_crate::"]
message = "forbidden_crate usage detected. Fix: remove the runtime dispatch."
files = ["*.rs"]
excluded_paths = ["tests/", "examples/", "benches/", "build.rs"]
```

Run the relevant rule-validation target. If the rule passes schema validation and the
tripwire gate is green, the rule is live.

Do not edit any Rust file.  One file, one responsibility, zero modifications
elsewhere.

---

## How rules are loaded

At build or scan time, vyre walks `rules/{category}/*.toml`.  Each file is
parsed, validated against `SCHEMA.md`, and flattened into an in-memory rule
table.  If a file fails validation, the build fails with an actionable error
message.  There is no silent skipping.

---

## Rule lifecycle

- **Proposal**: Open a draft PR with the new `.toml` file.
- **Validation**: CI runs schema checks and uniqueness lints.
- **Review**: A maintainer verifies the rule semantics and the fix hint.
- **Merge**: The rule goes live on the next release or nightly scan.
- **Deprecation**: Removing a rule requires the same PR rigor as adding one.

---

## Questions?

For schema details, see `SCHEMA.md` in this directory.
