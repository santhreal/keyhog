# `.keyhogignore.toml` - declarative finding suppression

A `.keyhogignore.toml` file in your scan root expresses suppression
rules in TOML, evaluated per-finding via VYRE's CPU rule engine
(`vyre_libs::rule`). Sits alongside the legacy line-based
`.keyhogignore` - both are loaded; either alone suppresses a finding.

## Schema

Every rule is a `[[suppress]]` table. Within one table, named
predicates combine with **AND**. Across multiple tables they combine
with **OR**.

| Field              | Type         | Predicate                                         |
| ------------------ | ------------ | ------------------------------------------------- |
| `literal_true`     | boolean      | explicit unconditional match; `true` suppresses every finding |
| `detector`         | string       | detector_id exact match                           |
| `service`          | string       | service exact match                               |
| `severity`         | string       | severity exact match (`info`, `client-safe`, `low`, `medium`, `high`, or `critical`) |
| `severity_lte`     | string       | severity ≤ threshold (curated rank set)           |
| `path_eq`          | string       | file path exact match                             |
| `path_contains`    | string       | file path contains substring                      |
| `path_starts_with` | string       | file path starts with prefix                      |
| `path_ends_with`   | string       | file path ends with suffix                        |
| `path_regex`       | string       | file path matches regex                           |
| `credential_hash`  | string       | credential SHA-256 exact match                    |

A `[[suppress]]` table with no predicates is rejected at parse time
(prevents accidentally suppressing every finding). If an unconditional rule is
intentional, write `literal_true = true`; the explicit name makes a
match-everything policy reviewable. `literal_true = false` does not count as a
predicate and is rejected when it is the only field. Because predicates in one
table use AND semantics, combining `literal_true = true` with another field is
equivalent to using that other field alone; use it alone to suppress everything.

## Examples

```toml
# Drop every aws-access-key finding inside test directories.
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"

# Drop every low, client-safe, or info Stripe finding regardless of where it lives.
[[suppress]]
service = "stripe"
severity_lte = "low"

# Drop a single credential by hash, anywhere it appears.
[[suppress]]
credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

# Drop everything in vendored/minified files.
[[suppress]]
path_starts_with = "vendor/"

[[suppress]]
path_ends_with = ".min.js"

[[suppress]]
path_regex = "^docs/[a-z]+\\.md$"

# Deliberately suppress every finding. Prefer a scoped predicate whenever possible.
[[suppress]]
literal_true = true
```

## Why TOML and why a rule engine

The legacy `.keyhogignore` is one allowlist entry per line:
`hash:<sha>`, `detector:<id>`, `path:<glob>`. That covers the simple
cases but can't express "drop aws-access-key findings ONLY in
`/tests/`" - the conditions need to combine.

Each TOML table compiles into a VYRE `RuleFormula` that ANDs typed conditions
such as `FieldInSet` and `SubstringMatch`; KeyHog applies OR semantics across
tables by accepting the first formula that evaluates true. VYRE's CPU evaluator
(`vyre_libs::rule::evaluate_formula`) walks those formulas once per finding.
VYRE also exposes GPU lowering through
`vyre_libs::rule::build_rule_program`, but KeyHog does not use that route for
suppression decisions; the active contract is the deterministic CPU evaluator
after finding extraction.

## Errors

Missing `.keyhogignore.toml` means no declarative rules. A present file that
cannot be read or parsed is fatal: KeyHog prints the file and corrective action,
refuses to scan with silently ignored suppression policy, and exits `2`. The
legacy `.keyhogignore` is loaded independently, but it does not make a malformed
declarative policy safe to ignore.
