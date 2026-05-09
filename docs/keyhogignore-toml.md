# `.keyhogignore.toml` — declarative finding suppression

A `.keyhogignore.toml` file in your scan root expresses suppression
rules in TOML, evaluated per-finding via vyre's CPU rule engine
(`vyre_libs::rule`). Sits alongside the legacy line-based
`.keyhogignore` — both are loaded; either alone suppresses a finding.

## Schema

Every rule is a `[[suppress]]` table. Within one table, named
predicates combine with **AND**. Across multiple tables they combine
with **OR**.

| Field              | Type         | Predicate                                         |
| ------------------ | ------------ | ------------------------------------------------- |
| `detector`         | string       | detector_id exact match                           |
| `service`          | string       | service exact match                               |
| `severity`         | string       | severity exact match (info\|low\|medium\|high\|critical) |
| `severity_lte`     | string       | severity ≤ threshold (curated rank set)           |
| `path_eq`          | string       | file path exact match                             |
| `path_contains`    | string       | file path contains substring                      |
| `path_starts_with` | string       | file path starts with prefix                      |
| `path_ends_with`   | string       | file path ends with suffix                        |
| `path_regex`       | string       | file path matches regex                           |
| `credential_hash`  | string       | credential SHA-256 exact match                    |

A `[[suppress]]` table with no predicates is rejected at parse time
(prevents accidentally suppressing every finding).

## Examples

```toml
# Drop every aws-access-key finding inside test directories.
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"

# Drop every low-or-info Stripe finding regardless of where it lives.
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
```

## Why TOML and why a rule engine

The legacy `.keyhogignore` is one allowlist entry per line:
`hash:<sha>`, `detector:<id>`, `path:<glob>`. That covers the simple
cases but can't express "drop aws-access-key findings ONLY in
`/tests/`" — the conditions need to combine.

The TOML schema compiles into a vyre `RuleFormula` tree (And/Or/Not
of typed conditions like `FieldInSet` and `SubstringMatch`). Vyre's
CPU evaluator (`vyre_libs::rule::cpu_eval`) walks the tree once per
finding (~µs cost). The same `RuleFormula` shape can also lower to
GPU IR via `vyre_libs::rule::build_rule_program` — useful when a
future scan path wants to evaluate the rule alongside the literal-set
dispatch instead of post-process.

## Errors

Parse errors are non-fatal: a malformed `.keyhogignore.toml` logs a
warning at the top of the scan and is then ignored (zero rules
loaded). The legacy `.keyhogignore` still applies. To gate CI on a
clean rules file, use:

```bash
keyhog scan --backend simd --path . 2>&1 | grep -q "failed to load .keyhogignore.toml" && exit 1
```
