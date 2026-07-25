# `.keyhogignore.toml` reference

Use `.keyhogignore.toml` for exceptions that need more than one condition. Put
the file at the filesystem scan root. A single-file scan uses the file's parent
directory. A source mode without a filesystem path uses the current directory.

KeyHog also loads the line-based `.keyhogignore`. A finding is suppressed when
either file matches. `[allowlist].file` can select a different line-based file,
but it does not move or disable `.keyhogignore.toml`. There is no negation or
last-rule-wins behavior.

## Rule composition

Each rule is a `[[suppress]]` table. Predicates in one table use AND. Separate
tables use OR.

```toml
# Suppress one reviewed AWS fixture value and nothing broader.
[[suppress]]
detector = "aws-access-key"
path_eq = "fixtures/aws.env"
credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

# Suppress low-or-lower Stripe findings only below test directories.
[[suppress]]
service = "stripe"
severity_lte = "low"
path_regex = '(^|/)tests/'
```

In the first rule, changing the path, detector, or hash makes the rule fail to
match. In the second rule, a medium Stripe finding still reports. A low finding
outside a `tests` directory also reports.

## Fields

| Field | Type | Predicate |
|---|---|---|
| `literal_true` | boolean | Explicit unconditional match. Only `true` is a predicate. |
| `detector` | string | Exact detector ID |
| `service` | string | Exact service |
| `severity` | string | Exact severity |
| `severity_lte` | string | Severity at or below the threshold |
| `path_eq` | string | Exact finding path |
| `path_contains` | string | Finding path contains the substring |
| `path_starts_with` | string | Finding path starts with the prefix |
| `path_ends_with` | string | Finding path ends with the suffix |
| `path_regex` | string | Finding path matches the regular expression |
| `credential_hash` | string | Exact SHA-256 hex digest reported as `credential_hash` |

Severity values are `info`, `client-safe`, `low`, `medium`, `high`, and
`critical`. `severity_lte = "low"` includes `info`, `client-safe`, and `low`.
Other string comparisons are exact and case-sensitive.

The path fields inspect the path stored on the finding. They do not perform
line-based `.keyhogignore` glob matching. Use `path_regex` when an exact,
prefix, suffix, or substring comparison is not enough. Archive member paths
include every container, for example `bundle.zip//examples/demo.env`. A finding
without a path does not match a path-scoped rule.

## Unconditional rules

An empty table is rejected:

```toml
[[suppress]]
```

`literal_true = false` by itself is also rejected. To suppress every finding,
you must state that policy explicitly:

```toml
[[suppress]]
literal_true = true
```

Combining `literal_true = true` with another predicate is equivalent to using
the other predicate alone.

## Failure behavior

A missing file means that no declarative rules are active. A present file that
cannot be read or parsed stops the scan with exit `2`. An empty table, unknown
field inside `[[suppress]]`, or unsupported severity also stops the scan.
KeyHog does not fall back to an empty declarative policy.

A valid rule with the wrong case, path, detector, or hash does not match. It
does not produce an error. A file with no `[[suppress]]` tables loads no
rules. Run the same scan after adding a rule and confirm that only the reviewed
finding disappears.
