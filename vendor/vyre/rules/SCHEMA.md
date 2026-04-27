# rules/ TOML Schema

This document is the **authoritative** schema for every `.toml` file under
`rules/`.  Automated validators enforce it.  If a field is not documented here,
it is not allowed.

---

## Shared conventions

- Every rule file MUST have a `.toml` extension.
- `id` MUST be unique within its category.  Valid characters: `[a-zA-Z0-9_]`,
  hyphens (`-`), and dots (`.`).
- `id` length MUST be between 1 and 64 characters, inclusive.
- `message` MUST be actionable and SHOULD start with `Fix: ` when a concrete
  remedy exists.
- Arrays MUST NOT be empty unless the field description explicitly allows it.
- Glob patterns use Rust `glob` crate syntax.
- No TODO comments, no stub values, and no placeholder strings.

---

## `category_b` — Cat B tripwires

Cat B rules detect forbidden runtime-abstraction patterns that break vyre's
closed-enum and zero-cost invariants.  Each rule in this category is a
`text_scan` record.

### Required fields

| Field      | Type              | Description                                                            |
|------------|-------------------|------------------------------------------------------------------------|
| `id`       | string            | Unique rule identifier within `category_b`.                            |
| `type`     | string            | Rule engine selector.  MUST be exactly `"text_scan"`.                  |
| `patterns` | array of string   | Literal substrings to search for.  At least one non-empty string.      |
| `message`  | string            | Human-readable finding text.  Must include a fix hint.                 |
| `files`    | array of string   | Glob patterns for files to scan (e.g. `["*.rs"]`).                     |

### Optional fields

| Field            | Type            | Default | Description                                                              |
|------------------|-----------------|---------|--------------------------------------------------------------------------|
| `excluded_paths` | array of string | `[]`    | Path substrings that exclude a file from this rule.  Common values: `["tests/", "examples/", "benches/", "build.rs"]`.

### Validation rules

1. `patterns` MUST contain at least one non-empty string.
2. Every pattern MUST be <= 256 characters.
3. `files` MUST contain at least one valid glob string.
4. Every glob string MUST be <= 256 characters.
5. `excluded_paths` entries MUST be <= 256 characters each.
6. Duplicate `id` values within the same category are rejected by CI.
7. A pattern MUST NOT be a pure whitespace string.

### Example

```toml
# rules/category_b/typetag.toml
id = "typetag_serde"
type = "text_scan"
patterns = ["typetag::", "erased_serde"]
message = "typetag/erased_serde serde graph. Fix: use closed enums or static IR decode tables."
files = ["*.rs"]
excluded_paths = ["tests/", "examples/", "benches/", "build.rs"]
```

---

## `cve` — CVE signatures

CVE rules map known vulnerabilities to detectable patterns in dependency
manifests or source code.  The schema is stabilizing; the fields below are
mandatory for all new contributions.

### Required fields

| Field             | Type              | Description                                                              |
|-------------------|-------------------|--------------------------------------------------------------------------|
| `id`              | string            | CVE identifier or internal slug (e.g. `CVE_2024_1234_rustls`).           |
| `type`            | string            | Engine selector.  MUST be exactly `"cve_signature"`.                   |
| `affected_crates` | array of string   | Crate names to watch.                                                    |
| `bad_versions`    | array of string   | Version requirements in Cargo-semver syntax (e.g. `">= 1.2.0, < 1.2.3"`). |
| `message`         | string            | Actionable guidance, including the recommended upgrade version.          |

### Optional fields

| Field            | Type            | Default                        | Description                        |
|------------------|-----------------|--------------------------------|------------------------------------|
| `files`          | array of string | `["Cargo.lock", "Cargo.toml"]` | Files to inspect.                  |
| `excluded_paths` | array of string | `[]`                           | Paths to ignore.                   |

### Validation rules

1. `affected_crates` MUST NOT be empty.
2. Each crate name MUST be a valid Cargo crate name.
3. `bad_versions` MUST contain at least one valid semver requirement string.
4. `message` MUST mention a concrete fix (e.g. upgrade to version X.Y.Z).

---

## `kat` — Known-answer test vectors (op ground truth)

KAT rules are the external contract that defines an op's correct behavior. Each file
corresponds to exactly one op (e.g. `rules/kat/primitive/add.toml`). The vyre-conform
pipeline walks `core::ops::registry`, loads the matching KAT file, and verifies the
op's `CpuOp` implementation and compiled GPU output both match every vector.

This is Tier B community data: contributors add new KAT vectors by editing TOML,
with **zero Rust knowledge required**. A new vector is picked up automatically on
next run.

### Required fields

| Field       | Type                                  | Description                                                                  |
|-------------|---------------------------------------|------------------------------------------------------------------------------|
| `op_id`     | string                                | Dotted operation id matching `core::OpDef::id()` exactly (e.g. `"primitive.math.add"`). |
| `kat`       | array of `[[kat]]` tables             | Hand-verified input/expected pairs. At least one entry.                      |

### Optional sections

| Section         | Description                                                                                  |
|-----------------|----------------------------------------------------------------------------------------------|
| `[[adversarial]]` | Hostile inputs meant to exercise validation and boundary handling. `input` + `reason`.      |
| `[[golden]]`     | Additional reference vectors (typically duplicating hand-verified cases for regression use). |

### `[[kat]]` entry fields

| Field      | Type   | Description                                                                      |
|------------|--------|----------------------------------------------------------------------------------|
| `input`    | string | Hex-encoded input bytes (no `0x` prefix, no whitespace). Example: `"ffffffff01000000"`. |
| `expected` | string | Hex-encoded expected output bytes.                                               |
| `source`   | string | Where the vector came from (e.g. `"hand-verified from Rust u32 wrapping_add"`). Required. |

### `[[adversarial]]` entry fields

| Field    | Type   | Description                                                                 |
|----------|--------|-----------------------------------------------------------------------------|
| `input`  | string | Hex-encoded hostile input bytes. MAY be empty (`""`) to exercise zero-byte handling. |
| `reason` | string | Why this input is adversarial. Required.                                   |

### `[[golden]]` entry fields

| Field      | Type   | Description                                                        |
|------------|--------|--------------------------------------------------------------------|
| `input`    | string | Hex-encoded input bytes.                                           |
| `expected` | string | Hex-encoded expected output bytes.                                 |
| `reason`   | string | Context or invariant being pinned (e.g. `"wrap boundary u32::MAX"`). |

### Validation rules

1. `op_id` MUST match an id registered in `core::ops::registry`. Unknown ids are a CI failure.
2. Every `input` / `expected` string MUST be valid hex, even-length, and non-`0x`-prefixed.
3. `kat` array MUST contain at least one entry.
4. Every `source` and `reason` MUST be a non-empty string; "TODO" / "placeholder" fail CI.
5. A single op MAY have exactly one `rules/kat/<layer>/<op_name>.toml` file; duplicate op_id across files is a CI failure.
6. Vector byte widths MUST be consistent with the op's declared inputs/outputs (`OpDef::inputs` / `OpDef::outputs`). The conform loader rejects mismatched widths.

### Example

```toml
# rules/kat/primitive/add.toml
op_id = "primitive.math.add"

[[kat]]
input    = "ffffffff01000000"
expected = "00000000"
source   = "u32::MAX + 1 = 0 (wrapping add), hand-verified from Rust semantics"

[[kat]]
input    = "0000000000000000"
expected = "00000000"
source   = "add(0, 0) identity boundary"

[[kat]]
input    = "ffffffffffffffff"
expected = "feffffff"
source   = "add(u32::MAX, u32::MAX) = u32::MAX - 1 (wrap)"

[[adversarial]]
input  = ""
reason = "empty input exercises validation and boundary handling"

[[adversarial]]
input  = "01"
reason = "single byte — shorter than any valid input width"
```

---

## `waf` — WAF fingerprints

WAF rules detect attack strings in input buffers (e.g. SQLi fragments,
script tags, path-traversal sequences).  These rules are evaluated by the
`security_detection` ops pipeline.

### Required fields

| Field      | Type            | Description                                                            |
|------------|-----------------|------------------------------------------------------------------------|
| `id`       | string          | Unique slug within `waf/`.                                             |
| `type`     | string          | Engine selector.  MUST be exactly `"waf_fingerprint"`.                 |
| `patterns` | array of string | Literal or regex fragments to match.                                   |
| `severity` | string          | MUST be one of `critical`, `high`, `medium`, `low`.                    |
| `message`  | string          | Actionable guidance for the operator.                                  |

### Optional fields

| Field                | Type    | Default | Description                                                       |
|----------------------|---------|---------|-------------------------------------------------------------------|
| `case_sensitive`     | boolean | `true`  | Whether matching is case-sensitive.                               |
| `max_match_distance` | integer | `1024`  | Maximum byte distance between multi-part pattern pieces.          |

### Validation rules

1. `patterns` MUST contain at least one non-empty string.
2. `severity` MUST be exactly one of the four allowed values.
3. `max_match_distance`, when present, MUST be a positive integer.

---

## Contribution review checklist

Every PR that adds or edits a rule is checked by CI and a human reviewer.

- Schema validation passes (`cargo test -p vyre-conform` or the dedicated
  `rules/schema-check` target).
- `id` is unique within the category.
- `message` contains a concrete fix or mitigation step.
- No empty arrays in required fields.
- No TODO comments, stub values, or placeholder strings.
- File name matches `id` in `snake_case` form.

Rules that fail any of the above are rejected.  There are no exceptions.

---

## Engine selectors

The `type` field selects the engine that evaluates the rule.  The following
values are sanctioned.  Any other value is rejected by CI.

| `type` value      | Category     | Description                                      |
|-------------------|--------------|--------------------------------------------------|
| `text_scan`       | `category_b` | Literal substring scan over source files.        |
| `cve_signature`   | `cve`        | Semver-based vulnerable-dependency detector.     |
| `kat_vectors`     | `kat`        | Known-answer test vectors for op conformance.    |
| `waf_fingerprint` | `waf`        | Pattern matcher for attack strings in buffers.   |

New engine selectors require a maintainer RFC and a corresponding engine
implementation in `vyre-conform`.

---

## Versioning and compatibility

- `rules/` is versioned by file.  There is no monolithic schema version
  number in each file.
- Breaking changes to a category schema are announced in `CHANGELOG.md` at
  least one release cycle in advance.
- After vyre reaches 1.0, existing rule files that were valid at 1.0 will
  remain valid for the entire major version series.
- Validators run against the HEAD schema; pinned releases validate against
  the schema that shipped with that release.

---

## Reserved fields

The following top-level keys are reserved for future use and MUST NOT appear
in a rule file unless documented above:

- `schema_version`
- `enabled`
- `metadata`
- `author`
- `tags`

Using a reserved field causes CI validation to fail.
