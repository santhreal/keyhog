# How detection works

A KeyHog scan is a pipeline. Files come in one side, findings go out
the other. In between, four stages:

```text
files → [chunker] → [prefilter] → [detector match] → [post-process] → findings
```

Each stage is a hard filter - if a chunk fails the prefilter, no
detector ever runs on it. That's where the speed comes from: the
expensive regex evaluation only sees chunks that already plausibly
contain something.

## Stage 1 - chunker

A file becomes one or more **chunks**. A chunk is `{data: str, metadata:
{source_type, path, line_offsets, …}}`. The chunker:

- Skips obvious binaries via magic-byte sniffing (PDF, PNG, zip, …).
- Skips files matching `is_default_excluded` (node_modules, .min.js,
  build/, etc.).
- Splits files larger than the 1 MiB window size into overlapping ~1 MiB
  windows so a single giant log file doesn't blow scratch memory. Each
  window carries its absolute base byte offset and base line so findings
  report the real file `offset`/`line`, not the per-window one.
  Cross-window secrets are reassembled in stage 4.
- Decodes UTF-16 BOM files into UTF-8 (PowerShell / .NET configs).

Specialized chunkers run too:
- Git history → one chunk per (commit × file × diff line)
- Docker images → one chunk per layer × file
- Web URLs → one chunk per response body / sourcemap / WASM strings
- S3 buckets → one chunk per object body
- GCS buckets → one chunk per object body
- Azure Blob containers → one chunk per blob body

## Stage 2 - prefilter (the cheap pass)

Three gates, in order, each cheaper than the next:

1. **Alphabet screen.** A 256-bit mask of which bytes the corpus's
   detectors care about. If a chunk doesn't contain ANY byte in the
   mask, it's discarded. Most random-binary chunks fail here.

2. **Bigram bloom.** A 4096-bit bloom filter of 2-byte sequences from
   detector keyword prefixes. If a chunk has no overlapping bigram,
   discard. Catches the "this is a Go source file with no `key=`
   anywhere" case in microseconds.

3. **SIMD prefilter (Hyperscan).** A multi-pattern SIMD regex scanner.
   The detector corpus is compiled to a single Hyperscan database;
   one scan call returns "which detector IDs have a candidate match."
   On AVX-512 hardware this runs at ~3 GB/s.

   On GPUs above the breakeven threshold (2 MiB on 5090-class, 16 MiB
   on 4090-class), the prefilter switches to a CUDA literal-set scan
   via vyre - same patterns, parallelized across thousands of cores.

## Stage 3 - detector match

For each detector that the prefilter flagged, the FULL regex evaluates.
The regex is what's in the `.toml` file - `detector.patterns[].regex`.
The capture group becomes the candidate **credential**.

A detector's `.toml` carries:

- `id`, `name`, `service`, `severity`, `keywords`
- one or more `patterns`, each with `regex` + `group` + optional `description`
- optional `companions` (e.g. AWS access key needs the secret key nearby)
- optional `verify` block - HTTP method, URL template, auth scheme,
  success status

Detectors fall into two camps:

- **Service-anchored.** Regex requires a service-specific keyword
  (`AWS_SECRET_ACCESS_KEY=`, `stripe.com/v1/`, `dn_` Deepnote prefix).
  These have HIGH precision: the keyword itself is positive evidence,
  not just a hint.

- **Generic / entropy fallback** (`generic-password`, `entropy-api-key`,
  `entropy-token`). Triggered by entropy + assignment shape only -
  `password = "..."`, `secret: "..."`, JSON `{ "token": "..." }`. Lower
  precision; suppression filters do most of the work.

The split matters for the post-process stage.

## Stage 4 - post-process

Even a regex match isn't always a credential. Stage 4 filters:

- **Known example fixtures** (Stripe docs key, AWS docs key, RFC 7519
  specimen JWT).
- **Placeholder language** - credentials containing `YOUR_`, `INSERT`,
  `EXAMPLE`, `PLACEHOLDER`, `TODO`, `FIXME`, etc.
- **Shape gates.**
  - *Universal:* `punctuation_decorated_identifier` - credentials
    starting with `--`, `&`, `@`, `!`, `/`, `$` (CLI flags, pointers,
    SQL vars, shell vars, GraphQL refs) or ending in `:` / `!`
    (UI labels, TypeScript non-null assertions).
  - *Generic / entropy only:* `pure_identifier`,
    `word_separated_identifier`, `scheme_prefixed_uri`,
    `url_or_path_segment`, `contains_uuid_v4_substring`. These shapes
    CAN be real credentials when paired with a service anchor (PowerBI
    client_id is a UUID, mongodb-atlas is a URI), so we only apply
    them to anchorless detectors.
- **Path-based suppressions** - vendored bundles (`node_modules/`,
  `wp-includes/`, `bower_components/`), CI workflow files (where
  `${{ secrets.NAME }}` references are syntactic, not credentials),
  i18n translation files, secret-scanner source files (the file IS a
  scanner; its regex literals shouldn't fire on itself).
- **Cross-chunk reassembly.** A secret split across window boundaries
  gets reassembled from the tail of chunk N + the head of chunk N+1.

A finding that survives stage 4 makes it to output.

## Where the speed comes from

| Stage             | Throughput on a modern laptop |
|-------------------|-------------------------------|
| Chunker           | ~5 GB/s (mmap + magic-byte sniff) |
| Alphabet screen   | ~12 GB/s (256-bit table lookup, vectorized) |
| Bigram bloom      | ~8 GB/s (4096-bit table, vectorized) |
| Hyperscan SIMD    | ~3 GB/s (multi-pattern regex) |
| Per-detector regex | ~150 MB/s × detectors flagged |
| Post-process      | ~200 MB/s |

The end-to-end number on the dogfood corpus is ~800 MB/s sustained.
Hardware acceleration (AVX-512, CUDA) raises the SIMD-prefilter ceiling
substantially on big inputs; small inputs (< 100 KB) bottleneck on the
chunker and post-process, not the regex.

## Where the precision comes from

| Filter                                     | What it catches                                  |
|--------------------------------------------|--------------------------------------------------|
| Known example fixtures                     | Stripe docs key, AWS docs key, RFC 7519 JWT      |
| `pure_identifier`                          | `getParameter`, `Benutzername`, `auth_decoders`  |
| `word_separated_identifier`                | `s3_secret_access_key` (function name)           |
| `scheme_prefixed_uri`                      | `urn:foo:bar` (URI literal, not creds)           |
| `url_or_path_segment`                      | `/api/v1/users/123` (REST path)                  |
| `contains_uuid_v4_substring`               | `TOKEN_LIST=636765a9-…` (UUID identifier)        |
| `punctuation_decorated_identifier`         | `--api-secret`, `&password`, `Password:`         |
| Vendored-minified-path                     | `node_modules/jquery-3.6.0.min.js`               |
| CI workflow path                           | `.github/workflows/ci.yml` - `${{ secrets.X }}`  |
| i18n translation path                      | `locale/de.po` - translated `password` word      |

Each filter has a known-FP-cluster it was built to defuse. The
[Suppressions](./suppressions.md) page enumerates them with examples.

## What this looks like for one finding

```text
file.env contains: AWS_SECRET_ACCESS_KEY=ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1

stage 1 - chunker:        emit chunk{ path: "file.env", data: "AWS_SECRET..." }
stage 2 - alphabet:       PASS (chunk has `=`, alphanumerics from the corpus)
stage 2 - bigram bloom:   PASS (`AW`, `WS`, `_S` are in the bloom)
stage 2 - Hyperscan:      MATCH → triggers `aws-secret-access-key` + `generic-password`
stage 3 - regex eval:
  `aws-secret-access-key` regex `(?i)(?:AWS[_-]?SECRET[_-]?ACCESS[_-]?KEY|...)[=:\s"']+([0-9a-zA-Z/+=]{40})(?:[^0-9a-zA-Z/+=]|$)`
    captures `ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1`
  `generic-password` regex doesn't match (no `_password`/`_pwd` substring)
stage 4 - post-process:
  known-example check: no
  `looks_like_pure_identifier`: false (has digits + /)
  `looks_like_punctuation_decorated_identifier`: false
  → EMIT
```

That's one finding's life. Multiply by 10⁶ files and the throughput
math is why each stage matters.
