# How detection works

A KeyHog scan is a pipeline. Files come in one side, findings go out
the other. In between, four stages:

```text
files → [chunker] → [prefilter] → [detector match] → [post-process] → findings
```

Most chunks that fail the cheap prefilter stop there, which keeps full regex
evaluation focused on plausible inputs. This is not an unconditional hard drop:
a rejected chunk that looks encoded can enter a bounded decode-only recovery
pass, so an encoded secret is not lost merely because its plaintext anchor is
absent from the original bytes.

## Detection mechanisms

KeyHog does not use one universal test for "secret-like." It composes several
mechanisms, and their roles are deliberately different:

| Mechanism | Role | Can create a candidate? |
|---|---|---|
| Service-anchored detector regex | Matches a vendor or credential-specific shape from detector TOML | Yes |
| Companion patterns | Requires related fields or fragments near a primary match | Confirms an existing candidate |
| Structured and multiline extraction | Reassembles assignments and strings that syntax splits across lines or nodes | Yes |
| Decode-through transforms | Scans supported encoded or transformed representations while preserving source attribution | Yes |
| Generic assignment bridge | Extracts values beside credential-role keys when no vendor shape exists | Yes |
| Shannon entropy | Measures byte-distribution uncertainty for opaque generic values | Yes, on the entropy fallback path |
| BPE token efficiency | Rejects language-like values that compress into common subword tokens when the owning detector enables it | No; precision gate |
| Shape, placeholder, path, and context policy | Rejects examples, references, prose, identifiers, and context-specific noise | No; precision gates |
| Checksums and structural validators | Proves or rejects formats that carry intrinsic validity bits or grammar | Adjusts acceptance/confidence |
| On-device MoE scoring | Scores ambiguous candidates using local features; never sends content away | Adjusts confidence |
| Live verification | Optionally asks the owning service whether a surviving credential is active | Adds a verdict after detection |

Regex, generic extraction, entropy, and decode-through therefore find different
candidate classes. BPE is not a replacement name for entropy: it is an
independent post-candidate signal. Betterleaks calls the approach
[Token Efficiency](https://github.com/betterleaks/betterleaks#notable-features);
KeyHog uses the same broad BPE idea while keeping its own detector schema,
thresholds, pipeline, and behavioral evidence.

Terminology matters here: Betterleaks' current source calls the predicate
[`failsTokenEfficiency`](https://github.com/betterleaks/betterleaks/blob/0b4063d7990e0ab6366a5b4eb58789584af5f945/internal/exprruntime/bindings_filter.go#L111-L139),
not “BPD.” It uses `cl100k_base`, a byte-length/token ratio, word-list checks,
and short-value threshold branches. KeyHog names its related mechanism **BPE
token efficiency**, measures UTF-8 bytes per token, and resolves the
ceiling per detector. If “BPD” is being used informally to mean a bits/byte or
bytes/token density, do not treat it as a third implemented score: Shannon
entropy and BPE token efficiency are the two separate signals documented here.

## Stage 1 - chunker

A file becomes one or more **chunks**. A chunk is `{data: str, metadata:
{source_type, path, line_offsets, …}}`. The chunker:

- Skips obvious binaries via magic-byte sniffing (PDF, PNG, zip, …).
- Skips files matching `is_default_excluded_path` (node_modules, .min.js,
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
   detectors care about. A chunk with no relevant byte becomes a prefilter miss.

2. **Bigram bloom.** A 4096-bit bloom filter of 2-byte sequences from
   detector keyword prefixes. A chunk with no overlapping bigram becomes a
   prefilter miss. This cheaply recognizes source that carries no relevant
   anchor vocabulary.

After these screens, ordinary misses stop. Decode-shaped misses instead take
the bounded decode-only path described above; transformed plaintext is then
attributed back to the original source.

3. **SIMD prefilter (`simd-regex`).** A multi-pattern trigger scanner.
   When the `simd` feature is compiled, the detector corpus is also compiled
   into Hyperscan databases; portable builds use the pure-Rust trigger path.
   One scan pass returns "which detector IDs have a candidate match."

   GPU-capable builds add vyre's region-presence literal-set backend. There is
   no universal model-name or byte threshold at which KeyHog silently switches
   to it. `--backend auto` requires an exact persisted calibration decision for
   the current binary, detector/config digest, host/device/driver, workload
   class, and size bucket. Calibration keeps a GPU route only when its complete
   findings are identical and it is the fastest eligible backend for that key.

## Stage 3 - detector match

For each pattern-backed detector that the prefilter flagged, the full regex
evaluates. The regex is `detector.patterns[].regex` in that detector's TOML, and
its configured capture group becomes the candidate **credential**. Generic
phase-2 detector TOMLs intentionally carry no regex: their keyword, length,
entropy, token-efficiency, and shape policy governs candidates extracted from
assignments or isolated opaque values.

A detector's `.toml` carries:

- `id`, `name`, `service`, `severity`, `keywords`
- zero or more `patterns`, each with `regex` + `group` + optional `description`
  (required for service-anchored detectors; absent for `phase2-generic`)
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

  Surviving candidates also pass a BPE token-efficiency gate. Shannon entropy
  asks how evenly bytes are distributed; token efficiency asks how readily a
  fixed subword vocabulary compresses the value. Dotted API names and prose can
  have high Shannon entropy but tokenize into a few common pieces, while opaque
  secrets usually require many short tokens. The mechanisms are complementary,
  and generic detector TOMLs may own their token-efficiency ceiling through
  `bpe_max_bytes_per_token`. Opaque API-key/secret policies use the measured
  2.3 ceiling; password/passphrase policies set `bpe_enabled = false` because
  human-chosen credentials may intentionally be word-like. Disabled policies
  skip tokenizer work entirely rather than using a magic oversized ceiling.

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

The alphabet screen and bigram bloom reject irrelevant chunks before regex
confirmation. Literal triggers narrow the active detector set, and the scanner
shares confirmation, suppression, and reporting tails across CPU and GPU
backends. Windowing bounds scratch space for large inputs; caches avoid repeated
compiler and index work.

End-to-end throughput depends on the detector/config digest, source shape,
candidate density, decoding and verification policy, cache state, CPU, GPU,
driver, and storage. Use `keyhog calibrate-autoroute` for routing evidence on
the installed host and the repository benchmark harness for reproducible
cross-version measurements; do not treat a throughput number from another
machine or detector corpus as a routing threshold.

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
stage 2 - simd-regex:     MATCH → triggers `aws-secret-access-key` + `generic-password`
stage 3 - regex eval:
  `aws-secret-access-key` detector pattern captures the 40-byte value
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
