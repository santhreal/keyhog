# How detection works

A KeyHog scan is a pipeline. Files come in one side, findings go out
the other. In between, four stages:

```text
files → [chunker] → [prefilter] → [detector match] → [post-process] → findings
```

Most chunks that fail the cheap prefilter stop there, which keeps full regex
evaluation focused on plausible inputs. This is not an unconditional hard drop:
a rejected chunk that looks encoded can enter a bounded decode-only recovery
pass (recursively decoding up to a `max_decode_depth`, defaulting to 10), so an
encoded secret is not lost merely because its plaintext anchor is absent from
the original bytes.

## Detection mechanisms

KeyHog does not use one universal test for "secret-like." It composes several
mechanisms, and their roles are deliberately different:

| Mechanism | Role | Can create a candidate? |
|---|---|---|
| Service-anchored detector regex | Matches a vendor or credential-specific shape from detector TOML | Yes |
| Companion patterns | Finds related fields near a primary match; `required = true` gates acceptance, while optional companions enrich confidence or verification | Confirms an existing candidate |
| Structured and multiline extraction | Reassembles assignments and strings that syntax splits across lines or nodes | Yes |
| Decode-through transforms | Scans supported encoded or transformed representations while preserving source attribution | Yes |
| Bounded static program recovery | Evaluates recognized side-effect-free JavaScript XOR, explicit-key AES-256-CBC, and CryptoJS/OpenSSL passphrase expressions when every operand is embedded and immutable | Yes |
| Generic assignment bridge | Extracts values beside credential-role keys when no vendor shape exists | Yes |
| Shannon entropy | Measures byte-distribution uncertainty for opaque generic values | Yes, on the entropy-discovery path |
| BPE token efficiency | Rejects language-like values that compress into common subword tokens; eligible candidates use it by default, and detector TOML can tune or disable it | No; precision gate |
| English bigram discriminator | Distinguishes random alphabetic tokens from pronounceable identifiers, dictionary placeholders, and low-diversity masks inside specific shape and context gates | No; admits or rejects an extracted candidate within those gates |
| Shape, placeholder, path, and context policy | Rejects examples, references, prose, identifiers, and context-specific noise | No; precision gates |
| Checksums and structural validators | Proves or rejects formats that carry intrinsic validity bits or grammar | Adjusts acceptance/confidence |
| On-device MoE scoring | Scores ambiguous candidates using local features; never sends content away | Adjusts confidence |
| Live verification | Optionally asks the owning service whether a surviving credential is active | Adds a verdict after detection |

Regex, generic extraction, entropy, and decode-through therefore find different
candidate classes. Named regexes and generic assignment extraction create
candidates; companions, validators, BPE, English bigram evidence, shape/context
policy, and confidence then confirm, reject, or score them. Verification runs
only after a candidate survives detection and reporting policy.

Static program recovery is a decode mechanism, not arbitrary code execution.
KeyHog does not invoke Node.js or evaluate source. It recognizes a bounded
grammar for cyclic byte-array XOR and Node-style AES-256-CBC decryption,
resolves only literal numeric arrays, Base64-encoded JSON arrays, buffer
literals, and empty-separator string joins, then checks binding consistency,
UTF-8, AES block shape, and PKCS#7 padding before rescanning the recovered
plaintext. Recovered XOR calls and Node AES ciphertext bindings are spliced
back into bounded parent context, preserving assignment evidence and absolute
source offsets. The CryptoJS dialect additionally requires an exact immutable
`require("crypto-js")` alias, decrypt wrapper, literal passphrase and
ciphertext bindings, an OpenSSL `Salted__` envelope, and EVP_BytesToKey MD5
derivation. Dynamic values or unsupported syntax produce no derived candidate.
The original source still follows the normal detector pipeline. The mechanism
is disabled with decode recursion, including under `--fast`.

BPE is not a replacement name for entropy: it is an independent post-candidate
signal. BetterLeaks calls the approach
[Token Efficiency](https://github.com/betterleaks/betterleaks#notable-features);
KeyHog uses the same broad BPE idea while keeping its own detector schema,
thresholds, pipeline, and behavioral evidence.

Terminology matters here: BetterLeaks' public documentation names the feature
**Token Efficiency** and describes BPE tokenization as a natural-language false
positive filter; it does not present “BPD” as a separate score. KeyHog names its
related mechanism **BPE token efficiency**, uses `cl100k_base`, measures UTF-8
bytes per token, and resolves the ceiling per detector. If “BPD” is being used
informally to mean a bits/byte or bytes/token density, do not treat it as a
third byte-density score. KeyHog also uses a separate English letter-bigram
discriminator, but it does not measure bits per byte or bytes per token.

The English bigram discriminator evaluates lowercase ASCII alphabetic runs
against an embedded 26 by 26 log-probability model. Digits and symbols end a
run. Fewer than six alphabetic characters produce no randomness verdict. A
random-token verdict requires a mean score at or below `-6.85` and at least
three distinct letters. Depending on the calling gate, that evidence can keep
an otherwise identifier-shaped random credential or reject a confidently
English placeholder. The model does not model arbitrary bytes, numeric keys,
hexadecimal or Base64 alphabets as such, or short values. Its current
thresholds are scanner-wide constants, not detector TOML fields.

## Detector-owned tuning: what each setting changes

Detection policy belongs in the detector TOML whenever the choice is specific
to a credential type. Scan-wide CLI/TOML values are operational overrides for
controlled comparisons or a corpus-wide policy; they are not a second hidden
detector definition. `keyhog explain <detector-id>` shows the policy declared by
that detector TOML and its provenance; `keyhog config --effective` shows the
resolved scan-wide policy.

Practical ownership rule: any numeric value that changes one secret family's
recall, precision, shape admission, or scoring must be a named detector-TOML
field. If the schema cannot express it, extend the typed schema and its
explain/contract surfaces rather than adding a detector-specific literal in
scanner code. Only true shared invariants, such as parser safety caps or a
model's fixed vocabulary, remain global.

| Detector TOML field | If increased / enabled | If decreased / disabled |
|---|---|---|
| `entropy_low` | Requires more Shannon entropy for keyword-anchored generic values; fewer low-randomness passwords/tokens survive | Admits more values when the assignment key supplies evidence; shape, BPE, context, and confidence gates still apply |
| `entropy_high` | Tightens keyword-independent generic admission | Admits more opaque candidates without strong assignment context |
| `entropy_very_high` | Tightens isolated, anchor-free token admission | Expands the no-keyword search and therefore its false-positive surface |
| `sensitive_path_entropy_very_high` | Raises the keyword-free bar even in sensitive files | Lowers the explicit sensitive-path bar for that detector, improving recall in `.env`/secret manifests |
| `[detector.entropy_fallback]` | Changes the emitted synthetic entropy finding identity for that detector's class | Omitting it uses the explicit custom-spec compatibility identity |
| `[[detector.entropy_shapes]]` | Allows only the declared structural exception to cross the broad isolated floor | Omitting the shape removes that detector's isolated exception |
| `entropy_floor` | A higher applicable length-bucket floor suppresses more low-entropy candidates for that detector | A lower floor preserves more human-chosen or structured credentials |
| `mixed_alnum_floor` | Rejects more identifier-like alphanumeric runs | Preserves more low-randomness mixed-alphanumeric values |
| `entropy_policy_priority` | Wins more overlapping generic keyword-policy claims | Yields shared keywords to a more specific detector; unique keywords are unchanged |
| `bpe_max_bytes_per_token` | A higher ceiling is looser: fewer compressible/word-like candidates are rejected | A lower ceiling is stricter: more language-like values are rejected, with corresponding recall risk |
| `bpe_enabled = false` | Not applicable | Skips token-efficiency rejection for detectors such as human-chosen passwords |
| `decoded_hex_key_material_lengths` | Adds only the declared pure-hex widths after transport decoding | Omitted widths remain decoded-digest negatives |
| `canonical_hex_key_material` | Adds only the declared pure-hex lengths under exact `keywords` or vendor-prefixed `suffixes`; `excluded_keywords` carve out ambiguous names | Omitted policy, keyword, suffix, or length remains a digest-shaped negative |
| `min_len` / `keyword_free_min_len` | Longer values are required; short false positives fall, but short real credentials can also fall | Shorter credential shapes become eligible |
| `max_len` (phase-2 generic) | Longer assignment values remain eligible; increase only when the credential contract permits them | Long assignment values are rejected rather than truncated into an apparently valid finding |
| `allowlist_paths`, `allowlist_values`, `stopwords` | Adds detector-specific path, value-regex, or literal exclusions | Removing an exclusion makes that detector consider the matching path/value again; it does not affect other detectors |
| `min_confidence` | Raises this detector's reporting floor | Lowers this detector's reporting floor; an operator override can still replace it |
| `weak_anchor` | Keeps generic shape/entropy gates active for a service detector whose captured value collides with generic identifiers | Trusts the service anchor without the weak-anchor policy; use only when the pattern itself proves the credential shape |
| `structural_password_slot` | Applies password-slot placeholder policy to a free-form value captured from a syntactic credential slot | Leaves that detector outside the structural-password family |
| `private_key_block` | Makes the detector's enclosing key block suppress less-specific findings nested inside it | Treats the match as an ordinary, non-enclosing finding |
| `[detector.credential_shape]` | Declares exact prefix/length/shape constraints that a captured credential must satisfy | Omitting it leaves that detector without an additional credential-shape constraint |

### Resolution rules

These settings do not all use one generic “last value wins” rule:

- **Generic keyword ownership:** the highest `entropy_policy_priority` among
  detectors claiming the normalized assignment keyword owns entropy and BPE
  policy. Equal priorities use compiled detector order only as a deterministic
  tie-break. Custom detector policy keywords join entropy discovery directly;
  they do not need to be repeated in `[scan].secret_keywords`.
- **BPE ceiling:** the compiled fallback is `2.2` UTF-8 bytes per
  `cl100k_base` token. The owning detector's `bpe_max_bytes_per_token` replaces
  that fallback. An explicitly supplied
  `[scan].entropy_bpe_max_bytes_per_token` or
  `--entropy-bpe-max-bytes-per-token` replaces every BPE-enabled
  entropy/generic detector ceiling; the CLI wins over the config file.
  `bpe_enabled = false` still disables the gate for that detector.
- **Confidence floor:** the scan floor defaults to `0.40`. A detector TOML
  `min_confidence` replaces the scan floor for that detector, and an operator
  `[detector.<id>].min_confidence` replaces the detector-declared floor. Under
  `--precision`, the resolved global and per-detector floors are clamped to at
  least `0.85`; neither source can weaken the precision preset.
- **Entropy policy:** omitted detector fields use `4.5` (`entropy_high`), `3.0`
  (`entropy_low`), `5.8` (`entropy_very_high`), and `4.0`
  (`mixed_alnum_floor`). Detector TOML values replace those individual
  fallbacks. The scan-wide `entropy_threshold` is deliberately not a blanket
  replacement for all four bands. On the phase-2 generic bridge it tightens
  only when it exceeds the owning detector's high band. On the entropy scanner,
  a value above that high band tightens keyword and isolated candidates; a
  value below the keyword detector's low band loosens that keyword path, while
  values between the low and high bands leave its low floor in place. The
  isolated path keeps its mixed-alphanumeric floor unless the scan threshold
  exceeds the high band. These rules preserve the different evidence carried
  by an assignment key, an isolated opaque token, and an unanchored generic
  value.
- **Sensitive paths:** `sensitive_path_entropy_very_high` is an optional
  detector-local threshold for keyword-free candidates in paths classified as
  sensitive. When omitted, that detector's `entropy_very_high` applies; there
  is no hidden scanner-wide discount.
- **Synthetic entropy identity:** generic detector TOMLs may declare
  `[detector.entropy_fallback]` with an `entropy-*` id, display name, and
  service. The compiled scanner uses this metadata for entropy-only findings;
  custom specs that omit the block use the documented compatibility labels, so
  omission is visible in `explain` rather than silently changing a shipped
  detector's identity.
- **Isolated entropy shapes:** generic entropy owners may declare a typed
  `lower-dash-app-password` shape with its entropy floor, group count/length,
  and special minimum length. The candidate length is derived as
  `group_count * group_length + group_count - 1`, with one dash between groups;
  `special_min_length` controls the short-candidate revisit and must not exceed
  that derived length. The shape is used for anchorless synthetic entropy
  recovery; the anchored `bluesky-app-password` regex remains the source of the
  named Bluesky finding. A custom corpus without the shape has no isolated
  exception, rather than inheriting an embedded detector policy.

Token efficiency can carry more of the precision burden for a detector whose
assignment key or regex already creates the candidate. That is the practical
per-detector alternative to making Shannon entropy the decisive signal: use a
permissive detector-owned entropy floor appropriate to the credential family,
then let its BPE, shape, context, and confidence policy reject word-like noise.
It is not equivalent to blindly replacing entropy with one global BPE number,
and `bpe_enabled` alone never creates a candidate. Both configured gates still
execute; the current pipeline has no entropy-or-BPE branch.

Detector-owned `canonical_hex_key_material` is the deliberate exception to the
BPE and generic low-diversity/decode-as-data gates. Hexadecimal key bytes
tokenize efficiently and use a small alphabet for the same mechanical reasons
hexadecimal digests do, so the exact detector-owned keyword/length contract
supplies the discriminator. Placeholder, degenerate-repeat, entropy, context,
and reporting gates remain active. When ML is enabled, this exact TOML match is
structural positive evidence and therefore preserves the detector heuristic
floor; the model may raise its score but cannot erase a policy-proven key as if
it were an unowned entropy candidate.

Scan-wide settings remain operational controls, but they do not all compose the
same way. Explicit CLI values take precedence over config-file values. An
explicit scan-wide BPE ceiling takes precedence over detector-local BPE ceilings
so a benchmark can compare one bound consistently. `entropy_threshold` can
tighten a detector's high band but does not silently replace its lower
detector-owned keyword band. A detector's `min_confidence` replaces the global
reporting floor for that detector, and `[detector.<id>] min_confidence` is the
operator override for that one ID. For production detector tuning, put the
stable value in the owning detector TOML and prove it with that detector's
positive, negative, evasion, backend-parity, and corpus contracts.

## Settings, hardware, and result parity

Hardware changes execution, not detection policy. CPU, SIMD/Hyperscan, and GPU
routes consume the same resolved detector/config digest. Autoroute admits a
candidate only when its canonical detection identities match the reference:
chunk membership, detector id/name/service/severity, exact credential,
stored-hash, and companion identity, source, file, line, byte offset, commit,
author, date, entropy, confidence, and multiplicity. Mismatch diagnostics name
only the differing fields and occurrence counts. They never expose raw
values or deterministic value fingerprints.
Built-in suppression, confidence, decode, and scanner postprocessing are already
part of those backend results. CLI allowlists and rules, policy floors,
cross-source deduplication, verification, and output formatting run after
selection. Missing or stale exact evidence is an error; calibration never
relaxes a detector to make a backend look faster.

| Change | Finding-set effect | Routing/calibration effect |
|---|---|---|
| Different CPU, GPU, driver, or accelerator availability | None for the same resolved detector/config and input; a parity mismatch rejects that route | Host/device/runtime identity changes, so old autoroute evidence is not reusable |
| Different detector TOML, thresholds, allowlists, or enabled detectors | May change candidates, suppressions, confidence, and final findings | Detector/config digest changes; recalibration is required |
| `--fast`, `--deep`, or `--precision` | Changes the resolved feature and confidence policy, so results may differ by design | Each preset has a distinct config identity and calibration coverage |
| Explicit `--backend cpu|simd|gpu-cuda|gpu-wgpu` | Intended to be parity-identical; it is a diagnostic/benchmark override, not proof | Bypasses autoroute and does not create reusable fastest-correct evidence |
| Input size, chunk count, source family, decoder-kind mask, decode candidate count or byte bucket, decoder uncertainty, or full-source-size availability | The input itself can change findings; backend choice must not | Selects a different exact workload key, including whether each source family's size bucket came from full-source or payload evidence |
| One-shot process versus ready daemon | None: runtime lifetime cannot change detector policy or canonical matches | The same timing record derives a cold-aware one-shot route and a warm persistent-daemon route; the winners may differ |

### Configuration Presets

*   `--fast` (or `ScannerConfig::fast()`): Disables high-FP generic entropy checks, ML, and deep decoding (`max_decode_depth = 0`). Maximizes throughput.
*   `--deep` (or `ScannerConfig::thorough()`): Enables source-file entropy, combines heuristic and ML evidence without an ML-only veto, removes comment confidence penalties, raises decode-through to one 1 MiB chunk, and uses decode depth 10. This is the highest-recall built-in preset with bounded recovery.
*   `--precision` (or `ScannerConfig::high_precision()`): Sets `min_confidence` to `0.85` (`HIGH_PRECISION_MIN_CONFIDENCE`), keeps ML enabled, limits decoding depth (`max_decode_depth = 1`), and disables high-FP generic entropy checks. Maximizes precision.

### Strict Backend Parity

KeyHog exposes three search-backend classes: pure Rust CPU, SIMD/Hyperscan
(`simd-regex`), and GPU/VYRE region presence. Autoroute measures four concrete
runtime peers when eligible: scalar CPU, Hyperscan CPU, CUDA, and WGPU. Portable
builds retain the pure-Rust trigger path without Hyperscan. `keyhog
calibrate-autoroute` rejects any peer whose canonical match identity differs
from the reference. It records the first real GPU dispatch plus warm trials: an
ordinary process resolves against the cold-aware GPU cost, while a daemon that
initialized its engines before readiness resolves against the warm GPU
evidence. A missing or invalid decision is an error; automatic routing never
silently substitutes another backend.

When comparing settings, record the effective config, detector digest, input
identity, backend, host/accelerator identity, and complete findings, not only
elapsed time or finding count. A faster run with a different result set is a
detection change or parity failure, not a routing win.

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

3. **Backend trigger pass.** The `simd-regex` backend compiles the detector
   corpus into Hyperscan databases when the `simd` feature is present;
   `cpu-fallback` uses the pure-Rust trigger path. One pass returns which
   detector IDs have a candidate match.

   GPU-capable builds add VYRE's region-presence literal-set backend. There is
   no universal model-name or byte threshold at which KeyHog silently switches
   to it. `--backend auto` requires an exact persisted calibration decision for
   the current binary, detector/config digest, host/device/driver, workload
   class, and size bucket. Calibration keeps a GPU route only when its canonical
   match identities equal the reference and it is the fastest eligible backend
   for that key.

## Stage 3 - detector match

For each pattern-backed detector that the prefilter flagged, the full regex
evaluates. The regex is `detector.patterns[].regex` in that detector's TOML, and
its configured capture group becomes the candidate **credential**. Generic
phase-2 detector TOMLs use keyword, length, entropy, token-efficiency, and shape
policy for shapeless assignments or isolated opaque values. They may also carry
explicit patterns for strongly structured envelopes such as JSON `"secret"`,
`"token"`, or `"apiKey"` fields; both mechanisms remain owned by the same
detector TOML instead of a central compatibility detector.

A detector's `.toml` carries:

- `id`, `name`, `service`, `severity`, `keywords`
- zero or more `patterns`, each with `regex` + `group` + optional `description`
  (required for service-anchored detectors; optional structured-envelope
  anchors for `phase2-generic`)
- optional `companions`; only entries with `required = true` gate acceptance
- optional `verify` block - HTTP method, URL template, auth scheme,
  success status

Detectors fall into two camps:

- **Service-anchored.** Regex requires a service-specific keyword
  (`AWS_SECRET_ACCESS_KEY=`, `stripe.com/v1/`, `dn_` Deepnote prefix).
  These have HIGH precision: the keyword itself is positive evidence,
  not just a hint.

- **Generic / entropy discovery** (`generic-password`, `entropy-api-key`,
  `entropy-token`). Triggered by entropy + assignment shape only -
  `password = "..."`, `secret: "..."`, JSON `{ "token": "..." }`. Lower
  precision; suppression filters do most of the work.

  Surviving candidates also pass a BPE token-efficiency gate. Shannon entropy
  asks how evenly bytes are distributed; token efficiency asks how readily a
  fixed subword vocabulary compresses the value. Dotted API names and prose can
  have high Shannon entropy but tokenize into a few common pieces, while opaque
  secrets usually require many short tokens. The mechanisms are complementary,
  and generic detector TOMLs may own their token-efficiency ceiling through
  `bpe_max_bytes_per_token`. Opaque API-key/secret policies use their
  detector-owned ceiling, falling back to the scan-wide default of `2.2` UTF-8
  bytes per token when they do not declare one; password/passphrase policies
  set `bpe_enabled = false` because human-chosen credentials may intentionally
  be word-like. Disabled policies skip tokenizer work entirely rather than
  using a magic oversized ceiling.

The `entropy-generic`, `entropy-password`, `entropy-token`, and
`entropy-api-key` IDs are output classifications for entropy-discovered
findings, not four additional detector TOML files. Their candidate policy is
owned by the corresponding phase-2 TOMLs selected from the assignment context:
`generic-secret`, `generic-password`, `generic-keyword-secret`, or
`generic-api-key`. Use `keyhog explain` on those owning detector IDs when
tuning entropy, BPE, length, or canonical-key policy.

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
    can be real credentials when paired with a service or protocol anchor, so
    named detector TOMLs and structural authorization detectors own those
    cases. A generic `token=<uuid>` remains an identifier; an
    `Authorization: Bearer <uuid>` value is a credential because the Bearer
    envelope supplies the missing evidence. Public salts and nonces are not
    generic secrets. A detector for a product whose field is genuinely secret
    despite that name must own the product syntax explicitly.
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
