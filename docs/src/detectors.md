# Detectors

A **detector** is a single TOML file that teaches KeyHog one shape of
credential. The embedded corpus is generated from `detectors/*.toml`; query the
running binary for its exact corpus size rather than relying on a number copied
into documentation.

## Pattern counts

KeyHog counts **detectors** and **patterns** separately. A detector is one
TOML file; each file may define one or more `[[detector.patterns]]` rows.
The startup banner's parenthesized pattern total is the compiled scanner
count after the engine expands those rows (and related trigger keywords)
into the literal and regex slots it actually runs, so it is always larger
than the raw TOML row count. Use `keyhog detectors --format json | jq length` for
the embedded detector count; the banner line shows the live compiled total
for your binary.

## Anatomy of a detector

```toml
# detectors/stripe-secret-key.toml

[detector]
id = "stripe-secret-key"
name = "Stripe Secret Key"
service = "stripe"
severity = "critical"
ml = { match_mode = "lift", entropy_mode = "disabled", weight = 1.0, context_radius_lines = 5 }
match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.2999999999999998, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.1, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.8, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }
validators = [{ type = "pattern-shape", prefixes = ["sk_live_", "sk_test_", "rk_live_", "rk_test_"], allow_overlong = false }]
keywords = ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "stripe"]
simdsieve_prefixes = ["sk_live_", "sk_test_", "rk_live_", "rk_test_"]

[[detector.patterns]]
regex = 'sk_live_[a-zA-Z0-9]{24,}'
description = "Stripe live secret key"

[[detector.patterns]]
regex = 'sk_test_[a-zA-Z0-9]{24,}'
description = "Stripe test secret key"

[[detector.patterns]]
regex = 'rk_live_[a-zA-Z0-9]{24,}'
description = "Stripe live restricted key"

[[detector.patterns]]
regex = 'rk_test_[a-zA-Z0-9]{24,}'
description = "Stripe test restricted key"

[detector.verify]
method = "GET"
url = "https://api.stripe.com/v1/charges?limit=1"
allowed_domains = ["api.stripe.com"]

[detector.verify.auth]
type = "basic"
username = "match"
password = ""

[detector.verify.success]
status = 200
```

That's the whole contract for one service. Every other detector
follows the same shape.

Verification success and metadata `json_path` fields use the single rooted
response-selector grammar documented in [Verification](./verification.md#what-live-means).

Each shipped detector also owns a canonical positive/negative truth pair:

```toml
[[detector.tests]]
test_positive = "STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789aBcD"
test_negative = "sk_live_short"
```

These are executable production-path fixtures, not documentation examples.
The positive must surface that exact detector id and the negative must leave
that detector silent. Keeping the pair beside the detector's patterns and
policy makes a TOML change reviewable and independently tunable without hunting
through a second registry. Larger adversarial, evasion, performance, and scale
corpora remain separate because one compact pair cannot prove those contracts.

### Fields

`detector.id` - kebab-case, globally unique. Shows up in JSON output
as `detector_id` and in CLI output as the third column.

`detector.kind` - optional execution class. Omission or `"regex"` selects the
normal anchored-regex contract. `"phase2-generic"` selects the shared generic
discovery engine with every detector-specific decision owned by this TOML; it
may have no `patterns`, but must declare the mechanism-specific fields
validation requires. `service` is report taxonomy and never selects either
execution class.

`detector.ml` - model policy compiled with the detector. `match_mode` controls
regex and generic-assignment candidates; `entropy_mode` controls synthetic
entropy candidates owned by this detector. Each mode is `disabled`, `lift`,
`blend`, or `authoritative`. `lift` applies the declared fraction of positive
model evidence without letting an uncalibrated model veto structural evidence;
`blend` is the arithmetic mixture and can raise or lower confidence;
`authoritative` uses the model score directly. `weight` controls `lift` and
`blend`, and `context_radius_lines` is the bounded source window supplied to feature
extraction. Normal scans use these detector values. An explicitly supplied
`--ml-weight` is a scan-wide diagnostic or benchmark override. Detectors that
do not own entropy policy set `entropy_mode = "disabled"`.
The model input also carries detector facts from this same TOML: exact service
context, entropy-policy/phase-2 ownership, weak-anchor and structural-password-slot
classification, verification, required companions, and the pattern or entropy
candidate channel. Entropy candidates additionally carry a one-hot family read
from this detector's `entropy_fallback.class`, so API keys, passwords, tokens,
and generic entropy do not collapse into one model input. The shared scorer does
not infer a detector family from its id or apply one unconditioned probability
to every secret type.
Every detector TOML must declare `detector.ml`; omission fails parsing instead
of silently applying an embedded or scanner-side model policy. Programmatic
`DetectorSpec::default()` disables both model paths until the caller opts in.

`detector.match_confidence` is the complete pre-model scoring policy for regex
matches. The six signal weights define the maximum normalized evidence.
`high_entropy_partial_weight`, `moderate_entropy_threshold`, and
`moderate_entropy_weight` define the lower entropy tiers.
`very_high_entropy_margin` is added to the resolved operational entropy
threshold for the full entropy weight. The shipped value is the exact binary64
difference between the historical 5.8 and 4.5 tiers. The low-entropy fields
define the long-value penalty. The seven context multipliers define how
assignment, string-literal, unknown, documentation, comment, test, and encrypted
source contexts affect this detector before and after model scoring. The two
context-suppression thresholds decide when a comment, test, documentation, or
encrypted candidate is too weak to report. The nested `post_match` policy owns
the placeholder, byte-diversity, repeated-run, decoded-envelope, fixture-path,
and post-model context adjustments. `data_envelope_multiplier` is present only
when decoded payload evidence applies to that detector. A named detector declares
`named_anchor_floor` and omits `low_promise_confidence`. A
phase-two generic owner does the reverse. This lets the cheap promise gate
reject only unaccompanied generic candidates. Missing, misplaced, non-finite,
or non-monotonic policy fails detector validation. KeyHog precomputes the
normalization reciprocal once in the detector execution plan.
`DetectorSpec::default()` leaves this policy unset, so a programmatic detector
must declare it before scanner compilation.

`detector.validators` - optional typed offline validation programs compiled with
this detector. `crc32-base62` declares `prefixes`, `entropy_len`,
`checksum_len`, `reject_overlong`, and the confidence floor earned by a valid
checksum. `github-fine-grained-crc32` declares both segment lengths and checksum
width. `base64-payload` declares the exact base64 `alphabet` (`standard`,
`standard-no-pad`, `url-safe`, or `url-safe-no-pad`) plus encoded and decoded
length bounds, so the hot path performs one direct decode without guessing a
dialect from candidate bytes.
`pattern-shape` reuses this detector's patterns as its structural contract and
does not claim checksum proof or raise confidence. Prefixes, widths, bounds, and
floors belong here, never in a scanner-side service table. Named matches dispatch
directly through their compiled detector plan; generic candidates use a compiled
first-byte prefix index. One verdict follows the candidate through suppression,
ML batching, and final confidence, so validation is not repeated after inference.

`detector.decode_transforms` declares admission for asymmetric evasion recovery.
Use plaintext prefixes. KeyHog compiles the reversed and rotated spellings once
from the active corpus:

```toml
decode_transforms = { reverse_prefixes = ["dapi"], caesar_prefixes = ["dapi"] }
```

An empty list disables that transform for this detector. A custom corpus does
not inherit prefixes from the embedded corpus. Reverse prefixes must contain at
least three ASCII bytes. Caesar prefixes must contain an ASCII letter. These
fields control only reverse and Caesar admission. Base64, hex, URL, JSON,
Unicode, MIME, quoted-printable, and bounded static-program recovery use shared
representation grammars because their eligibility is not specific to a secret
type.

`detector.name` - human-readable name. Shows up in `keyhog detectors`
listing and IDE plugins.

`detector.service` - the upstream service slug. Used for grouping
findings (e.g. "you leaked 3 stripe credentials"); a single service
can have multiple detectors (`stripe-secret-key`,
`stripe-restricted-key`, `stripe-publishable-key`).

`detector.simdsieve_prefixes` - optional literal prefixes for the first-pass
AVX-512/AVX2/NEON accelerator. This is detector-owned Tier-B policy: each value
must be non-empty ASCII, unique in the loaded corpus, and must be an actual
literal prefix of one of the same detector's regex patterns. The loaded corpus
may declare at most 16 total (the backend ABI limit); duplicate ownership,
unbacked prefixes, and over-capacity corpora fail scanner construction instead
of silently disabling acceleration. Most detectors leave this empty.

`detector.severity` - one of `critical | high | medium | low | client-safe | info`.
The CLI exits non-zero when any finding clears the active gate; under
`--verify`, confirmed live credentials escalate that outcome to exit `10`.
SARIF / GitHub Code Scanning surface severity prominently.

`client-safe` is the bug-bounty tier for keys public by design
(Sentry DSN, Stripe `pk_*`, Mapbox `pk.`, PostHog `phc_`, Firebase
Web API key, Google Maps browser key, Mixpanel project token,
Algolia search-only, Datadog browser RUM, Bugsnag, Segment write
key). The detector still fires (a token grep is a token grep), but
the finding renders below `low` and `--hide-client-safe` filters it
out entirely. Set per-pattern via the `client_safe = true` field on
a `[[detector.patterns]]` block - detectors that fire on both the
public and the secret prefix (Stripe `pk_*` vs `sk_*`, Mapbox `pk.`
vs `sk.`) tag only the public pattern so a misused secret key still
surfaces at its nominal severity.

`detector.keywords` - optional prefilter and context signals. Regexes with an
extractable leading literal use that prefix automatically. A prefixless regex
uses only its declared `required_literals`; without either route it uses the
keyword-gated or always-active phase-2 path. `kind = "phase2-generic"` detectors
require keywords because their assignment/context bridge is the candidate
source.

`detector.patterns[]` - one or more regexes. Each carries:

- `regex` - the pattern. Every regex is compiled `case_insensitive`, so
  it matches both cases without explicit alternation. To make a single
  pattern case-SENSITIVE (AWS `AKIA` is uppercase; some GCP/Snowflake ids
  are lowercase), prefix its regex with the inline flag `(?-i)` in the
  TOML - no schema field needed. The loaded expression is byte-for-byte the
  authored TOML value: KeyHog never widens separator classes or quantifiers at
  load. When an anchor intentionally accepts joined, spaced, underscored, and
  hyphenated words, write `[_\-\s]*` explicitly in that detector. A narrower
  class remains narrow and changes only that detector's digest and behavior.
- `group` - which capture group is the credential. `0` = whole match,
  `1` = first captured group, etc.
- `description` - what shape this captures (env var, header, URL, …).
- `required_literals` - optional detector-owned routing literals. Every regex
  match must contain at least one listed ASCII literal. Corpus loading proves
  that OR-condition from the regex AST, then scalar, Hyperscan, CUDA, and WGPU
  compile the same literals into their candidate plan. Invalid, optional, or
  branch-incomplete declarations reject the detector instead of risking recall.
  KeyHog never selects a non-prefix literal from the regex implicitly.
- `client_safe` - optional bool, default `false`. When `true`, any
  match against this pattern collapses to `Severity::ClientSafe`
  regardless of the detector's nominal severity. Use for patterns
  that capture keys the vendor expects to ship in client bundles
  (Sentry DSN, Stripe `pk_*`, etc.). Per-pattern (not per-detector)
  so a detector that covers both the public and the secret prefix
  can tag only the public one.

Multiple patterns means "any of these shapes". A typical detector has
1-3 patterns covering env-var, JSON, and inline forms.

`detector.companions[]` - optional nearby values described by `name`, `regex`,
`within_lines`, and `required` (default `false`). Optional companions enrich the
finding and can strengthen confidence or verification. Only a companion marked
`required = true` gates the primary finding when absent.

`detector.verify` - optional. If present, `keyhog scan --verify`
makes the documented API call with the captured credential and:
- live + valid -> keep severity, mark `verification: "live"`
- live + invalid -> downgrade severity one tier, mark `verification: "dead"`

Every shipped HTTP verifier declares `allowed_domains` beside its URL. Literal
hosts must match that list when the TOML loads, and the resolved host must match
again before a request is sent. Use the narrowest service-owned host. Do not add
localhost, a generic decoder site, or an unresolved tenant placeholder to make
a non-verifiable detector appear live-capable.

`detector.verify.metadata[]` maps provider responses to report evidence. Each
entry owns three fields in this detector TOML:

- `name`: a reviewed provider-neutral semantic role. Unknown and duplicate
  canonical roles fail detector validation.
- `json_path`: the rooted response selector.
- `sensitivity`: `public` emits a scalar value up to 256 bytes, `hashed` emits
  only its SHA-256 digest, and `secret` never enters findings. Omission defaults
  to `hashed` for compatibility with older custom detectors.

Multi-step `extract` entries use arbitrary flow-local names because later
request templates consume them. They are transport state and never become
report metadata.

## Per-detector recall/precision knobs

Credential-family policy belongs in the individual detector TOML whenever the
schema provides a detector field. This is where stable entropy bands, length
bounds, BPE behavior, confidence floors, allowlists, and shape classifications
are tuned for one secret type. Scan-wide CLI and `[scan]` settings remain
explicit operational overrides for corpus-wide policy and controlled
comparisons; they are not hidden detector definitions.

This follows the design precedent established by `min_confidence` (the per-detector confidence floor) and `entropy_floor` (the low-entropy suppression floor).

Active entropy owners must declare their complete policy. Missing tuning data
fails corpus validation or scanner construction instead of inheriting
scanner-side detector policy. An explicitly supplied scan-wide override has
final authority only where the field documents that precedence, such as BPE or
the ML weight diagnostic override.

The available per-detector tuning fields are:

### Entropy Thresholds

For example, an entropy owner can declare its complete confidence mapping:

```toml
entropy_fallback_confidence = { low_entropy_max = 0.55, high_entropy = 0.65, very_high_entropy = 0.75, keyword_lift = 0.1, max_confidence = 0.9 }
```

KeyHog compiles this mapping with the detector. A custom corpus can tune one
secret family without changing another family or inheriting scanner literals.

The same owner declares how a generic assignment becomes a confidence score:

```toml
[detector.generic_assignment_confidence]
ordinary_base = 0.60
test_base = 0.25
documentation_base = 0.30
comment_base = 0.30
scanned_comment_base = 0.60
entropy_reference = 3.5
entropy_gain_per_bit = 0.10
entropy_lift_max = 0.25
length_reference = 16
length_gain_per_byte = 0.005
length_lift_max = 0.15
max_confidence = 0.95
```

For example, a 20-byte value gains four times `length_gain_per_byte`. Entropy
above `entropy_reference` gains `entropy_gain_per_bit` for each additional bit.
Each lift stops at its declared maximum, and the final score stops at
`max_confidence`.

*   **`entropy_high`** (float, required for active entropy owners): Per-detector high-entropy threshold (bits/byte) for keyword-independent detection and the partial entropy-fallback heuristic-confidence tier.
*   **`entropy_low`** (float, required for active entropy owners): Per-detector keyword-context entropy threshold.
*   **`entropy_very_high`** (float, required for active entropy owners): Per-detector very-high threshold for keyword-free or isolated tokens and the full entropy-fallback heuristic-confidence tier. Compiled policy requires `entropy_low <= entropy_high <= entropy_very_high`.
*   **`sensitive_path_entropy_very_high`** (float, required for active entropy owners): Per-detector keyword-free threshold for clearly sensitive paths. It must not exceed `entropy_very_high`; omission is invalid rather than an undocumented scanner-wide discount.
*   **`plausibility.keyword_free_operator_margin`** (float, required only for the `keyword-free` role owner): Margin added to the resolved Tier-A `entropy_threshold` before keyword-free admission. The effective floor is `max(path-specific entropy_very_high, entropy_threshold + keyword_free_operator_margin)`; no scanner-owned margin is applied.
*   **`entropy_fallback`** (table, required for active entropy owners): Identity metadata for synthetic entropy findings owned by this detector. `class` is one of `generic`, `password`, `token`, or `api-key`; `id` must use the `entropy-` namespace; and `name`/`service` must be non-empty. Both regex-kind detectors that set `entropy_policy_priority` and phase-2 generic owners must declare this block. The primary detector's reporting `service` may name any taxonomy and does not grant or deny entropy ownership. Omitting the block is a compile error, never a compatibility identity.
*   **`entropy_fallback_confidence`** (inline table, required for active entropy owners): Maps this detector's Shannon evidence to report confidence. `low_entropy_max` caps candidates below `entropy_high`; `high_entropy` and `very_high_entropy` are the base scores for those detector thresholds; `keyword_lift` applies only when a configured keyword owns the candidate; and `max_confidence` caps the result. Every value must be a finite probability, and the three base tiers must be monotonic. The scanner does not supply confidence tiers for an omitted policy.
*   **`generic_assignment_confidence`** (table, required for active entropy owners): Maps generic assignment evidence to confidence for the detector that owns the assignment keyword. The five context fields choose the base score. `entropy_reference`, `entropy_gain_per_bit`, and `entropy_lift_max` define the entropy lift. `length_reference`, `length_gain_per_byte`, and `length_lift_max` define the byte-length lift. Every base, gain, lift cap, and maximum must be a finite value from 0 to 1. `entropy_reference` must be from 0 to 8. The scanner does not supply a hidden assignment-confidence policy.
*   **`entropy_roles`** (string array): Corpus-level entry roles owned by this detector. `keyword-free` owns anchor-free high-entropy candidates, `isolated-bare` owns detector-shaped bare candidates, and `unclaimed-keyword` owns configured credential keywords not claimed by another detector. A role may have only one owner in a compiled corpus. Omission disables that entry path for a focused custom corpus; the scanner never substitutes a built-in detector ID or global policy.
*   **`entropy_shapes`** (one array-table entry required for active entropy owners): Declarative isolated-shape policy owned by this detector. The entry declares a `charset`, `entropy_floor`, `special_min_length`, optional fixed-width `grouping`, and explicit diversity requirements such as `require_group_alpha_digit` or `require_non_hex_alpha`. A grouped candidate's exact length is derived from its group count, group width, and separator, so adding a shape family does not require a scanner enum variant. Multiple entries are rejected rather than silently ignored or ambiguously combined.
*   **`plausibility`** (inline table, required for active entropy owners): Complete strict candidate-shape policy. Its entropy floors, length boundaries, diversity requirements, isolated-token shapes, and rejection switches are all required detector data. `second_half_min_len`, `unique_chars_min_len`, `min_unique_chars`, `unanchored_hex_max_len`, `identical_char_max_len`, `structured_dotted_min_len`, and `leading_slash_base64_min_len` own boundaries that were formerly scanner literals. `isolated_mixed_entropy_floor` governs contiguous or underscore-delimited mixed tokens. The three isolated-symbolic fields govern the shorter symbol-rich exception's byte length, minimum symbol count, and whether one symbol must differ from underscore. `reject_program_identifiers` covers pure source-language names, while `reject_source_symbol_identifiers` independently controls digit-bearing mixed alphanumeric names. An exact lower-dash layout declared by `entropy_shapes` cannot bypass its shape-specific rules. The `keyword-free` role owner additionally declares `keyword_free_operator_margin`; no detector inherits an invisible family decision from scanner code.
*   **`entropy_floor`** (array of tables, required for active entropy owners and detectors or patterns using `weak_anchor`): Length-bucketed low-entropy suppression floor mapping maximum lengths to minimum entropy scores. Weak-anchor regex findings read their own table; they never borrow another detector's calibration.
    *   `max_len` (integer, optional): Inclusive maximum length for this bucket.
    *   `floor` (float): Shannon entropy floor.
*   **`entropy_policy_priority`** (integer, optional): Resolves overlapping
    generic keyword claims. Higher values own entropy, length, canonical-shape,
    and BPE policy for the shared keyword. Phase-2 generic detectors
    participate at priority zero when omitted. Regex detectors do not
    participate unless they set this field. This makes the primary precedence
    explicit in detector TOML without overloading reporting service. Equal
    priorities use stable detector identity, so corpus order cannot change the
    owner.

### BPE token efficiency
*   **`bpe_enabled`** (bool, optional): Detector-local token-efficiency switch.
    Omission inherits the enabled default. Set `false` for families such as
    human-chosen passwords where word-like values are legitimate; the scanner
    then skips BPE tokenization for that detector. Do not combine `false` with a
    `bpe_max_bytes_per_token` ceiling; detector validation rejects the conflict.
*   **`bpe_max_bytes_per_token`** (float, optional): Per-detector
    `cl100k_base` UTF-8-bytes-per-token ceiling. Values above the ceiling use
    fewer common subword tokens per byte, which makes them more likely to be
    word-like; they are suppressed after the cheaper shape and entropy gates.
    The detector field takes precedence over
    the compiled scan fallback. An explicitly configured
    `[scan].entropy_bpe_max_bytes_per_token` or CLI flag is the final Tier-A
    override for all eligible detectors. Lower ceilings favor precision and
    higher ceilings favor recall. This field tunes the precision gate after a
    detector or phase-2 discovery path has produced a candidate; it never
    creates one. The runtime relationship between BPE, Shannon entropy, and
    BetterLeaks' Token Efficiency terminology is defined in
    [How detection works](./detection.md#detection-mechanisms).

### Decoded key material
*   **`decoded_hex_key_material_lengths`** (integer array, optional;
    `kind = "phase2-generic"` only): Exact printable-hex character counts this
    detector may retain after transport decoding. Each width must be even and
    at least 16, with no duplicates. `generic-api-key.toml` declares `[32, 48]`;
    broad token/secret detectors declare none, so decoded 40-hex SHA-1 and
    64-hex SHA-256 shapes remain digest-suppressed. Structured decoders preserve
    transport provenance, so direct `secret_key=<64hex>` policy cannot silently
    reclassify a base64-wrapped digest.
*   **`canonical_hex_key_material`** (array of tables, optional): Declares exact
    pure-hex character counts this detector may treat as key material instead
    of a digest. A `kind = "phase2-generic"` table must include `keywords` or
    `suffixes`; exact keywords must also appear in the detector's top-level
    `keywords`, suffixes admit only vendor-prefixed names, and
    `excluded_keywords` removes ambiguous names such as `license_key`.
    A regex detector instead declares a length-only table. Its matched pattern
    supplies the scope, so assignment scopes are rejected on that path rather
    than silently ignored. Matching assignment keys ignores case and `_`, `-`,
    or `.` separators.
    Direct assignments and structured assignment extraction (including XML)
    resolve the same policy; there is no format-specific override. For
    example, `generic-api-key.toml` admits 64-hex only for its explicit
    cryptographic roles such as `signing_key`, `encryption_key`, and
    `hmac_secret`, while `generic-secret.toml` owns `private_key`,
    `signing_secret`, and its declared vendor suffixes. Neither turns a broad
    `api_key=<sha256>` assignment into a finding. Canonical hex admitted by
    this policy skips BPE token efficiency
    and the generic low-diversity/decode-as-data confidence penalties because
    those mechanisms inherently classify pure hexadecimal as non-secret. The
    entropy, placeholder, degenerate-repeat, context, and reporting gates still
    apply. The owning detector's `ml.match_mode` governs structurally proven key
    material, while `ml.entropy_mode` governs its weaker entropy fallback.

The fields live beside the detector's other top-level policy, not in a
scan-wide suppression table. A phase-2 example is:

```toml
decoded_hex_key_material_lengths = [32, 48]
canonical_hex_key_material = [
  { lengths = [32, 48], keywords = ["api_key"], suffixes = ["key", "secret"], excluded_keywords = ["license_key"] },
  { lengths = [64], keywords = ["encryption_key"] },
]
```

A weak-anchor named detector declares only the widths its own regex captures:

```toml
canonical_hex_key_material = [{ lengths = [32] }]
```

Omitting that declaration leaves a pure-hex capture digest-suppressed. KeyHog
does not infer widths from the service name, confidence floor, or a global list.

`keyhog explain <detector-id>` prints both declarations in the human-readable
policy view. `keyhog detectors --format json` exposes them under each detector's
`policy` object, so automation can inspect the same loaded TOML contract the
scanner uses.

### Candidate Lengths
*   **`keyword_free_min_len`** (integer): Per-detector minimum length for an anchor-free (keyword-free or isolated) candidate. Active entropy owners must declare it; omission fails compilation instead of selecting a scanner constant. The backend-neutral no-hit router combines the active role owner's value with a conservative necessary length derived from that owner's effective Shannon floor, so replacement detector corpora keep their own boundary without widening the shipped hot path to candidates that cannot reach its entropy threshold.
*   **`min_len`** (integer, optional): Per-detector minimum candidate length in UTF-8 bytes for any candidate this detector emits. Falls back to no detector-specific floor beyond the path-wide default if unset.
*   **`max_len`** (integer, required for every entropy-policy owner): Inclusive maximum byte length for every candidate owned by the detector. Generic assignment, entropy fallback, and explicit regex envelopes use one compiled bound before entropy or BPE. An overlength value is rejected whole with `value_too_long`; it is never reported as a truncated prefix. The generic candidate generator uses the largest ceiling in the loaded corpus so the resolved owner can apply its exact value. `max_len` must be at least 8 and no smaller than `min_len`. Omission fails scanner construction. Regex patterns can use narrower repetition bounds.

The generic assignment bridge exists only when the loaded corpus contains at
least one `phase2-generic` detector. A focused custom corpus without one compiles
without that bridge; KeyHog does not silently inject the bundled generic rules.

### Allowlists & Exclusions
*   **`allowlist_paths`** (array of strings, optional): Per-detector path-exclusion regexes (BetterLeaks-style allowlist). Any candidate match whose file path matches any of these regexes is suppressed.
*   **`allowlist_values`** (array of strings, optional): Per-detector value-exclusion regexes. Any candidate secret value matching any of these regexes is suppressed (useful for filtering out test, example, or placeholder values).
*   **`stopwords`** (array of strings, optional): Per-detector literal stopwords. A matched value equal to or containing any of these strings (case-insensitive) is suppressed.
*   **`public_identifier_assignment_markers`** (array of strings, optional): Detector-local canonical-uppercase assignment-key fragments for public IDs such as wallet, contract, address, or peer identifiers. Boundary bytes are significant; KeyHog performs allocation-free ASCII-insensitive matching against the source line. An empty list disables this suppression for that detector.

### Classification and shape policy

These fields are detector facts, not operator preferences. They therefore live
only in the individual detector TOML and have no CLI or global-config override:

*   **`structural_password_slot`** (bool, default `false`): The pattern proves a
    syntactic password slot, such as URL userinfo, `IDENTIFIED BY`, a password
    CLI flag, or an authorization scheme. The scanner keeps the dedicated
    placeholder checks but does not reject a legitimate free-form password with
    the generic randomness floor.
*   **`weak_anchor`** (bool, default `false`): At detector level it applies to
    every pattern. Inside one `[[detector.patterns]]` table it applies only to
    that regex, so a strong sibling does not inherit its gates. Use it when the
    service context is useful but the captured value still collides with broad
    hex/base64/identifier shapes. Generic shape and randomness safeguards
    remain active, and the detector must declare `entropy_high` and
    `entropy_floor`. KeyHog does not infer this field from regex syntax.
*   **`private_key_block`** (bool, default `false`): The match spans an enclosing
    PEM/OpenSSH private-key block. Resolution suppresses lower-specificity child
    findings inside that span instead of reporting the key body repeatedly.
*   **`generic_vendor_suffixes`** (string array, default empty): A phase-two
    generic detector can own structural `<vendor>_<suffix>` assignments that no
    exact keyword claims. Only one detector may declare this list. Entries are
    lowercase ASCII alphanumeric tokens.
*   **`generic_assignment_tail_suffixes`** (string array, default empty): The
    same owner can admit suffix segments after an exact keyword, such as
    `secret_key_base`. KeyHog compiles this list into the assignment matcher;
    omission disables the extra tail grammar.
*   **`resolution_priority`** (integer, default `0`): When two detectors claim
    overlapping credentials, the higher value wins before generic class and
    confidence tie-breakers. Use it only for demonstrably more specific
    attribution, such as a GitHub App key over a generic PEM block. Equal values
    keep the normal deterministic resolution order.
*   **`[detector.credential_shape]`** (table, optional): A fail-closed byte-shape
    contract. It can declare `exact_length`, `prefix`, `body_min_length`, and
    `body_max_length`; candidates outside the declared shape are suppressed.

Because these values are loaded from the active detector corpus, custom corpora
carry their classifications with them. There is no separate detector-id list or
hidden Rust-side family table to keep synchronized.

### Confidence Floors
*   **`min_confidence`** (float, optional): Per-detector minimum confidence floor. Overrides the global scan confidence floor.

## Listing detectors

With no `--detectors` flag, KeyHog searches the platform user data locations,
system data locations, and the executable directory for an installed
`keyhog/detectors` corpus. The first existing directory is the complete active
corpus. If none exists, KeyHog uses the embedded corpus. An explicit path
replaces discovery and never merges with another corpus.

```sh
keyhog detectors                  # human-readable list, grouped by service
keyhog detectors --format json           # one JSON array of detector objects
keyhog detectors --format json | jq length
```

Structured listings include a `policy` object for every detector. It carries
the loaded detector-local kind, entropy/BPE/length thresholds, stopwords,
allowlists, classifications, and credential shape; absent optional fields are
`null`, not silently filled with an undocumented value.

Filter by service:

```sh
keyhog detectors --format json \
  | jq '.[] | select(.service == "stripe")'
```

## Explaining one detector

```sh
keyhog explain stripe-secret-key
```

Prints the loaded detector's keywords, patterns, companions, verification
endpoint, and detector-local admission policy. For generic detectors that
policy includes Shannon-entropy floors, BPE UTF-8 bytes/token ceilings, length
bounds, stopwords, and allowlists exactly as declared by the detector TOML:

```sh
keyhog explain generic-secret
```

This is the first place to look when debugging why a detector did or did not
fire; it makes detector-owned tuning visible without searching for a Rust-side
override table.

## Custom detector corpora

Put custom detector TOMLs in an explicit corpus directory:

```toml
# my-detectors/my-internal-token.toml

[detector]
id = "acme-internal-token"
name = "ACME internal API token"
service = "acme-internal"
severity = "high"
keywords = ["ACME_API_TOKEN", "acme_internal_"]

[[detector.patterns]]
regex = "acme_internal_[a-zA-Z0-9]{32}"
group = 0
```

Then name that corpus on every operator path that should use it:

```sh
keyhog detectors --detectors my-detectors --audit
keyhog scan . --detectors my-detectors
```

`--detectors` selects the directory as the complete active corpus; it does not
silently merge the directory with embedded detectors. Copy any built-in TOMLs
you still want into the directory. A named path that is missing, is not a
directory, contains no detectors, or contains invalid TOML fails closed instead
of substituting the embedded corpus.

## Disabling specific detectors

Turn off a detector by id in `.keyhog.toml`:

```toml
[detector.aws-access-key]
enabled = false

[detector.generic-secret]
enabled = false
```

Detector ids are the `detector_id` field in `--format json`/`jsonl` output, or
the left column of `keyhog detectors`. Accelerated literal slots remain owned by
the same canonical TOML detector id; there is no separate `hot-*` detector to
disable. Retired `hot-*` ids are rejected with the exact canonical `explain`
command instead of executing as aliases. Disabled detectors are dropped before the corpus compiles (zero scan
cost). If an id matches nothing in the loaded corpus, KeyHog warns rather than
silently ignoring it.

## Running only a chosen subset

To run a curated set instead of the full corpus, point `--detectors` at a
directory holding only the TOMLs you want:

```sh
mkdir my-detectors
cp detectors/stripe-secret-key.toml detectors/aws-*.toml my-detectors/
keyhog scan . --detectors my-detectors/
```

## Quieting a noisy detector

When a detector produces persistent false positives in your repo,
down-weight it instead of dropping it entirely so a real hit still
surfaces:

```sh
CACHE="$XDG_CACHE_HOME/keyhog/calibration.json"
keyhog calibrate --cache "$CACHE" --fp generic-api-key
keyhog scan . --calibration-cache "$CACHE" --min-confidence 0.7
```

Each `--fp` lowers that detector's Bayesian confidence multiplier
(persisted under the platform cache directory, normally
`$XDG_CACHE_HOME/keyhog/calibration.json`). Scans use those counters only when
you pass `--calibration-cache <PATH>` or set `[system].calibration_cache`, so
repeated FPs steadily push that detector below your `--min-confidence` floor
without hidden host-state drift. To suppress *specific* findings rather than a
whole detector, use a
[`.keyhogignore`](./suppressions.md), the `[allowlist]` config, or a
`--baseline`.

## Severity bumps and downgrades

Severity is a property of the detector, but can shift per-finding:

- **Git history → severity one tier lower.** A credential present only
  in non-HEAD git history (the developer already removed it from
  `main`) is still a leak - anyone can fetch it - but strictly less
  urgent than one live in HEAD. Reported in the `chunk.metadata.commit`
  field of the finding.

- **Verification: dead → severity one tier lower.** The credential was
  format-valid but the API rejected it. Could be a rotated key, a fake
  in a test file, or a typo.

- **Verification: live → severity unchanged.** The credential authenticates
  successfully. As bad as it can get.

## Writing your own - the short version

1. Find a real example of the credential format (vendor docs, leaked
   public sample, source).
2. Write the regex. Test it against the example, against a similar
   non-credential ("looks like, isn't"), and against an attacker-rotated
   form.
3. Add to `detectors/<service>-<thing>.toml` - `id`, `keywords`,
   `patterns`, optionally `verify`.
4. Add a contract file at `crates/scanner/tests/contracts/<id>.toml`
   with at least:
   - 2 positives (env-var form, quoted form)
   - 2 negatives (placeholder, EXAMPLE marker)
   - 2 evasions (the actual deployed credential shape from production)
5. Run `cargo test -p keyhog-scanner --test contracts_runner` - must
   pass for your detector to ship.

That's it. The contracts gate enforces that every shipped detector
catches what it claims to catch.
