# Write a detector

A detector is one TOML file that tells KeyHog what a credential looks like, how
confident to be about a match, and how to check whether the credential is live.

This page takes you from an example credential to a detector that passes the
gates. Read [Detectors and custom corpora](../detectors.md) first for the field
reference; this page is the workflow and the rules that reject a file.

## Start from a real example

Find one real instance of the format. Vendor documentation, a public leaked
sample, or the provider's own SDK are all fine. You need three shapes before you
write a line of TOML:

- The credential itself.
- Something that looks like it but is not one. A request ID with the same
  alphabet, a hash of the same length.
- The form your provider actually emits in production, which is often not the
  form in the docs.

If you cannot produce all three, you do not yet know the format well enough to
write a detector that will not generate false positives.

## Put the file in place

Work in your own directory first. You do not need to touch the shipped corpus to
write and test a detector:

```sh
mkdir -p /tmp/acme-detectors
$EDITOR /tmp/acme-detectors/acme-api-key.toml
```

Four things are required: an identity block, an `ml` policy, a
`match_confidence` table, and at least one pattern.

```toml
[detector]
id = "acme-api-key"
name = "Acme API Key"
service = "acme"
severity = "high"
keywords = ["acme", "ACME_API_KEY"]
ml = { match_mode = "lift", entropy_mode = "disabled", weight = 1.0, context_radius_lines = 5 }
# Copy this line unchanged from an existing detector, then tune it.
match_confidence = { literal_prefix_weight = 0.35, ... }

[[detector.patterns]]
regex = '''ACME_API_KEY[\s"'=:]+(acme_[a-zA-Z0-9]{32})'''
description = "Acme API key with context anchor"
group = 1
```

`group = 1` is the capture group holding the credential. Group `0` is the whole
match, which would report the keyword as part of the secret.

`match_confidence` is a single inline table with about thirty required weights.
There is no partial form: omitting one field fails the load with
`missing field <name>`. Copy the whole line from a detector whose shape is
closest to yours and change the weights you care about:

```sh
grep '^match_confidence' detectors/1password-secret-key.toml
```

The same applies to `ml`. Omitting it fails with `missing field ml`, and setting
`entropy_mode` to anything other than `"disabled"` makes the detector an entropy
owner, which then requires the whole entropy policy.

## Check it before you scan

Validation runs at corpus load. An invalid detector fails the load with an exact
message rather than being skipped:

```sh
keyhog detectors --detectors /tmp/acme-detectors
```

A valid corpus prints what loaded:

```text
Loaded 1 detectors (/tmp/acme-detectors):
  - acme (1 detectors)
    - acme-api-key
```

An invalid one refuses the whole corpus rather than scanning with a hole in it:

```text
error: loading detectors from directory: 1 of 1 detector file(s) from
/tmp/acme-detectors failed to load, pass the quality gate, or exist at all,
that is a partial detector corpus, so keyhog is refusing to scan without a
complete detector corpus (a partial corpus silently drops recall).
```

That refusal is the point. A corpus that quietly loses a detector is a silent
clean.

Read the resolved policy for one detector:

```sh
keyhog explain acme-api-key --detectors /tmp/acme-detectors
```

That prints the compiled spec, the patterns with their capture groups, the
keywords, the severity, and the declared detector policy, so you can confirm the
file you wrote is the policy that loaded.

Then prove it fires:

```sh
mkdir -p /tmp/acme-fixture
printf 'ACME_API_KEY=acme_%s\n' \
  "$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)" \
  > /tmp/acme-fixture/app.env
keyhog scan /tmp/acme-fixture --detectors /tmp/acme-detectors \
  --format json-envelope | jq '[.findings[].detector_id]'
```

Expect `["acme-api-key"]`.

## Rules that reject a file

The quality gate in `crates/core/src/spec/validate.rs` rejects a detector rather
than accepting a weaker one. These are the rules that catch most first drafts.

### Identity

`detector.id` must be non-empty and free of leading or trailing whitespace. Ids
are the stable handle used by suppressions, baselines, and reports, so a padded
id is an error, not a trim.

### Patterns

At least one pattern is required. Each `regex` must compile, must be at most
4096 characters, and must stay inside the complexity bounds on AST node count,
alternation branches, and repetition. A pattern that names `group = N` must
expose group `N`.

A pattern that is only a character class is rejected when its context radius is
wide. `[a-f0-9]{32}` with no anchor matches every MD5 in the tree. Give it a
keyword anchor in the regex, or bound it with a tight companion.

### Keywords

`keywords` are the literal strings that admit a chunk to the detector's phase-2
work. Without them the detector runs against every chunk. Include the
environment-variable spelling, the vendor's own spelling, and any prefix that
appears in the credential itself.

### Companions

A companion is a second value that must appear near the first, such as an AWS
secret key beside an access key. Companions are bounded:

- `within_lines` has a search-window limit, and `scope = "same-line"` requires
  `within_lines = 0`.
- `within_bytes` must be between 1 and 1048576.
- A pure character-class companion regex is rejected unless `within_lines` is at
  most 5, because a wide radius plus a loose class is a false-positive machine.
- Schema-v2 `required = true` cannot be mixed with a typed requirement. Use one.

### Entropy policy

A detector that owns an entropy policy must declare all of it. There is no
runtime fallback to a scanner constant. An active entropy owner must declare
`entropy_floor`, `detector.entropy_shapes` with exactly one entry,
`bpe_enabled`, `entropy_fallback`, `entropy_fallback_confidence`,
`generic_assignment_confidence`, and a non-disabled `ml.entropy_mode`. Omitting
any of them fails the load.

Most detectors are not entropy owners. In the shipped corpus, 929 of 934
detectors set `entropy_mode = "disabled"`. Write a regex detector unless you are
deliberately adding a generic channel.

### Lengths

`max_len` is required for every entropy-policy owner. It must be at least 8 and
no smaller than `min_len`. An overlength value is rejected whole and reported as
`value_too_long`; KeyHog never reports a truncated prefix as a finding.

`keyword_free_min_len` is required for active entropy owners. Omission fails
compilation rather than picking a scanner constant.

### Confidence

`min_confidence` is a probability in the closed range `[0.0, 1.0]`. A value
below `0.0` clears the floor for every candidate, a value above `1.0` means the
detector never fires, and `NaN` makes every comparison false. All three are
rejected. `detector.match_confidence` is required; scanner-wide match scoring
defaults are not permitted.

### Verification

A `[detector.verify]` block must name an HTTP method, a URL, and the domains it
is allowed to reach. Success status codes must be in the range 100 to 599.
Verification sends credential-derived requests to a live provider, so
`allowed_domains` is the boundary that keeps a detector from being turned into
an outbound request primitive.

## Write the contract

Every shipped detector has a contract file. The contract is the behavioral test,
and it lives beside the corpus rather than in Rust:

```sh
$EDITOR crates/scanner/tests/contracts/acme-api-key.toml
```

A contract declares its identity, then positives, negatives, evasions, and a
performance budget:

```toml
schema_version = 1
detector_id = "acme-api-key"
service = "acme"
severity = "high"
readme_claim = "Acme"

[[positive]]
text = "ACME_API_KEY=acme_<32 generated characters>"
credential = "acme_<32 generated characters>"
reason = "env-var-style assignment, common CI shape."

[[negative]]
text = "ACME_API_KEY=acme_REPLACE_ME_WITH_YOUR_KEY_00000000"
reason = "Placeholder value, not a credential."

[[evasion]]
text = "<config><acme>acme_xMlEnCoDeDxMlEnCoDeDxMlEnCoDeD</acme></config>"
credential = "acme_xMlEnCoDeDxMlEnCoDeDxMlEnCoDeD"
reason = "Inside an XML element body."

[perf]
fixture_bytes = 4096
max_microseconds = 15000

[scale]
fixture_bytes = 1048576
min_findings = 1
max_seconds = 1.0
```

Write at least two of each:

- Two positives. The environment-variable form and the quoted form. Add the
  `Authorization:` header form when the provider uses bearer tokens.
- Two negatives. A placeholder and a same-alphabet non-credential. These are the
  cases that decide whether your detector is usable in a real repository.
- Two evasions. The shape your provider actually deploys, and the credential
  nested in a structured format such as XML, YAML, or JSON.

Do not use the vendor's documentation sample as a positive. KeyHog suppresses
the well-known samples on purpose, so a contract built on
`sk_live_4eC39HqLyjWDarjtT1zdp7dc` tests the suppression list rather than your
detector. Generate your own value with the same shape.

Run the contract:

```sh
cargo test -p keyhog-scanner --test contracts_runner
```

Every positive must be found with the exact credential span. Every negative must
not be found. Every evasion must be found. A detector that fails its own
contract does not ship.

## Common first-draft mistakes

**The regex captures the keyword.** Set `group` to the capture group holding the
credential, not `0`.

**The pattern has no anchor.** A bare character class with a wide radius is
rejected by the gate, and if it were not, it would report every hash in every
lockfile. Anchor on the vendor prefix or on the assignment keyword.

**The negatives are too easy.** A negative that is obviously not a credential
proves nothing. Use the value your users will actually have in the repository: a
placeholder, a truncated key, a request ID with the same alphabet.

**The detector claims entropy ownership by accident.** Setting one entropy field
makes the detector an active entropy owner and requires the whole policy. Leave
`ml.entropy_mode = "disabled"` unless you mean it.

**The positives are all from the docs.** See above. Generate values.

## Ship it in your own corpus

You do not have to modify the shipped corpus. Point KeyHog at a directory:

```sh
keyhog scan . --detectors /tmp/acme-detectors
```

An explicitly named directory replaces the embedded corpus by default. Compose
instead of replacing with:

```sh
keyhog scan . --detectors /tmp/acme-detectors --detectors-mode overlay
```

Overlay rejects an id that collides with an embedded detector, so a custom
corpus cannot silently shadow a shipped one. A named directory that does not
exist is an error, never a quiet fallback to the embedded corpus.

Confirm the corpus that actually loaded:

```sh
keyhog detectors --detectors /tmp/acme-detectors
```

Then confirm the count in a report. `metadata.resolved_scan.effective` carries
`detector_corpus_source`, `detector_corpus_mode`, `detector_corpus_digest`, and
the custom and embedded counts, so a report proves which corpus produced it.
