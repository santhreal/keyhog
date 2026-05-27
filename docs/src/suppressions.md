# Suppressions

A suppression is a filter that drops a candidate match after the regex
fires but before it becomes a finding. KeyHog applies them in layers.

## The two suppression lists

### Test fixtures (always on, opt-out)

`data/suppressions/test-fixtures.toml`, baked into the binary. Lists
publicly documented credentials that vendor docs ship as examples:

```toml
[[fixture]]
detector = "stripe-secret-key"
credential = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
reason = "Stripe docs sample, https://stripe.com/docs/api/auth"

[[fixture]]
detector = "aws-access-key"
credential = "AKIAIOSFODNN7EXAMPLE"
reason = "AWS docs sample, https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html"
```

Disable with `--no-suppress-test-fixtures` if you want to see them
fire (rare, but useful when validating that a detector still matches
the canonical shape).

### Repo-local suppressions (opt-in, project-scoped)

`.keyhog.toml` in your repo root:

```toml
[suppress]
# Drop findings on these credential hashes (sha256 of the captured value).
# Use when a finding is a true positive that you've intentionally accepted
# (e.g. a published OAuth client_id, or a fixture you've cleared with
# the upstream service).
hashes = [
    "sha256:abc123...",
    "sha256:def456...",
]

# Drop findings from these files entirely (gitignore-style globs).
paths = [
    "fixtures/**",
    "docs/example_*.env",
]

# Drop findings from these detectors entirely.
detectors = [
    "generic-password",
]
```

Compute the hash of an existing finding:

```sh
keyhog scan . --format json | jq -r '.[] | "\(.detector_id) \(.credential_hash)"'
```

## Shape-based suppression (always on, can't opt out)

These don't depend on a list. They're heuristics about credential
shape that are universally true:

| Filter                             | Drops shapes like                                |
|------------------------------------|--------------------------------------------------|
| `punctuation_decorated_identifier` | `--api-secret`, `&password`, `$API_KEY`, `Password:`, `apiKey!` |

For generic-only / entropy-only detectors, additional shape gates
apply. See [How detection works](./detection.md#stage-4-post-process)
for the full list and rationale.

## Path-based suppression (always on)

Specific directories produce findings that are almost always not
credentials. KeyHog hard-codes a small set:

| Path pattern                       | Why                                              |
|------------------------------------|--------------------------------------------------|
| `node_modules/`, `vendor/`, `bower_components/`, `jspm_packages/`, `site-packages/` | Vendored third-party code, minified bytes coincide with secret prefixes |
| `wp-content/plugins/`, `wp-content/themes/`, `wp-includes/` | WordPress vendored trees |
| `app/assets/javascripts/bootstrap*.js`, `app/assets/javascripts/jquery*.js`, etc. | Rails legacy asset path, vendored JS |
| `*.min.js`, `*.bundle.js`, `*.min.css` | Minified bundles |
| `.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `Jenkinsfile`, `.travis.yml`, `azure-pipelines*`, `bitbucket-pipelines*` | CI config, `${{ secrets.X }}` is syntactic |
| `locale/`, `locales/`, `i18n/`, `l10n/`, `translations/`, `lang/`, `langs/`, `*.po`, `*.pot` | i18n translation files, translated `password`/`token` words are not credentials |
| Files containing `secretscanner`, `secret-scanner`, `trufflehog`, `gitleaks`, `detect-secrets` in the path | The file IS itself a secret scanner; its regex literals shouldn't fire on itself |

These are not configurable. They have such high precision / low recall
loss that making them opt-in would just make the scanner louder for
no benefit. If a specific path you care about is being suppressed
incorrectly, that's a bug worth reporting.

## Telemetry: what got suppressed

Pass `--dogfood` to surface what was dropped:

```sh
keyhog scan . --dogfood --format json | jq '.dogfood.events[]'
```

Each event has the suppressor name (`test_fixture_suppression`,
`pure_identifier_no_digit`, `vendored_minified_path`, etc.), the
path, the redacted credential, and the rule that fired. Useful when
asking "is the scanner being too aggressive on my code?".

## Adding a suppression for FP cluster

If you find a cluster of 5+ FPs that share a shape, file an issue
with:

1. The detector that fired
2. A sanitized example of the FP (replace the captured value with
   `[REDACTED]`)
3. Why it's not a credential (regex shouldn't have matched, or
   shape gate should have caught it)

The right fix is either a tightened regex, a new shape filter, or a
path / file-extension exclusion. Adding the literal credential to
the test-fixtures list is the LAST resort because it only hides one
specific FP, not the underlying shape.
