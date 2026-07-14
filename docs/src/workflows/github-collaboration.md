# GitHub collaboration scans

Repository clones do not contain every place a credential can be pasted. Select
collaboration surfaces explicitly when they are part of the review boundary:

```bash
export KEYHOG_GITHUB_TOKEN='read-only-token'

keyhog scan \
  --github-collaboration acme/payments \
  --github-issues \
  --github-pull-requests \
  --github-discussions \
  --github-wiki \
  --github-gists
```

No collaboration surface is implied by `--github-org`. A repository-only scan
makes no issue, pull request, discussion, wiki, or gist request.

## Surface contract

| Flag | Scanned content |
| --- | --- |
| `--github-issues` | Issue title, body, and issue comments. Pull requests returned by the issues API are excluded. |
| `--github-pull-requests` | Pull request title and body, conversation comments, and review comments. |
| `--github-discussions` | Discussion title, body, top-level comments, and replies through the GitHub GraphQL API. |
| `--github-wiki` | Every reachable unique blob in the full `<repo>.wiki.git` history. |
| `--github-gists` | Every readable revision and comment for gists owned by the repository owner. This is an account surface, not a repository-only surface. |

Each flag is independent. Pass only the surfaces the token is allowed to read.
Use `KEYHOG_GITHUB_TOKEN` instead of `--github-token` so the credential does not
enter the process argument list.

Limit a fine-grained token to the target repository and grant read-only access
for the selected Issues, Pull requests, Discussions, and Contents resources.
Owner-gist scanning also needs the token's Gists user permission. A classic
token may need `repo` for private repository surfaces and `gist` for non-public
gists. Public access still depends on the repository and organization policy.

## Bounds and coverage

All API calls share one request budget. `--limit-hosted-git-pages` controls that
budget for a collaboration source, including item pages, comment pages, gist
revisions, and GraphQL pages. API responses use
`--limit-web-response-bytes`. Collaboration chunks also honor the Git aggregate
byte and chunk limits.

An inaccessible selected surface produces a typed `inaccessible` source
coverage error. A request, response, byte, or chunk cap produces a typed
`truncated` source coverage error. These errors make coverage incomplete. KeyHog
does not report the selected surface as clean.

GitHub response bodies and credentials are never included in diagnostics.
Redirects are disabled while an authorization header is present.

## Provenance and edits

Findings use credential-free `github://` paths. Issue, pull request, discussion,
and comment revisions combine the immutable GitHub node identity with its
`updated_at` value. Wiki and gist revisions use Git object IDs. Repeated objects
with the same immutable revision identity are scanned once. Edited content gets
a new reproducible revision identity.
