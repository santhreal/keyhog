# Access targets: what the credential opens

A finding tells you where a credential is. It does not tell you what that
credential reaches, which is the first thing you need in order to decide whether
to page someone.

`--access-targets` answers the second question. It runs after the scan, over the
findings the report is about to publish, and attaches typed targets to them.

```sh
keyhog scan <path> --access-targets --format json-envelope -o keyhog.json
```

The flag is off by default. A report produced without it has no
`access_targets` key at all, and its findings are byte-identical.

## Read one target

```sh
jq '.access_targets.targets[0]' keyhog.json
```

```json
{
  "credential_hash": "bfca93e20109530d8937af3f30a33b0441c4372d08d145924a35cc5edd57551b",
  "detector_id": "url-credentials",
  "service": "generic",
  "location": {
    "source": "filesystem",
    "file_path": "corpus/02/mirror-pos-0001794.js",
    "line": 1
  },
  "targets": [
    {
      "kind": "endpoint",
      "value": "zajgrjseiiwa.example.org:3306",
      "redaction": "none",
      "label": "database host",
      "confidence": 0.95,
      "evidence": {
        "relation": "same_line",
        "rule_id": "database-uri-endpoint",
        "file_path": "corpus/02/mirror-pos-0001794.js",
        "line": 1,
        "column": 65,
        "span_bytes": 29,
        "line_distance": 0,
        "provenance": {
          "source": "tier_b_rule",
          "base": 0.95,
          "decay_steps": 0,
          "decay_factor": 0.85
        }
      }
    },
    {
      "kind": "database",
      "value": "tigiwuns",
      "redaction": "none",
      "label": "database name",
      "confidence": 0.9,
      "evidence": {
        "relation": "same_line",
        "rule_id": "database-uri-name",
        "line": 1,
        "column": 95,
        "span_bytes": 8,
        "line_distance": 0,
        "provenance": {
          "source": "tier_b_rule",
          "base": 0.9,
          "decay_steps": 0,
          "decay_factor": 0.85
        }
      }
    }
  ]
}
```

`credential_hash` is the join key back into `.findings[]`.

## The five kinds

Ordered by blast radius, widest first.

| Kind | Boundary | Example value |
| --- | --- | --- |
| `account` | billing or ownership | an AWS account id, an Azure storage account |
| `tenant` | identity or organization inside a provider | a Slack workspace, an Okta org, a GCP project |
| `endpoint` | a network address it authenticates to | `db.example.org:5432`, an API base URL |
| `database` | a named logical database inside an endpoint | `customers` |
| `resource` | one addressable object | an S3 bucket, an ARN, a git repository |

Rank by the widest kind present:

```sh
jq -r '.access_targets.targets[]
       | select([.targets[].kind] | index("account"))
       | "\(.location.file_path)\t\(.targets[0].value)"' keyhog.json
```

## Three ways a target is tied to a credential

`evidence.relation` says which, and it is the primary sort key.

- `decoded`. Recovered from the credential itself, offline, with no file read.
  An `AKIA` key carries its AWS account id. This cannot be a coincidence of
  proximity, so it scores highest.
- `same_line`. Found on the finding's own line. The usual case for a connection
  string, where the password and the host are the same token.
- `same_file`. Found elsewhere in the indexed part of the file. Confidence
  decays by a factor of `0.85` for every 25 lines of distance, up to four
  applications. `evidence.line_distance` and `provenance.decay_steps` show
  exactly what was charged.

## Which providers are understood

Every rule lives in `crates/core/data/access-targets.toml`. There is no provider
match arm in the Rust. Adding a provider is a data edit reviewable in one diff,
the same as the detector corpus.

Measured on `benchmarks/corpora/homefield`, 2,251 findings produced 1,213 rows.
Sixteen distinct rule ids appear: 15 of the 21 `[[rule]]` entries, plus the
`[[metadata]]` account mapping.

```
3559 endpoint  database-uri-endpoint
1366 tenant    atlassian-site
 910 account   azure-storage-account
 746 tenant    supabase-project
 708 tenant    slack-workspace
 686 database  database-uri-name
 315 resource  git-repository
 305 endpoint  declared-api-endpoint
 247 endpoint  jdbc-endpoint
 187 endpoint  aws-service-endpoint
 142 endpoint  azure-sql-server
 140 resource  firebase-instance
  79 tenant    shopify-store
  75 resource  slack-webhook-channel
   3 tenant    gcp-project-id
   2 account   metadata:account_id
```

## No document text is ever emitted

A target value is an address. Three rules make that true rather than hoped for.

1. A connection-string rule skips userinfo with a non-capturing group. Given a
   URI of the form `scheme://` then userinfo, then `host`, then `:port`, then
   `/database`, only the host, the port, and the database name can reach a
   capture. The credential between `//` and `@` has no capturing group to
   land in.
2. A rule must capture a numbered group. Group 0, the whole match, is rejected
   at policy load, because the whole match includes surrounding text.
3. Any candidate whose SHA-256 equals a credential digest in the same report is
   dropped, whatever the rule intended.

Evidence is structural: a rule id, a line, a column, a span length, a distance.
There is no excerpt field, and there will not be one, because the line that
holds a credential holds the credential.

Verify it on your own report:

```sh
jq -c '.access_targets' keyhog.json | grep -c -F -f your-known-secrets.txt
```

On the 3,000-secret mirror corpus that count is `0`.

## Telling "no door" from "never looked"

An empty target list means one of two very different things, so the report says
which.

```sh
jq '.access_targets.coverage' keyhog.json
```

```json
{
  "findings_total": 1,
  "findings_with_file_context": 0,
  "files_indexed": 0,
  "bytes_indexed": 0,
  "complete": false,
  "gaps": [
    {
      "reason": "historical_content",
      "explanation": "the finding is historical content at a commit; the working-tree file was not indexed because its neighbours may postdate the credential",
      "findings": 1,
      "examples": [".env"]
    }
  ]
}
```

`complete: true` with no targets means the pass read the file and found no door.
`complete: false` means some findings were never inspected, and `gaps` names why.

The reasons:

| Reason | What happened |
| --- | --- |
| `historical_content` | the finding is at a commit; the working-tree file may have changed since |
| `source_not_readable` | the backend exposes no re-readable local file (container layer, cloud object, stdin) |
| `no_file_path` | the finding carries no path |
| `transient_read_failed` | the file was removed, replaced, or locked between the scan and this pass, so a rerun may cover it |
| `permanent_read_failed` | the file cannot be read and a rerun will not change that: permissions, or not a regular file |
| `not_utf8` | the prefix is not valid UTF-8, so byte offsets cannot become lines |
| `file_truncated` | the file is larger than 1 MiB, so only its prefix was indexed |
| `derived_view_anchorless` | the credential came from a decode view or a windowed read, so its line does not index the file |
| `byte_budget_exhausted` | the pass reached its 256 MiB whole-run ceiling first |

`derived_view_anchorless` is the subtle one. A finding's source is sometimes
`filesystem/<view>` rather than `filesystem`: `filesystem/base64`,
`filesystem/hex`, `filesystem/reverse` and `filesystem/quoted-printable` mean
the credential was recovered from a decoded view, and `filesystem/windowed`
means the file was large enough to be read in windows and the line number is
relative to the window. In every one of those the line does not index the file.

The file is still indexed and its doors are still reported. What is dropped is
the proximity claim: those targets are `same_file` with no `line_distance` and
the maximum decay applied, so a door on the adjacent line scores the same as
one four hundred lines away. That under-claims on purpose. The alternative is
asserting a distance the line number cannot support.

Worked example, one 1.3 MB file scanned with `--access-targets`, credential on
line 1 and the door on line 2:

```
source                 filesystem/windowed
targets                endpoint prod-db.example.org:5432   confidence 0.496
                       database customers                  confidence 0.470
relation               same_file, line_distance null
coverage.complete      false
coverage.gaps          derived_view_anchorless (1), file_truncated (1)
```

The same door on line 2 of a small file scores 0.95 and 0.90 as `same_line`.

## Cost

The pass reads each distinct file at most once, over at most 1 MiB of it, under
a 256 MiB ceiling for the whole run. Cost is linear in indexed bytes plus one
sort per finding, never quadratic in findings.

Two runs on this host, both with `--access-targets`:

| Corpus | Findings | Files indexed | Bytes indexed | Rows |
| --- | --- | --- | --- | --- |
| `benchmarks/corpora/mirror/corpus` | 2,862 | 2,841 | 708,174 | 198 |
| `benchmarks/corpora/homefield` | 2,251 | 1,057 | 772,974 | 1,213 |

Files indexed is below findings on both, because several findings share a file
and the index is built once.

## What this is not

`--access-targets` is intra-file. It answers "what does this one credential
open". For "where else does this same credential appear", use `--correlate`,
which joins findings across files. The two are independent and can be combined.
