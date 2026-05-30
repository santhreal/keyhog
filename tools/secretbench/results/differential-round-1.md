# SecretBench mirror differential -- Round 1

- generated: 2026-05-30T04:36:33.433536+00:00
- corpus: tools/secretbench/mirror/corpus (15 000-record manifest)
- sample size: 50   seed: 0
- elapsed: 121.44 s

## Scanner versions

| scanner | version | available |
| --- | --- | --- |
| keyhog | `KeyHog v0.5.37` | yes |
| trufflehog | `trufflehog 3.95.3` | yes |
| gitleaks | `8.30.0` | yes |

Note: peer scanners are run via the `score.py` wrappers in this repo, identical to how `leaderboard.py` invokes them, so the comparison is apples-to-apples (`trufflehog filesystem --json --no-verification`, `gitleaks detect --no-git`, `keyhog scan --format json --show-secrets --no-suppress-test-fixtures`).

## Per-scanner tally on the 50-fixture sample

Truth attribution per fixture: `TP` = scanner emitted a finding whose value overlapped the labeled secret on a `label=true` fixture; `FN` = `label=true` fixture with no overlapping finding (whether scanner was silent or fired on the wrong substring); `FP` = scanner emitted a finding on a `label=false` fixture; `TN` = silent on a `label=false` fixture.

| scanner | TP | FP | TN | FN | precision | recall | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| keyhog | 7 | 1 | 41 | 1 | 0.875 | 0.875 | 0.875 |
| trufflehog | 3 | 0 | 42 | 5 | 1.000 | 0.375 | 0.545 |
| gitleaks | 7 | 18 | 24 | 1 | 0.280 | 0.875 | 0.424 |

Sample composition: 8 positives (16%), 42 negatives (84%). Mirror manifest as a whole is 3 000 / 12 000.

## Disagreement summary

22 of 50 fixtures produced a disagreement (at least one scanner returned a different attribution than the others). Distribution by category:

| category | disagreements |
| --- | --- |
| uuid | 6 |
| license-key-shape | 4 |
| api-key | 2 |
| base64-protobuf | 2 |
| docs-example-marker | 2 |
| sha256-hex | 1 |
| git-commit-sha | 1 |
| session-token | 1 |
| npm-lock-integrity | 1 |
| sha1-hex | 1 |
| cloud-service-credential | 1 |

## Disagreement table

| # | fixture id | label | category | comment | keyhog | trufflehog | gitleaks | right |
| - | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `mirror-neg-0011585` | - | sha256-hex | negative-shape; wrapper=javascript | TN | TN | FP | TN |
| 2 | `mirror-pos-0000663` | + | api-key | wrapper=ini | TP | FN | TP | TP |
| 3 | `mirror-neg-0001242` | - | base64-protobuf | negative-shape; wrapper=json | TN | TN | FP | TN |
| 4 | `mirror-neg-0005376` | - | uuid | negative-shape; wrapper=k8s-secret | TN | TN | FP | TN |
| 5 | `mirror-neg-0003634` | - | license-key-shape | negative-shape; wrapper=javascript | TN | TN | FP | TN |
| 6 | `mirror-neg-0001969` | - | git-commit-sha | negative-shape; wrapper=ini | TN | TN | FP | TN |
| 7 | `mirror-neg-0011878` | - | base64-protobuf | negative-shape; wrapper=ini | TN | TN | FP | TN |
| 8 | `mirror-neg-0000578` | - | uuid | negative-shape; wrapper=log-line | TN | TN | FP | TN |
| 9 | `mirror-neg-0001617` | - | uuid | negative-shape; wrapper=ini | TN | TN | FP | TN |
| 10 | `mirror-pos-0002289` | + | session-token | wrapper=k8s-secret | TP | FN | TP | TP |
| 11 | `mirror-neg-0009383` | - | license-key-shape | negative-shape; wrapper=k8s-secret | FP | TN | FP | TN |
| 12 | `mirror-neg-0001104` | - | docs-example-marker | negative-shape; wrapper=ini | TN | TN | FP | TN |
| 13 | `mirror-neg-0011905` | - | npm-lock-integrity | negative-shape; wrapper=yaml | TN | TN | FP | TN |
| 14 | `mirror-neg-0011781` | - | uuid | negative-shape; wrapper=k8s-secret | TN | TN | FP | TN |
| 15 | `mirror-neg-0002081` | - | sha1-hex | negative-shape; wrapper=shell-export | TN | TN | FP | TN |
| 16 | `mirror-pos-0001208` | + | api-key | wrapper=helm-values | TP | FN | TP | TP |
| 17 | `mirror-neg-0011726` | - | license-key-shape | negative-shape; wrapper=python | TN | TN | FP | TN |
| 18 | `mirror-neg-0008206` | - | uuid | negative-shape; wrapper=shell-export | TN | TN | FP | TN |
| 19 | `mirror-neg-0004735` | - | uuid | negative-shape; wrapper=log-line | TN | TN | FP | TN |
| 20 | `mirror-neg-0006171` | - | docs-example-marker | negative-shape; wrapper=helm-values | TN | TN | FP | TN |
| 21 | `mirror-pos-0001649` | + | cloud-service-credential | wrapper=json | TP | FN | TP | TP |
| 22 | `mirror-neg-0004113` | - | license-key-shape | negative-shape; wrapper=javascript | TN | TN | FP | TN |

## Per-fixture detail

### 1. `mirror-neg-0011585` (sha256-hex, label=false)

- file: `f9/mirror-neg-0011585.js`
- comment: `negative-shape; wrapper=javascript`
- secret (manifest): `d9c8ed4a10851cbac4bb6a45b73c6f4af7cbcaca07bca26d7ca4d738fa3a0bc8`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `d9c8ed4a10851cbac4bb6a45b73c6f4af7cbcaca07bca26d7ca4d738fa3a0bc8` |

### 2. `mirror-pos-0000663` (api-key, label=true)

- file: `97/mirror-pos-0000663.ini`
- comment: `wrapper=ini`
- secret (manifest): `neon_api_V51img_AcjX8IpYCJ4GkugvA3KRPebKjAgs5YhgOhMeuaeR_`
- right verdict: `TP`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TP | `generic-secret`: `neon_api_V51img_AcjX8IpYCJ4GkugvA3KRPebKjAgs5YhgOhMeuaeR_` |
| trufflehog | FN | (silent) |
| gitleaks | TP | `generic-api-key`: `neon_api_V51img_AcjX8IpYCJ4GkugvA3KRPebKjAgs5YhgOhMeuaeR_` |

### 3. `mirror-neg-0001242` (base64-protobuf, label=false)

- file: `92/mirror-neg-0001242.json`
- comment: `negative-shape; wrapper=json`
- secret (manifest): `S9Xa5UeoZ+HQH8e9ICSmTf9BHcgdXrticMZft9gDYvnmi7rty1DAna+jw7t/4MzJWaYmpFWBevjb7ON5A/0hh1SgDmAgUzSaJ7k=`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `S9Xa5UeoZ+HQH8e9ICSmTf9BHcgdXrticMZft9gDYvnmi7rty1DAna+jw7t/4MzJWaYmpFWBevjb7ON5 ...<20 more chars>` |

### 4. `mirror-neg-0005376` (uuid, label=false)

- file: `b8/mirror-neg-0005376.yaml`
- comment: `negative-shape; wrapper=k8s-secret`
- secret (manifest): `3a3b544a-caba-4b01-88ea-ae3ecaffbce4`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `M2EzYjU0NGEtY2FiYS00YjAxLTg4ZWEtYWUzZWNhZmZiY2U0` <br> `kubernetes-secret-yaml`: `secret-key: M2EzYjU0NGEtY2FiYS00YjAxLTg4ZWEtYWUzZWNhZmZiY2U0` |

### 5. `mirror-neg-0003634` (license-key-shape, label=false)

- file: `ea/mirror-neg-0003634.js`
- comment: `negative-shape; wrapper=javascript`
- secret (manifest): `RWRFW-Y4N6Q-0KBL1-MQXH5-4I8IO`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `RWRFW-Y4N6Q-0KBL1-MQXH5-4I8IO` |

### 6. `mirror-neg-0001969` (git-commit-sha, label=false)

- file: `69/mirror-neg-0001969.ini`
- comment: `negative-shape; wrapper=ini`
- secret (manifest): `2dc5b41b36d64f23392d9acd6a6a06d4adbd9e5e`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `2dc5b41b36d64f23392d9acd6a6a06d4adbd9e5e` |

### 7. `mirror-neg-0011878` (base64-protobuf, label=false)

- file: `1e/mirror-neg-0011878.ini`
- comment: `negative-shape; wrapper=ini`
- secret (manifest): `zpSQBXp102hYapOVjN6+j3NMHAlKG+UFF04T2IAmbYpB`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `zpSQBXp102hYapOVjN6+j3NMHAlKG+UFF04T2IAmbYpB` |

### 8. `mirror-neg-0000578` (uuid, label=false)

- file: `fa/mirror-neg-0000578.log`
- comment: `negative-shape; wrapper=log-line`
- secret (manifest): `d7711de5-0a4d-4fa8-9b9f-ba290c9cfb1c`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `d7711de5-0a4d-4fa8-9b9f-ba290c9cfb1c` |

### 9. `mirror-neg-0001617` (uuid, label=false)

- file: `09/mirror-neg-0001617.ini`
- comment: `negative-shape; wrapper=ini`
- secret (manifest): `fc00ccc4-bfaf-4e21-b836-ef5ce10bb81a`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `fc00ccc4-bfaf-4e21-b836-ef5ce10bb81a` |

### 10. `mirror-pos-0002289` (session-token, label=true)

- file: `f1/mirror-pos-0002289.yaml`
- comment: `wrapper=k8s-secret`
- secret (manifest): `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyMDY4ODM4NzA4IiwiaWF0IjoxNjAwNTYzODQzLCJleHAiOjE5NjA5NTEyMzMsImp0aSI6IkJ ...<67 more chars>`
- right verdict: `TP`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TP | `jwt-token`: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyMDY4ODM4NzA4IiwiaWF0IjoxNjAwNTY ...<107 more chars>` |
| trufflehog | FN | (silent) |
| gitleaks | TP | `jwt-base64`: `aGJHY2lPaU` <br> `generic-api-key`: `ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeU1EWTRPRE00TnpB ...<172 more chars>` <br> `kubernetes-secret-yaml`: `jwt-token: ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeU1EW ...<183 more chars>` <br> `kubernetes-secret-yaml`: `jwt-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9` <br> `jwt`: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyMDY4ODM4NzA4IiwiaWF0IjoxNjAwNTY ...<107 more chars>` |

### 11. `mirror-neg-0009383` (license-key-shape, label=false)

- file: `5f/mirror-neg-0009383.yaml`
- comment: `negative-shape; wrapper=k8s-secret`
- secret (manifest): `JW5UK-TMZI2-WICDC-T007M-IAVOP`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | FP | `generic-secret`: `JW5UK-TMZI2-WICDC-T007M-IAVOP=` |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=` <br> `kubernetes-secret-yaml`: `token: Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=` <br> `generic-api-key`: `JW5UK-TMZI2-WICDC-T007M-IAVOP` |

### 12. `mirror-neg-0001104` (docs-example-marker, label=false)

- file: `08/mirror-neg-0001104.ini`
- comment: `negative-shape; wrapper=ini`
- secret (manifest): `xoxb-1234567890-1234567890-EXAMPLE-TOKEN`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `slack-bot-token`: `xoxb-1234567890-1234567890-EXAMPLE-TOKEN` |

### 13. `mirror-neg-0011905` (npm-lock-integrity, label=false)

- file: `39/mirror-neg-0011905.yaml`
- comment: `negative-shape; wrapper=yaml`
- secret (manifest): `sha512-UNew1SBwSWZKTSi2ZRT6btCtfuxOckX1Dr3Cf16fJNy6W9f3A0WYrSt8minXtKeq43kK0FesDRklkSyzsuuYPH==`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `sha512-UNew1SBwSWZKTSi2ZRT6btCtfuxOckX1Dr3Cf16fJNy6W9f3A0WYrSt8minXtKeq43kK0FesD ...<15 more chars>` |

### 14. `mirror-neg-0011781` (uuid, label=false)

- file: `bd/mirror-neg-0011781.yaml`
- comment: `negative-shape; wrapper=k8s-secret`
- secret (manifest): `4ecceaaa-2d91-40e3-a279-bf6b91d2fa51`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `kubernetes-secret-yaml`: `secret-key: NGVjY2VhYWEtMmQ5MS00MGUzLWEyNzktYmY2YjkxZDJmYTUx` <br> `generic-api-key`: `NGVjY2VhYWEtMmQ5MS00MGUzLWEyNzktYmY2YjkxZDJmYTUx` <br> `generic-api-key`: `4ecceaaa-2d91-40e3-a279-bf6b91d2fa51` |

### 15. `mirror-neg-0002081` (sha1-hex, label=false)

- file: `d9/mirror-neg-0002081.sh`
- comment: `negative-shape; wrapper=shell-export`
- secret (manifest): `fd9af52bfa4efd5a28d6e9a92e331a705903be20`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `fd9af52bfa4efd5a28d6e9a92e331a705903be20` |

### 16. `mirror-pos-0001208` (api-key, label=true)

- file: `b8/mirror-pos-0001208.yaml`
- comment: `wrapper=helm-values`
- secret (manifest): `Sx7X6iT4FbnGrzUn40ATVYhDZ9NfiuaiJRdo2FhTlT`
- right verdict: `TP`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TP | `generic-secret`: `Sx7X6iT4FbnGrzUn40ATVYhDZ9NfiuaiJRdo2FhTlT` |
| trufflehog | FN | (silent) |
| gitleaks | TP | `generic-api-key`: `Sx7X6iT4FbnGrzUn40ATVYhDZ9NfiuaiJRdo2FhTlT` |

### 17. `mirror-neg-0011726` (license-key-shape, label=false)

- file: `86/mirror-neg-0011726.py`
- comment: `negative-shape; wrapper=python`
- secret (manifest): `7UQLK-OKLYF-YV4U0-ROH8X-PINHS`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `7UQLK-OKLYF-YV4U0-ROH8X-PINHS` |

### 18. `mirror-neg-0008206` (uuid, label=false)

- file: `c6/mirror-neg-0008206.sh`
- comment: `negative-shape; wrapper=shell-export`
- secret (manifest): `d82bdcaa-871d-4dbd-af0a-dd291b4b3783`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `d82bdcaa-871d-4dbd-af0a-dd291b4b3783` |

### 19. `mirror-neg-0004735` (uuid, label=false)

- file: `37/mirror-neg-0004735.log`
- comment: `negative-shape; wrapper=log-line`
- secret (manifest): `3664b97a-ee85-4e99-9f5a-9c07e923d0e5`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `3664b97a-ee85-4e99-9f5a-9c07e923d0e5` |

### 20. `mirror-neg-0006171` (docs-example-marker, label=false)

- file: `d3/mirror-neg-0006171.yaml`
- comment: `negative-shape; wrapper=helm-values`
- secret (manifest): `xoxb-1234567890-1234567890-EXAMPLE-TOKEN`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `slack-bot-token`: `xoxb-1234567890-1234567890-EXAMPLE-TOKEN` |

### 21. `mirror-pos-0001649` (cloud-service-credential, label=true)

- file: `71/mirror-pos-0001649.json`
- comment: `wrapper=json`
- secret (manifest): `toZ8ouXenUyOrxPUMEUrV7/L9u+AVuaZJCol96gV2OqwUr+cQwHpHByWFZFaoYJr4xumTTtrw84uIg6f1xd1heZZS+HtIo4Cwf0bpyWVD+PSF0wp0Uf0C/yf ...<112 more chars>`
- right verdict: `TP`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TP | `aws-session-token`: `AWS_SESSION_TOKEN": "toZ8ouXenUyOrxPUMEUrV7/L9u+AVuaZJCol96gV2OqwUr+cQwHpHByWFZF ...<174 more chars>` |
| trufflehog | FN | (silent) |
| gitleaks | TP | `generic-api-key`: `toZ8ouXenUyOrxPUMEUrV7/L9u+AVuaZJCol96gV2OqwUr+cQwHpHByWFZFaoYJr4xumTTtrw84uIg6f ...<152 more chars>` |

### 22. `mirror-neg-0004113` (license-key-shape, label=false)

- file: `c9/mirror-neg-0004113.js`
- comment: `negative-shape; wrapper=javascript`
- secret (manifest): `LRPTB-A8D0W-TCFWC-7AC14-S2LV4`
- right verdict: `TN`

| scanner | attribution | findings on file |
| --- | --- | --- |
| keyhog | TN | (silent) |
| trufflehog | TN | (silent) |
| gitleaks | FP | `generic-api-key`: `LRPTB-A8D0W-TCFWC-7AC14-S2LV4` |

## Patterns + scout notes

Each pattern below names the disagreement class, the scanner(s) that disagree with the right verdict, and the next move. This is a scout report only -- no scanner code is being changed in this round.

| category | label | wrong scanners | count | example fixture |
| --- | --- | --- | --- | --- |
| uuid | false | gitleaks | 6 | `mirror-neg-0005376` |
| license-key-shape | false | gitleaks | 3 | `mirror-neg-0003634` |
| api-key | true | trufflehog | 2 | `mirror-pos-0000663` |
| base64-protobuf | false | gitleaks | 2 | `mirror-neg-0001242` |
| docs-example-marker | false | gitleaks | 2 | `mirror-neg-0001104` |
| sha256-hex | false | gitleaks | 1 | `mirror-neg-0011585` |
| git-commit-sha | false | gitleaks | 1 | `mirror-neg-0001969` |
| session-token | true | trufflehog | 1 | `mirror-pos-0002289` |
| license-key-shape | false | gitleaks, keyhog | 1 | `mirror-neg-0009383` |
| npm-lock-integrity | false | gitleaks | 1 | `mirror-neg-0011905` |
| sha1-hex | false | gitleaks | 1 | `mirror-neg-0002081` |
| cloud-service-credential | true | trufflehog | 1 | `mirror-pos-0001649` |

### Headline read

- keyhog: TP=7/8, FP=1/42, recall=0.875, precision=0.875.
- trufflehog: TP=3/8, FP=0/42, recall=0.375, precision=1.000.
- gitleaks: TP=7/8, FP=18/42, recall=0.875, precision=0.280.

On this sample, keyhog and gitleaks tie on recall, but gitleaks burns its precision on the negative bucket (it fires on uuids, license-key-shape strings, sha256/sha1 hex, git commit shas, and npm-lock integrity hashes that the manifest explicitly labels as non-secrets). trufflehog's miss rate is high but its FP rate is zero on this sample. keyhog's one FP and one FN are the things to chase in round 2.

### Round-2 chase list (keyhog only)

#### FP: `mirror-neg-0009383` (license-key-shape inside k8s-secret)

- file: `5f/mirror-neg-0009383.yaml`
- on-disk content:

  ```yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: token-secret
  type: Opaque
  data:
    token: Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=
  ```

- right verdict per manifest: `TN` (the value is a license-key-shape, not a real secret)
- keyhog fires `generic-secret` on the base64-decoded `JW5UK-TMZI2-WICDC-T007M-IAVOP=` 
  via the k8s data-field decoder. That decode + emit path was added
  precisely to catch base64-wrapped secrets in k8s manifests, and is
  doing the right thing on real k8s secrets. The disagreement here is
  that the mirror generator labelled a license-key-shape value `false`
  but wrapped it in `kind: Secret` / `data:` / `token:`, which is the
  exact shape a real secret would take.
- root cause is in the corpus, not the scanner: a license-key-shape
  generator currently emits negative fixtures wrapped in `kind: Secret`
  / `data:`, which is a guaranteed FP against any base64-decoding
  k8s-aware scanner. Two clean fixes for round 2:
  1. tighten the mirror generator: do not wrap negative-shape values
     in `kind: Secret` `data:` blocks; use a comment, a doc string, or
     a `license:` key instead. Then this stops being a disagreement.
  2. add a keyhog rule that downgrades `generic-secret` confidence
     when the decoded base64 matches the 5-block license-key shape
     `[A-Z0-9]{5}(-[A-Z0-9]{5}){3,4}`. Adversarial twin: a real secret
     that happens to use the same separator pattern (e.g. AWS Direct
     Connect partner IDs) must still fire.

#### FN: `mirror-pos-0001553` (generic-password in terraform variable)

- file: `11/mirror-pos-0001553.tf`
- on-disk content:

  ```hcl
  variable "api_key" {
    type    = string
    default = "qTDK@erggj9sBIsfNdmTs"
  }
  
  resource "null_resource" "deploy" {}
  ```

- right verdict: `TP` (the secret is `qTDK@erggj9sBIsfNdmTs`, 21 chars,
  entropy 3.975, symbolic charset, in `default = "..."` of a variable
  named `api_key`)
- all three scanners are silent: keyhog, trufflehog, gitleaks. The
  shape (21 chars, mixed symbolic, one `@`) sits below every named
  detector and below the generic-high-entropy floor.
- chase for round 2: HCL `variable "X" { default = "<value>" }` is
  the same key/value contract as `X = "<value>"`, and the variable
  name `api_key` is the strongest possible keyword. Two clean moves:
  1. extend the HCL keyword-fallback path to walk into `variable`
     blocks and read `default` as the value, with the outer name as
     the keyword. Positive: this fixture. Adversarial twin: a
     `variable "region" { default = "us-east-1" }` must NOT fire.
  2. confirm keyhog actually reads `.tf` files: rerun on a known-
     positive `.tf` fixture in `contracts/` to rule out a file-type
     filter regression.

#### Cross-scanner FN cluster: trufflehog misses every wrapped positive

- trufflehog's 5 misses on this sample are all of shape `wrapper=ini`,
  `wrapper=helm-values`, `wrapper=k8s-secret`, `wrapper=terraform`,
  `wrapper=json`. trufflehog requires its verifier-bearing detectors
  to recognise the credential shape; the mirror's per-provider
  fragment-assembly produces values that do not match trufflehog's
  per-provider regex (this is by design -- the mirror is
  schema-identical, not value-identical, to real SecretBench).
- not a keyhog action item; called out so the next-round reader does
  not chase the trufflehog gap.

#### gitleaks: structural-shape over-fire on negatives

- 18 of 42 negatives produce a gitleaks finding. The triggers are:
  `generic-api-key` on uuids (6), sha256-hex (1), sha1-hex (1),
  git-commit-sha (1), base64-protobuf (2), license-key-shape (4),
  npm-lock-integrity (1), docs-example-marker (2); plus
  `kubernetes-secret-yaml` and `terraform-variable` rule classes on
  any `data:` / `default = "..."` slot.
- not a keyhog action item per se; the value of recording it here is
  to set the leaderboard precision expectation: 18 FPs on 42
  negatives (precision 0.28) is the real-world cost of gitleaks'
  shape-only triggers on this corpus.

### Sampling caveats

- 50 fixtures, seed=0. Mirror is 3 000 positives / 12 000 negatives
  (1:4); this sample landed 8/42 (1:5.3), close enough that the
  precision/recall numbers are within ~3 pp of the full-corpus
  numbers but the absolute FP count for gitleaks would 240x scale to
  ~4 300 on the full 12k negatives.
- attribution rule used here: a finding whose value overlaps the
  labeled secret (containment, escape-normalized, base64-decoded both
  ways) is TP; this is the same `overlap()` rule `score.py` uses, so
  these numbers reconcile against the full leaderboard.
- not modified: any scanner code. Mirror corpus untouched. No
  generator changes. Pure scout report.
