# SecretBench dataset access request — template

Subject: **SecretBench dataset access request — benchmarking keyhog secret scanner**

To: `sbasak4@ncsu.edu`
Cc: `lnneil@ncsu.edu`, `bgreaves@ncsu.edu`, `laurie_williams@ncsu.edu`
From: `security@santh.dev`

---

Hi Setu, Lorenzo, Bradley, Laurie,

I'm building an open-source secret scanner called **keyhog**
(<https://github.com/santhsecurity/keyhog>) and would like to
evaluate it against the SecretBench dataset and report results
publicly with full citation.

A few specifics so you can decide if this is a fit:

* **Tool**: keyhog v0.5.16 — Rust, 889 first-class detectors plus
  generic-entropy scanning, decode-through pipeline (base64/hex/
  url-percent/json/gzip/z85/rot13), live verification for a subset
  of credential families. MIT/Apache-2.0 dual licensed.
* **Why your dataset**: the public alternatives (small synthetic
  fixtures, mining git history ad-hoc) don't let me publish
  apples-to-apples precision/recall numbers against trufflehog,
  gitleaks, etc. SecretBench's 15 084 manually-labeled true
  positives + ~82 k labeled negatives across 311 file types is the
  only dataset I'm aware of that supports a defensible scoreboard.
* **What I'd publish**: per-category precision/recall/F1 against
  keyhog + the comparison scanners (trufflehog, gitleaks; possibly
  noseyparker / detect-secrets / ggshield). Aggregate scoreboard
  JSON committed to the keyhog repo, paper cited prominently.
* **Data protection**: happy to sign your standard agreement.
  Specifically: no redistribution, no exposure of raw secrets in
  any output, scoreboard JSON contains only label/category/scanner
  outcomes (TP/FP/FN counts), no raw credential bytes ever leave
  the host. I'll mirror that pattern in the keyhog CI config too.
* **Citation**: every scoreboard run includes the paper citation
  (`Basak et al., MSR 2023 — SecretBench: A Dataset of Software
  Secrets`) in both the README and the JSON output.

If there's a form or DPA to fill in I'll get it back same-day.

Thanks for putting this dataset together — the comparative-study
methodology in the follow-up paper has been useful for thinking
about what a fair benchmark looks like.

Best,
Mukund Thiru
Santh Security
security@santh.dev

---

## Tracking

| Date | Event |
| --- | --- |
| TBD  | Request sent |
| TBD  | Response received |
| TBD  | DPA signed |
| TBD  | BigQuery access granted |
| TBD  | First scoreboard run on real corpus |

Update this file as each step lands.
