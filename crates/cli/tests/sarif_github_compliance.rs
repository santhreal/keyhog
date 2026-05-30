//! Enterprise integration gate: keyhog's SARIF must be consumable by GitHub
//! code-scanning (Advanced Security) - the #1 enterprise integration point.
//!
//! Structural SARIF validity is NOT sufficient. GitHub additionally requires,
//! and no schema validator catches:
//!   1. a REPO-RELATIVE `artifactLocation.uri` - an absolute `file:///...` uri
//!      uploads fine but never maps to a PR file, so alerts never annotate the
//!      diff (the entire point of code-scanning);
//!   2. `partialFingerprints` for stable alert identity - without it the same
//!      leak re-opens as a new alert every run and fixed alerts don't close;
//!   3. each `ruleId` resolving into `tool.driver.rules[]`;
//!   4. a valid SARIF `level`.
//!
//! Both (1) and (2) were silently broken before. This drives the REAL binary
//! exactly as the GitHub Action does - `keyhog scan . --format sarif` from the
//! repository root (`current_dir` = scan root) - so the relativization is
//! exercised end to end, not just at the helper level.

use std::process::Command;
use tempfile::TempDir;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn sarif_is_github_code_scanning_compliant() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir src");
    std::fs::write(
        dir.path().join("src/leak.env"),
        concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n"),
    )
    .expect("write fixture");

    // Run FROM the repo root, like the Action (`cd $repo && keyhog scan .`).
    let out = Command::new(binary())
        .current_dir(dir.path())
        .args(["scan", ".", "--no-daemon", "--format", "sarif"])
        .output()
        .expect("spawn keyhog scan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("SARIF stdout must be valid JSON");

    assert_eq!(v["version"], "2.1.0", "SARIF version must be 2.1.0");
    let run = &v["runs"][0];
    let rule_ids: std::collections::HashSet<String> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("tool.driver.rules must be an array")
        .iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect();
    // Each rule must carry GitHub code-scanning severity metadata: a numeric
    // `security-severity` (sets the Critical/High/Medium/Low band - without it
    // every alert shows a flat default) and a `security` tag.
    for rule in run["tool"]["driver"]["rules"].as_array().unwrap() {
        let props = &rule["properties"];
        let sev = props["security-severity"]
            .as_str()
            .unwrap_or_else(|| panic!("rule {} missing security-severity", rule["id"]));
        sev.parse::<f64>()
            .unwrap_or_else(|_| panic!("security-severity must be numeric; got {sev:?}"));
        let tags: Vec<&str> = props["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
            .unwrap_or_default();
        assert!(
            tags.contains(&"security"),
            "rule {} must be tagged `security` for code-scanning categorization; tags={tags:?}",
            rule["id"]
        );
    }

    let results = run["results"].as_array().expect("runs[0].results array");
    assert!(
        !results.is_empty(),
        "the planted AWS key must produce at least one SARIF result"
    );

    for r in results {
        let uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .expect("each result needs artifactLocation.uri");
        // (1) repo-relative — GitHub maps the alert to the PR file.
        assert!(
            !uri.starts_with("file:") && !uri.starts_with('/'),
            "artifactLocation.uri must be repo-relative for code-scanning (no file://, no leading /); got {uri:?}"
        );
        assert!(
            uri.starts_with("src/"),
            "uri must be relative to the scan root; got {uri:?}"
        );
        // (3) ruleId resolves into driver.rules[].
        let rule_id = r["ruleId"].as_str().expect("each result needs a ruleId");
        assert!(
            rule_ids.contains(rule_id),
            "ruleId {rule_id:?} is not present in tool.driver.rules[] - GitHub would drop it"
        );
        // (2) stable partialFingerprints for cross-run dedup.
        let fps = r["partialFingerprints"].as_object();
        assert!(
            fps.map(|m| !m.is_empty()).unwrap_or(false),
            "every result needs non-empty partialFingerprints for alert dedup; got {}",
            r["partialFingerprints"]
        );
        // (4) a SARIF level GitHub understands.
        assert!(
            matches!(
                r["level"].as_str(),
                Some("error" | "warning" | "note" | "none")
            ),
            "result.level must be a valid SARIF level; got {}",
            r["level"]
        );
        // (5) `relatedLocations` must not contain duplicate items. This is the
        // exact failure class the upload-sarif Action rejects on
        // ("relatedLocations contains duplicate item"); when it fires GitHub
        // drops the ENTIRE run, so no schema validator and none of (1)-(4)
        // above catches it. Assert it here, end to end through the real binary,
        // not just at the renderer/property level. The dedup key is the same
        // (uri, startLine, charOffset) triple the renderer dedups on.
        if let Some(related) = r["relatedLocations"].as_array() {
            let mut keys: Vec<(String, Option<i64>, i64)> = related
                .iter()
                .map(|loc| {
                    let uri = loc
                        .pointer("/physicalLocation/artifactLocation/uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let line = loc
                        .pointer("/physicalLocation/region/startLine")
                        .and_then(|v| v.as_i64());
                    let offset = loc
                        .pointer("/physicalLocation/region/charOffset")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    (uri, line, offset)
                })
                .collect();
            let before = keys.len();
            keys.sort();
            keys.dedup();
            assert_eq!(
                keys.len(),
                before,
                "relatedLocations contains a duplicate (uri, line, offset) item; \
                 GitHub Code Scanning rejects this with 'relatedLocations contains \
                 duplicate item' and drops the whole run. result={r}"
            );
        }
    }
}
