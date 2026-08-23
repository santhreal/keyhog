//! E2E: real-world config files a developer commits, each with a planted,
//! real-shape credential. Every test drives the actual `keyhog` binary and
//! asserts the EXACT detector id + line + exit code - not just "something was
//! found". These are the shapes that, if keyhog missed them, would leak a
//! live credential in a real repo. Detector ids/lines were verified against
//! the binary before being written here.
//!
//! Each fixture carries the file name of the shape it stands for, because the
//! name decides the source role. A `.env`, YAML, JSON, INI or TOML value, a
//! shell command argument, and a JS string literal are all credential-bearing
//! roles: the evidence is `likely`/`vendor-pattern` and blocks the default
//! policy. A bare token in an inert text file has no role at all: the detector
//! still fires, the evidence is `review`/`unsupported-context`, and only
//! `--evidence-policy paranoid` blocks. Both halves are asserted, so a
//! regression in either direction goes red.

use crate::e2e::support::{scan_path, write_temp_file};

/// (detector_id, line) pairs from a JSON scan of `content` written as `name`.
fn findings(name: &str, content: &str, extra: &[&str]) -> (Vec<(String, u64)>, Option<i32>) {
    let (_dir, path) = write_temp_file(name, content);
    let output = scan_path(&path, extra);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "stdout not JSON: {e}\n{stdout}\nstderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let mut out: Vec<(String, u64)> = v
        .as_array()
        .expect("findings is a JSON array")
        .iter()
        .map(|f| {
            (
                f["detector_id"].as_str().unwrap_or("").to_string(),
                f["location"]["line"].as_u64().unwrap_or(0),
            )
        })
        .collect();
    out.sort();
    (out, output.status.code())
}

/// Assert `content`, written as `name`, yields `det` at `line` and blocks the
/// default policy. For a file syntax the classifier parses.
fn assert_finds(name: &str, content: &str, det: &str, line: u64) {
    let (got, code) = findings(name, content, &[]);
    assert_eq!(
        code,
        Some(1),
        "a credential-bearing {name} must exit 1; got {got:?}"
    );
    assert!(
        got.iter().any(|(d, l)| d == det && *l == line),
        "expected detector '{det}' at line {line}; got {got:?}"
    );
}

/// Assert `content`, written as `name`, yields `det` at `line` in a source the
/// classifier has no parser for: visible and exit 0 by default, blocking under
/// paranoid.
fn assert_finds_review(name: &str, content: &str, det: &str, line: u64) {
    let (got, code) = findings(name, content, &[]);
    assert!(
        got.iter().any(|(d, l)| d == det && *l == line),
        "expected detector '{det}' at line {line} in {name}; got {got:?}"
    );
    assert_eq!(
        code,
        Some(0),
        "an unparsed source role is review evidence and must not block the default policy in {name}; got {got:?}"
    );
    let (paranoid_got, paranoid_code) = findings(name, content, &["--evidence-policy", "paranoid"]);
    assert_eq!(
        paranoid_code,
        Some(1),
        "paranoid must block the same review finding in {name}; got {paranoid_got:?}"
    );
}

/// Assert `content`, written as `name`, yields zero findings, exit 0.
fn assert_clean(name: &str, content: &str) {
    let (got, code) = findings(name, content, &[]);
    assert!(
        got.is_empty(),
        "expected zero findings in {name}; got {got:?}"
    );
    assert_eq!(code, Some(0), "a clean {name} must exit 0");
}

/// Build a Slack bot-token-shaped string at runtime so the complete `xoxb-...`
/// literal never lands in source. GitHub push protection blocks a literal Slack
/// token, and this e2e file (unlike the LFS-tracked contract fixtures) is plain
/// source. The scanner sees the identical assembled bytes either way.
fn slack_bot_token() -> String {
    format!(
        "xoxb-{}-{}-{}",
        "2417823592", "2417823592", "AbCdEfGhIjKlMnOpQrStUvWx"
    )
}

// ── Positive: real-world files with a planted credential ──────────────────

#[test]
fn dotenv_aws_access_key() {
    let f =
        "# production env\nDB_HOST=db.internal\nAWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\nLOG=info\n";
    assert_finds(".env", f, "aws-access-key", 3);
}

#[test]
fn git_config_token_in_remote_url() {
    // The classic: a PAT baked into a remote URL in .git/config.
    let f = "[remote \"origin\"]\n\turl = https://oauth2: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@github.com/acme/app.git\n";
    assert_finds("config", f, "github-classic-pat", 2);
}

#[test]
fn npmrc_github_packages_token() {
    // GitHub Packages auth in .npmrc - a PAT after `_authToken=`. Deterministic
    // shape (the npm_ entropy-token form is threshold-based and not suited to a
    // stable assertion).
    let f = "//npm.pkg.github.com/:_authToken=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\n";
    // A `ghp_` PAT carries a checksum, so its evidence is confirmed and blocks
    // even though `.npmrc` has no source-role parser.
    assert_finds(".npmrc", f, "github-classic-pat", 1);
}

#[test]
fn slack_bot_token_in_yaml() {
    let f = format!("slack:\n  bot_token: {}\n", slack_bot_token());
    assert_finds("config.yaml", &f, "slack-bot-token", 2);
}

#[test]
fn google_api_key_in_js_config() {
    let f =
        "const firebaseConfig = {\n  apiKey: \"AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q\",\n};\n";
    assert_finds("firebase.js", f, "google-api-key", 2);
}

#[test]
fn postgres_url_with_password() {
    let f = "DATABASE_URL=postgres://admin:S3cr3tP4ssw0rd@db.example.com:5432/prod\n";
    assert_finds(".env", f, "postgresql-connection-string", 1);
}

#[test]
fn docker_compose_env_aws_key() {
    let f = "services:\n  web:\n    image: acme/web\n    environment:\n      AWS_ACCESS_KEY_ID: AKIAQYLPMN5HFIQR7XYA\n";
    assert_finds("docker-compose.yml", f, "aws-access-key", 5);
}

#[test]
fn dockerfile_env_aws_key() {
    let f = "FROM debian:bookworm\nENV AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\nRUN echo build\n";
    assert_finds("Dockerfile", f, "aws-access-key", 2);
}

#[test]
fn github_actions_hardcoded_aws_key() {
    let f = "name: deploy\njobs:\n  deploy:\n    steps:\n      - run: echo done\n        env:\n          AWS_ACCESS_KEY_ID: AKIAQYLPMN5HFIQR7XYA\n";
    assert_finds("deploy.yml", f, "aws-access-key", 7);
}

#[test]
fn shell_script_export_aws_key() {
    let f = "#!/bin/sh\nset -e\nexport AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA\naws s3 ls\n";
    assert_finds("deploy.sh", f, "aws-access-key", 3);
}

#[test]
fn slack_token_at_first_line() {
    // Boundary: credential as the very first bytes of the file.
    let f = format!("{}\n", slack_bot_token());
    assert_finds_review("token.txt", &f, "slack-bot-token", 1);
}

// ── Negative: real-world files that must NOT fire ─────────────────────────

#[test]
fn placeholder_env_is_clean() {
    let f = "AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY_HERE\nAWS_SECRET_ACCESS_KEY=<your-secret-here>\nTOKEN=${TOKEN}\n";
    assert_clean(".env", f);
}

#[test]
fn example_dotenv_is_clean() {
    let f = "# .env.example - copy to .env and fill in\nSTRIPE_KEY=sk_test_EXAMPLE\nGITHUB_TOKEN=ghp_example_token_replace_me\n";
    assert_clean(".env.example", f);
}

#[test]
fn git_commit_sha_is_not_a_secret() {
    let f = "commit 9fceb02d0ae598e95dc970b74767f19372d61af8\nAuthor: dev\n";
    assert_clean("git-log.txt", f);
}

#[test]
fn uuid_is_not_a_secret() {
    let f = "request_id = 550e8400-e29b-41d4-a716-446655440000\n";
    assert_clean("app.toml", f);
}

#[test]
fn prose_readme_is_clean() {
    let f = "# keyhog\nA fast secret scanner. Configure via environment variables.\nSee the docs for the full list of options.\n";
    assert_clean("README.md", f);
}
